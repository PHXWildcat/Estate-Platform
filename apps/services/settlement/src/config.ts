import { z } from 'zod';

/**
 * Environment configuration for the Settlement service, zod-validated so the
 * process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the vault/documents services' config posture.
 *
 * PR2 adds envelope encryption for distribution amounts under a DEDICATED KEK
 * alias ('settlement/kek') backed by `settlement_deks` — the plaid_deks
 * precedent. Profile co-owns this cluster but its KMS grant can never unwrap a
 * distribution amount (docs/03 §5.3: the grant, not the database, is the
 * chokepoint).
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3007),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production — audit is a hard dependency of every sensitive action, and
    // in THIS service the audit trail is itself a docs/03 §5.1 control.
    KAFKA_BROKERS: z.string().optional(),
    // Base URL of the identity service. Used twice: cross-service session
    // verification (CallerGuard/StepUpGuard) AND the settlement-lock internal
    // API (account lock + owner-liveness re-check). Required IN production;
    // dev defaults to localhost.
    IDENTITY_URL: z.string().url().optional(),
    // Shared secret authenticating THIS service on identity's internal
    // settlement-lock routes. Optional in dev/test — identity's guard fails
    // closed while unset, so the lock-touching transitions (approve, void,
    // verify) refuse until both sides are provisioned. REQUIRED (and
    // non-trivial) in production: docs/03 §5.1 control 4 must not be
    // silently unreachable.
    SETTLEMENT_INTERNAL_TOKEN: z.string().optional(),
    // Owner-contact channel (docs/03 §5.1 control 3). Only the stub exists
    // today; real channels arrive with the notifications milestone, and a
    // real mode joins this enum then. Deliberately NOT a boot-time production
    // requirement — instead the intake and review-approve routes refuse in
    // production while only the stub is wired (see SettlementService), the
    // M6 emergency-access precedent: a waiting period nobody can be told
    // about is not a control.
    NOTIFY_MODE: z.enum(['stub']).default('stub'),
    // Interval for the in-process workflow driver's contact-attempt sweep.
    // The driver never transitions case state — it only records/sends due
    // contact attempts — so this is a liveness knob, not a safety one.
    DRIVER_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
    // Dev/test only: drives LocalKmsProvider. Required OUTSIDE production;
    // production uses AWS KMS instead (see AWS_KMS_KEY_ID).
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    // Production KMS: the key that wraps THIS service's DEKs (never profile's
    // 'core/kek'), plus its region.
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && !env.KAFKA_BROKERS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KAFKA_BROKERS'],
        message: 'KAFKA_BROKERS is required in production (audit emission must not be a no-op)',
      });
    }
    if (env.NODE_ENV === 'production' && !env.IDENTITY_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['IDENTITY_URL'],
        message: 'IDENTITY_URL is required in production (cross-service session verification)',
      });
    }
    if (env.NODE_ENV === 'production') {
      // Production must use AWS KMS (CloudHSM-rooted KEKs). The in-process
      // LocalKmsProvider is never permitted outside dev/test.
      for (const key of ['AWS_KMS_KEY_ID', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (LocalKmsProvider is dev/test only)`,
          });
        }
      }
    } else if (!env.KMS_MASTER_KEY_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KMS_MASTER_KEY_HEX'],
        message: 'KMS_MASTER_KEY_HEX is required outside production (drives LocalKmsProvider)',
      });
    }
    if (
      env.NODE_ENV === 'production' &&
      (!env.SETTLEMENT_INTERNAL_TOKEN || env.SETTLEMENT_INTERNAL_TOKEN.length < 32)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SETTLEMENT_INTERNAL_TOKEN'],
        message:
          'SETTLEMENT_INTERNAL_TOKEN is required in production (>= 32 chars; the account lock must not be unreachable or weakly guarded)',
      });
    }
  });

/** Which adapter delivers settlement notifications to the owner. */
export type NotifyConfig = { readonly mode: 'stub' };

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | { readonly mode: 'aws'; readonly keyId: string; readonly region: string };

export interface SettlementConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kafkaBrokers: string[] | null;
  /** Identity service base URL (session verification + settlement-lock API). */
  readonly identityUrl: string;
  /** Shared secret for identity's internal settlement-lock routes ('' ⇒ those calls fail closed). */
  readonly settlementInternalToken: string;
  readonly notify: NotifyConfig;
  readonly driverIntervalMs: number;
  /** Selected KMS backend (LocalKmsProvider in dev/test, AWS KMS in prod). */
  readonly kms: KmsConfig;
  /** KEK alias wrapping THIS service's per-decedent DEKs (never 'core/kek'). */
  readonly kekAlias: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid settlement-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SettlementConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  const e = parsed.data;
  const brokers = e.KAFKA_BROKERS
    ? e.KAFKA_BROKERS.split(',')
        .map((b) => b.trim())
        .filter((b) => b.length > 0)
    : [];
  if (e.NODE_ENV === 'production' && brokers.length === 0) {
    throw new ConfigError(['KAFKA_BROKERS: must list at least one broker in production']);
  }
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    // superRefine requires IDENTITY_URL in production; dev falls back to local.
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    settlementInternalToken: e.SETTLEMENT_INTERNAL_TOKEN ?? '',
    notify: { mode: e.NOTIFY_MODE },
    driverIntervalMs: e.DRIVER_INTERVAL_MS,
    // The superRefine above guarantees the required fields per environment, so
    // these non-null assertions are sound.
    kms:
      e.NODE_ENV === 'production'
        ? { mode: 'aws', keyId: e.AWS_KMS_KEY_ID!, region: e.AWS_REGION! }
        : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') },
    kekAlias: 'settlement/kek',
  };
}
