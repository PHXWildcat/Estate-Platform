import { z } from 'zod';

/**
 * Environment configuration for the Settlement service, zod-validated so the
 * process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the vault/documents services' config posture.
 *
 * Notice what is NOT here: no KMS key, no master key. PR1 stores no ciphertext
 * — cases carry IDs, enums, and timestamps only. PR2's encrypted distribution
 * amounts bring a dedicated 'settlement/kek' + settlement_deks (the plaid_deks
 * precedent), and the KMS config arrives with that feature, not before.
 */

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
  };
}
