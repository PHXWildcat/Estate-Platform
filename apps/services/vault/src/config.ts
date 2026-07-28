import { z } from 'zod';

/**
 * Environment configuration for the Vault service, zod-validated so the process
 * fails fast on a bad deployment instead of limping into runtime errors.
 * Mirrors the documents/assets/plaid services' config posture.
 *
 * Notice what is NOT here: no KMS key, no master key, no index key. Zone A
 * means every sensitive value arrives already encrypted by the user's device
 * (docs/01 §1), so this service holds no key material and has no KMS grant to
 * scope. If a future change adds one, that is a zone boundary moving and
 * belongs in a design discussion, not a config field.
 */

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3006),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production - audit is a hard dependency of every sensitive action.
    KAFKA_BROKERS: z.string().optional(),
    // Base URL of the identity service, for cross-service session verification
    // (CallerGuard/StepUpGuard introspect the caller's token). Required IN
    // production; dev defaults to localhost.
    IDENTITY_URL: z.string().url().optional(),
    // Owner-notification channel for emergency access (docs/03 §5.2). Only the
    // stub exists today; real channels arrive with the notifications
    // milestone, and a real mode joins this enum then. Deliberately NOT a
    // boot-time production requirement - that would take the whole vault down
    // for a feature most users never arm. Instead the emergency-access routes
    // refuse in production while only the stub is wired (see
    // EmergencyAccessService), so the failure is scoped to the flow whose
    // safety actually depends on it.
    NOTIFY_MODE: z.enum(['stub']).default('stub'),
    // Base URL of the settlement service (M7 PR2, docs/03 §6a): emergency
    // access is the LAST staged grant of a settlement, so release consults it.
    // Required IN production; dev defaults to localhost.
    SETTLEMENT_URL: z.string().url().optional(),
    // Service credential PRESENTED TO settlement for that gate. The question is
    // about the OWNER's settlement state, not the calling grantee's authority,
    // so it cannot ride on a user bearer. Unset ⇒ the client blocks locally,
    // which keeps Zone A closed rather than open.
    //
    // Named for the CALLEE (ServiceCredentialGuard's one-secret-per-callee
    // rule): this value opens settlement's read-only gate route and NOTHING
    // else. It is deliberately NOT the value settlement presents to identity —
    // the M7 security review found that collapse, which would have let anyone
    // holding this vault secret call identity's account-lock API and entomb a
    // living user.
    SETTLEMENT_INTERNAL_TOKEN: z.string().optional(),
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
    if (env.NODE_ENV === 'production' && !env.SETTLEMENT_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SETTLEMENT_URL'],
        message: 'SETTLEMENT_URL is required in production (the docs/03 §6a emergency-access gate)',
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
          'SETTLEMENT_INTERNAL_TOKEN is required in production (>= 32 chars; without it the settlement gate blocks every release)',
      });
    }
  });

/** Which adapter delivers emergency-access notifications to the owner. */
export type NotifyConfig = { readonly mode: 'stub' };

export interface VaultConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kafkaBrokers: string[] | null;
  /** Identity service base URL for cross-service session verification. */
  readonly identityUrl: string;
  readonly notify: NotifyConfig;
  /** Settlement base URL for the docs/03 §6a emergency-access gate. */
  readonly settlementUrl: string;
  /**
   * Credential presented to SETTLEMENT's gate route ('' ⇒ the client blocks
   * locally). Opens that one read-only route; confers no other authority.
   */
  readonly settlementInternalToken: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only - never env values.
    super(`invalid vault-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): VaultConfig {
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
    notify: { mode: e.NOTIFY_MODE },
    settlementUrl: e.SETTLEMENT_URL ?? 'http://localhost:3007',
    settlementInternalToken: e.SETTLEMENT_INTERNAL_TOKEN ?? '',
  };
}
