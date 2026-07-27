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
  };
}
