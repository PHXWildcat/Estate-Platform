import { z } from 'zod';

/**
 * Environment configuration, zod-validated so the process fails fast on a bad
 * deployment instead of limping into runtime errors.
 *
 * KMS_MASTER_KEY_HEX drives LocalKmsProvider and is a DEV/TEST convenience
 * only — it MUST be replaced by the AWS KMS adapter (CloudHSM-backed KEKs,
 * IAM-scoped grants) before any real deployment. The production guard below
 * enforces that Kafka is configured; a matching guard for the KMS adapter
 * lands with that adapter.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3001),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)'),
    EMAIL_INDEX_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'EMAIL_INDEX_KEY_HEX must be 32 bytes of hex (64 chars)'),
    // Comma-separated broker list. Optional in dev/test (audit emission falls
    // back to an injectable no-op producer); REQUIRED in production — audit is
    // a hard dependency of every sensitive action, so production without
    // Kafka must fail fast at startup rather than silently drop audit events.
    KAFKA_BROKERS: z.string().optional(),
    // WebAuthn Relying Party identity. Optional in dev/test (localhost defaults
    // applied in loadConfig); REQUIRED in production — a wrong RP ID/origin
    // silently breaks every passkey ceremony and, worse, weakens the origin
    // binding that anchors WebAuthn's phishing resistance, so production must
    // fail fast rather than fall back to a localhost default.
    RP_ID: z.string().min(1).optional(),
    RP_ORIGIN: z.string().url().optional(),
    RP_NAME: z.string().min(1).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && !env.KAFKA_BROKERS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KAFKA_BROKERS'],
        message: 'KAFKA_BROKERS is required in production (audit emission must not be a no-op)',
      });
    }
    if (env.NODE_ENV === 'production') {
      for (const key of ['RP_ID', 'RP_ORIGIN', 'RP_NAME'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (WebAuthn must bind to the real RP, never a localhost default)`,
          });
        }
      }
    }
  });

export interface IdentityConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  /** 32-byte master key for LocalKmsProvider (dev/test only — see above). */
  readonly kmsMasterKey: Buffer;
  /** 32-byte HMAC key for email blind indexes. */
  readonly emailIndexKey: Buffer;
  /** Parsed broker list; null means "no Kafka" (never allowed in production). */
  readonly kafkaBrokers: string[] | null;
  /** KEK alias used when wrapping per-user DEKs. */
  readonly kekAlias: string;
  /** WebAuthn RP ID (registrable domain, no scheme/port). Prod must set this. */
  readonly rpId: string;
  /** WebAuthn expected origin (scheme + host + port). Prod must set this. */
  readonly rpOrigin: string;
  /** User-visible RP name shown by the authenticator during ceremonies. */
  readonly rpName: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid identity-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): IdentityConfig {
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
    kmsMasterKey: Buffer.from(e.KMS_MASTER_KEY_HEX, 'hex'),
    emailIndexKey: Buffer.from(e.EMAIL_INDEX_KEY_HEX, 'hex'),
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    kekAlias: 'local/auth-kek',
    // Dev/test localhost fallbacks; production is guaranteed non-default by the
    // superRefine guard above (which fails fast when these are unset in prod).
    rpId: e.RP_ID ?? 'localhost',
    rpOrigin: e.RP_ORIGIN ?? 'http://localhost:3000',
    rpName: e.RP_NAME ?? 'Estate Platform',
  };
}
