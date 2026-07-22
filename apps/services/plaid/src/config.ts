import { z } from 'zod';

/**
 * Environment configuration for the Plaid isolating service, zod-validated so
 * the process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the assets service's config posture.
 *
 * KMS_MASTER_KEY_HEX drives LocalKmsProvider and is a DEV/TEST convenience
 * only — production uses the AWS KMS adapter instead, enforced below. This
 * service's DEKs are wrapped under a DEDICATED KEK alias ('plaid/kek'), never
 * the assets service's 'financial/kek': the KMS grant is the TB5 isolation
 * chokepoint, so a compromise of the asset service can never unwrap a Plaid
 * token DEK.
 *
 * PLAID_MODE selects the gateway. 'stub' is the deterministic in-process
 * sandbox (no credentials exist yet); 'live' talks to Plaid's REST API and
 * requires credentials. Production REQUIRES 'live' — a real deployment can
 * never silently run the stub.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3004),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Dev/test only: drives LocalKmsProvider. Required OUTSIDE production;
    // production uses AWS KMS instead (see AWS_KMS_KEY_ID).
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    // Production KMS: the KMS key id/alias/ARN that wraps THIS service's DEKs
    // (a different key than the asset service's), plus its region.
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // Blind-index key for plaid_items.item_bidx (webhook routing lookup).
    // Required in every environment — the column is NOT NULL.
    ITEM_INDEX_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'ITEM_INDEX_KEY_HEX must be 32 bytes of hex (64 chars)'),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production — audit is a hard dependency of every sensitive action.
    KAFKA_BROKERS: z.string().optional(),
    PLAID_MODE: z.enum(['stub', 'live']).default('stub'),
    PLAID_ENV: z.enum(['sandbox', 'development', 'production']).default('sandbox'),
    PLAID_CLIENT_ID: z.string().min(1).optional(),
    PLAID_SECRET: z.string().min(1).optional(),
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
      for (const key of ['AWS_KMS_KEY_ID', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (LocalKmsProvider is dev/test only)`,
          });
        }
      }
      if (env.PLAID_MODE !== 'live') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['PLAID_MODE'],
          message: 'PLAID_MODE must be "live" in production (the stub gateway is dev/test only)',
        });
      }
    } else if (!env.KMS_MASTER_KEY_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KMS_MASTER_KEY_HEX'],
        message: 'KMS_MASTER_KEY_HEX is required outside production (drives LocalKmsProvider)',
      });
    }
    if (env.PLAID_MODE === 'live') {
      for (const key of ['PLAID_CLIENT_ID', 'PLAID_SECRET'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when PLAID_MODE is "live"`,
          });
        }
      }
    }
  });

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | { readonly mode: 'aws'; readonly keyId: string; readonly region: string };

/** Which Plaid gateway to construct. */
export type PlaidGatewayConfig =
  | { readonly mode: 'stub' }
  | {
      readonly mode: 'live';
      readonly env: 'sandbox' | 'development' | 'production';
      readonly clientId: string;
      readonly secret: string;
    };

export interface PlaidConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kms: KmsConfig;
  readonly kafkaBrokers: string[] | null;
  /** KEK alias wrapping THIS service's per-user DEKs (never 'financial/kek'). */
  readonly kekAlias: string;
  /** HMAC key for the plaid_items.item_bidx blind index. */
  readonly itemIndexKey: Buffer;
  readonly plaid: PlaidGatewayConfig;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid plaid-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): PlaidConfig {
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
  // The superRefine above guarantees the required fields per mode, so these
  // non-null assertions are sound.
  const kms: KmsConfig =
    e.NODE_ENV === 'production'
      ? { mode: 'aws', keyId: e.AWS_KMS_KEY_ID!, region: e.AWS_REGION! }
      : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') };
  const plaid: PlaidGatewayConfig =
    e.PLAID_MODE === 'live'
      ? { mode: 'live', env: e.PLAID_ENV, clientId: e.PLAID_CLIENT_ID!, secret: e.PLAID_SECRET! }
      : { mode: 'stub' };
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    kms,
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    kekAlias: 'plaid/kek',
    itemIndexKey: Buffer.from(e.ITEM_INDEX_KEY_HEX, 'hex'),
    plaid,
  };
}
