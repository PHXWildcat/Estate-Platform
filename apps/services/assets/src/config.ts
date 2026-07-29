import { z } from 'zod';

/**
 * Environment configuration for the Asset service, zod-validated so the
 * process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the profile service's config posture exactly.
 *
 * KMS_MODE selects the KMS backend; KMS_MASTER_KEY_HEX drives the
 * LocalKmsProvider half of it and is a DEV/TEST convenience
 * only — production uses the AWS KMS adapter (CloudHSM-backed KEKs, IAM-scoped
 * grants) instead, enforced by the production guard below. The financial
 * cluster's DEKs are wrapped under a dedicated KEK alias ('financial/kek') so
 * a compromise of one domain's KEK never unwraps another's data keys.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3003),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Which KMS backs envelope encryption. 'local' is the in-process
    // LocalKmsProvider (dev/test only); 'aws' is the real KMS adapter.
    // Production REQUIRES 'aws' — see the superRefine below, which keeps the
    // production guarantee exactly as strong as when this was derived from
    // NODE_ENV. Making it an explicit enum, as the other adapter selectors
    // already are, is what lets the AWS adapter be exercised outside
    // production (e.g. against a local KMS emulator) without ever permitting
    // the in-process key in a real deployment.
    KMS_MODE: z.enum(['local', 'aws']).default('local'),
    // Dev/test only: drives LocalKmsProvider. Required when KMS_MODE is
    // 'local'; unused under 'aws', so a real deployment never depends on an
    // in-process master key.
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    // Production KMS: the KMS key id/alias/ARN that wraps the financial
    // cluster's DEKs, plus its region. Required when KMS_MODE is "aws".
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // Endpoint override for the AWS SDK client. Unset means real AWS.
    //
    // The SDK already honours this variable ambiently, so we deliberately
    // read the SAME name rather than inventing one: our explicitly-passed
    // value and the SDK's own resolution can then never disagree. Reading it
    // here is what makes the production TLS guard below possible at all.
    AWS_ENDPOINT_URL: z.string().url().optional(),
    // Comma-separated broker list. Optional in dev/test (audit emission falls
    // back to an injectable no-op producer); REQUIRED in production — audit is
    // a hard dependency of every sensitive action, so production without Kafka
    // must fail fast at startup rather than silently drop audit events.
    KAFKA_BROKERS: z.string().optional(),
    // Base URL of the identity service, for cross-service session verification
    // (CallerGuard/StepUpGuard introspect the caller's token via its
    // /v1/auth/session route). Required IN production; dev defaults to
    // localhost so no config is needed to run the service locally.
    IDENTITY_URL: z.string().url().optional(),
    // Base URL of the settlement service (M7 PR2): the executor estate-read
    // route asks it whether a staged grant permits the caller. Required IN
    // production; dev defaults to localhost. The client fails closed, so a
    // wrong value disables executor reads rather than widening them.
    SETTLEMENT_URL: z.string().url().optional(),
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
      // Production must use AWS KMS (CloudHSM-rooted KEKs). The in-process
      // LocalKmsProvider is never permitted outside dev/test.
      if (env.KMS_MODE !== 'aws') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['KMS_MODE'],
          message: 'KMS_MODE must be "aws" in production (LocalKmsProvider is dev/test only)',
        });
      }
      // A plaintext endpoint would put wrapped DEKs on the wire in the clear.
      // The SDK performs no such check on the variable.
      if (env.AWS_ENDPOINT_URL && !env.AWS_ENDPOINT_URL.startsWith('https://')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AWS_ENDPOINT_URL'],
          message:
            'AWS_ENDPOINT_URL must be https in production (KMS traffic must not be plaintext)',
        });
      }
      if (!env.IDENTITY_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['IDENTITY_URL'],
          message: 'IDENTITY_URL is required in production (cross-service session verification)',
        });
      }
      if (!env.SETTLEMENT_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SETTLEMENT_URL'],
          message: 'SETTLEMENT_URL is required in production (executor staged-access checks)',
        });
      }
    }
    // Mode-conditional requirements, enforced in EVERY environment — the
    // shape the other adapter selectors already use. Combined with the
    // production pin above, production still requires exactly AWS_KMS_KEY_ID
    // + AWS_REGION and still cannot reach LocalKmsProvider.
    if (env.KMS_MODE === 'aws') {
      for (const key of ['AWS_KMS_KEY_ID', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when KMS_MODE is "aws"`,
          });
        }
      }
    } else if (!env.KMS_MASTER_KEY_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KMS_MASTER_KEY_HEX'],
        message:
          'KMS_MASTER_KEY_HEX is required when KMS_MODE is "local" (drives LocalKmsProvider)',
      });
    }
  });

/**
 * Which KMS backs envelope encryption. `local` (dev/test) wraps DEKs with an
 * in-process master key; `aws` (production) delegates to AWS KMS / CloudHSM.
 */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | {
      readonly mode: 'aws';
      readonly keyId: string;
      readonly region: string;
      /** Non-AWS KMS endpoint (a local emulator); null means real AWS. */
      readonly endpoint: string | null;
    };

export interface AssetsConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  /** Selected KMS backend (LocalKmsProvider in dev/test, AWS KMS in prod). */
  readonly kms: KmsConfig;
  /** Parsed broker list; null means "no Kafka" (never allowed in production). */
  readonly kafkaBrokers: string[] | null;
  /** KEK alias used when wrapping the financial cluster's per-user DEKs. */
  readonly kekAlias: string;
  /** Identity service base URL for cross-service session verification. */
  readonly identityUrl: string;
  /** Settlement base URL for executor staged-access checks (M7 PR2). */
  readonly settlementUrl: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid assets-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AssetsConfig {
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
  // The superRefine above guarantees the required fields per environment, so
  // these non-null assertions are sound.
  const kms: KmsConfig =
    e.KMS_MODE === 'aws'
      ? {
          mode: 'aws',
          keyId: e.AWS_KMS_KEY_ID!,
          region: e.AWS_REGION!,
          endpoint: e.AWS_ENDPOINT_URL ?? null,
        }
      : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') };
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    kms,
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    kekAlias: 'financial/kek',
    // superRefine requires IDENTITY_URL in production; dev falls back to local.
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    settlementUrl: e.SETTLEMENT_URL ?? 'http://localhost:3007',
  };
}
