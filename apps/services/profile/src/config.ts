import { z } from 'zod';

/**
 * Environment configuration for the Profile & Contacts service, zod-validated
 * so the process fails fast on a bad deployment instead of limping into
 * runtime errors. Mirrors the identity service's config posture exactly.
 *
 * KMS_MODE selects the KMS backend; KMS_MASTER_KEY_HEX drives the
 * LocalKmsProvider half of it and is a DEV/TEST convenience
 * only — production uses the AWS KMS adapter (CloudHSM-backed KEKs, IAM-scoped
 * grants) instead, enforced by the production guard below. The core cluster's
 * DEKs are wrapped under a dedicated KEK alias ('core/kek') so a compromise of
 * one domain's KEK never unwraps another's data keys.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3002),
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
    // Production KMS: the KMS key id/alias/ARN that wraps the core cluster's
    // DEKs, plus its region. Required when KMS_MODE is "aws".
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // Endpoint override for the AWS SDK client. Unset means real AWS.
    //
    // The SDK already honours this variable ambiently, so we deliberately
    // read the SAME name rather than inventing one: when it is SET the value we
    // pass explicitly wins, so ours and the SDK's resolution cannot disagree.
    // Reading it here is what makes the production TLS guard below possible at
    // all.
    //
    // Precisely scoped, because an earlier phrasing here overclaimed "can never
    // disagree": when this is UNSET we pass no endpoint and the SDK resolves
    // ambiently, which includes the per-service overrides
    // (`AWS_ENDPOINT_URL_KMS` and friends) and `endpoint_url` in an AWS config
    // file. Those take precedence and the guard below never sees them. The
    // local stack's preflight refuses them outright; the production residual is
    // recorded in docs/05.
    AWS_ENDPOINT_URL: z.string().url().optional(),
    // 32-byte HMAC key for the contact email blind index (equality lookup
    // without decryption). SSNs deliberately get no blind index (docs/02 §8).
    EMAIL_INDEX_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'EMAIL_INDEX_KEY_HEX must be 32 bytes of hex (64 chars)'),
    // Comma-separated broker list. Optional in dev/test (audit emission falls
    // back to an injectable no-op producer); REQUIRED in production — audit is
    // a hard dependency of every sensitive action, so production without Kafka
    // must fail fast at startup rather than silently drop audit events.
    KAFKA_BROKERS: z.string().optional(),
    // Base URL of the identity service, for cross-service session verification
    // (CallerGuard introspects the caller's token). Required IN production; dev
    // defaults to localhost.
    IDENTITY_URL: z.string().url().optional(),
    // Base URL of the settlement service. Profile asks it ONE question, on the
    // caller's own forwarded bearer: does an approved DOCUMENTS stage let this
    // executor read the estate's contacts (docs/03 §5.1 control 5). Required
    // IN production; dev defaults to localhost. The client fails closed, so a
    // wrong value disables executor reads rather than widening them — which is
    // the property that makes a default safe here at all.
    SETTLEMENT_URL: z.string().url().optional(),
    /*
     * OWNER NOTIFICATIONS for the M13 contact link ceremony. Profile's first
     * outbound service credential, and its first peer of any kind.
     *
     * Production PINS the real adapter by NAMING THE STUB, so a third mode
     * cannot be silently admitted (the M10 rule). The reason it is a hard
     * requirement rather than a preference: redemption REFUSES in production
     * behind an adapter that reaches nobody, because a link claimed silently is
     * how somebody who obtained a code acquires a docs/03 §5.1 reporter
     * capability with the owner never hearing about it.
     */
    NOTIFY_MODE: z.enum(['stub', 'http']).default('stub'),
    NOTIFICATIONS_URL: z.string().url().optional(),
    // OUTBOUND: presented to the notifications service's SEND route and nothing
    // else (credential-graph.ts). Profile is deliberately NOT a holder of the
    // recipients credential — it has no business repointing where anybody's
    // notifications go, which is the split the M9 review forced.
    NOTIFICATIONS_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M14): what this service PRESENTS to the notifications
    // RECIPIENT-STATUS read route, to ask — at MINT time only — whether the
    // owner has proved the address a link claim would be announced to. A
    // different secret from the send one: reading delivery state is a
    // different capability with different legitimate holders
    // (credential-graph.ts). Unwired, the mint gate refuses, which is the
    // fail-closed direction.
    NOTIFICATIONS_STATUS_INTERNAL_TOKEN: z.string().optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && env.NOTIFY_MODE === 'stub') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['NOTIFY_MODE'],
        message:
          'NOTIFY_MODE must not be "stub" in production (the stub notifier reaches nobody, and link redemption refuses behind it)',
      });
    }
    if (env.NOTIFY_MODE === 'http' && !env.NOTIFICATIONS_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['NOTIFICATIONS_URL'],
        message: 'NOTIFICATIONS_URL is required when NOTIFY_MODE is "http"',
      });
    }
    if (env.NODE_ENV === 'production') {
      if (!env.NOTIFICATIONS_INTERNAL_TOKEN || env.NOTIFICATIONS_INTERNAL_TOKEN.length < 32) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_INTERNAL_TOKEN'],
          message:
            'NOTIFICATIONS_INTERNAL_TOKEN is required in production (>= 32 chars; an owner who is never told a link was claimed cannot remove it)',
        });
      }
      if (
        !env.NOTIFICATIONS_STATUS_INTERNAL_TOKEN ||
        env.NOTIFICATIONS_STATUS_INTERNAL_TOKEN.length < 32
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_STATUS_INTERNAL_TOKEN'],
          message:
            'NOTIFICATIONS_STATUS_INTERNAL_TOKEN is required in production (>= 32 chars; unwired, no link code can ever be minted because the M14 gate fails closed)',
        });
      }
      // Profile's two notifications credentials must never be one value: the
      // send edge is broadly held and the status edge is not, so collapsing
      // them would hand settlement and vault a read they were denied.
      if (
        env.NOTIFICATIONS_INTERNAL_TOKEN &&
        env.NOTIFICATIONS_INTERNAL_TOKEN === env.NOTIFICATIONS_STATUS_INTERNAL_TOKEN
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_STATUS_INTERNAL_TOKEN'],
          message:
            'NOTIFICATIONS_STATUS_INTERNAL_TOKEN must differ from NOTIFICATIONS_INTERNAL_TOKEN (one value opening both surfaces re-creates the over-grant the split exists to remove)',
        });
      }
    }
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

export interface ProfileConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  /** Selected KMS backend (LocalKmsProvider in dev/test, AWS KMS in prod). */
  readonly kms: KmsConfig;
  /** 32-byte HMAC key for the contact email blind index. */
  readonly emailIndexKey: Buffer;
  /** Parsed broker list; null means "no Kafka" (never allowed in production). */
  readonly kafkaBrokers: string[] | null;
  /** KEK alias used when wrapping the core cluster's per-user DEKs. */
  readonly kekAlias: string;
  /** Identity service base URL for cross-service session verification. */
  readonly identityUrl: string;
  /** Settlement base URL — the executor staged-access question (M23 PR4a). */
  readonly settlementUrl: string;
  /** Owner-notification adapter selection (M13 link ceremony). */
  readonly notify: { readonly mode: 'stub' | 'http' };
  readonly notificationsUrl: string;
  /** Empty ⇒ the client short-circuits and every send records as undelivered. */
  readonly notificationsInternalToken: string;
  /** OUTBOUND: presented to the notifications RECIPIENT-STATUS route (M14). */
  readonly notificationsStatusToken: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid profile-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ProfileConfig {
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
    emailIndexKey: Buffer.from(e.EMAIL_INDEX_KEY_HEX, 'hex'),
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    kekAlias: 'core/kek',
    // superRefine requires IDENTITY_URL in production; dev falls back to local.
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    settlementUrl: e.SETTLEMENT_URL ?? 'http://localhost:3007',
    notify: { mode: e.NOTIFY_MODE },
    notificationsUrl: e.NOTIFICATIONS_URL ?? 'http://localhost:3008',
    notificationsInternalToken: e.NOTIFICATIONS_INTERNAL_TOKEN ?? '',
    notificationsStatusToken: e.NOTIFICATIONS_STATUS_INTERNAL_TOKEN ?? '',
  };
}
