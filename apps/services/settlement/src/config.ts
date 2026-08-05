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
    // TWO credentials, deliberately distinct — one per direction. The M7
    // security review found that using a single value for both collapsed four
    // services onto one secret: because settlement's inbound-expected value
    // and its outbound-presented value were the same string, vault's copy was
    // necessarily identical to identity's expected value, handing the Zone A
    // service (and documents) a working key to identity's irreversible
    // account-lock API. Each secret now opens exactly one callee's routes.
    //
    // INBOUND: what THIS service expects on its own internal routes (the
    // docs/03 §6a vault-release gate). Held by vault. Opens a read-only
    // authority answer and nothing else.
    SETTLEMENT_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND: what this service PRESENTS to identity's internal
    // settlement-lock routes. Held by settlement alone; this is the value that
    // can lock an account, so it must never be handed to another service.
    // Optional in dev/test — identity's guard fails closed while unset, so the
    // lock-touching transitions (approve, void, verify) refuse until both
    // sides are provisioned. REQUIRED in production: docs/03 §5.1 control 4
    // must not be silently unreachable.
    IDENTITY_INTERNAL_TOKEN: z.string().optional(),
    // Owner-contact channel (docs/03 §5.1 control 3). 'http' (M9) delegates
    // to the notifications service, which owns address resolution and the
    // closed template registry — this service keeps its no-email-lookup
    // boundary. Production now PINS 'http': the earlier "not a boot-time
    // requirement" stance predated a real adapter existing (the KMS/clamd/OCR
    // rule). The per-route 503 gates REMAIN as defense in depth.
    NOTIFY_MODE: z.enum(['stub', 'http']).default('stub'),
    // Base URL of the notifications service; required whenever NOTIFY_MODE is
    // 'http'.
    NOTIFICATIONS_URL: z.string().url().optional(),
    // OUTBOUND: presented to the notifications service's internal routes
    // (send + recipient-upsert and nothing else; credential-graph.ts). The
    // THIRD credential this service touches — distinct from both its own
    // inbound value and the identity account-lock value it presents.
    NOTIFICATIONS_INTERNAL_TOKEN: z.string().optional(),
    // Interval for the in-process workflow driver's contact-attempt sweep.
    // The driver never transitions case state — it only records/sends due
    // contact attempts — so this is a liveness knob, not a safety one.
    DRIVER_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
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
    // Production KMS: the key that wraps THIS service's DEKs (never profile's
    // 'core/kek'), plus its region.
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
    if (env.NODE_ENV === 'production') {
      const credentials = [
        ['SETTLEMENT_INTERNAL_TOKEN', 'the docs/03 §6a vault-release gate'],
        ['IDENTITY_INTERNAL_TOKEN', "identity's docs/03 §5.1 account lock"],
      ] as const;
      for (const [key, purpose] of credentials) {
        const value = env[key];
        if (!value || value.length < 32) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (>= 32 chars; ${purpose} must not be unreachable or weakly guarded)`,
          });
        }
      }
      // The whole point of splitting them: one value must never authenticate
      // both directions, or the collapse the M7 review found returns.
      if (
        env.SETTLEMENT_INTERNAL_TOKEN &&
        env.SETTLEMENT_INTERNAL_TOKEN === env.IDENTITY_INTERNAL_TOKEN
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['IDENTITY_INTERNAL_TOKEN'],
          message:
            'IDENTITY_INTERNAL_TOKEN must differ from SETTLEMENT_INTERNAL_TOKEN (sharing one value hands every gate caller a key to the account-lock API)',
        });
      }
      if (env.NOTIFY_MODE !== 'http') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFY_MODE'],
          message:
            'NOTIFY_MODE must be "http" in production (the stub notifier reaches nobody; a real adapter exists as of M9)',
        });
      }
      if (!env.NOTIFICATIONS_INTERNAL_TOKEN || env.NOTIFICATIONS_INTERNAL_TOKEN.length < 32) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_INTERNAL_TOKEN'],
          message:
            'NOTIFICATIONS_INTERNAL_TOKEN is required in production (>= 32 chars; unreachable owner contact hollows out the §5.1 waiting period)',
        });
      }
      // Three credentials touch this service; no two may share a value.
      for (const [other, label] of [
        ['SETTLEMENT_INTERNAL_TOKEN', 'SETTLEMENT_INTERNAL_TOKEN'],
        ['IDENTITY_INTERNAL_TOKEN', 'IDENTITY_INTERNAL_TOKEN'],
      ] as const) {
        if (env.NOTIFICATIONS_INTERNAL_TOKEN && env.NOTIFICATIONS_INTERNAL_TOKEN === env[other]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['NOTIFICATIONS_INTERNAL_TOKEN'],
            message: `NOTIFICATIONS_INTERNAL_TOKEN must differ from ${label} (one value must never open two callees)`,
          });
        }
      }
    }
    if (env.NOTIFY_MODE === 'http' && !env.NOTIFICATIONS_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['NOTIFICATIONS_URL'],
        message: 'NOTIFICATIONS_URL is required when NOTIFY_MODE is "http"',
      });
    }
  });

/** Which adapter delivers settlement notifications to the owner. */
export type NotifyConfig = { readonly mode: 'stub' } | { readonly mode: 'http' };

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | {
      readonly mode: 'aws';
      readonly keyId: string;
      readonly region: string;
      /** Non-AWS KMS endpoint (a local emulator); null means real AWS. */
      readonly endpoint: string | null;
    };

export interface SettlementConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kafkaBrokers: string[] | null;
  /** Identity service base URL (session verification + settlement-lock API). */
  readonly identityUrl: string;
  /** INBOUND: what this service expects on its own §6a gate route ('' ⇒ refuse all). */
  readonly internalApiToken: string;
  /** OUTBOUND: what this service presents to identity's account-lock API
   * ('' ⇒ those calls fail closed). Never shared with another service. */
  readonly identityInternalToken: string;
  readonly notify: NotifyConfig;
  /** Notifications service base URL (M9). */
  readonly notificationsUrl: string;
  /** OUTBOUND: presented to the notifications service ('' ⇒ sends record as
   * attempted-not-confirmed). Never either of the other two credentials. */
  readonly notificationsInternalToken: string;
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
    internalApiToken: e.SETTLEMENT_INTERNAL_TOKEN ?? '',
    identityInternalToken: e.IDENTITY_INTERNAL_TOKEN ?? '',
    notify: { mode: e.NOTIFY_MODE },
    notificationsUrl: e.NOTIFICATIONS_URL ?? 'http://localhost:3008',
    notificationsInternalToken: e.NOTIFICATIONS_INTERNAL_TOKEN ?? '',
    driverIntervalMs: e.DRIVER_INTERVAL_MS,
    // The superRefine above guarantees the required fields per environment, so
    // these non-null assertions are sound.
    kms:
      e.KMS_MODE === 'aws'
        ? {
            mode: 'aws',
            keyId: e.AWS_KMS_KEY_ID!,
            region: e.AWS_REGION!,
            endpoint: e.AWS_ENDPOINT_URL ?? null,
          }
        : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') },
    kekAlias: 'settlement/kek',
  };
}
