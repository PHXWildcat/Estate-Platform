import { z } from 'zod';

/**
 * Environment configuration for the Notifications service, zod-validated so
 * the process fails fast on a bad deployment (the settlement/vault posture).
 *
 * This service is the isolating boundary for delivery carriers (docs/01
 * §2.10, TB5): SES credentials and the SES SDK exist only here. Its one piece
 * of Zone B data — the recipient address store — is encrypted under the
 * DEDICATED 'notifications/kek' alias backed by `notification_deks`, so the
 * core cluster's other tenants (profile, settlement) can never unwrap an
 * address (docs/03 §5.3: the grant, not the database, is the chokepoint).
 *
 * EMAIL_MODE follows the scan/OCR/KMS adapter rule: production PINS the real
 * carrier. A notifications service running the stub in production would make
 * every caller's `deliversToRealChannels` bit a lie and silently hollow out
 * the M6/M7 waiting-period controls — exactly the fail-open-in-style failure
 * the M4 scan gate taught.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3008),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production — every send and every recipient change is an audited action.
    KAFKA_BROKERS: z.string().optional(),
    // INBOUND #1 — SENDING. Held by vault + settlement. Lets a holder fire one
    // of nine closed template kinds at a user; the wire has no text field, so
    // it chooses neither the words nor the destination (credential-graph.ts).
    NOTIFICATIONS_INTERNAL_TOKEN: z.string().optional(),
    // INBOUND #2 — RECIPIENTS. Held by IDENTITY ALONE, and deliberately a
    // different secret from the one above: this one decides WHERE a user's
    // notifications go, so a holder can silence the §5.1 contact sweep and the
    // §5.2 emergency-access alerts by pointing them at their own mailbox. The
    // M9 security review found both surfaces behind one secret, which handed
    // that power to vault and settlement, which only ever send.
    NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: z.string().optional(),
    // Which carrier delivers email. 'stub' records without delivering
    // (dev/test); 'ses' is the real adapter. Production REQUIRES 'ses' — see
    // the superRefine below.
    EMAIL_MODE: z.enum(['stub', 'ses']).default('stub'),
    // The verified SES sender identity. Required whenever EMAIL_MODE is 'ses'.
    SES_FROM_ADDRESS: z.string().email().optional(),
    // Which KMS backs envelope encryption for the recipient store.
    KMS_MODE: z.enum(['local', 'aws']).default('local'),
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    // Region for the AWS SDK clients (KMS and SES share it).
    AWS_REGION: z.string().min(1).optional(),
    // Endpoint override for the AWS SDK clients. Unset means real AWS. Same
    // name the SDK honours ambiently, same precisely-scoped caveat as every
    // other service: per-service overrides (AWS_ENDPOINT_URL_SES and friends)
    // resolve ahead of this when it is unset; the stack preflight refuses
    // them, production does not (recorded in docs/05).
    AWS_ENDPOINT_URL: z.string().url().optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production') {
      if (!env.KAFKA_BROKERS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['KAFKA_BROKERS'],
          message: 'KAFKA_BROKERS is required in production (audit emission must not be a no-op)',
        });
      }
      if (env.EMAIL_MODE !== 'ses') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['EMAIL_MODE'],
          message:
            'EMAIL_MODE must be "ses" in production (a stub carrier would silently hollow out the M6/M7 waiting-period controls)',
        });
      }
      if (env.KMS_MODE !== 'aws') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['KMS_MODE'],
          message: 'KMS_MODE must be "aws" in production (LocalKmsProvider is dev/test only)',
        });
      }
      if (env.AWS_ENDPOINT_URL && !env.AWS_ENDPOINT_URL.startsWith('https://')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AWS_ENDPOINT_URL'],
          message:
            'AWS_ENDPOINT_URL must be https in production (KMS and SES traffic must not be plaintext)',
        });
      }
      const credentials = [
        ['NOTIFICATIONS_INTERNAL_TOKEN', 'an open send surface is a phishing primitive'],
        [
          'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN',
          "an open recipient surface lets anyone redirect an owner's alerts",
        ],
      ] as const;
      for (const [key, why] of credentials) {
        const token = env[key];
        if (!token || token.length < 32) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (>= 32 chars; ${why})`,
          });
        }
      }
      // Splitting the surfaces buys nothing if one value is pasted into both
      // slots — the same reasoning settlement's config applies to its four.
      if (
        env.NOTIFICATIONS_INTERNAL_TOKEN &&
        env.NOTIFICATIONS_INTERNAL_TOKEN === env.NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN'],
          message:
            'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN must differ from NOTIFICATIONS_INTERNAL_TOKEN (one value opening both surfaces re-creates the over-grant the split exists to remove)',
        });
      }
    }
    if (env.EMAIL_MODE === 'ses') {
      if (!env.SES_FROM_ADDRESS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SES_FROM_ADDRESS'],
          message: 'SES_FROM_ADDRESS is required when EMAIL_MODE is "ses" (the verified sender)',
        });
      }
      if (!env.AWS_REGION) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AWS_REGION'],
          message: 'AWS_REGION is required when EMAIL_MODE is "ses"',
        });
      }
    }
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

/** Which carrier delivers email. */
export type EmailConfig =
  | { readonly mode: 'stub' }
  | {
      readonly mode: 'ses';
      readonly fromAddress: string;
      readonly region: string;
      /** Non-AWS endpoint (LocalStack); null means real AWS. */
      readonly endpoint: string | null;
    };

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | {
      readonly mode: 'aws';
      readonly keyId: string;
      readonly region: string;
      readonly endpoint: string | null;
    };

export interface NotificationsConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kafkaBrokers: string[] | null;
  /** INBOUND: what this service expects on its SEND route ('' ⇒ refuse all). */
  readonly internalApiToken: string;
  /** INBOUND: what it expects on the RECIPIENT-UPSERT route, held by identity
   * alone ('' ⇒ refuse all). Never equal to the send credential. */
  readonly recipientsApiToken: string;
  readonly email: EmailConfig;
  readonly kms: KmsConfig;
  /** KEK alias wrapping THIS service's per-user DEKs (never 'core/kek'). */
  readonly kekAlias: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid notifications-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): NotificationsConfig {
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
    internalApiToken: e.NOTIFICATIONS_INTERNAL_TOKEN ?? '',
    recipientsApiToken: e.NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN ?? '',
    // The superRefine above guarantees the required fields per mode, so these
    // non-null assertions are sound.
    email:
      e.EMAIL_MODE === 'ses'
        ? {
            mode: 'ses',
            fromAddress: e.SES_FROM_ADDRESS!,
            region: e.AWS_REGION!,
            endpoint: e.AWS_ENDPOINT_URL ?? null,
          }
        : { mode: 'stub' },
    kms:
      e.KMS_MODE === 'aws'
        ? {
            mode: 'aws',
            keyId: e.AWS_KMS_KEY_ID!,
            region: e.AWS_REGION!,
            endpoint: e.AWS_ENDPOINT_URL ?? null,
          }
        : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') },
    kekAlias: 'notifications/kek',
  };
}
