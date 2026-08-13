import { z } from 'zod';

/**
 * Environment configuration, zod-validated so the process fails fast on a bad
 * deployment instead of limping into runtime errors.
 *
 * KMS_MODE selects the KMS backend; KMS_MASTER_KEY_HEX drives the
 * LocalKmsProvider half of it and is a DEV/TEST convenience
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
    // Production KMS: the KMS key id/alias/ARN that wraps this domain's DEKs,
    // plus its region. Required when KMS_MODE is "aws".
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
    // Inbound credential for THIS service's internal routes (the M7
    // settlement-lock API). Named for the CALLEE, not the caller: the value
    // opens identity's account-lock API and nothing else, so only a service
    // that must lock accounts (settlement) ever holds it.
    //
    // The M7 security review found the earlier name — SETTLEMENT_INTERNAL_TOKEN,
    // shared with settlement's own inbound credential — collapsed four services
    // onto one secret, handing vault and documents a working key to this API.
    // One secret per callee, per direction.
    //
    // Optional in dev/test: unset means ServiceCredentialGuard fails closed and
    // refuses every internal call. REQUIRED (and non-trivial) in production —
    // docs/03 §5.1's account lock must not be silently unreachable.
    IDENTITY_INTERNAL_TOKEN: z.string().optional(),
    // Base URL of the notifications service. Identity feeds its recipient
    // store at registration and login — the two moments the user themselves
    // supplies the plaintext address — which is why NO service anywhere needs
    // an email-ciphertext read path (M9). Required in production: recipients
    // that never populate would silently starve the M6/M7 waiting-period
    // notifications.
    NOTIFICATIONS_URL: z.string().url().optional(),
    // OUTBOUND: what this service PRESENTS to the notifications service's
    // RECIPIENT-UPSERT route — the only notifications route identity uses, and
    // one it is the sole holder of (credential-graph.ts). Deliberately NOT the
    // send credential: identity never sends, and the M9 security review found
    // one secret opening both, which handed vault and settlement the power to
    // repoint any owner's alerts. Optional in dev/test — the client
    // short-circuits to a no-op while unset.
    NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M14): what this service PRESENTS to the notifications
    // VERIFICATION-SEND route, to mail an address-verification code it minted.
    // Identity is the sole holder, and it is a THIRD secret rather than a reuse
    // of either neighbour: not the send credential, because identity must not
    // be able to fire an estate alarm ("a death report was filed on your
    // account"); not the recipients credential, because that one can REPOINT an
    // address while this can only mail to whatever is already stored, so the
    // first future holder of a resend capability does not inherit the power the
    // M9 review split out.
    NOTIFICATIONS_VERIFY_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M14): what this service PRESENTS to the notifications
    // RECIPIENT-STATUS read route, to learn whether an address has been proved.
    // Identity reads it to decide whether to mint a code at login and to answer
    // the settings page; vault and profile join as holders in PR2, where the
    // two ARMING gates start asking.
    NOTIFICATIONS_STATUS_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M17): what this service PRESENTS to the notifications
    // ACCOUNT-SECURITY route, to tell a user their account's credentials
    // changed. A FOURTH outbound secret rather than a reuse: not the send
    // credential (identity must not be able to fire an estate alarm), and not
    // the verification one, because that mails a caller-minted code and the
    // first future holder of a resend capability must not thereby gain the
    // ability to announce credential changes — the message an attacker would
    // most like to be able to send.
    NOTIFICATIONS_SECURITY_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M17 PR3): presented to the notifications PASSWORD-RESET route.
    // A FIFTH outbound secret, and the most powerful: what it mails can be
    // redeemed with no session, so a holder who also reads the mailbox owns the
    // account. Kept off the verification credential for exactly that difference.
    NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN: z.string().optional(),
    // M17 PR4: presented to the EMAIL-CHANGE route — the one send whose
    // payload names a destination, so identity is its only legitimate holder.
    NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN: z.string().optional(),
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
    if (
      env.NODE_ENV === 'production' &&
      (!env.IDENTITY_INTERNAL_TOKEN || env.IDENTITY_INTERNAL_TOKEN.length < 32)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['IDENTITY_INTERNAL_TOKEN'],
        message:
          'IDENTITY_INTERNAL_TOKEN is required in production (>= 32 chars; the settlement account-lock must not be unreachable or weakly guarded)',
      });
    }
    if (env.NODE_ENV === 'production') {
      if (!env.NOTIFICATIONS_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['NOTIFICATIONS_URL'],
          message:
            'NOTIFICATIONS_URL is required in production (an unfed recipient store silently starves the M6/M7 owner notifications)',
        });
      }
      const required = [
        [
          'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN',
          'recipient upserts must not be silently unauthenticated',
        ],
        [
          'NOTIFICATIONS_VERIFY_INTERNAL_TOKEN',
          'unwired, no verification code is ever mailed and every arming gate refuses forever',
        ],
        [
          'NOTIFICATIONS_STATUS_INTERNAL_TOKEN',
          'unwired, identity cannot tell a verified address from an unverified one and stops asking',
        ],
        [
          'NOTIFICATIONS_SECURITY_INTERNAL_TOKEN',
          'unwired, a password change is silent — the one notice whose absence an attacker relies on',
        ],
        [
          'NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN',
          'unwired, no reset code is ever mailed and a forgotten password is unrecoverable',
        ],
        [
          'NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN',
          'unwired, no change challenge is ever mailed and a mistyped address is permanent (§6h)',
        ],
      ] as const;
      for (const [key, why] of required) {
        const token = env[key];
        if (!token || token.length < 32) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (>= 32 chars; ${why})`,
          });
        }
      }
      // A FULL PAIRWISE LOOP over every credential this service touches — its
      // own inbound one and its six outbound ones. One value must never
      // authenticate two directions (the M7 collapse), and splitting the fields
      // cannot stop one value being pasted into several slots. Derived from the
      // list rather than written pair by pair, because the hand-written form
      // stays correct only until the next credential lands: this check was a
      // single `if` when there were two, and M14 added two more.
      const touched = [
        'IDENTITY_INTERNAL_TOKEN',
        'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN',
        'NOTIFICATIONS_VERIFY_INTERNAL_TOKEN',
        'NOTIFICATIONS_STATUS_INTERNAL_TOKEN',
        'NOTIFICATIONS_SECURITY_INTERNAL_TOKEN',
        'NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN',
        'NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN',
      ] as const;
      for (let i = 0; i < touched.length; i += 1) {
        for (let j = i + 1; j < touched.length; j += 1) {
          const a = touched[i]!;
          const b = touched[j]!;
          if (env[a] && env[a] === env[b]) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: [b],
              message: `${b} must differ from ${a} (sharing one value collapses two capability boundaries into one, which is the M7 failure)`,
            });
          }
        }
      }
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

export interface IdentityConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  /** Selected KMS backend (LocalKmsProvider in dev/test, AWS KMS in prod). */
  readonly kms: KmsConfig;
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
  /** Inbound credential for THIS service's internal routes ('' ⇒ refuse all). */
  readonly internalApiToken: string;
  /** Notifications service base URL (recipient-store feed; M9). */
  readonly notificationsUrl: string;
  /** OUTBOUND: what this service presents to the notifications RECIPIENT
   * routes ('' ⇒ the client short-circuits to a no-op). Never the inbound
   * value. */
  readonly notificationsInternalToken: string;
  /** OUTBOUND: presented to the notifications VERIFICATION-SEND route (M14). */
  readonly notificationsVerifyToken: string;
  /** OUTBOUND: presented to the notifications RECIPIENT-STATUS route (M14). */
  readonly notificationsStatusToken: string;
  /** OUTBOUND: presented to the notifications EMAIL-CHANGE route (M17 PR4). */
  readonly notificationsEmailChangeToken: string;
  /** OUTBOUND: presented to the notifications ACCOUNT-SECURITY route (M17). */
  readonly notificationsSecurityToken: string;
  /** OUTBOUND: presented to the notifications PASSWORD-RESET route (M17 PR3). */
  readonly notificationsRecoveryToken: string;
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
    kekAlias: 'local/auth-kek',
    // Dev/test localhost fallbacks; production is guaranteed non-default by the
    // superRefine guard above (which fails fast when these are unset in prod).
    rpId: e.RP_ID ?? 'localhost',
    rpOrigin: e.RP_ORIGIN ?? 'http://localhost:3000',
    rpName: e.RP_NAME ?? 'Estate Platform',
    internalApiToken: e.IDENTITY_INTERNAL_TOKEN ?? '',
    notificationsUrl: e.NOTIFICATIONS_URL ?? 'http://localhost:3008',
    notificationsInternalToken: e.NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN ?? '',
    notificationsVerifyToken: e.NOTIFICATIONS_VERIFY_INTERNAL_TOKEN ?? '',
    notificationsStatusToken: e.NOTIFICATIONS_STATUS_INTERNAL_TOKEN ?? '',
    notificationsSecurityToken: e.NOTIFICATIONS_SECURITY_INTERNAL_TOKEN ?? '',
    notificationsRecoveryToken: e.NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN ?? '',
    notificationsEmailChangeToken: e.NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN ?? '',
  };
}
