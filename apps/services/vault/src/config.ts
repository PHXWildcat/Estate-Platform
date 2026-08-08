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
    // Owner-notification channel for emergency access (docs/03 §5.2). 'http'
    // (M9) delegates to the notifications service, which owns address
    // resolution and the closed template registry. Production now PINS 'http'
    // — the earlier "not a boot-time requirement" stance predated a real
    // adapter existing; with one shipped, a production vault running the stub
    // would be a misconfiguration wearing the control's clothes (the
    // KMS/clamd/OCR adapter rule). The per-route 503 gate REMAINS as defense
    // in depth for any future adapter whose capability bit is false.
    NOTIFY_MODE: z.enum(['stub', 'http']).default('stub'),
    // Base URL of the notifications service; required whenever NOTIFY_MODE is
    // 'http'.
    NOTIFICATIONS_URL: z.string().url().optional(),
    // OUTBOUND: presented to the notifications service's internal routes
    // (send + recipient-upsert and nothing else; credential-graph.ts). Unset ⇒
    // the client short-circuits and every send records as undelivered.
    NOTIFICATIONS_INTERNAL_TOKEN: z.string().optional(),
    // OUTBOUND (M14): what this service PRESENTS to the notifications
    // RECIPIENT-STATUS read route, to ask whether the owner has PROVED the
    // address their §5.2 alerts go to. A DIFFERENT secret from the send one
    // above because reading delivery state is a different capability with
    // different legitimate holders — settlement sends and never asks
    // (credential-graph.ts). Without it the arming gates refuse, which is the
    // fail-closed direction.
    NOTIFICATIONS_STATUS_INTERNAL_TOKEN: z.string().optional(),
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
    if (env.NODE_ENV === 'production' && env.NOTIFY_MODE !== 'http') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['NOTIFY_MODE'],
        message:
          'NOTIFY_MODE must be "http" in production (the stub notifier reaches nobody; a real adapter exists as of M9)',
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
            'NOTIFICATIONS_INTERNAL_TOKEN is required in production (>= 32 chars; undelivered owner notifications hollow out the §5.2 waiting period)',
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
            'NOTIFICATIONS_STATUS_INTERNAL_TOKEN is required in production (>= 32 chars; unwired, no escrow can ever arm because the M14 gate fails closed)',
        });
      }
      // A FULL PAIRWISE LOOP over every credential this service touches. One
      // value must never authenticate two callees (the M7 collapse), and a
      // hand-written comparison per pair stays correct only for the arity it
      // was written at — this was a single `if` when vault touched two.
      const touched = [
        'SETTLEMENT_INTERNAL_TOKEN',
        'NOTIFICATIONS_INTERNAL_TOKEN',
        'NOTIFICATIONS_STATUS_INTERNAL_TOKEN',
      ] as const;
      for (let i = 0; i < touched.length; i += 1) {
        for (let j = i + 1; j < touched.length; j += 1) {
          const a = touched[i]!;
          const b = touched[j]!;
          if (env[a] && env[a] === env[b]) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: [b],
              message: `${b} must differ from ${a} (one value must never open two surfaces)`,
            });
          }
        }
      }
    }
  });

/** Which adapter delivers emergency-access notifications to the owner. */
export type NotifyConfig = { readonly mode: 'stub' } | { readonly mode: 'http' };

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
  /** Notifications service base URL (M9). */
  readonly notificationsUrl: string;
  /** OUTBOUND: presented to the notifications service ('' ⇒ sends record as
   * undelivered). Never the settlement value — one secret per callee. */
  readonly notificationsInternalToken: string;
  /** OUTBOUND: presented to the notifications RECIPIENT-STATUS route (M14). */
  readonly notificationsStatusToken: string;
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
    notificationsUrl: e.NOTIFICATIONS_URL ?? 'http://localhost:3008',
    notificationsInternalToken: e.NOTIFICATIONS_INTERNAL_TOKEN ?? '',
    notificationsStatusToken: e.NOTIFICATIONS_STATUS_INTERNAL_TOKEN ?? '',
  };
}
