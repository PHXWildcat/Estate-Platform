import { z } from 'zod';

/**
 * Environment configuration for the AI estate assistant, zod-validated so the
 * process fails fast on a bad deployment (the settlement/notifications
 * posture).
 *
 * This service is the isolating boundary for LLM providers (docs/01 §2.8,
 * docs/03 §4 TB5). Two properties are worth reading the whole file for:
 *
 * 1. It holds NO service credential, inbound or outbound. There is no
 *    `*_INTERNAL_TOKEN` key below and there never should be. It authenticates
 *    its callers on their own bearer via CallerGuard, and reaches assets,
 *    documents and profile by FORWARDING that same bearer — so it can only
 *    ever see what the calling user could already see, and a compromised
 *    assistant replays the sessions it is currently serving rather than
 *    minting new authority. `test/config.spec.ts` asserts the empty holding
 *    against the credential graph, in both directions.
 *
 * 2. Its Zone B data — conversation turns and the estate content quoted inside
 *    them — is encrypted under the DEDICATED 'ai-assistant/kek' alias backed by
 *    `assistant_deks`, so the core cluster's other tenants (profile,
 *    settlement, notifications) can never unwrap a conversation (docs/03 §5.3:
 *    the KMS grant, not the database, is the chokepoint).
 *
 * LLM_MODE follows the adapter rule and, as of M10 PR2, completes the
 * NOTIFY_MODE timeline: the enum carried both modes from the start and the
 * production PIN arrives now, WITH the real adapter, rather than pinning a mode
 * that did not yet exist. Production must run 'anthropic'; the stub reaches no
 * provider and would make an assistant that silently answers from nothing.
 *
 * ANTHROPIC_API_KEY is a THIRD-PARTY credential, not an internal one, and the
 * distinction is the reason this service exists. It holds no `*_INTERNAL_TOKEN`
 * in either direction — nothing here opens another service's routes — while the
 * provider key lives ONLY here, in the isolating service for TB5's newest third
 * party (the Plaid and SES precedent: the SDK and its credentials exist in one
 * namespace and nowhere else).
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3009),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production — every tool invocation and every consent change is an
    // audited action, and this service's audit trail is the only record of
    // what estate data reached a model provider.
    KAFKA_BROKERS: z.string().optional(),

    // Peer services. Every one of these is reached with the CALLER'S bearer,
    // never a service credential, so a wrong value fails closed: the request
    // is refused downstream and nothing widens.
    IDENTITY_URL: z.string().url().optional(),
    ASSETS_URL: z.string().url().optional(),
    DOCUMENTS_URL: z.string().url().optional(),
    PROFILE_URL: z.string().url().optional(),

    // Which gateway answers a turn. 'stub' is deterministic and makes no
    // network call at all; 'anthropic' reaches the live provider.
    LLM_MODE: z.enum(['stub', 'anthropic']).default('stub'),
    // Required whenever LLM_MODE is 'anthropic', in EVERY environment — the
    // shape the KMS and OCR selectors already use. Never defaulted, never
    // logged: ConfigError prints paths and messages only.
    ANTHROPIC_API_KEY: z.string().min(1).optional(),
    /*
     * Server-side refusal fallbacks. Anthropic recommends them for this model,
     * and they turn a safety-classifier refusal into an answer from a fallback
     * model instead of a dead turn.
     *
     * It is a config switch rather than a hardcoded default because it has a
     * TB5 dimension: on a refusal the SAME estate payload is re-run on a
     * DIFFERENT model, so the zero-data-retention requirement must hold for the
     * fallback too. Set 'none' if that contract cannot be evidenced.
     */
    LLM_FALLBACKS: z.enum(['default', 'none']).default('default'),
    /*
     * Deadline for ONE provider call, in milliseconds (the unit the TypeScript
     * SDK uses). Load-bearing rather than hygienic: a turn holds a pooled
     * connection and the conversation's row lock open across every provider
     * hop, so this is what bounds them. The SDK also retries twice by default,
     * so worst-case wall clock is roughly this times the attempt count — size
     * it against the transaction, not against a single hop.
     */
    LLM_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().max(600000).default(60000),

    // Which KMS backs envelope encryption for the conversation store.
    KMS_MODE: z.enum(['local', 'aws']).default('local'),
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // The SDK also resolves AWS_ENDPOINT_URL_KMS before this plain name, and
    // only this one is guarded below; the stack's preflight refuses the
    // per-service overrides outright, production does not (docs/05).
    AWS_ENDPOINT_URL: z.string().url().optional(),
  })
  .superRefine((env, ctx) => {
    // Mode-conditional, and enforced in EVERY environment rather than only in
    // production: a deployment that selects the live provider without a key
    // must fail at boot, not per request.
    if (env.LLM_MODE === 'anthropic' && !env.ANTHROPIC_API_KEY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ANTHROPIC_API_KEY'],
        message: 'ANTHROPIC_API_KEY is required when LLM_MODE is "anthropic"',
      });
    }

    if (env.NODE_ENV === 'production') {
      if (!env.KAFKA_BROKERS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['KAFKA_BROKERS'],
          message: 'KAFKA_BROKERS is required in production (audit emission must not be a no-op)',
        });
      }
      // Each peer names the capability it serves, so a missing value reads as
      // the control it removes rather than as a generic misconfiguration.
      const peers = [
        ['IDENTITY_URL', 'cross-service session verification'],
        ['ASSETS_URL', 'the estate-summary and beneficiary tools'],
        ['DOCUMENTS_URL', 'the document-inventory and search tools'],
        ['PROFILE_URL', 'the non-identifying profile-facts tool'],
      ] as const;
      for (const [key, purpose] of peers) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (${purpose})`,
          });
        }
      }
      // Pin the REAL adapter, naming the stub so a future third mode is not
      // accidentally admitted (the KMS/clamd/OCR/SES rule). The stub answers
      // from a deterministic script and reaches no provider at all, so in
      // production it would be an assistant confidently answering from nothing.
      if (env.LLM_MODE !== 'anthropic') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['LLM_MODE'],
          message:
            'LLM_MODE must be "anthropic" in production (the stub gateway reaches no provider)',
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
            'AWS_ENDPOINT_URL must be https in production (KMS traffic must not be plaintext)',
        });
      }
    }

    // Mode-conditional requirements hold in every environment — the shape the
    // other adapter selectors already use.
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

/** Which gateway answers a turn (deterministic stub in dev/test). */
export type LlmConfig =
  | { readonly mode: 'stub' }
  | {
      readonly mode: 'anthropic';
      /** THIRD-PARTY credential. Lives only in this service (docs/03 §4 TB5). */
      readonly apiKey: string;
      /** Re-run a refused request on a fallback model, server-side. */
      readonly fallbacks: boolean;
    };

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

export interface AiAssistantConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kafkaBrokers: string[] | null;
  /** Session introspection for CallerGuard — the caller's own bearer. */
  readonly identityUrl: string;
  readonly assetsUrl: string;
  readonly documentsUrl: string;
  readonly profileUrl: string;
  readonly llm: LlmConfig;
  /** Per-provider-call deadline in ms; bounds the turn's open transaction. */
  readonly llmRequestTimeoutMs: number;
  readonly kms: KmsConfig;
  /** KEK alias wrapping THIS service's per-user DEKs (never 'core/kek'). */
  readonly kekAlias: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid ai-assistant-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AiAssistantConfig {
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
    // superRefine requires each peer in production; dev falls back to local.
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    assetsUrl: e.ASSETS_URL ?? 'http://localhost:3003',
    documentsUrl: e.DOCUMENTS_URL ?? 'http://localhost:3005',
    profileUrl: e.PROFILE_URL ?? 'http://localhost:3002',
    // The superRefine above guarantees the key whenever the mode needs it.
    llmRequestTimeoutMs: e.LLM_REQUEST_TIMEOUT_MS,
    llm:
      e.LLM_MODE === 'anthropic'
        ? {
            mode: 'anthropic',
            apiKey: e.ANTHROPIC_API_KEY!,
            fallbacks: e.LLM_FALLBACKS === 'default',
          }
        : { mode: 'stub' },
    // The superRefine above guarantees the required fields per mode, so these
    // non-null assertions are sound.
    kms:
      e.KMS_MODE === 'aws'
        ? {
            mode: 'aws',
            keyId: e.AWS_KMS_KEY_ID!,
            region: e.AWS_REGION!,
            endpoint: e.AWS_ENDPOINT_URL ?? null,
          }
        : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') },
    kekAlias: 'ai-assistant/kek',
  };
}
