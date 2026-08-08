import { z } from 'zod';

/**
 * Environment configuration, zod-validated so the process fails fast on a bad
 * deployment. Validation errors name the offending variable — never its value.
 */
const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(4000),
    /** Base URL of the identity service's internal REST API. */
    IDENTITY_URL: z.string().url().default('http://localhost:3001'),
    /**
     * Base URL of the assets service (M8 PR5, the first non-identity
     * downstream). The BFF forwards the caller's own bearer token to it —
     * never an identity header, never a service credential — so a wrong value
     * fails closed: requests are refused downstream, nothing widens.
     */
    ASSETS_URL: z.string().url().default('http://localhost:3003'),
    /**
     * Base URL of the AI assistant service (M10 PR4, the second non-identity
     * downstream). Same posture as ASSETS_URL, and one more reason for it: the
     * BFF forwards the caller's own bearer, and the assistant holds no
     * credential either — so the whole chain from browser to analyser runs on
     * one session's authority and a wrong value here fails closed.
     */
    AI_ASSISTANT_URL: z.string().url().default('http://localhost:3009'),
    /**
     * Base URL of the document service (M12, the third non-identity
     * downstream). Same posture again — the caller's own bearer is forwarded
     * and no credential is held, so a wrong value fails closed. Note what is
     * NOT reachable from here whatever this points at: documents' two internal
     * routes are service-credential guarded, and the BFF holds no such
     * credential in either direction.
     */
    DOCUMENTS_URL: z.string().url().default('http://localhost:3005'),
    /**
     * Base URL of the profile & contacts service (M13, the fourth non-identity
     * downstream). Same posture: the caller's own bearer is forwarded and no
     * credential is held, so a wrong value fails closed. Profile has no
     * service-credential routes at all, so unlike documents there is nothing
     * here that a bearer token could not have opened anyway.
     */
    PROFILE_URL: z.string().url().default('http://localhost:3002'),
    /**
     * M15. NOT a downstream — the BFF never calls the vault origin and holds no
     * credential for it. This is the address it HANDS THE BROWSER so the app
     * can submit its top-level handoff form there, returned per request rather
     * than baked into the web bundle (the M8 PR5 BFF_URL lesson: a value
     * serialised at build time gets baked wrong and nothing notices until
     * production).
     */
    VAULT_ORIGIN: z.string().url().default('http://vault.localhost:3010'),
    /**
     * Path to the persisted-operations manifest (JSON: sha256 hex → GraphQL
     * document). Optional in dev/test (empty manifest ⇒ arbitrary operations
     * are still allowed there); REQUIRED in production, where only manifest
     * hashes may execute — a production BFF without a manifest could serve
     * nothing and would signal a broken deploy pipeline, so fail fast.
     */
    PERSISTED_MANIFEST_PATH: z.string().min(1).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && !env.PERSISTED_MANIFEST_PATH) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['PERSISTED_MANIFEST_PATH'],
        message:
          'PERSISTED_MANIFEST_PATH is required in production (persisted operations are mandatory)',
      });
    }
  });

export interface BffConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly identityUrl: string;
  readonly assetsUrl: string;
  readonly aiAssistantUrl: string;
  readonly documentsUrl: string;
  readonly profileUrl: string;
  /** Browser-facing origin of the isolated vault surface (M15). */
  readonly vaultOrigin: string;
  /** null means "no manifest" (never allowed in production). */
  readonly persistedManifestPath: string | null;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid bff configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): BffConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  const e = parsed.data;
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    identityUrl: e.IDENTITY_URL.replace(/\/+$/, ''),
    assetsUrl: e.ASSETS_URL.replace(/\/+$/, ''),
    aiAssistantUrl: e.AI_ASSISTANT_URL.replace(/\/+$/, ''),
    documentsUrl: e.DOCUMENTS_URL.replace(/\/+$/, ''),
    profileUrl: e.PROFILE_URL.replace(/\/+$/, ''),
    vaultOrigin: e.VAULT_ORIGIN.replace(/\/+$/, ''),
    persistedManifestPath: e.PERSISTED_MANIFEST_PATH ?? null,
  };
}
