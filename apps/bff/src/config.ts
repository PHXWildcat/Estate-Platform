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
    persistedManifestPath: e.PERSISTED_MANIFEST_PATH ?? null,
  };
}
