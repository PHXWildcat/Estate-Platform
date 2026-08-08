import { z } from 'zod';

/**
 * The vault origin's configuration.
 *
 * NOTICE WHAT IS NOT HERE, because it is the same absence the vault service's
 * own config documents: no KMS key, no master key, no index key — and no
 * SERVICE CREDENTIAL of any kind, in either direction. This edge authenticates
 * nobody to anybody. It holds the caller's own bearer in a cookie scoped to
 * this origin and forwards exactly that, so it can only ever reach what the
 * calling user could already reach (the M8 PR5 / M10 / M12 rule). If a future
 * change adds an `*_INTERNAL_TOKEN` here, that is a trust boundary moving and
 * belongs in a design discussion — `test/config.spec.ts` asserts the empty
 * holding the way the ai-assistant service does.
 */
const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3010),
    /** Base URL of the vault service — the only estate data this origin sees. */
    VAULT_URL: z.string().url().optional(),
    /** Base URL of identity: handoff redemption, step-up, session, logout. */
    IDENTITY_URL: z.string().url().optional(),
    /**
     * Base URL of profile. PR3's grantee picker reads the caller's contact
     * SUMMARIES through here — the one Zone B read on this origin, projected at
     * the edge to {contactId, linkedUserId, name} and filtered to linked
     * contacts, because an owner has to know WHO they are confirming a
     * fingerprint with.
     */
    PROFILE_URL: z.string().url().optional(),
    /**
     * The app origin, e.g. `http://localhost:3000`. Used for exactly two
     * things, both of which must be an exact ORIGIN rather than a pattern:
     * the "back to Estate" link, and the `Origin` header this edge requires on
     * the handoff POST.
     */
    APP_ORIGIN: z.string().url().optional(),
  })
  .superRefine((env, ctx) => {
    const requiredInProduction = [
      'VAULT_URL',
      'IDENTITY_URL',
      'PROFILE_URL',
      'APP_ORIGIN',
    ] as const;
    for (const key of requiredInProduction) {
      if (env.NODE_ENV === 'production' && !env[key]) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} is required in production`,
        });
      }
    }
  });

export interface VaultWebConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly vaultUrl: string;
  readonly identityUrl: string;
  readonly profileUrl: string;
  readonly appOrigin: string;
  /**
   * Whether cookies get `Secure`. TRUE IN EVERY ENVIRONMENT, unlike the BFF's,
   * and that is deliberate: this origin's cookie carries the `__Host-` prefix,
   * which the browser refuses without `Secure` — so making it conditional would
   * mean the dev profile exercised a different cookie from the production one.
   * Measured in a real browser first: `vault.localhost` is a
   * potentially-trustworthy origin, so a `__Host-` cookie is accepted there
   * over plain http exactly as it is on `localhost`.
   */
  readonly secureCookies: true;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid vault-web configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): VaultWebConfig {
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
    vaultUrl: e.VAULT_URL ?? 'http://localhost:3006',
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    profileUrl: e.PROFILE_URL ?? 'http://localhost:3002',
    appOrigin: e.APP_ORIGIN ?? 'http://localhost:3000',
    secureCookies: true,
  };
}
