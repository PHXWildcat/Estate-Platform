import { z } from 'zod';

/**
 * The operator origin's configuration.
 *
 * NOTICE WHAT IS NOT HERE, because the absence is the whole trust story: no
 * SERVICE CREDENTIAL of any kind, in either direction. This edge authenticates
 * nobody to anybody. It holds the caller's own bearer in a cookie scoped to
 * this origin and forwards exactly that, so it can only ever reach what the
 * calling operator could already reach (the M8 PR5 / M10 / M15 rule). A
 * compromised operator edge replays the sessions it is currently serving; it
 * cannot mint one, and it cannot mint an OPERATOR — that write path is the
 * broker-gated CLI ceremony M21 PR1 shipped, which lives nowhere near here.
 *
 * If a future change adds an `*_INTERNAL_TOKEN` here, that is a trust boundary
 * moving and belongs in a design discussion. `test/config.spec.ts` asserts the
 * empty holding the way the ai-assistant service and the vault origin do —
 * equal to the granted set AND explicitly empty, because without the second
 * assertion the test passes vacuously if the graph ever changes shape.
 *
 * TWO UPSTREAMS NOW (M21 PR3b): identity and settlement. The settlement URL
 * arrived in the same change as the thirteen routes that reach it and the
 * screens that call them — the M9 PR2 rule that a capability and its callers
 * ship together, which is the only thing that keeps a zero-callers gap from
 * opening. A THIRD upstream is a trust decision and not a configuration one:
 * this origin can address exactly the services named here, so adding a
 * variable is how the console would gain reach into a cluster it has never
 * touched.
 */
const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3011),
    /** Base URL of identity: handoff redemption, step-up, session, logout. */
    IDENTITY_URL: z.string().url().optional(),
    /** Base URL of settlement: the review queue and the case surface. */
    SETTLEMENT_URL: z.string().url().optional(),
    /**
     * The app origin, e.g. `http://localhost:3000`. Used for exactly two
     * things, both of which must be an exact ORIGIN rather than a pattern: the
     * "back to Estate" link, and the `Origin` header this edge requires on the
     * handoff POST.
     */
    APP_ORIGIN: z.string().url().optional(),
  })
  .superRefine((env, ctx) => {
    const requiredInProduction = ['IDENTITY_URL', 'SETTLEMENT_URL', 'APP_ORIGIN'] as const;
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

export interface OperatorWebConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly identityUrl: string;
  readonly settlementUrl: string;
  readonly appOrigin: string;
  /**
   * Whether cookies get `Secure`. TRUE IN EVERY ENVIRONMENT, unlike the BFF's,
   * and that is deliberate: this origin's cookie carries the `__Host-` prefix,
   * which the browser refuses without `Secure` — so making it conditional would
   * mean the dev profile exercised a different cookie from the production one.
   * The vault origin measured this in a real browser first: an
   * `<name>.localhost` host is a potentially-trustworthy origin, so a `__Host-`
   * cookie is accepted there over plain http exactly as it is on `localhost`.
   */
  readonly secureCookies: true;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid operator-web configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): OperatorWebConfig {
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
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    settlementUrl: e.SETTLEMENT_URL ?? 'http://localhost:3007',
    appOrigin: e.APP_ORIGIN ?? 'http://localhost:3000',
    secureCookies: true,
  };
}
