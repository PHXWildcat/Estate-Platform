/**
 * The runtime half of the "this origin holds no credential" claim (M21 PR3a).
 *
 * The source half is in `fences.spec.ts`. This is the one that loads the REAL
 * config with EVERY credential in the graph present in the environment and
 * asserts it absorbs none of them — the check that proves the operator origin
 * would not use identity's key even when handed it.
 *
 * The precedent is `apps/services/ai-assistant/test/config.spec.ts` and the
 * vault origin's copy of it, including the second assertion: the granted set is
 * asserted to be explicitly EMPTY as well as equal to what the config holds.
 * Without that, the whole test passes vacuously if the graph ever changes
 * shape.
 */
import { credentialSentinelEnv, credentialsHeldIn } from '@estate/auth-guard';
import { ConfigError, loadConfig } from '../src/config';

const BASE = {
  IDENTITY_URL: 'http://identity:3001',
  APP_ORIGIN: 'http://localhost:3000',
} as const;

describe('operator-web configuration', () => {
  it('ABSORBS NO SERVICE CREDENTIAL, even with every one of them present', () => {
    const config = loadConfig({
      NODE_ENV: 'production',
      ...BASE,
      ...credentialSentinelEnv(),
    });

    // Both directions, deliberately: equal to the granted set AND that set is
    // empty. This origin is the third component in the product of which this is
    // true by design (the assistant service, then the vault origin).
    expect(credentialsHeldIn(config)).toEqual([]);
    expect(credentialsHeldIn(config)).toHaveLength(0);
  });

  it('requires every upstream in production', () => {
    for (const missing of ['IDENTITY_URL', 'APP_ORIGIN'] as const) {
      const env = { NODE_ENV: 'production', ...BASE } as Record<string, string>;
      delete env[missing];
      expect(() => loadConfig(env)).toThrow(ConfigError);
    }
  });

  it('defaults the upstreams in development so the inner loop works', () => {
    const config = loadConfig({});
    expect(config.nodeEnv).toBe('development');
    expect(config.identityUrl).toBe('http://localhost:3001');
    expect(config.appOrigin).toBe('http://localhost:3000');
    // A port of its own: the vault origin has 3010, and two isolated origins
    // sharing a port would mean only one of them could run.
    expect(config.port).toBe(3011);
  });

  it('HAS NO SETTLEMENT UPSTREAM YET, and that is the zero-callers rule', () => {
    // M21 PR3b adds it in the same change as the screens that reach it. A
    // configured upstream nothing calls is a capability sitting ahead of its
    // consumer, which is the shape this milestone exists to close.
    expect(Object.keys(loadConfig({}))).toEqual([
      'nodeEnv',
      'port',
      'identityUrl',
      'appOrigin',
      'secureCookies',
    ]);
  });

  it('sets Secure cookies in EVERY environment, not only production', () => {
    // The `__Host-` prefix requires Secure, so a conditional would mean the dev
    // profile exercised a different cookie from the production one. The vault
    // origin measured this first: an `<name>.localhost` host is a
    // potentially-trustworthy origin.
    expect(loadConfig({}).secureCookies).toBe(true);
    expect(loadConfig({ NODE_ENV: 'production', ...BASE }).secureCookies).toBe(true);
  });

  it('never echoes an environment value in the error', () => {
    // ConfigError carries zod issue paths and messages only. Triggered by a
    // DIFFERENT missing variable while a real-looking value is present, so the
    // assertion cannot pass just because the value was blanked (the M10 lesson
    // about a vacuous version of exactly this test).
    const env = { NODE_ENV: 'production', ...BASE } as Record<string, string>;
    delete env.APP_ORIGIN;
    env.IDENTITY_URL = 'http://identity.internal.example:3001';
    try {
      loadConfig(env);
      throw new Error('expected a ConfigError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).message).not.toContain('identity.internal.example');
    }
  });
});
