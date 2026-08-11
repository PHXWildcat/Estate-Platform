// Import through the barrel so the public surface (index.ts re-exports) is
// itself covered — a symbol dropped from index.ts breaks this suite.
import * as authGuard from '../src';

describe('@estate/auth-guard public surface', () => {
  it('re-exports the guards, verifier, tokens, and step-up helpers', () => {
    expect(authGuard.CallerGuard).toBeDefined();
    expect(authGuard.StepUpGuard).toBeDefined();
    expect(authGuard.HttpSessionVerifier).toBeDefined();
    expect(authGuard.requireCaller).toBeInstanceOf(Function);
    expect(authGuard.isStepUpFresh).toBeInstanceOf(Function);
    expect(authGuard.STEPUP_WINDOW_MS).toBe(5 * 60 * 1000);
    expect(typeof authGuard.SESSION_VERIFIER).toBe('symbol');
    expect(typeof authGuard.SESSION_CLOCK).toBe('symbol');
    expect(authGuard.ServiceCredentialGuard).toBeDefined();
    expect(typeof authGuard.SERVICE_CREDENTIAL).toBe('symbol');
    expect(authGuard.SERVICE_CREDENTIAL_HEADER).toBe('x-estate-service-credential');
  });

  it('re-exports the M15 session-audience surface', () => {
    // Same reasoning as the credential-graph case below, and I made the same
    // mistake it warns about: these landed in index.ts with nothing importing
    // them through the barrel, so the re-export getters were uncovered and the
    // package fell under its own functions floor. Every one of these is
    // consumed by a service or a fence, so the barrel is load-bearing.
    expect(authGuard.SESSION_AUDIENCES).toEqual(['account', 'vault', 'extension']);
    expect(authGuard.DEFAULT_SESSION_AUDIENCE).toBe('account');
    // The declaration the fence checks source against — vault, and only vault.
    expect(authGuard.AUDIENCE_ADMITTERS.vault).toEqual(['vault']);
    // M16's extension audience is admitted PER ROUTE and nowhere service-wide,
    // so its service-wide entry is deliberately empty. Asserted here rather than
    // left implicit: an `extension: ['vault']` slipped into that table would
    // open all 23 vault routes at once, and this is the barrel test that would
    // notice.
    expect(authGuard.AUDIENCE_ADMITTERS.extension).toEqual([]);
    // The DI token a service binds to widen its guard. Absence is the secure
    // setting, so the symbol existing is what makes opting in explicit.
    expect(typeof authGuard.ALLOWED_SESSION_AUDIENCES).toBe('symbol');
  });

  it('re-exports the M15 PR3 per-route surface', () => {
    // The narrower grant: a service stays account-only and opens ONE route.
    // Identity's guard and every downstream CallerGuard read the SAME metadata
    // key — two guards with two copies of a string is how a route ends up
    // decorated for a key nobody checks.
    expect(authGuard.SESSION_AUDIENCE_METADATA).toBe('estate:session-audiences');
    expect(authGuard.AllowSessionAudiences).toBeInstanceOf(Function);
    // The declaration both fences check source against, in both directions.
    expect(authGuard.AUDIENCE_ROUTE_ADMITTERS.vault).toContain('profile:granteeCandidates');
    expect(authGuard.AUDIENCE_ROUTE_ADMITTERS.vault).toContain('identity:session');
    // And NOT the route that mints authority — a vault session cannot mint
    // another handoff, which is what stops a leaked one chaining itself forward.
    expect(authGuard.AUDIENCE_ROUTE_ADMITTERS.vault).not.toContain('identity:mintHandoff');
  });

  it('re-exports the credential graph and the helpers services assert with', () => {
    // Every service's config spec imports these THROUGH the barrel. A symbol
    // added to credential-graph.ts but forgotten here compiles fine inside this
    // package and breaks every consumer — which is exactly what happened while
    // building this, and the barrel had no test covering the new surface.
    expect(authGuard.SERVICE_CREDENTIAL_GRAPH.length).toBeGreaterThanOrEqual(3);
    expect(authGuard.SERVICE_NAMES.length).toBeGreaterThanOrEqual(8);
    for (const fn of [
      authGuard.credentialEnvVarsFor,
      authGuard.credentialSentinel,
      authGuard.credentialSentinelEnv,
      authGuard.credentialsHeldIn,
      authGuard.envVarPrefixFor,
      authGuard.inboundCredentialsFor,
      authGuard.outboundCredentialsFor,
    ]) {
      expect(fn).toBeInstanceOf(Function);
    }
  });
});
