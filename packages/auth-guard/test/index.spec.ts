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
      authGuard.expectedEnvVarFor,
      authGuard.inboundCredentialFor,
      authGuard.outboundCredentialsFor,
    ]) {
      expect(fn).toBeInstanceOf(Function);
    }
  });
});
