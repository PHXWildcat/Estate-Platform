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
  });
});
