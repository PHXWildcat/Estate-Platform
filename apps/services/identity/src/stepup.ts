// Step-up freshness now has ONE definition, in the shared PEP package: identity
// grants the elevation, every downstream StepUpGuard verifies it, so the ≤5-min
// rule (docs/01 §5) cannot drift between the two. Re-exported here so identity's
// existing call sites keep importing from './stepup'.
export { isStepUpFresh, STEPUP_WINDOW_MS } from '@estate/auth-guard';

/** Opaque access-token lifetime (short by design; refresh rotates). */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;

/** Session / refresh-token lifetime. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * THE STEP-UP ATTEMPT CAP (M16). Reviewed CONSTANTS, deliberately not config.
 *
 * docs/03 §6a has recorded "no rate limiting on failed SRP proofs yet" since
 * M6, tracked against identity's login rate limiting. M16 makes that reachable:
 * a browser extension holds a long-lived refresh token, so an attacker with a
 * stolen copy has an indefinite platform from which to call `POST
 * /v1/auth/stepup` at whatever rate they can sustain, against a SIX-DIGIT code.
 *
 * Capping HERE bounds more than this route. Both of the vault's SRP legs are
 * themselves step-up gated, so every credential in the product — extension,
 * vault handoff, or an ordinary stolen account session — has to pass step-up
 * before it can reach a handshake. One chokepoint covers both, which is why
 * this is the cheapest place to spend the effort and why §6a's SRP half is
 * partially rather than fully closed by it (a caller holding a GENUINE step-up
 * can still burn handshakes).
 *
 * FIVE PER FIFTEEN MINUTES is roughly 480 guesses a day against a 10^6 space —
 * years of expected work — while costing a user with a drifted phone clock one
 * quarter-hour. Constants rather than config on the `TEMPLATE_CACHE_TTL_MS`
 * precedent: a bound on guessing is a security parameter, so it changes by
 * reviewed commit, not by an environment variable somebody can widen under
 * deploy pressure.
 *
 * A ROLLING COOLDOWN, NEVER A STICKY LOCK. M6's sticky-denial reasoning does
 * not transfer: a step-up lock that had to be cleared out of band would be a
 * denial-of-service primitive against the OWNER, reachable by anyone holding
 * any stolen credential, and it would simultaneously block vault open, document
 * generation, data export, beneficiary changes and deletion. That inverts the
 * rule that the protective action must never be harder than the permissive one.
 */
export const STEPUP_MAX_DENIALS = 5;
export const STEPUP_DENIAL_WINDOW_MS = 15 * 60 * 1000;
