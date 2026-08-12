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
 * NO LONGER THE ONLY BOUND IN THE PRODUCT: M17 added login and register bounds,
 * declared in `rate-bounds.ts`, which is also where this one is now expressed as
 * data. The kind sets below became PARAMETERS to the repo predicate in that
 * change — a second bound sharing them would let one bound's success clear the
 * other's window, which was measured rather than reasoned about.
 *
 * docs/03 §6a has recorded "no rate limiting on failed SRP proofs yet" since
 * M6, tracked against identity's login rate limiting. M16 makes that reachable:
 * a browser extension holds a long-lived refresh token, so an attacker with a
 * stolen copy has an indefinite platform from which to call `POST
 * /v1/auth/stepup` at whatever rate they can sustain, against a SIX-DIGIT code.
 *
 * Capping the SECOND FACTOR bounds more than one route. Both of the vault's SRP
 * legs are themselves step-up gated, so every credential in the product —
 * extension, vault handoff, or an ordinary stolen account session — has to
 * prove the factor before it can reach a handshake. §6a's SRP half is therefore
 * partially rather than fully closed by this (a caller holding a GENUINE
 * step-up can still burn handshakes).
 *
 * "ONE CHOKEPOINT" IS WHAT THIS PARAGRAPH USED TO SAY, and it was wrong by one
 * route. The cap lived in `stepUp` alone while `POST /v1/auth/totp/verify`
 * checked the SAME secret with no cap at all — see `SECOND_FACTOR_FAILURES`
 * below for the measurement. The chokepoint is the SET of routes that read the
 * factor, which is why the gate is now a method both of them call rather than a
 * block inside one of them.
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
 *
 * ═══ AND THE ROLLING WINDOW DID NOT ESCAPE THAT, WHICH THE M16 REVIEW MEASURED
 *
 * The paragraph above named the harm exactly and then claimed a rolling window
 * avoided it. It does not. The count was keyed on the USER and every live
 * session of that user wrote into it, so five wrong codes from ONE stolen
 * credential refused every OTHER session of the account — proven against real
 * Postgres, where the owner's own untouched session got 429 where it should
 * have got 401. The only thing that clears the window is a SUCCESS, which is
 * precisely what the 429 prevents, so an attacker repeating five denials each
 * quarter-hour holds the account there indefinitely: the sticky lock this file
 * says it refused to build, re-armed on a timer, and reachable from the
 * long-lived extension credential M16 itself introduced. What it blocks is the
 * list two paragraphs up plus docs/03 §5.1's rescue path, where a step-up is
 * the owner's liveness proof against a fraudulent death case.
 *
 * THE FIX IS TWO SCOPES, not a different number. A single credential is capped
 * at `STEPUP_MAX_DENIALS` on ITS OWN failures, so a stolen one exhausts itself
 * and stops; the ACCOUNT is capped at `STEPUP_MAX_ACCOUNT_DENIALS`, which stays
 * keyed on the user for M14's reason and remains the real bound on guessing.
 * Because a capped session's refusals are `stepup.rate_limited` and not
 * `stepup.denied`, an attacker who keeps hammering adds nothing to the account
 * total: it rests at five, the owner's own sessions each still hold their full
 * five, and the lockout is gone. What survives — recorded in docs/03 §6j rather
 * than implied — is that an attacker who can MINT sessions (i.e. who has the
 * password) can still walk the account total to its ceiling. That is a strictly
 * higher bar than holding one session, and it is the bar the account-wide cap
 * exists for.
 *
 * TWENTY, for the account. Four exhausted credentials' worth, so the owner is
 * not locked out by one or two; and 20 per 15 minutes is ~1,900 guesses a day
 * against a 10^6 space, which is still centuries of expected work.
 */
export const STEPUP_MAX_DENIALS = 5;
export const STEPUP_MAX_ACCOUNT_DENIALS = 20;
export const STEPUP_DENIAL_WINDOW_MS = 15 * 60 * 1000;

/**
 * EVERY LEDGER KIND THAT MEANS "SOMEBODY GUESSED THIS SECRET AND WAS WRONG".
 *
 * The cap counted `stepup.denied` alone until the M16 review, which measured
 * `POST /v1/auth/totp/verify` as an uncapped oracle on the SAME `mfa_methods`
 * row: forty wrong codes there produced forty 401s, never a 429, and left the
 * counter at zero — after which the code it found elevated at `stepup` on the
 * first try. A bound on guessing has to cover every route that checks the
 * secret, so this is a SET and a third checker must join it. `kind` is a plain
 * string at the repo boundary, so there is no type to pin these against — the
 * pin is `test/second-factor-kinds.spec.ts`, which scans `auth.service.ts` for
 * every kind it writes and fails if one that means "a wrong code" is missing
 * here. A set that silently stops matching is the failure this whole review
 * keeps finding.
 */
export const SECOND_FACTOR_FAILURES = ['stepup.denied', 'totp.verify_failed'] as const;

/**
 * And every kind that means somebody PROVED possession, which clears the window.
 *
 * `totp.verified` belongs here for the same reason `stepup.granted` does — both
 * require a correct code — and it cannot be farmed to reset the counter,
 * because enrolling a NEW factor while one already exists is itself step-up
 * gated (`AuthService.enrollTotp`).
 */
export const SECOND_FACTOR_SUCCESSES = ['stepup.granted', 'totp.verified'] as const;
