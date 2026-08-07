/**
 * How long a fresh step-up can take to become visible to a peer service, and
 * therefore how long an inline prompt must keep retrying before it gives up.
 *
 * WHY THIS NUMBER EXISTS HERE. Identity grants the elevation, but every other
 * service learns about it by introspecting the caller's token through
 * `HttpSessionVerifier`, which keeps a SHORT-TTL POSITIVE CACHE (the 2026-07-23
 * decision: negatives are never cached so an outage cannot lock anyone out,
 * positives are cached so introspection is not a per-request round trip). The
 * consequence is that for up to one TTL after a successful step-up, the peer is
 * still answering from a cached un-elevated session — so the prompt-and-retry
 * pattern M10/M12/M13 all claim ("retries the SAME action, so nobody loses a
 * filled-in form") can hand back another `stepup_required` through no fault of
 * the user.
 *
 * The M13 security review found that claim over-promising: the retry was
 * single-shot, so a user whose code was accepted saw the prompt sit there doing
 * nothing. This is the same propagation delay the stack e2e already treats as a
 * contract rather than a flake ("step-up to propagate through the introspection
 * cache… the deadline is the contract; a bare retry would hide it") — so the UI
 * polls to the same deadline instead of pretending the delay is not there.
 *
 * MIRRORED, NOT GUESSED. `SESSION_CACHE_TTL_MS` must equal
 * `DEFAULT_CACHE_TTL_MS` in packages/auth-guard/src/verifier.ts, and
 * `step-up.test.ts` reads that file and asserts it — the compose-parity
 * precedent, because the web app cannot import a Nest package and a number
 * duplicated without a check is a number that drifts.
 */
export const SESSION_CACHE_TTL_MS = 30_000;

/**
 * A little past the TTL, so the last attempt lands after the cache has certainly
 * expired rather than exactly as it does.
 */
export const STEP_UP_PROPAGATION_BUDGET_MS = SESSION_CACHE_TTL_MS + 5_000;

/** Gap between retries. Short enough to feel prompt, long enough not to spin. */
export const STEP_UP_RETRY_INTERVAL_MS = 2_000;

/**
 * What a retried action reports back to the prompt.
 *
 * `applied` — it went through (or failed for a reason the caller has already
 * surfaced), so the prompt is done. `stale` — the server STILL says
 * `stepup_required`, which after a successful elevation means the peer's cache
 * has not caught up yet, so the prompt should wait and try again.
 */
export type StepUpRetryOutcome = 'applied' | 'stale';
