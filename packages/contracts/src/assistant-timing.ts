/**
 * The assistant's TURN BUDGET, shared between the service that enforces it and
 * the edge that waits on it (M11 security review).
 *
 * ===========================================================================
 * WHY THIS NUMBER LIVES IN CONTRACTS AND NOT IN EITHER SERVICE
 * ===========================================================================
 *
 * M11 shipped a BFF timeout with a comment claiming it sat "deliberately ABOVE
 * the assistant's own deadline", so the BFF would never abandon a turn the
 * service was still committing. The claim was arithmetic, and the arithmetic
 * was wrong: the assistant bounded ONE PROVIDER CALL (60s), the SDK retries
 * twice with the timeout applied PER ATTEMPT (~180s for one call), and a turn
 * makes up to six calls with tool reads in between — a ceiling of roughly
 * eighteen minutes against a 150s edge timeout.
 *
 * The consequence was not a slow request. Nothing cancels the server side when
 * a client aborts, so the turn COMMITTED — both messages sealed, the audit
 * event emitted, the estate payload already across TB5 — while the user was
 * told it failed and invited to retry. The retry then blocked on the
 * conversation's row lock and re-sent a longer transcript to the provider: a
 * second egress nobody asked for, and a transcript recording an exchange the
 * user was told never happened, in a product where the transcript is evidence.
 *
 * Prose could not hold that invariant, so it is a number both sides IMPORT.
 * The assistant enforces `ASSISTANT_TURN_BUDGET_MS` as a wall-clock bound
 * across its whole loop; the BFF waits `assistantTurnTimeoutMs()`, which is
 * derived from it rather than chosen to look bigger. A spec on each side pins
 * its half, and the ordering is a fact about one constant instead of a claim in
 * two comments.
 */

/**
 * How long ONE TURN may take, wall clock, measured in the assistant service
 * across every provider call and tool read it makes.
 *
 * Two minutes is a long time to watch a spinner, and it is deliberately not
 * the sum of the worst case: the point of a wall-clock budget is that the
 * worst case stops being the product of three independent numbers. A turn that
 * exceeds it stops looping and answers with what it has, which is the same
 * shape as the iteration cap that has always existed.
 */
export const ASSISTANT_TURN_BUDGET_MS = 120_000;

/**
 * Headroom the edge allows on top of the budget, for everything that is not
 * the model: the transaction, the encryption, the audit flush, and the network
 * between the browser and the service.
 */
const EDGE_HEADROOM_MS = 30_000;

/**
 * What a caller at the edge should wait for one turn.
 *
 * DERIVED, never hand-picked. If the budget moves, this moves with it, and the
 * relationship the M11 review found broken cannot silently invert again.
 */
export function assistantTurnTimeoutMs(): number {
  return ASSISTANT_TURN_BUDGET_MS + EDGE_HEADROOM_MS;
}

/**
 * Retries the provider SDK may make for ONE call.
 *
 * Pinned rather than left to the SDK's default (2), because the default is
 * invisible from this repo and multiplies the per-call bound by three — which
 * is precisely the term the M11 arithmetic missed. One retry keeps a transient
 * 429 or a dropped connection recoverable while leaving the per-call worst
 * case small enough to fit inside a turn budget that has other work to do.
 */
export const ASSISTANT_PROVIDER_MAX_RETRIES = 1;
