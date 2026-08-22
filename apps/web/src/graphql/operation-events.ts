import type { OperationName } from './operations';

/**
 * A one-way announcement channel from the transport: "this operation just
 * SUCCEEDED". `gqlRequest` notifies here after every successful MUTATION, and
 * the shared read cache subscribes with its own mutation→read map.
 *
 * WHY THIS EXISTS AS A MODULE. The cache must learn about mutations without
 * the transport importing the cache (client.ts is imported BY the cache for
 * its reads, so that import would be a cycle) — and without every ceremony
 * call site being trusted to remember an invalidate call. The §6v banner
 * residual this shipped with IS the forgot-to-invalidate class: the fix that
 * relies on each future ceremony remembering a second call would reintroduce
 * the defect one ceremony later. The transport announces; interested parties
 * subscribe; no call site holds the duty.
 *
 * QUERIES NEVER ANNOUNCE. A read changes nothing, so a read completing is not
 * an event any cached read should react to — and a cache refetching on its own
 * fetches would feed itself forever.
 */

type OperationSuccessListener = (operation: OperationName) => void;

const listeners = new Set<OperationSuccessListener>();

/** Subscribe to successful-mutation announcements. Returns an unsubscribe. */
export function onOperationSuccess(listener: OperationSuccessListener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Called by the transport only. A listener that throws must not break the
 * caller's own result handling — announcements are best-effort by contract.
 */
export function notifyOperationSuccess(operation: OperationName): void {
  for (const listener of [...listeners]) {
    try {
      listener(operation);
    } catch {
      // A misbehaving listener is that listener's defect; the mutation result
      // still belongs to the caller untouched.
    }
  }
}

type SessionEndedListener = () => void;

const sessionEndedListeners = new Set<SessionEndedListener>();

/**
 * THE SECOND ANNOUNCEMENT, AND IT IS THE SAME ARGUMENT AS THE FIRST (M24 PR4).
 *
 * "This session is gone" is a fact about the whole app, and before this it was
 * learned privately by whichever component happened to make the request that
 * died. The dashboard's own escalation collapsed the PAGE to its signed-out
 * arm while the rail — a separate component, one `Session` read at mount, no
 * subscription — went on rendering a green dot and the word "Signed in" beside
 * it. The page then asserted two contradictory session states at once, and the
 * SECURITY-STATE INDICATOR was the wrong one; pressing its Sign-out control
 * made the page say "you are still signed in" about a session that was already
 * revoked. Fail closed means DE-ESCALATE.
 *
 * Announced from the transport's one refused-refresh point rather than from
 * each surface's error arm — the same reasoning as the mutation channel above:
 * a convention asking every future reader to notice a 401 and tell the chrome
 * is the forgot-to-tell class, one component later.
 */
export function onSessionEnded(listener: SessionEndedListener): () => void {
  sessionEndedListeners.add(listener);
  return () => {
    sessionEndedListeners.delete(listener);
  };
}

/**
 * Called by the transport only, and ONLY when the session is known dead: a
 * refresh that was REFUSED. An unavailable refresh says nothing about the
 * session (the credential may be perfectly alive behind an outage) and must
 * never announce, or an outage would sign people out.
 */
export function notifySessionEnded(): void {
  for (const listener of [...sessionEndedListeners]) {
    try {
      listener();
    } catch {
      // Best-effort, as above.
    }
  }
}
