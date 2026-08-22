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
