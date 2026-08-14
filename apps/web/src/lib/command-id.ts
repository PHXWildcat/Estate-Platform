/**
 * Client-minted idempotency keys for asset commands (M19 PR2).
 *
 * The ledger treats a retried command carrying the same eventId as a no-op
 * that answers the ORIGINAL ack — which protects exactly one case: the
 * response was lost (timeout, closed laptop) and the user presses the button
 * again. For that to be safe the id must be HELD ACROSS RETRIES OF THE SAME
 * PAYLOAD and REGENERATED THE MOMENT THE PAYLOAD CHANGES: if the first
 * attempt actually committed and the user then edits the form and resubmits,
 * a reused id would silently answer the OLD command's ack while the edit
 * never happened.
 *
 * Pure function so the property is trivially testable; callers hold the
 * returned pair in a ref.
 */
export interface CommandId {
  readonly key: string;
  readonly id: string;
}

export function commandEventId(previous: CommandId | null, payloadKey: string): CommandId {
  if (previous !== null && previous.key === payloadKey) {
    return previous;
  }
  return { key: payloadKey, id: crypto.randomUUID() };
}
