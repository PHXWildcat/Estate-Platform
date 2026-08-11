/**
 * THE OFFSCREEN DOCUMENT'S LIFECYCLE — the service worker's only power.
 *
 * Its only job is the offscreen document's lifecycle: an MV3 service worker is
 * terminated after seconds of inactivity, so it cannot hold a key — and the
 * offscreen document, which has no lifetime limit, can. That inversion is the
 * whole reason the offscreen document exists (docs/04 M16 decision 1).
 *
 * It routes no vault message and receives no secret: `offscreen-router.ts`
 * filters on `target`, and the popup addresses the offscreen document directly.
 * Stated plainly because it is a design rule rather than an isolation claim —
 * `chrome.runtime.sendMessage` broadcasts, so this context RECEIVES the same
 * messages and simply does not act on them. All extension contexts are one
 * signed artifact.
 */
const OFFSCREEN_PAGE = 'offscreen.html';

/**
 * Create the offscreen document if it is not already there.
 *
 * IDEMPOTENT AND RACE-TOLERANT: only one offscreen document may exist per
 * extension, and two popups opening at once would otherwise both try. The
 * `hasDocument` check narrows the window and the catch closes it — a failed
 * create because one already exists is success for this function's purpose.
 */
export async function ensureOffscreenDocument(api: typeof chrome = chrome): Promise<void> {
  if (await api.offscreen.hasDocument()) return;
  try {
    await api.offscreen.createDocument({
      url: OFFSCREEN_PAGE,
      // TRUE, not convenient: this document's entire job is to spawn and host
      // the worker in which the vault's master key lives. PR2a recorded that no
      // value in the closed enum describes holding keys, and this is the shape
      // that makes the one we declare accurate.
      reasons: ['WORKERS'],
      justification:
        'Runs the vault worker that performs SRP key derivation and item decryption off the main thread.',
    });
  } catch {
    // Another context won the race. The document exists, which is all this
    // function promises.
  }
}
