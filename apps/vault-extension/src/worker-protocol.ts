import type { KeyHolderPort } from './vault-host.js';
import type { OpenedSummary, SrpChallenge, VaultItemRow } from './vault-worker-core.js';

/**
 * WHAT MAY BE ASKED OF THE KEY HOLDER ACROSS THE WORKER BOUNDARY.
 *
 * A closed union again, and for the reason the message union has one: the
 * worker is the only thing that can decrypt, so what it will do on request IS
 * the capability. There is deliberately no variant meaning "give me the key" or
 * "give me an item's secret" — `summarise` returns titles, and PR3's fill will
 * arrive with the gesture requirement that governs it rather than by widening
 * this quietly.
 *
 * EVERY RESPONSE IS A VALUE, NEVER AN ERROR OBJECT. A thrown error crossing
 * `postMessage` loses its type and can carry a stack naming internals, so
 * failures come back as a plain `{ ok: false }` and the host maps them. The
 * worker never explains itself: which half of 2SKD was wrong is exactly what
 * the platform refuses to say.
 */

export type WorkerRequest =
  | {
      readonly id: number;
      readonly kind: 'prepare';
      readonly userId: string;
      readonly password: string;
      readonly secretKey: string;
      readonly challenge: SrpChallenge;
    }
  | {
      readonly id: number;
      readonly kind: 'finish';
      readonly serverM2: string;
      readonly wrappedMasterKey: string;
      readonly vaultSessionId: string;
    }
  | { readonly id: number; readonly kind: 'summarise'; readonly rows: readonly VaultItemRow[] }
  | { readonly id: number; readonly kind: 'lock' }
  | { readonly id: number; readonly kind: 'state' };

export type WorkerResponse =
  | { readonly id: number; readonly ok: true; readonly proof: { publicA: string; m1: string } }
  | { readonly id: number; readonly ok: true; readonly summaries: readonly OpenedSummary[] }
  | { readonly id: number; readonly ok: true; readonly unlocked: boolean }
  | { readonly id: number; readonly ok: false };

/**
 * Run one request against the holder.
 *
 * Exported and pure of any `self`/`Worker` reference so the suite drives it
 * directly: `vault-worker.ts` is the four-line entry that wires it to
 * `onmessage`, which is the only part a test could not exercise anyway.
 */
export async function handleWorkerRequest(
  holder: KeyHolderPort,
  request: WorkerRequest,
): Promise<WorkerResponse> {
  const { id } = request;
  try {
    switch (request.kind) {
      case 'prepare': {
        const proof = await holder.prepare({
          userId: request.userId,
          password: request.password,
          secretKey: request.secretKey,
          challenge: request.challenge,
        });
        return { id, ok: true, proof };
      }
      case 'finish': {
        await holder.finish({
          serverM2: request.serverM2,
          wrappedMasterKey: request.wrappedMasterKey,
          vaultSessionId: request.vaultSessionId,
        });
        return { id, ok: true, unlocked: holder.isUnlocked };
      }
      case 'summarise': {
        return { id, ok: true, summaries: await holder.summarise(request.rows) };
      }
      case 'lock': {
        holder.lock();
        return { id, ok: true, unlocked: holder.isUnlocked };
      }
      case 'state':
        return { id, ok: true, unlocked: holder.isUnlocked };
    }
  } catch {
    // No message, no code, no stack. The host turns a refusal into the one
    // sentence 2SKD allows, and anything this could add would be a hint about
    // which half was wrong.
    return { id, ok: false };
  }
}
