import type { KeyHolderPort } from './vault-host.js';
import type {
  MatchedSummary,
  OpenedSummary,
  SrpChallenge,
  VaultItemRow,
} from './vault-worker-core.js';

/**
 * WHAT MAY BE ASKED OF THE KEY HOLDER ACROSS THE WORKER BOUNDARY.
 *
 * A closed union again, and for the reason the message union has one: the
 * worker is the only thing that can decrypt, so what it will do on request IS
 * the capability. There is deliberately no variant meaning "give me the key" or
 * "give me an item's secret" — `summarise` returns titles.
 *
 * `fill` ARRIVED IN PR3b, and it is the first and only variant that can produce
 * a secret. It is written the way this docstring promised it would be: the
 * caller names AN ITEM AND A PAGE, never a secret, and the holder re-takes the
 * origin decision itself before answering. So the widest thing a compromised
 * popup can ask for is a fill it could already have driven with the user's own
 * gesture — not the key, not an arbitrary item's password, and not a credential
 * for a page the item does not belong to.
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
  | {
      readonly id: number;
      readonly kind: 'matches';
      readonly rows: readonly VaultItemRow[];
      readonly pageUrl: string;
    }
  | {
      readonly id: number;
      readonly kind: 'fill';
      readonly rows: readonly VaultItemRow[];
      readonly itemId: string;
      readonly pageUrl: string;
    }
  /**
   * SEAL, and it is the only variant that carries plaintext INWARD (M16 PR4a).
   * The holder turns content into ciphertext under the key it holds; it decides
   * nothing about whether the write is allowed, which is the service's job.
   */
  | {
      readonly id: number;
      readonly kind: 'seal';
      readonly itemId: string;
      readonly blobVersion: number;
      readonly content: Record<string, unknown>;
    }
  /** Merge changes into an item's existing content and re-seal it (PR4a). */
  | {
      readonly id: number;
      readonly kind: 'reseal';
      readonly rows: readonly VaultItemRow[];
      readonly itemId: string;
      readonly changes: Record<string, unknown>;
    }
  | { readonly id: number; readonly kind: 'lock' }
  | { readonly id: number; readonly kind: 'state' };

export type WorkerResponse =
  | { readonly id: number; readonly ok: true; readonly proof: { publicA: string; m1: string } }
  | { readonly id: number; readonly ok: true; readonly summaries: readonly OpenedSummary[] }
  | { readonly id: number; readonly ok: true; readonly matched: readonly MatchedSummary[] }
  | { readonly id: number; readonly ok: true; readonly unlocked: boolean }
  /**
   * The ONE arm carrying a secret. `credential: null` is a REFUSAL — the item
   * does not belong to that page, or cannot be opened — and it is deliberately
   * indistinguishable between those, like every other refusal here.
   */
  | {
      readonly id: number;
      readonly ok: true;
      readonly credential: { readonly username: string; readonly secret: string } | null;
    }
  | { readonly id: number; readonly ok: true; readonly blob: string }
  /** `null` = no such item, or content this build cannot read. */
  | { readonly id: number; readonly ok: true; readonly resealed: string | null }
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
      case 'matches': {
        return { id, ok: true, matched: await holder.matchesFor(request.rows, request.pageUrl) };
      }
      case 'fill': {
        return {
          id,
          ok: true,
          credential: await holder.fillFor(request.rows, request.itemId, request.pageUrl),
        };
      }
      case 'seal': {
        return {
          id,
          ok: true,
          blob: await holder.sealItem({
            itemId: request.itemId,
            blobVersion: request.blobVersion,
            content: request.content,
          }),
        };
      }
      case 'reseal': {
        return {
          id,
          ok: true,
          resealed: await holder.resealItem({
            rows: request.rows,
            itemId: request.itemId,
            changes: request.changes,
          }),
        };
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
