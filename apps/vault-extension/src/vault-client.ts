import type { ApiFailure } from './api.js';
import {
  BACKGROUND,
  OFFSCREEN,
  type ItemSummary,
  type MatchedItem,
  type VaultState,
} from './messages.js';

/**
 * THE POPUP'S VIEW OF THE VAULT: a message away, and no closer.
 *
 * The popup never holds a key, never imports the crypto, and never talks to the
 * vault service — it asks the offscreen document, which owns the worker that
 * does. This module is the whole of that conversation.
 *
 * IT ASKS THE SERVICE WORKER FIRST. Only one offscreen document may exist per
 * extension and it is created on demand, so every call ensures it is there
 * before addressing it. Doing that here rather than in each screen means a
 * popup opened before the document exists is not a race anybody has to
 * remember.
 */

export type VaultOutcome<T> = { ok: true; data: T } | { ok: false; code: ApiFailure };

async function ask<T>(message: unknown): Promise<VaultOutcome<T>> {
  try {
    await chrome.runtime.sendMessage({ target: BACKGROUND });
    const reply = await chrome.runtime.sendMessage(message);
    if (typeof reply !== 'object' || reply === null) {
      // A context that never answered. Treated as an outage rather than as a
      // locked vault: the popup must not tell somebody their vault is closed
      // because a message went nowhere.
      return { ok: false, code: 'UNAVAILABLE' };
    }
    const { ok, code } = reply as { ok?: unknown; code?: unknown };
    if (ok !== true) {
      return { ok: false, code: (typeof code === 'string' ? code : 'UNKNOWN') as ApiFailure };
    }
    return { ok: true, data: reply as T };
  } catch {
    return { ok: false, code: 'UNAVAILABLE' };
  }
}

export async function vaultState(): Promise<VaultOutcome<VaultState>> {
  const reply = await ask<{ state: VaultState }>({ target: OFFSCREEN, kind: 'state' });
  return reply.ok ? { ok: true, data: reply.data.state } : reply;
}

export async function unlockVault(input: {
  userId: string;
  password: string;
  secretKey: string;
  bearer: string;
}): Promise<VaultOutcome<VaultState>> {
  const reply = await ask<{ state: VaultState }>({ target: OFFSCREEN, kind: 'unlock', ...input });
  return reply.ok ? { ok: true, data: reply.data.state } : reply;
}

export async function listItems(bearer: string): Promise<VaultOutcome<readonly ItemSummary[]>> {
  const reply = await ask<{ items: readonly ItemSummary[] }>({
    target: OFFSCREEN,
    kind: 'list',
    bearer,
  });
  return reply.ok ? { ok: true, data: reply.data.items } : reply;
}

export async function matchesFor(
  bearer: string,
  pageUrl: string,
): Promise<VaultOutcome<readonly MatchedItem[]>> {
  const reply = await ask<{ matched: readonly MatchedItem[] }>({
    target: OFFSCREEN,
    kind: 'matches',
    bearer,
    pageUrl,
  });
  return reply.ok ? { ok: true, data: reply.data.matched } : reply;
}

/**
 * Ask the key holder to fill one item into one page (PR3b).
 *
 * `null` data is the holder REFUSING — the item does not belong to that page,
 * or could not be opened — and it is passed through as itself rather than
 * turned into a failure, because the two need different words on screen and
 * neither may say which of the several reasons applied.
 */
export async function fillFor(
  bearer: string,
  itemId: string,
  pageUrl: string,
): Promise<VaultOutcome<{ username: string; secret: string } | null>> {
  const reply = await ask<{ credential: { username: string; secret: string } | null }>({
    target: OFFSCREEN,
    kind: 'fill',
    bearer,
    itemId,
    pageUrl,
  });
  return reply.ok ? { ok: true, data: reply.data.credential } : reply;
}

export async function lockVault(bearer: string): Promise<VaultOutcome<VaultState>> {
  const reply = await ask<{ state: VaultState }>({ target: OFFSCREEN, kind: 'lock', bearer });
  return reply.ok ? { ok: true, data: reply.data.state } : reply;
}
