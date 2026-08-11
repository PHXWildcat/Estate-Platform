import { isVaultRequest, OFFSCREEN, type VaultRequest, type VaultResponse } from './messages.js';
import type { VaultHost } from './vault-host.js';

/**
 * WHAT THE OFFSCREEN DOCUMENT WILL DO WHEN ASKED.
 *
 * `chrome.runtime.sendMessage` delivers to EVERY extension context with a
 * listener, so this one filters on `target` and ignores everything else — and
 * the service worker's listener does the mirror image. That is a routing
 * convention, NOT an isolation boundary, and the messages module says so at
 * length: all extension contexts are one signed artifact, and the offscreen
 * document exists so keys can outlive a service worker, not to hide them from
 * the popup.
 *
 * The routing still matters for a duller reason: two listeners answering the
 * same message is a race, and `sendResponse` may only be called once.
 */
export type AddListener = (
  listener: (
    message: unknown,
    sender: unknown,
    sendResponse: (response: unknown) => void,
  ) => boolean | undefined,
) => void;

export function installOffscreenListener(host: VaultHost, addListener: AddListener): void {
  addListener((message, _sender, sendResponse) => {
    if (!isVaultRequest(message)) {
      // Not ours. Returning undefined lets whichever context owns it answer.
      return undefined;
    }
    void answer(host, message).then(sendResponse);
    // `true` keeps the channel open for the async reply. Without it the popup
    // gets `undefined` and every screen reads as a failure.
    return true;
  });
}

async function answer(host: VaultHost, message: VaultRequest): Promise<VaultResponse> {
  switch (message.kind) {
    case 'state':
      return { ok: true, state: host.state };
    case 'unlock': {
      const opened = await host.unlock({
        userId: message.userId,
        password: message.password,
        secretKey: message.secretKey,
        bearer: message.bearer,
      });
      return opened.ok ? { ok: true, state: opened.data } : { ok: false, code: opened.code };
    }
    case 'list': {
      const listed = await host.list(message.bearer);
      return listed.ok ? { ok: true, items: listed.data } : { ok: false, code: listed.code };
    }
    case 'matches': {
      const matched = await host.matchesFor(message.bearer, message.pageUrl);
      return matched.ok ? { ok: true, matched: matched.data } : { ok: false, code: matched.code };
    }
    case 'fill': {
      const filled = await host.fillFor(message.bearer, message.itemId, message.pageUrl);
      return filled.ok ? { ok: true, credential: filled.data } : { ok: false, code: filled.code };
    }
    case 'create': {
      const made = await host.createItem(message.bearer, message.itemType, message.content);
      return made.ok ? { ok: true, item: made.data } : { ok: false, code: made.code };
    }
    case 'update': {
      const saved = await host.updateItem({
        bearer: message.bearer,
        itemId: message.itemId,
        itemType: message.itemType,
        changes: message.changes,
        blobVersion: message.blobVersion,
      });
      return saved.ok ? { ok: true, item: saved.data } : { ok: false, code: saved.code };
    }
    case 'lock':
      await host.lock(message.bearer);
      return { ok: true, state: host.state };
  }
}

export { OFFSCREEN };
