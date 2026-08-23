/**
 * THE ONLY THINGS THE POPUP MAY ASK THE KEY HOLDER TO DO.
 *
 * A closed union, and the closure is the control rather than the typing
 * convenience. The offscreen document is the one context that can decrypt, so
 * what it will do on request IS the extension's capability surface — and
 * docs/03 §4 TB9's second finding is that the content script must be
 * structurally unable to REQUEST a credential. PR3 adds a content script; the
 * shape that keeps that promise is a message union with no variant meaning
 * "give me a secret", established now, before there is a page in the picture.
 *
 * NOTHING HERE RETURNS PLAINTEXT except `list`, which returns the decrypted
 * TITLES a person is choosing between. Item secrets are not in any response in
 * PR2b: reading one is a PR3 concern and will arrive with the gesture
 * requirement that governs it.
 *
 * WHAT CROSSES THIS CHANNEL, stated plainly because it is the honest limit of
 * the offscreen design. `chrome.runtime.sendMessage` delivers to EVERY
 * extension context with a listener, so the vault password and Secret Key in
 * `unlock` transit a broadcast that the service worker also receives and
 * ignores by `target`. That is a filter, not an isolation boundary. All
 * extension contexts are one signed artifact and one trust domain: the
 * offscreen document exists so keys can live as NON-EXTRACTABLE CryptoKeys for
 * longer than a service worker lives, NOT to hide them from the rest of the
 * extension. Anyone who can read this channel has already compromised the
 * artifact, and could simply ask the offscreen document to decrypt instead.
 */

import type { MatchVerdict } from './origin-match.js';

/** Which context a broadcast message is addressed to. */
export const OFFSCREEN = 'offscreen' as const;
export const BACKGROUND = 'background' as const;

export type VaultRequest =
  /** Is the vault open on this device, and until when? */
  | { readonly target: typeof OFFSCREEN; readonly kind: 'state' }
  /** Run the SRP unlock. The two secrets exist in this message and nowhere else. */
  | {
      readonly target: typeof OFFSCREEN;
      readonly kind: 'unlock';
      readonly userId: string;
      readonly password: string;
      readonly secretKey: string;
      readonly bearer: string;
    }
  /** Decrypt and return item TITLES. No item secret is ever in a response. */
  | { readonly target: typeof OFFSCREEN; readonly kind: 'list'; readonly bearer: string }
  /**
   * Which saved items relate to a page. Still titles only — the verdict says
   * whether PR3b would be allowed to fill, never the credential itself.
   */
  | {
      readonly target: typeof OFFSCREEN;
      readonly kind: 'matches';
      readonly bearer: string;
      readonly pageUrl: string;
    }
  /**
   * FILL one named item into one named page (PR3b) — the only variant whose
   * response can carry a credential, and the shape is what keeps §4 TB9's
   * promise that a content script is structurally unable to REQUEST one.
   *
   * There is no `itemId`-to-secret variant here and never will be: the caller
   * names an item AND the page it believes it is on, and the key holder
   * re-reads the item's own encrypted `url` and decides for itself. So the most
   * this message can buy is a fill the user's own gesture could already have
   * driven.
   */
  | {
      readonly target: typeof OFFSCREEN;
      readonly kind: 'fill';
      readonly bearer: string;
      readonly itemId: string;
      readonly pageUrl: string;
    }
  /** Drop every key. Also what an idle timeout and a teardown do. */
  /**
   * AUTHORING, TYPED IN THE POPUP (M16 PR4a).
   *
   * The content is whatever the user entered in extension-owned UI. It is NOT
   * captured from a page: doing that needs a page observing submissions, which
   * PR3b refused (no standing channel a page can address, and the manifest fence
   * keeps `content_scripts` absent). So these two variants add no page surface
   * at all — they are the popup talking about its own form.
   */
  | {
      readonly target: typeof OFFSCREEN;
      readonly kind: 'create';
      readonly bearer: string;
      readonly itemType: string;
      readonly content: Record<string, unknown>;
    }
  | {
      readonly target: typeof OFFSCREEN;
      readonly kind: 'update';
      readonly bearer: string;
      readonly itemId: string;
      readonly itemType: string;
      /** Only what is CHANGING — absent means unchanged, so a blank field in a
       * form the user did not fill cannot erase a password they cannot see. */
      readonly changes: Record<string, unknown>;
      /**
       * The version the popup READ. The blob is sealed for `blobVersion + 1`,
       * because that is what the service will write and the number is inside
       * the AEAD's AAD. It is NOT what `If-Match` carries — see `revision`.
       */
      readonly blobVersion: number;
      /**
       * The concurrency token the popup read, sent on as `If-Match` (M27 PR1a).
       * Separate from `blobVersion` because a version restore puts a captured
       * version back, so a version can recur on a row and an equality check on
       * a recurring value silently admits a stale write.
       */
      readonly revision: number;
    }
  | { readonly target: typeof OFFSCREEN; readonly kind: 'lock'; readonly bearer?: string };

/** One item as the popup sees it: enough to recognise, never enough to use. */
export interface ItemSummary {
  readonly id: string;
  readonly itemType: string;
  readonly title: string;
  /** The version this summary was read at; it opens the blob. */
  readonly blobVersion: number;
  /** The concurrency token this summary was read at; an edit sends it back as If-Match. */
  readonly revision: number;
  /**
   * The blob decrypted but its content did not parse. Listed rather than
   * hidden — a user must be able to see that something is there (M15 PR2).
   */
  readonly unreadable?: boolean;
}

/** A summary plus the verdict that explains why it is on screen. */
export interface MatchedItem extends ItemSummary {
  readonly verdict: MatchVerdict;
}

export type VaultState =
  { readonly status: 'locked' } | { readonly status: 'unlocked'; readonly expiresAt: string };

export type VaultResponse =
  | { readonly ok: true; readonly state: VaultState }
  | { readonly ok: true; readonly items: readonly ItemSummary[] }
  | { readonly ok: true; readonly matched: readonly MatchedItem[] }
  /**
   * The one response arm that carries a credential, and it exists so the popup
   * can hand it straight to `chrome.scripting` — the popup is the only context
   * that may call it, since an offscreen document has `chrome.runtime` alone.
   * `credential: null` is the holder REFUSING, and is deliberately the same
   * answer for "wrong page" and "could not open it".
   */
  | {
      readonly ok: true;
      readonly credential: { readonly username: string; readonly secret: string } | null;
    }
  /** A create or an update, answered with the row as it now stands. */
  | { readonly ok: true; readonly item: ItemSummary }
  | { readonly ok: false; readonly code: string };

/** Narrowing helpers, so a stray message from anywhere is simply ignored. */
export function isVaultRequest(value: unknown): value is VaultRequest {
  if (typeof value !== 'object' || value === null) return false;
  const { target, kind } = value as { target?: unknown; kind?: unknown };
  return (
    target === OFFSCREEN &&
    (kind === 'state' ||
      kind === 'unlock' ||
      kind === 'list' ||
      kind === 'matches' ||
      kind === 'fill' ||
      kind === 'create' ||
      kind === 'update' ||
      kind === 'lock')
  );
}
