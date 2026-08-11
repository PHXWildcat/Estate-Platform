/**
 * THE EXTENSION PLATFORM SURFACE THIS APP TOUCHES, WRITTEN OUT BY HAND.
 *
 * `@types/chrome` describes every API Chrome has ever shipped. This describes
 * the four members this extension actually uses, and that difference is the
 * point rather than a size optimisation: the file is a readable statement of
 * how much platform the artifact is exposed to, sitting next to the manifest's
 * declared permissions, and adding an API here is as visible in review as
 * adding a permission.
 *
 * It also keeps the package's promise literally. `@estate/vault-crypto` has
 * zero dependencies by requirement (docs/04 boundary rule 3), `vault-web`'s
 * browser client has none, and this artifact — signed, auto-updated, and
 * running beside code we did not write (docs/03 TB9) — has none either, in
 * `dependencies` or `devDependencies`.
 *
 * `chrome.storage.local` is the ONLY persistence. It holds the session tokens
 * from pairing and nothing else, ever: key material does not go here, not in
 * PR2b and not later, which is why this declaration types the value as the
 * session record rather than as `unknown`.
 */

interface ChromeStorageArea {
  get(keys: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string): Promise<void>;
}

interface ChromeManifest {
  readonly host_permissions?: readonly string[];
  readonly permissions?: readonly string[];
  readonly version?: string;
}

/**
 * The offscreen API (M16 PR2b).
 *
 * `reasons` is the closed enum PR2a found had no value describing "hold vault
 * keys". The extension declares `WORKERS`, and that is TRUE rather than
 * convenient: the offscreen document's entire job is to spawn and host the
 * worker in which the master key lives (`vault-worker-core.ts`).
 */
type OffscreenReason = 'WORKERS';

interface ChromeOffscreen {
  createDocument(options: {
    url: string;
    reasons: readonly OffscreenReason[];
    justification: string;
  }): Promise<void>;
  hasDocument(): Promise<boolean>;
  closeDocument(): Promise<void>;
}

type MessageListener = (
  message: unknown,
  sender: unknown,
  sendResponse: (response: unknown) => void,
) => boolean | undefined;

/**
 * The active tab, which `activeTab` grants at INVOCATION and revokes on
 * navigation — no `tabs` permission is needed to read `url` this way, and the
 * extension has no view of any page until the user clicks it.
 */
interface ChromeTab {
  readonly id?: number;
  readonly url?: string;
}

declare const chrome: {
  readonly storage: { readonly local: ChromeStorageArea };
  readonly runtime: {
    getManifest(): ChromeManifest;
    getURL(path: string): string;
    sendMessage(message: unknown): Promise<unknown>;
    readonly onMessage: { addListener(listener: MessageListener): void };
  };
  readonly offscreen: ChromeOffscreen;
  readonly tabs: {
    query(info: { active: boolean; currentWindow: boolean }): Promise<ChromeTab[]>;
  };
};
