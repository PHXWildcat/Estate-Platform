/**
 * THE EXTENSION PLATFORM SURFACE THIS APP TOUCHES, WRITTEN OUT BY HAND.
 *
 * `@types/chrome` describes every API Chrome has ever shipped. This describes
 * the five members this extension actually uses, and that difference is the
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

/**
 * `chrome.scripting`, ADDED IN PR3b — the API that turns "read the active tab's
 * URL" into "run code in that page", and the reason the manifest gains
 * `scripting` in the same change.
 *
 * DECLARED NARROWLY, on purpose. `executeScript` also accepts `files`, a `world`
 * of `MAIN`, and `css` siblings (`insertCSS`/`removeCSS`); none is declared,
 * so none can be reached without editing this file. Two of those absences are
 * load-bearing rather than tidy:
 *
 *   · `world` is omitted so the injection stays in the ISOLATED world, which is
 *     the default. MAIN would put this code in the page's own JS context, where
 *     the page can redefine the very setters a fill depends on.
 *   · `allFrames` is omitted because it was MEASURED to return PARTIAL results
 *     silently — two of four frames on a page whose others were not permitted,
 *     `ok: true`, no error. A caller cannot tell "no such frame" from "not
 *     permitted", so the fill names ONE frame and infers nothing from a count.
 *     (MDN states Chrome fails the whole call; that is false on 151.)
 *
 * `func` is SERIALIZED and deserialized for injection, so it closes over
 * nothing: everything it needs arrives through `args`, which must be
 * JSON-serializable. That is why the credential travels as an argument rather
 * than a captured variable, and it is the second path by which a secret leaves
 * the key holder — `test/fences.spec.ts` says so where it names the first.
 */
interface ChromeInjectionTarget {
  readonly tabId: number;
  /** Exactly one frame. See above for why `allFrames` is not declared. */
  readonly frameIds?: readonly number[];
}

interface ChromeInjectionResult<T> {
  readonly frameId: number;
  readonly result?: T;
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
  readonly scripting: {
    executeScript<A extends readonly unknown[], T>(injection: {
      readonly target: ChromeInjectionTarget;
      readonly func: (...args: A) => T;
      readonly args?: A;
    }): Promise<readonly ChromeInjectionResult<T>[]>;
  };
  readonly tabs: {
    query(info: { active: boolean; currentWindow: boolean }): Promise<ChromeTab[]>;
  };
};
