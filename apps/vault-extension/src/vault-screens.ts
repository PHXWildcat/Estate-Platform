import { request } from './api.js';
import { messageFor } from './copy.js';
import { el, render } from './dom.js';
import { injectFill } from './inject.js';
import type { ItemSummary } from './messages.js';
import { hasPunycode, isFillable } from './origin-match.js';
import { registrableDomain } from './registrable-domain.js';
import { forgetSecretKey, rememberSecretKey, rememberedSecretKey } from './secret-key-store.js';
import {
  createItem,
  fillFor,
  listItems,
  lockVault,
  matchesFor,
  unlockVault,
  updateItem,
  vaultState,
} from './vault-client.js';
import type { MatchedItem } from './messages.js';

/**
 * THE VAULT HALF OF THE POPUP: unlock, list, lock.
 *
 * It holds no key and imports no crypto — it collects two secrets, hands them
 * to the offscreen document, and renders what comes back. The one thing it does
 * hold is the user's choice about whether this device remembers the Secret Key,
 * and the copy next to that choice says what it costs rather than presenting it
 * as free.
 *
 * THE STEP-UP IS EXPECTED, NOT AN ERROR. Both vault SRP legs are step-up gated,
 * and PR1 widened `POST /v1/auth/stepup` to the `extension` audience for exactly
 * this — so an unlock that comes back `STEPUP_REQUIRED` reveals a code field in
 * place and retries, rather than sending the user back to Estate. Sending them
 * back would mean re-pairing, which is the credential this design keeps scarce.
 */

export interface VaultScreensDeps {
  readonly host: HTMLElement;
  readonly userId: string;
  readonly bearer: string;
}

type View =
  | { kind: 'checking' }
  | { kind: 'locked'; error?: string; stepUp?: boolean }
  | { kind: 'busy'; label: string }
  | {
      kind: 'unlocked';
      items: readonly ItemSummary[];
      matched?: readonly MatchedItem[];
      pageUrl?: string;
      tabId?: number;
      error?: string;
      note?: string;
    }
  /**
   * AUTHORING, IN EXTENSION-OWNED UI (M16 PR4a). `editing` carries the item
   * being changed; its absence is a create. Nothing here observes a page —
   * capturing a credential from one would need a standing content script, which
   * PR3b refused and the manifest fence still forbids.
   */
  | { kind: 'composing'; editing?: ItemSummary; error?: string };

/** Six digits, the only shape identity's CodeSchema accepts. */
const CODE_PATTERN = /^[0-9]{6}$/;

export async function mountVaultScreens(deps: VaultScreensDeps): Promise<void> {
  const { host, userId, bearer } = deps;
  let view: View = { kind: 'checking' };
  let remembered: string | null = null;

  function show(next: View): void {
    view = next;
    draw();
  }

  /**
   * The active tab's URL, or undefined.
   *
   * `activeTab` grants this at INVOCATION and revokes it on navigation, so
   * there is no standing view of anything — and a tab the extension may not see
   * (a `chrome://` page, or a window with nothing active) simply yields nothing
   * rather than an error, because "we cannot tell what page this is" is not a
   * failure of the vault.
   */
  async function activeTab(): Promise<{ id?: number; url?: string }> {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return {
        ...(tab?.id === undefined ? {} : { id: tab.id }),
        ...(typeof tab?.url === 'string' && tab.url.length > 0 ? { url: tab.url } : {}),
      };
    } catch {
      return {};
    }
  }

  async function refresh(): Promise<void> {
    const listed = await listItems(bearer);
    if (listed.ok) {
      const tab = await activeTab();
      const pageUrl = tab.url;
      const matched = pageUrl === undefined ? undefined : await matchesFor(bearer, pageUrl);
      show({
        kind: 'unlocked',
        ...(tab.id === undefined ? {} : { tabId: tab.id }),
        items: listed.data,
        ...(pageUrl === undefined ? {} : { pageUrl }),
        ...(matched?.ok === true ? { matched: matched.data } : {}),
      });
      return;
    }
    if (listed.code === 'VAULT_LOCKED') {
      show({ kind: 'locked' });
      return;
    }
    show({ kind: 'unlocked', items: [], error: messageFor(listed.code) });
  }

  async function attemptUnlock(
    password: string,
    secretKey: string,
    remember: boolean,
  ): Promise<void> {
    show({ kind: 'busy', label: 'Opening…' });
    const opened = await unlockVault({ userId, password, secretKey, bearer });
    if (opened.ok) {
      // Remembered only AFTER a key has actually opened this vault, so a typo
      // is never persisted as though it were the device's key.
      if (remember) await rememberSecretKey(userId, secretKey);
      else await forgetSecretKey(userId);
      remembered = remember ? secretKey : null;
      await refresh();
      return;
    }
    if (opened.code === 'STEPUP_REQUIRED') {
      show({ kind: 'locked', stepUp: true });
      return;
    }
    show({ kind: 'locked', error: messageFor(opened.code) });
  }

  async function attemptStepUp(code: string): Promise<void> {
    if (!CODE_PATTERN.test(code)) {
      // Refused before the network, so a typo costs no attempt against the
      // account's own step-up cap.
      show({ kind: 'locked', stepUp: true, error: 'Enter the six digits.' });
      return;
    }
    show({ kind: 'busy', label: 'Checking…' });
    const done = await request('/api/auth/stepup', { method: 'POST', bearer, body: { code } });
    if (done.ok) {
      show({ kind: 'locked' });
      return;
    }
    show({
      kind: 'locked',
      stepUp: true,
      // identity answers `invalid_credentials` for a rejected TOTP code exactly
      // as for a rejected password, so the generic copy would name credentials
      // this form does not have — the M12 defect.
      error:
        done.code === 'UNAUTHENTICATED'
          ? 'That code was not accepted. Codes last about 30 seconds — try the current one.'
          : messageFor(done.code),
    });
  }

  async function doLock(): Promise<void> {
    show({ kind: 'busy', label: 'Locking…' });
    await lockVault(bearer);
    show({ kind: 'locked' });
  }

  function drawLocked(error: string | undefined, stepUp: boolean | undefined): void {
    if (stepUp) {
      const code = el('input', { id: 'stepup-code', type: 'text', class: 'code' });
      const label = el('label', { class: 'label' }, 'Six-digit code');
      label.htmlFor = 'stepup-code';
      const confirm = el('button', { class: 'primary' }, 'Confirm');
      confirm.addEventListener('click', () => {
        void attemptStepUp(code.value.trim());
      });
      render(
        host,
        el('h2', {}, 'Confirm it’s you'),
        el('p', { class: 'hint' }, 'Opening a vault needs a fresh check from your authenticator.'),
        label,
        code,
        confirm,
        ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
      );
      return;
    }

    const password = el('input', { id: 'vault-password', type: 'password', class: 'code' });
    const passwordLabel = el('label', { class: 'label' }, 'Vault password');
    passwordLabel.htmlFor = 'vault-password';

    const secret = el('input', { id: 'secret-key', type: 'password', class: 'code' });
    if (remembered !== null) secret.value = remembered;
    const secretLabel = el('label', { class: 'label' }, 'Secret Key');
    secretLabel.htmlFor = 'secret-key';

    const remember = el('input', { id: 'remember', type: 'checkbox' });
    remember.checked = remembered !== null;
    const rememberLabel = el('label', { class: 'label' }, 'Remember the Secret Key on this device');
    rememberLabel.htmlFor = 'remember';

    const open = el('button', { class: 'primary' }, 'Open vault');
    open.addEventListener('click', () => {
      void attemptUnlock(password.value, secret.value.trim(), remember.checked);
    });

    render(
      host,
      el('h2', {}, 'Vault locked'),
      passwordLabel,
      password,
      secretLabel,
      secret,
      el('p', { class: 'hint' }, remember, ' ', rememberLabel),
      el(
        'p',
        { class: 'hint' },
        'Remembering it means only your vault password is needed next time. Anything that can read this browser profile can read a remembered Secret Key — your password is never stored either way.',
      ),
      open,
      ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
    );
  }

  /**
   * WHAT IS SAVED FOR THIS PAGE — including the refusals.
   *
   * A `confusable` or a `scheme-downgrade` is SHOWN and never offered, because
   * §4 TB9 commits to refusing rather than warning, and because a refusal the
   * user cannot see is indistinguishable from having nothing saved. PR3b adds
   * the fill button, and it appears on `match` rows ONLY — `isFillable` is the
   * one predicate that decides, so a fourth verdict added later is not offered
   * by accident.
   *
   * THE PHISHING SENTENCE IS ON THIS SCREEN AND NOT IN A DOC. docs/04 records it
   * as a residual "*on screen*", and this is the screen: autofill does not
   * resist phishing, because it fills the site the user themselves saved. The
   * origin rule stops a credential going to a DIFFERENT domain; it cannot stop
   * one going to a domain the user was persuaded to save.
   */
  function drawMatches(
    matched: readonly MatchedItem[],
    pageUrl: string,
    tabId: number | undefined,
  ): HTMLElement {
    /*
     * ONE PARSE, ONE CATCH. The internationalised-domain notice below needs the
     * same `URL` this line already builds, and the first version of it built a
     * second one inside its own try/catch — two parses of one string, two
     * failure paths for one failure, and a branch nothing exercised. Folded
     * together: whatever cannot be parsed is displayed verbatim and is not
     * claimed to be internationalised either.
     */
    let host: string;
    let punycodePage = false;
    try {
      const parsed = new URL(pageUrl);
      host = parsed.host;
      const domain = registrableDomain(parsed.hostname);
      punycodePage = domain !== null && hasPunycode(domain);
    } catch {
      host = pageUrl;
    }
    const list = el('ul', { class: 'items' });
    for (const item of matched) {
      const label =
        item.verdict.kind === 'match'
          ? `${item.title || '(no title)'} — saved for this site`
          : item.verdict.kind === 'scheme-downgrade'
            ? `${item.title || '(no title)'} — not offered: this page is not secure`
            : `${item.title || '(no title)'} — not offered: this address only looks like the saved one`;
      const row = el('li', {}, label);
      // ONLY a fillable verdict gets a control. A refusal is shown with no
      // button at all, rather than a disabled one: a greyed-out button invites
      // the question "how do I enable it", and the answer must never be "you
      // cannot" for something we are refusing on purpose.
      if (isFillable(item.verdict) && tabId !== undefined) {
        const fill = el('button', { class: 'secondary' }, 'Fill');
        fill.addEventListener('click', () => void doFill(item.id, pageUrl, tabId));
        row.append(' ', fill);
      }
      list.append(row);
    }
    return el(
      'div',
      {},
      el('h3', {}, `For ${host}`),
      // THE INTERNATIONALISED-DOMAIN NOTICE IS ABOUT THE PAGE, once. It used to
      // be a per-ITEM verdict: `isConfusable` returned true whenever either
      // side carried punycode, without comparing them, so every saved item came
      // back `confusable` on any IDN page — the whole vault disclosed to answer
      // a question about one origin, and the lookalike refusal firing on items
      // it knew nothing about. The comparison is gone (see `origin-match.ts`);
      // what survives is the one fact that was ever true, said about the page
      // rather than claimed about each credential.
      ...(punycodePage
        ? [
            el(
              'p',
              { class: 'warn' },
              'This address uses an internationalised domain name. Those can be made to look like familiar sites — check it carefully before filling anything.',
            ),
          ]
        : []),
      matched.length === 0
        ? el('p', { class: 'hint' }, 'Nothing saved for this site.')
        : (list as HTMLElement),
      el(
        'p',
        { class: 'hint' },
        'Filling gives this page the password. Estate checks the address matches the one you saved — it cannot tell whether the site itself is genuine, and the page decides what to do with the value.',
      ),
    );
  }

  /**
   * Ask the key holder to fill, then hand what comes back to the page.
   *
   * THREE OUTCOMES, KEPT APART. A credential fills; a `null` credential means
   * the holder DECLINED — the item does not belong to this page, or could not be
   * opened — and that is not an error the user caused; a failure means the vault
   * is shut or unreachable and is worth retrying. Collapsing any two of them
   * would be the M9 shape where a control firing reads as an outage.
   *
   * The popup stays OPEN and reports. The injection would survive its closing
   * (measured), but the outcome would not be observable, and a fill that
   * silently did nothing is the worst of the three.
   */
  async function doFill(itemId: string, pageUrl: string, tabId: number): Promise<void> {
    /*
     * THE PAGE IS RE-READ AT THE GESTURE, not trusted from the render.
     *
     * `vault-worker-core.ts` says the holder re-decides "because the page can
     * navigate between the two calls" — and the M16 review found it could not
     * detect that, because both calls were handed the SAME captured string.
     * `refresh()` reads the tab once, the view holds it, and the Fill button
     * closes over it; a user reads the list for as long as they like before
     * clicking. So the second decision was f(x) === f(x) over the page URL and
     * could never disagree with the first about where the tab now is.
     *
     * What actually stood between a navigated tab and a misfill was Chromium
     * revoking `activeTab` on a cross-origin navigation — real, but nobody
     * measured it, no test asserts it, and the whole boundary was resting on it
     * while the code claimed otherwise. Reading the tab HERE makes the claim
     * true independently of the platform, and narrows the window from "however
     * long the popup is open" to the round trip.
     *
     * A tab we can no longer see is a REFUSAL, not a fallback to the old value:
     * `activeTab` is revoked exactly when the thing we would be falling back on
     * has become wrong.
     */
    const now = await activeTab();
    if (now.url === undefined || now.id !== tabId || now.url !== pageUrl) {
      show({
        ...(view as Extract<View, { kind: 'unlocked' }>),
        note: 'This tab changed. Open the extension again to fill.',
      });
      return;
    }
    const filled = await fillFor(bearer, itemId, pageUrl);
    if (!filled.ok) {
      show({ ...(view as Extract<View, { kind: 'unlocked' }>), error: messageFor(filled.code) });
      return;
    }
    if (filled.data === null) {
      show({
        ...(view as Extract<View, { kind: 'unlocked' }>),
        note: 'That item is not offered for this page.',
      });
      return;
    }
    const outcome = await injectFill(tabId, filled.data);
    // FOUR OUTCOMES, NOT TWO. `ok: false` means the platform REFUSED the
    // injection — the page navigated, the tab closed, the grant lapsed — and it
    // used to render as "no password field was found", a fact about the page's
    // markup rather than about the refusal. That is a control reading as an
    // absence, which is the shape `inject.spec.ts` says it keeps apart and this
    // caller did not.
    //
    // And "Nothing was submitted" is no longer asserted: the fill dispatches
    // `input` and `change`, which a page is free to submit on, so the extension
    // can promise only what IT did. See `fill-into-page.ts`.
    const note = !outcome.ok
      ? 'We couldn’t reach that page. Open the extension again on the page you want to fill.'
      : outcome.filledSecret
        ? 'Filled. Estate didn’t submit anything — check the address before you sign in.'
        : 'No password field was found on this page.';
    show({ ...(view as Extract<View, { kind: 'unlocked' }>), note });
  }

  /**
   * The add / edit form.
   *
   * ON AN EDIT, BLANK MEANS UNCHANGED, and the copy says so because the user
   * cannot see what they are leaving alone: the popup never receives the item's
   * content, the key holder merges inside itself, and a field left empty is
   * simply not sent. Clearing a value on purpose is therefore not expressible
   * here, which is stated rather than hidden — it is the price of not making
   * this surface a full vault reader.
   */
  function drawComposing(editing: ItemSummary | undefined, error: string | undefined): void {
    const isEdit = editing !== undefined;
    const line = (id: string, type = 'text'): HTMLInputElement =>
      el('input', { id, type, class: 'code' });
    const labelled = (input: HTMLInputElement, text: string): HTMLElement => {
      const label = el('label', { class: 'label' }, text);
      label.htmlFor = input.id;
      return el('div', {}, label, input);
    };

    const title = line('item-title');
    if (isEdit) title.value = editing.title;
    const username = line('item-username');
    const secret = line('item-secret', 'password');
    const url = line('item-url');

    const save = el('button', {}, isEdit ? 'Save changes' : 'Add to vault');
    save.addEventListener('click', () => {
      void submitComposed(editing, {
        title: title.value,
        username: username.value,
        secret: secret.value,
        url: url.value,
      });
    });
    const cancel = el('button', { class: 'secondary' }, 'Cancel');
    cancel.addEventListener('click', () => {
      void refresh();
    });

    render(
      host,
      el('h2', {}, isEdit ? 'Edit item' : 'New item'),
      labelled(title, 'Title'),
      labelled(username, 'Username'),
      labelled(secret, 'Password'),
      labelled(url, 'Web address'),
      el(
        'p',
        { class: 'hint' },
        isEdit
          ? 'Leave a field empty to keep what is already saved — this device never receives the values it is not changing.'
          : 'Saved to your vault, encrypted on this device.',
      ),
      // The address is what decides where this credential may later be filled,
      // so it is worth one sentence rather than none.
      el('p', { class: 'hint' }, 'The web address decides where this can be filled.'),
      save,
      cancel,
      ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
    );
  }

  /** Create, or send only what changed. */
  async function submitComposed(
    editing: ItemSummary | undefined,
    typed: { title: string; username: string; secret: string; url: string },
  ): Promise<void> {
    if (editing === undefined && typed.title.trim().length === 0) {
      show({ kind: 'composing', error: 'Give it a title so you can find it again.' });
      return;
    }
    show({ kind: 'busy', label: editing ? 'Saving…' : 'Adding…' });

    if (editing === undefined) {
      const made = await createItem(bearer, 'password', {
        title: typed.title.trim(),
        username: typed.username,
        secret: typed.secret,
        url: typed.url,
      });
      if (!made.ok) {
        show({ kind: 'composing', error: messageFor(made.code) });
        return;
      }
      await refresh();
      return;
    }

    // ONLY WHAT WAS TYPED. An empty field is omitted, so the holder leaves that
    // value alone — see `drawComposing`.
    const changes: Record<string, unknown> = {};
    if (typed.title.trim().length > 0 && typed.title.trim() !== editing.title) {
      changes['title'] = typed.title.trim();
    }
    for (const [key, value] of [
      ['username', typed.username],
      ['secret', typed.secret],
      ['url', typed.url],
    ] as const) {
      if (value.length > 0) changes[key] = value;
    }
    if (Object.keys(changes).length === 0) {
      await refresh();
      return;
    }
    const saved = await updateItem(bearer, {
      itemId: editing.id,
      itemType: editing.itemType,
      changes,
      blobVersion: editing.blobVersion,
      revision: editing.revision,
    });
    if (!saved.ok) {
      show({ kind: 'composing', editing, error: messageFor(saved.code) });
      return;
    }
    await refresh();
  }

  function drawUnlocked(
    items: readonly ItemSummary[],
    error: string | undefined,
    matched: readonly MatchedItem[] | undefined,
    pageUrl: string | undefined,
    note: string | undefined,
  ): void {
    const lock = el('button', { class: 'secondary' }, 'Lock');
    lock.addEventListener('click', () => {
      void doLock();
    });
    const list = el('ul', { class: 'items' });
    for (const item of items) {
      // A text node, never markup — the title is somebody's own data.
      const row = el(
        'li',
        {},
        item.unreadable ? '(this item could not be read)' : item.title || '(no title)',
      );
      // No edit control on an item this build cannot read: there is nothing to
      // merge into, and the holder would refuse anyway.
      if (!item.unreadable) {
        const edit = el('button', { class: 'secondary' }, 'Edit');
        edit.addEventListener('click', () => {
          show({ kind: 'composing', editing: item });
        });
        row.append(' ', edit);
      }
      list.append(row);
    }
    const add = el('button', { class: 'secondary' }, 'New item');
    add.addEventListener('click', () => {
      show({ kind: 'composing' });
    });
    render(
      host,
      el('h2', {}, 'Vault open'),
      ...(matched !== undefined && pageUrl !== undefined
        ? [drawMatches(matched, pageUrl, view.kind === 'unlocked' ? view.tabId : undefined)]
        : []),
      items.length === 0 ? el('p', { class: 'hint' }, 'No items in this vault yet.') : list,
      add,
      lock,
      // A NOTE IS NOT AN ERROR. "That item is not offered for this page" and
      // "filled, nothing was submitted" are outcomes the user asked for; styling
      // them as failures would make a working refusal look like a fault.
      ...(note === undefined ? [] : [el('p', { class: 'hint' }, note)]),
      ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
    );
  }

  function draw(): void {
    if (view.kind === 'checking') {
      render(host, el('p', { class: 'hint' }, 'Checking your vault…'));
      return;
    }
    if (view.kind === 'busy') {
      render(host, el('p', { class: 'hint' }, view.label));
      return;
    }
    if (view.kind === 'locked') {
      drawLocked(view.error, view.stepUp);
      return;
    }
    if (view.kind === 'composing') {
      drawComposing(view.editing, view.error);
      return;
    }
    drawUnlocked(view.items, view.error, view.matched, view.pageUrl, view.note);
  }

  draw();
  remembered = await rememberedSecretKey(userId);
  const state = await vaultState();
  if (state.ok && state.data.status === 'unlocked') {
    await refresh();
    return;
  }
  // An UNAVAILABLE state read is not a locked vault, but it is not an open one
  // either — and the only thing this screen can offer is an unlock, so it shows
  // the form with the reason attached rather than a dead end.
  show({ kind: 'locked', ...(state.ok ? {} : { error: messageFor(state.code) }) });
}
