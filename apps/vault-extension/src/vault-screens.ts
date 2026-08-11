import { request } from './api.js';
import { messageFor } from './copy.js';
import { el, render } from './dom.js';
import { injectFill } from './inject.js';
import type { ItemSummary } from './messages.js';
import { isFillable } from './origin-match.js';
import { forgetSecretKey, rememberSecretKey, rememberedSecretKey } from './secret-key-store.js';
import {
  fillFor,
  listItems,
  lockVault,
  matchesFor,
  unlockVault,
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
    };

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
    let host: string;
    try {
      host = new URL(pageUrl).host;
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
      matched.length === 0
        ? el('p', { class: 'hint' }, 'Nothing saved for this site.')
        : (list as HTMLElement),
      el(
        'p',
        { class: 'hint' },
        'Filling gives this page the password. Estate checks the address matches the one you saved — it cannot tell whether the site itself is genuine.',
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
    show({
      ...(view as Extract<View, { kind: 'unlocked' }>),
      note: outcome.filledSecret
        ? 'Filled. Nothing was submitted — check it and sign in yourself.'
        : 'No password field was found on this page.',
    });
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
      list.append(
        el(
          'li',
          {},
          item.unreadable ? '(this item could not be read)' : item.title || '(no title)',
        ),
      );
    }
    render(
      host,
      el('h2', {}, 'Vault open'),
      ...(matched !== undefined && pageUrl !== undefined
        ? [drawMatches(matched, pageUrl, view.kind === 'unlocked' ? view.tabId : undefined)]
        : []),
      items.length === 0 ? el('p', { class: 'hint' }, 'No items in this vault yet.') : list,
      el('p', { class: 'hint' }, 'Reading an item is not available yet.'),
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
