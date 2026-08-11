import { request } from './api.js';
import { messageFor } from './copy.js';
import { el, render } from './dom.js';
import type { ItemSummary } from './messages.js';
import { forgetSecretKey, rememberSecretKey, rememberedSecretKey } from './secret-key-store.js';
import { listItems, lockVault, unlockVault, vaultState } from './vault-client.js';

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
  | { kind: 'unlocked'; items: readonly ItemSummary[]; error?: string };

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

  async function refresh(): Promise<void> {
    const listed = await listItems(bearer);
    if (listed.ok) {
      show({ kind: 'unlocked', items: listed.data });
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

  function drawUnlocked(items: readonly ItemSummary[], error: string | undefined): void {
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
      items.length === 0 ? el('p', { class: 'hint' }, 'No items in this vault yet.') : list,
      el('p', { class: 'hint' }, 'Reading an item is not available yet.'),
      lock,
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
    drawUnlocked(view.items, view.error);
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
