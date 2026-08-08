import { formatSecretKey, parseSecretKey, wipe } from '/lib/vault-crypto/index.js';
import { request, type ApiFailure } from './api.js';
import { copyWithAutoClear, clearNow, CLIPBOARD_CLEAR_MS } from './clipboard.js';
import { el, field, onClick, onSubmit, replaceChildren, requireElement } from './dom.js';
import { downloadEmergencyKit } from './emergency-kit.js';
import { DEFAULT_LENGTH, entropyBits, generatePassword } from './generator.js';
import type { ItemContent } from './item-content.js';
import { forgetSecretKey, recallSecretKey, rememberSecretKey } from './secret-key-store.js';
import { IDLE_LOCK_MS, VaultSession, type OpenedItem } from './vault-session.js';

/**
 * The vault surface (M15 PR2).
 *
 * Screens are functions that replace the contents of one container. There is no
 * router and no framework: the vault has five states (no vault, locked,
 * unlocked, editing an item, settings) and a state variable reads more honestly
 * than a routing table would. Every node is built through `dom.ts`, so the
 * origin's `trusted-types 'none'` policy stays enforceable — see that module.
 *
 * WHAT THIS FILE DELIBERATELY NEVER DOES: touch a key. `VaultSession` owns all
 * of it, and this module passes user input in and gets rendered values out.
 * That is what keeps the "one place holds keys" claim checkable rather than a
 * property of how carefully each screen was written.
 */

const session = new VaultSession();

/** Item types the service accepts (`vault_items.item_type`, docs/02 §5). */
const ITEM_TYPES: ReadonlyArray<{ value: string; label: string }> = [
  { value: 'password', label: 'Password' },
  { value: 'pin', label: 'PIN' },
  { value: 'recovery_codes', label: 'Recovery codes' },
  { value: 'seed_phrase', label: 'Seed phrase' },
  { value: 'private_key', label: 'Private key' },
  { value: 'secure_note', label: 'Secure note' },
  { value: 'license', label: 'Licence' },
  // `attachment` is deliberately absent: blobs cap at 68 KiB and the streaming
  // path is a recorded follow-up (docs/04 M6), so offering it would promise
  // something the service cannot store.
];

/** One message per failure. Vague copy is worst on the screen holding secrets. */
function messageFor(code: ApiFailure): string {
  switch (code) {
    case 'UNAUTHENTICATED':
      return 'Your vault session has ended. Open the vault again from Estate.';
    case 'STEPUP_REQUIRED':
      return 'That action needs a fresh identity check. Open the vault again from Estate.';
    case 'VAULT_LOCKED':
      return 'The vault is locked. Unlock it and try again.';
    case 'CONFLICT':
      return 'This item changed since you opened it. Reload and try again.';
    case 'NOT_FOUND':
      return 'That item is no longer there.';
    case 'INVALID_REQUEST':
      return 'Something about that was not accepted. Check the fields and try again.';
    case 'UNAVAILABLE':
    case 'NETWORK':
      return 'The vault is temporarily unreachable. Try again shortly.';
    default:
      return 'Something went wrong. Try again.';
  }
}

function status(message: string, tone: 'ok' | 'warn' | 'error' = 'ok'): HTMLElement {
  return el('p', { class: `status status-${tone}`, role: 'status', 'aria-live': 'polite' }, [
    message,
  ]);
}

function main(): HTMLElement {
  return requireElement('app');
}

/** Who is signed in, from the session route the edge proxies. */
interface SessionInfo {
  userId: string;
  audience: string;
}

let account: SessionInfo | null = null;

// ---------------------------------------------------------------- screens

async function renderRoot(): Promise<void> {
  if (new URLSearchParams(window.location.search).get('open') === 'refused') {
    replaceChildren(
      main(),
      el('h1', {}, ['This vault link has expired']),
      status(
        'Vault links are valid for about a minute and can be used once. Go back to Estate and open the vault again.',
        'warn',
      ),
      backLink(),
    );
    return;
  }

  const who = await request<SessionInfo>('/api/auth/session');
  if (!who.ok) {
    replaceChildren(
      main(),
      el('h1', {}, ['Not signed in']),
      status(
        who.code === 'NETWORK' || who.code === 'UNAVAILABLE'
          ? 'The vault is temporarily unreachable. Try again shortly.'
          : 'Open the vault from Estate to continue.',
        who.code === 'NETWORK' || who.code === 'UNAVAILABLE' ? 'error' : 'warn',
      ),
      backLink(),
    );
    return;
  }
  account = who.data;

  const keyset = await session.keysetStatus();
  if (!keyset.ok) {
    replaceChildren(main(), el('h1', {}, ['Vault']), status(messageFor(keyset.code), 'error'));
    return;
  }
  if (!keyset.data.enrolled) {
    renderSetup();
    return;
  }
  await renderUnlock();
}

/** First run: choose a vault password, receive a Secret Key. */
function renderSetup(): void {
  const password = field({
    id: 'setup-password',
    label: 'Vault password',
    type: 'password',
    autocomplete: 'new-password',
    hint: 'Different from your Estate password. We never receive it and cannot reset it for you.',
  });
  const confirm = field({
    id: 'setup-confirm',
    label: 'Confirm vault password',
    type: 'password',
    autocomplete: 'new-password',
  });
  const note = el('div');
  const submit = el('button', { class: 'button', type: 'submit' }, ['Create my vault']);
  const form = el('form', {}, [password.row, confirm.row, el('p', {}, [submit]), note]);

  onSubmit(form, () => {
    void (async () => {
      replaceChildren(note);
      if (password.input.value.length < 12) {
        note.append(status('Use at least 12 characters.', 'error'));
        return;
      }
      if (password.input.value !== confirm.input.value) {
        note.append(status('Those two passwords do not match.', 'error'));
        return;
      }
      if (!account) return;
      submit.setAttribute('disabled', '');
      note.append(status('Setting up your vault — this takes a moment.'));
      const created = await session
        .enroll(account.userId, password.input.value)
        .catch(() => ({ ok: false as const, code: 'UNAVAILABLE' as const }));
      // The password is gone from the DOM the instant it has been used.
      password.input.value = '';
      confirm.input.value = '';
      if (!created.ok) {
        submit.removeAttribute('disabled');
        replaceChildren(note, status(messageFor(created.code), 'error'));
        return;
      }
      renderSecretKey(created.data.secretKey, created.data.entropy);
    })();
  });

  replaceChildren(
    main(),
    el('h1', {}, ['Set up your vault']),
    el('p', { class: 'status' }, [
      'Your vault is encrypted on this device. Estate stores only the encrypted result and cannot read it — not for a support request, and not for a court order.',
    ]),
    form,
  );
}

/**
 * The Secret Key, shown exactly once.
 *
 * There is no "show it again" anywhere in this app, because the server does not
 * have it. That is the whole point, and the screen has to say so before the
 * user clicks past it.
 */
function renderSecretKey(secretKey: string, entropy: Uint8Array): void {
  const remember = el('input', { id: 'remember', type: 'checkbox' });
  remember.checked = true;
  const acknowledged = el('input', { id: 'ack', type: 'checkbox' });
  const note = el('div');
  const done = el('button', { class: 'button', type: 'button' }, ['I have saved it — continue']);

  onClick(done, () => {
    void (async () => {
      if (!acknowledged.checked) {
        replaceChildren(note, status('Please confirm you have saved your Secret Key.', 'warn'));
        return;
      }
      if (!account) return;
      if (remember.checked) {
        await rememberSecretKey(account.userId, entropy);
      }
      // Whatever the choice, this copy goes.
      wipe(entropy);
      await renderUnlock();
    })();
  });

  const kit = el('button', { class: 'button-quiet', type: 'button' }, ['Download Emergency Kit']);
  onClick(kit, () => {
    if (!account) return;
    downloadEmergencyKit({
      secretKey,
      accountLabel: account.userId,
      issuedAt: new Date().toISOString().slice(0, 10),
    });
  });

  replaceChildren(
    main(),
    el('h1', {}, ['Save your Secret Key']),
    el('p', { class: 'status status-warn' }, [
      'This is shown once. Estate does not have a copy, so we cannot show it to you again or recover it if you lose it.',
    ]),
    el('p', { class: 'secret-key' }, [secretKey]),
    el('p', { class: 'status' }, [
      'You need it to unlock your vault on a new device. Losing it means the vault must be reset, which permanently destroys everything in it.',
    ]),
    el('p', {}, [kit]),
    el('div', { class: 'check' }, [
      remember,
      el('label', { for: 'remember' }, ['Remember it on this device']),
    ]),
    el('p', { class: 'field-hint' }, [
      'Stored only in this browser, on this origin. Anyone who can run script here could read it — which is what this origin’s restrictions exist to prevent.',
    ]),
    el('div', { class: 'check' }, [
      acknowledged,
      el('label', { for: 'ack' }, ['I have saved my Secret Key somewhere safe']),
    ]),
    el('p', {}, [done]),
    note,
  );
}

/** Unlock: vault password plus the Secret Key, unless this device remembers. */
async function renderUnlock(): Promise<void> {
  const remembered = account ? await recallSecretKey(account.userId) : null;
  const password = field({
    id: 'unlock-password',
    label: 'Vault password',
    type: 'password',
    autocomplete: 'current-password',
  });
  const secret = field({
    id: 'unlock-secret',
    label: 'Secret Key',
    hint: 'Looks like ES1-… — from your Emergency Kit.',
  });
  const note = el('div');
  const submit = el('button', { class: 'button', type: 'submit' }, ['Unlock']);

  const rows = [password.row];
  if (!remembered) {
    rows.push(secret.row);
  }
  const form = el('form', {}, [...rows, el('p', {}, [submit]), note]);

  onSubmit(form, () => {
    void (async () => {
      if (!account) return;
      replaceChildren(note, status('Unlocking…'));
      submit.setAttribute('disabled', '');
      const secretKeyText = remembered
        ? await formatSecretKey(remembered)
        : secret.input.value.trim();
      const opened = await session
        .unlock(account.userId, password.input.value, secretKeyText)
        // A mistyped Secret Key throws in `parseSecretKey` before any network
        // call. It is the SAME answer as a wrong password by design, so it
        // lands on the same message rather than telling the user which half of
        // 2SKD they got wrong.
        .catch(() => ({ ok: false as const, code: 'UNAUTHENTICATED' as const }));
      password.input.value = '';
      secret.input.value = '';
      submit.removeAttribute('disabled');
      if (!opened.ok) {
        // ONE MESSAGE for a wrong password and a wrong Secret Key. The server
        // answers one `srp_failed` for both by design, and naming which half
        // was wrong would tell someone holding a stolen Secret Key that it is
        // the right one — halving the work of the attack 2SKD exists to make
        // hard.
        replaceChildren(
          note,
          status(
            opened.code === 'UNAUTHENTICATED'
              ? 'That vault password and Secret Key did not open this vault.'
              : messageFor(opened.code),
            'error',
          ),
        );
        return;
      }
      await renderVault();
    })();
  });

  replaceChildren(
    main(),
    el('h1', {}, ['Unlock your vault']),
    remembered
      ? el('p', { class: 'status' }, ['This device remembers your Secret Key.'])
      : el('p', { class: 'status' }, ['This device does not have your Secret Key saved.']),
    form,
    el('p', {}, [linkButton('Vault settings', () => renderSettings())]),
  );
}

/** The list. Every title here was decrypted on this device a moment ago. */
async function renderVault(): Promise<void> {
  const listed = await session.list();
  if (!listed.ok) {
    replaceChildren(main(), el('h1', {}, ['Vault']), status(messageFor(listed.code), 'error'));
    return;
  }
  const items = listed.data;

  const rows = items.map((item) =>
    el('li', { class: 'item' }, [
      linkButton(
        item.unreadable ? '(this item could not be read)' : item.content.title || '(untitled)',
        () => renderItem(item),
      ),
      el('span', { class: 'item-type' }, [labelFor(item.itemType)]),
    ]),
  );

  replaceChildren(
    main(),
    el('div', { class: 'row-between' }, [
      el('h1', {}, ['Vault']),
      el('span', { class: 'field-hint' }, [`Locks after ${IDLE_LOCK_MS / 60000} minutes idle`]),
    ]),
    items.length === 0 ? status('Nothing here yet.') : el('ul', { class: 'items' }, rows),
    el('p', {}, [
      buttonEl('Add an item', () => renderItem(null)),
      ' ',
      quietButton('Lock now', () => {
        void (async () => {
          clearNow();
          await session.lock('user');
          await renderUnlock();
        })();
      }),
      ' ',
      quietButton('Settings', () => renderSettings()),
    ]),
  );
}

/** Create or edit. The same screen, because they differ only in the verb. */
function renderItem(existing: OpenedItem | null): void {
  const content: ItemContent = existing?.content ?? { title: '' };
  const title = field({ id: 'item-title', label: 'Title', value: content.title });
  const username = field({ id: 'item-username', label: 'Username', value: content.username ?? '' });
  const secret = field({
    id: 'item-secret',
    label: 'Password or secret',
    type: 'password',
    value: content.secret ?? '',
  });
  const url = field({ id: 'item-url', label: 'Website', value: content.url ?? '' });
  const notes = field({
    id: 'item-notes',
    label: 'Notes',
    value: content.notes ?? '',
    multiline: true,
  });

  const type = el('select', { id: 'item-type', class: 'field-input' });
  for (const option of ITEM_TYPES) {
    const node = el('option', { value: option.value }, [option.label]);
    if ((existing?.itemType ?? 'password') === option.value) {
      node.setAttribute('selected', '');
    }
    type.append(node);
  }

  const note = el('div');
  const save = el('button', { class: 'button', type: 'submit' }, [
    existing ? 'Save changes' : 'Add to vault',
  ]);

  const reveal = quietButton('Show', () => {
    const showing = secret.input.getAttribute('type') === 'text';
    secret.input.setAttribute('type', showing ? 'password' : 'text');
  });
  const copy = quietButton('Copy', () => {
    void (async () => {
      const outcome = await copyWithAutoClear(secret.input.value);
      replaceChildren(
        note,
        status(
          outcome === 'copied'
            ? `Copied. Your clipboard clears in ${CLIPBOARD_CLEAR_MS / 1000} seconds — this cannot reach a clipboard manager or another device.`
            : 'This browser would not let the page copy. Select the field and copy it yourself.',
          outcome === 'copied' ? 'ok' : 'warn',
        ),
      );
    })();
  });
  const suggest = quietButton('Generate', () => {
    secret.input.value = generatePassword(DEFAULT_LENGTH);
    secret.input.setAttribute('type', 'text');
    replaceChildren(
      note,
      status(`Generated — about ${entropyBits(DEFAULT_LENGTH)} bits of entropy.`),
    );
  });

  const form = el('form', {}, [
    title.row,
    el('div', { class: 'field' }, [
      el('label', { class: 'field-label', for: 'item-type' }, ['Type']),
      type,
    ]),
    username.row,
    secret.row,
    el('p', {}, [reveal, ' ', copy, ' ', suggest]),
    url.row,
    notes.row,
    el('p', {}, [save, ' ', quietButton('Cancel', () => void renderVault())]),
    note,
  ]);

  onSubmit(form, () => {
    void (async () => {
      if (title.input.value.trim().length === 0) {
        replaceChildren(note, status('Give it a title so you can find it later.', 'warn'));
        return;
      }
      save.setAttribute('disabled', '');
      const next: ItemContent = {
        title: title.input.value.trim(),
        username: username.input.value,
        secret: secret.input.value,
        url: url.input.value,
        notes: notes.input.value,
        // Anything a newer client wrote travels through an edit untouched.
        ...(content.unknown ? { unknown: content.unknown } : {}),
      };
      const saved = existing
        ? await session.update(existing, type.value, next)
        : await session.create(type.value, next);
      if (!saved.ok) {
        save.removeAttribute('disabled');
        replaceChildren(note, status(messageFor(saved.code), 'error'));
        return;
      }
      await renderVault();
    })();
  });

  const heading = existing ? 'Edit item' : 'Add an item';
  const children: Array<HTMLElement | string> = [el('h1', {}, [heading]), form];
  if (existing) {
    children.push(
      el('p', {}, [
        quietButton('Delete this item', () => {
          void (async () => {
            const removed = await session.remove(existing.id);
            if (!removed.ok) {
              replaceChildren(
                note,
                status(
                  removed.code === 'STEPUP_REQUIRED'
                    ? 'Deleting needs a fresh identity check. Open the vault again from Estate, then retry.'
                    : messageFor(removed.code),
                  'error',
                ),
              );
              return;
            }
            await renderVault();
          })();
        }),
      ]),
    );
  }
  replaceChildren(main(), ...children);
}

/**
 * Settings: change the password, forget this device, and the reset.
 *
 * Reachable from the UNLOCK screen as well as from inside the vault, because
 * the reset is for people who cannot get in — gating it behind an unlock would
 * make it useless in the one situation it exists for.
 */
function renderSettings(): void {
  const note = el('div');
  const unlocked = session.isUnlocked;

  // --- change the vault password (needs an open vault + the Secret Key) ---
  const current = field({
    id: 'change-secret',
    label: 'Secret Key',
    hint: 'Unchanged by this — only the password half of the derivation moves.',
  });
  const next = field({ id: 'change-new', label: 'New vault password', type: 'password' });
  const changeButton = el('button', { class: 'button', type: 'submit' }, ['Change password']);
  const changeForm = el('form', {}, [current.row, next.row, el('p', {}, [changeButton])]);

  onSubmit(changeForm, () => {
    void (async () => {
      if (next.input.value.length < 12) {
        replaceChildren(note, status('Use at least 12 characters.', 'error'));
        return;
      }
      changeButton.setAttribute('disabled', '');
      replaceChildren(note, status('Changing…'));
      // `parseSecretKey` THROWS on a malformed key (bad checksum, wrong
      // prefix, wrong length) rather than returning a result — so without this
      // the screen would sit on "Changing…" forever, which is the worst
      // possible answer on the screen that changes key material.
      const changed = await session
        .changePassword(next.input.value, current.input.value.trim())
        .catch(() => ({ ok: false as const, code: 'INVALID_REQUEST' as const }));
      next.input.value = '';
      current.input.value = '';
      changeButton.removeAttribute('disabled');
      replaceChildren(
        note,
        changed.ok
          ? status('Your vault password has changed. Other devices were signed out.', 'ok')
          : status(
              changed.code === 'CONFLICT' || changed.code === 'INVALID_REQUEST'
                ? 'That Secret Key does not match this vault.'
                : messageFor(changed.code),
              'error',
            ),
      );
    })();
  });

  // --- reset ---
  const resetPassword = field({
    id: 'reset-password',
    // Distinct from the change-password field above, which can be on the same
    // screen: two controls sharing a visible label is ambiguous to a person and
    // genuinely broken for a screen reader.
    label: 'Password for the new empty vault',
    type: 'password',
    hint: 'The vault starts empty with this password and a new Secret Key.',
  });
  const confirm = field({
    id: 'reset-confirm',
    label: 'Type DESTROY to confirm',
    hint: 'Nobody can undo this, including us.',
  });
  const reset = el('button', { class: 'button-danger', type: 'button' }, [
    'Reset my vault permanently',
  ]);
  onClick(reset, () => {
    void (async () => {
      if (confirm.input.value.trim() !== 'DESTROY') {
        replaceChildren(note, status('Type DESTROY exactly to confirm.', 'warn'));
        return;
      }
      if (resetPassword.input.value.length < 12) {
        replaceChildren(note, status('Choose a new password of at least 12 characters.', 'error'));
        return;
      }
      if (!account) return;
      reset.setAttribute('disabled', '');
      replaceChildren(note, status('Resetting…'));
      const done = await session
        .reset(account.userId, resetPassword.input.value)
        .catch(() => ({ ok: false as const, code: 'UNAVAILABLE' as const }));
      resetPassword.input.value = '';
      confirm.input.value = '';
      if (!done.ok) {
        reset.removeAttribute('disabled');
        replaceChildren(
          note,
          status(
            done.code === 'STEPUP_REQUIRED'
              ? 'Resetting needs a fresh identity check. Open the vault again from Estate, then retry.'
              : messageFor(done.code),
            'error',
          ),
        );
        return;
      }
      // The old Secret Key opens nothing now, so this device must forget it and
      // the user must save the new one.
      await forgetSecretKey(account.userId);
      renderSecretKey(done.data.secretKey, done.data.entropy);
    })();
  });

  const children: HTMLElement[] = [el('h1', {}, ['Vault settings'])];
  if (unlocked) {
    children.push(el('h2', {}, ['Change your vault password']), changeForm);
  }
  children.push(
    el('h2', {}, ['This device']),
    el('p', {}, [
      // Signing out of the ORIGIN, not just locking the vault. The edge clears
      // its `__Host-` cookie only when identity actually revoked the session —
      // a "signed out" screen over a live session is the worse outcome (M8 PR5).
      quietButton('Sign out of the vault', () => {
        void (async () => {
          await session.lock('user');
          const out = await request('/api/auth/logout', { method: 'POST' });
          if (!out.ok) {
            replaceChildren(
              note,
              status('Could not sign out. Your session is still open.', 'error'),
            );
            return;
          }
          window.location.assign('/');
        })();
      }),
    ]),
    el('p', {}, [
      quietButton('Forget my Secret Key on this device', () => {
        void (async () => {
          if (!account) return;
          await forgetSecretKey(account.userId);
          replaceChildren(note, status('This device will ask for your Secret Key next time.'));
        })();
      }),
    ]),
    el('h2', {}, ['Reset the vault']),
    el('p', { class: 'status status-warn' }, [
      'A reset is the only way back from a forgotten vault password, and it DESTROYS what is in the vault. It permanently erases:',
    ]),
    el('ul', { class: 'items' }, [
      el('li', {}, ['every item — the contents can never be decrypted again, by anyone']),
      el('li', {}, ['your emergency-access arrangement, and every share your contacts hold']),
      el('li', {}, ['the recovery keypair others may have sealed shares to']),
    ]),
    el('p', { class: 'status' }, [
      'Estate cannot recover any of it afterwards. The records remain; their meaning does not.',
    ]),
    resetPassword.row,
    confirm.row,
    el('p', {}, [
      reset,
      ' ',
      quietButton('Back', () => {
        void (unlocked ? renderVault() : renderUnlock());
      }),
    ]),
    note,
  );
  replaceChildren(main(), ...children);
}

// ---------------------------------------------------------------- helpers

function labelFor(itemType: string): string {
  return ITEM_TYPES.find((t) => t.value === itemType)?.label ?? itemType;
}

function buttonEl(label: string, onActivate: () => void): HTMLElement {
  const node = el('button', { class: 'button', type: 'button' }, [label]);
  onClick(node, onActivate);
  return node;
}

function quietButton(label: string, onActivate: () => void): HTMLElement {
  const node = el('button', { class: 'button-quiet', type: 'button' }, [label]);
  onClick(node, onActivate);
  return node;
}

function linkButton(label: string, onActivate: () => void): HTMLElement {
  const node = el('button', { class: 'link-button', type: 'button' }, [label]);
  onClick(node, onActivate);
  return node;
}

function backLink(): HTMLElement {
  const node = el('p', {}, [el('a', { class: 'link', id: 'back' }, ['Back to Estate'])]);
  queueMicrotask(wireBackLink);
  return node;
}

declare global {
  interface Window {
    ESTATE_APP_ORIGIN?: string;
  }
}

function wireBackLink(): void {
  const link = document.getElementById('back');
  const target = window.ESTATE_APP_ORIGIN;
  if (!link || !target) return;
  onClick(link, () => window.location.assign(target));
}

/**
 * The vault locks itself when the tab goes away, on top of the idle timer.
 *
 * `pagehide` rather than `beforeunload`: it fires for the bfcache case too, so
 * a page restored from history comes back locked rather than restored with keys
 * in memory.
 */
export function installLifecycle(): void {
  for (const event of ['pointerdown', 'keydown'] as const) {
    document.addEventListener(event, () => session.touch(), { passive: true });
  }
  window.addEventListener('pagehide', () => {
    clearNow();
    void session.lock('expired');
  });
  session.subscribe((state) => {
    if (state.status === 'locked' && document.getElementById('app')?.childNodes.length) {
      // An idle lock must not leave decrypted titles on screen.
      void renderUnlock();
    }
  });
}

export async function render(): Promise<void> {
  await renderRoot();
}

export { session as vaultSession, parseSecretKey };
