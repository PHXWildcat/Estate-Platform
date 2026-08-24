import {
  formatSecretKey,
  fromBase64,
  parseSecretKey,
  publicKeyFingerprint,
  wipe,
} from '/lib/vault-crypto/index.js';
import { request, type ApiFailure } from './api.js';
import { copyWithAutoClear, clearNow, CLIPBOARD_CLEAR_MS } from './clipboard.js';
import { el, field, onClick, onSubmit, replaceChildren, requireElement } from './dom.js';
import { downloadEmergencyKit } from './emergency-kit.js';
import {
  configureEscrow,
  denyPolicy,
  describeEscrow,
  grantedToMe,
  granteeCandidates,
  offerFor,
  ownRecoveryKey,
  publishRecoveryKey,
  rearmPolicy,
  releaseAndRecover,
  requestAccess,
  revokePolicy,
  type GranteeCandidate,
  type GranteeKeyOffer,
  type PolicyDto,
} from './emergency.js';
import { DEFAULT_LENGTH, entropyBits, generatePassword } from './generator.js';
import { promptForStepUp } from './stepup.js';
import type { ItemContent } from './item-content.js';
import { forgetSecretKey, recallSecretKey, rememberSecretKey } from './secret-key-store.js';
import {
  IDLE_LOCK_MS,
  VaultSession,
  type OpenedItem,
  type OpenedVersion,
} from './vault-session.js';

/**
 * The vault surface (M15 PR2).
 *
 * Screens are functions that replace the contents of one container. There is no
 * router and no framework: a state variable reads more honestly than a routing
 * table would. The screens are deliberately NOT counted or listed here — the
 * set has grown in M15, M18, M23 and M27, and a hand-maintained list beside a
 * thing that grows is this repo's most repeated defect. Every node is built
 * through `dom.ts`, so the origin's `trusted-types 'none'` policy stays
 * enforceable — see that module.
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

/**
 * Run a step-up-gated action, proving a factor ON THIS ORIGIN if it is refused.
 *
 * Redemption grants no step-up any more (the M15 review's bypass: a stolen
 * handoff code reaching `POST /v1/vault/reset`, which is gated on step-up
 * alone). So every gated action has to be able to ask, and the old copy —
 * "Open the vault again from Estate" — is now both wrong and dangerous advice,
 * because re-opening mints a fresh handoff, the very credential the change
 * exists to devalue.
 *
 * ONE retry, only after identity ACCEPTED the code. A cancel resolves without
 * running the action at all: proceeding past a withdrawn consent is the M13
 * round-3 defect and this is the same ceremony.
 */
async function withStepUp<T extends { ok: boolean; code?: ApiFailure }>(
  host: HTMLElement,
  what: string,
  run: () => Promise<T>,
): Promise<T | { ok: false; code: 'STEPUP_REQUIRED' }> {
  const first = await run();
  if (first.ok || first.code !== 'STEPUP_REQUIRED') {
    return first;
  }
  const outcome = await promptForStepUp(host, what, messageFor);
  if (outcome !== 'elevated') {
    return { ok: false, code: 'STEPUP_REQUIRED' };
  }
  return run();
}

/** One message per failure. Vague copy is worst on the screen holding secrets. */
function messageFor(code: ApiFailure): string {
  switch (code) {
    case 'UNAUTHENTICATED':
      return 'Your vault session has ended. Open the vault again from Estate.';
    case 'STEPUP_REQUIRED':
      // Reached only when the user CANCELLED the prompt, or the action is one
      // that does not offer one. Never "go back to Estate": re-opening mints a
      // fresh handoff, which is what the step-up change exists to devalue.
      return 'That action needs a fresh identity check, and it was not completed.';
    case 'VAULT_LOCKED':
      return 'The vault is locked. Unlock it and try again.';
    case 'CONFLICT':
      return 'This item changed since you opened it. Reload and try again.';
    case 'NOT_FOUND':
      return 'That item is no longer there.';
    // M27 PR2. THE THREE RESTORE REFUSALS, and the whole reason they are named
    // separately is that they call for three different things. Reloading fixes
    // the first, nothing fixes the second, and the third leaves the reader
    // exactly where they are.
    case 'VERSION_CONFLICT':
      return 'This item changed while you were looking at its history. Reload the history and try again.';
    case 'ITEM_UNRESTORABLE':
      // NOT "try again". The keyset that opened this blob was destroyed when
      // the vault was reset, so no retry can ever succeed and saying otherwise
      // sends someone back to press the same button forever.
      return 'This item cannot be brought back. Its contents were destroyed when the vault was reset, and nothing can decrypt them now.';
    case 'VERSION_NOT_FOUND':
      // The ITEM is fine and is still on screen — saying it is "no longer
      // there" would be a false sentence about something visibly present.
      return 'That version is no longer available. Refresh the history to see what is still there.';
    case 'FORBIDDEN':
      return 'You are not allowed to do that.';
    case 'INVALID_REQUEST':
      return 'Something about that was not accepted. Check the fields and try again.';
    case 'RECIPIENT_UNVERIFIED':
      // M14's arming gate. DISTINCT from an outage on purpose: "we cannot
      // reach anyone" and "you have never confirmed your address" call for
      // completely different actions, and the M9 rule is that a control firing
      // must never read as a failure.
      return 'Confirm your email address in Estate first. Emergency access depends on us being able to warn you while the waiting period runs, so we will not arm it until we know we can reach you.';
    case 'NOTIFICATIONS_UNAVAILABLE':
      return 'We cannot send notifications right now, so arming emergency access would leave you unable to interrupt it. Try again shortly.';
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
  // OUTSIDE the form, and that is load-bearing rather than cosmetic. A refused
  // action renders its step-up prompt — itself a `<form>` — into this node, and
  // a form nested inside a form is invalid HTML that no parser would build.
  // Anything reasoning over `document.querySelectorAll('form')` then gets a
  // wrong answer about which form holds the code field.
  const note = el('div');
  const submit = el('button', { class: 'button', type: 'submit' }, ['Create my vault']);
  const form = el('form', {}, [password.row, confirm.row, el('p', {}, [submit])]);

  /**
   * ONE enrollment at a time.
   *
   * The submit button is disabled while one runs, so a second CLICK cannot get
   * through — but a submit event arrives from more than a click, and nothing
   * else bounded this. A second enrollment mints a second master key and a
   * second Secret Key and overwrites the first keyset, so whichever of the two
   * `renderSecretKey` continuations lands LAST is what the user is told to
   * save: on a slow device that is a Secret Key for a keyset the server no
   * longer holds, on the one screen shown exactly once and never again.
   *
   * It is also a stale-continuation source: `renderSecretKey` resolves `#app`
   * when it runs, so a losing enrollment renders over whatever screen the user
   * has since moved to.
   */
  let enrolling = false;

  onSubmit(form, () => {
    if (enrolling) return;
    enrolling = true;
    void (async () => {
      try {
        await runEnrollment();
      } finally {
        enrolling = false;
      }
    })();
  });

  async function runEnrollment(): Promise<void> {
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
    const { userId } = account;
    submit.setAttribute('disabled', '');
    note.append(status('Setting up your vault — this takes a moment.'));
    // `POST /v1/vault/keyset` is step-up gated, and the redeemed session no
    // longer arrives with one (the M15 review's bypass), so first-time setup
    // is the FIRST place a factor has to be proved on this origin.
    const created = await withStepUp(note, 'Setting up your vault', () =>
      session
        .enroll(userId, password.input.value)
        .catch(() => ({ ok: false as const, code: 'UNAVAILABLE' as const })),
    );
    // The password is gone from the DOM the instant it has been used.
    password.input.value = '';
    confirm.input.value = '';
    if (!created.ok) {
      submit.removeAttribute('disabled');
      replaceChildren(note, status(messageFor(created.code ?? 'UNKNOWN'), 'error'));
      return;
    }
    renderSecretKey(created.data.secretKey, created.data.entropy);
  }

  replaceChildren(
    main(),
    el('h1', {}, ['Set up your vault']),
    el('p', { class: 'status' }, [
      'Your vault is encrypted on this device. Estate stores only the encrypted result and cannot read it — not for a support request, and not for a court order.',
    ]),
    form,
    note,
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
      // CAPTURED BEFORE THE RUN, because `withStepUp` may run it twice and the
      // step-up prompt renders over this form in between.
      const typedPassword = password.input.value;
      const userId = account.userId;
      // THE UNLOCK ELEVATES LIKE EVERY OTHER ACTION ON THIS ORIGIN (M27 PR2).
      // `srp/start` and `srp/verify` both carry `StepUpGuard`, whose 403
      // `stepup_required` exists — its own comment says so — to tell a
      // well-behaved client to elevate. This screen was the one that did not:
      // it called `unlock` bare, so once the vault-open step-up aged past five
      // minutes the refusal arrived as "that action needs a fresh identity
      // check, and it was not completed" with nothing on the page that could
      // complete it. Found by driving the stack; predates PR2 (M15 PR2) and is
      // fixed here because this is the screen every restore surface sits behind.
      const opened = await withStepUp(note, 'Unlocking your vault', () =>
        session
          .unlock(userId, typedPassword, secretKeyText)
          // A mistyped Secret Key throws in `parseSecretKey` before any network
          // call. It is the SAME answer as a wrong password by design, so it
          // lands on the same message rather than telling the user which half of
          // 2SKD they got wrong.
          .catch(() => ({ ok: false as const, code: 'UNAUTHENTICATED' as const })),
      );
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
      // FROM THE LIST, NOT FROM THE EDIT FORM. `renderItem` is a populated
      // form and this origin has no dirty check — entering history from inside
      // it would drop a half-typed secret with no warning.
      quietButton('History', () => void renderItemHistory(item)),
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
      quietButton('Deleted items', () => void renderDeletedItems()),
      ' ',
      quietButton('Settings', () => renderSettings()),
      ' ',
      quietButton('Emergency access', () => void renderEmergency()),
    ]),
  );
}

// ------------------------------------------------- restore surface (M27 PR2)

/**
 * A CAPTURE TIME A PERSON CAN READ, IN THEIR OWN ZONE.
 *
 * FOUND BY DRIVING THE REAL APP, and the first draft of this function was the
 * defect. It trimmed the ISO string the server sent — `2026-08-24T00:00:31Z`
 * became `2026-08-24 00:00` — on the reasoning that `package.json` fences
 * dependencies to exactly `['zod']` so there is no formatter available. The
 * premise was wrong: `Date` is the RUNTIME, not a dependency, and nothing about
 * the fence forced UTC. The consequence was not a few hours of skew but a wrong
 * DATE: the live drive edited an item at 17:00 on a Sunday and the history said
 * it happened on Monday. For every owner west of UTC editing in the afternoon
 * that is wrong every single day, on the one screen whose entire job is telling
 * them WHEN something changed.
 *
 * The parts are read off the Date, not off the string, so the same instant
 * spelled two ways renders identically — that equivalence is what the spec
 * asserts, because it holds in every zone including the CI runner's UTC, where
 * an expected-string assertion would pass against the trim that caused this.
 *
 * A value that is not a time renders as EMPTY rather than "Invalid Date", on
 * `apps/web/src/lib/datetime.ts`'s rule: both are a failure to show a time and
 * only one of them looks like a fault in the owner's own vault. Callers append
 * the separator only when there is something to separate.
 */
function captureTime(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return '';
  const pad = (n: number): string => String(n).padStart(2, '0');
  return (
    `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}` +
    ` ${pad(at.getHours())}:${pad(at.getMinutes())}`
  );
}

/** The label a row shows, for an item or a version that may not have opened. */
function titleOf(opened: { content: ItemContent; unreadable?: boolean }, noun: string): string {
  if (opened.unreadable) return `(this ${noun} could not be read)`;
  return opened.content.title || '(untitled)';
}

/**
 * WHAT THE OWNER DELETED, AND CAN STILL GET BACK (M27 PR2).
 *
 * ONE CLICK, NO CEREMONY, AND THAT IS THE POINT. `deleteItem` is the one item
 * route behind a step-up; bringing the item back carries none, and this screen
 * must not invent one. A confirmation dialog in front of the UNDO of a gated
 * destruction would make the protective action harder than the permissive one,
 * which is the inversion this milestone exists to close.
 *
 * ROWS THAT WILL NOT DECRYPT STILL OFFER THE BUTTON, unlike the version screen
 * below. Undelete writes no ciphertext — it clears `deleted_at` and nothing
 * else — so offering it on a row this client cannot open is honest: the item
 * comes back exactly as unreadable as it was, and hiding it would leave the
 * owner unable to see that it exists at all.
 */
async function renderDeletedItems(notice?: {
  readonly text: string;
  readonly tone?: 'ok' | 'warn' | 'error';
}): Promise<void> {
  try {
    session.requireVaultToken();
  } catch {
    await renderUnlock();
    return;
  }

  // Carried IN rather than left behind: every action here re-renders, and a
  // note written before that read is destroyed by it (the app.ts:499-503 rule).
  const note = el('div');
  const listed = await session.listRestorable();
  if (!listed.ok) {
    replaceChildren(
      main(),
      el('h1', {}, ['Deleted items']),
      // NEVER the empty-state sentence. A read that was refused and a vault
      // with nothing deleted are different facts with different remedies.
      status(`We could not load your deleted items just now. ${messageFor(listed.code)}`, 'error'),
      el('p', {}, [quietButton('Back', () => void renderVault())]),
    );
    return;
  }

  const items = listed.data;
  const rows = items.map((item) =>
    el('li', { class: 'item' }, [
      el('span', {}, [titleOf(item, 'item')]),
      el('span', { class: 'item-type' }, [labelFor(item.itemType)]),
      quietButton('Bring it back', () => {
        void (async () => {
          const back = await session.undelete(item.id);
          if (!back.ok) {
            replaceChildren(note, status(messageFor(back.code), 'error'));
            return;
          }
          await renderDeletedItems({
            text: `${titleOf(back.data, 'item')} is back in your vault.`,
          });
        })();
      }),
    ]),
  );

  replaceChildren(
    main(),
    el('h1', {}, ['Deleted items']),
    items.length === 0
      ? status('Nothing you have deleted is waiting to come back.')
      : el('ul', { class: 'items' }, rows),
    el('p', {}, [quietButton('Back', () => void renderVault())]),
    note,
    ...(notice ? [status(notice.text, notice.tone ?? 'ok')] : []),
  );
}

/**
 * ONE ITEM'S CAPTURED PAST (M27 PR2).
 *
 * EVERY VERSION THE SERVER RETURNS IS OFFERED, and there is no "current" row to
 * withhold. The capture trigger reads OLD, so an image always carries the
 * revision the row had BEFORE the write that captured it — every image's
 * revision is strictly below the live one, and the version you are already at
 * has no image at all. The server's no-op arm is unreachable from here by
 * ABSENCE rather than by a filter, which is the shape this repo prefers; the
 * spec asserts that absence instead of testing a branch that cannot run.
 *
 * REACHED FROM THE VAULT LIST, NEVER FROM THE EDIT FORM. `renderItem` is a
 * populated `<form>` and this origin has no dirty check, no cleanup hook and no
 * confirm — `replaceChildren` would silently drop a half-typed secret. It is
 * also why "Back" returns to the list rather than to the item: handing a reader
 * back a PRE-restore `OpenedItem` is the one path that bricks a row, because a
 * later edit would seal against a `blobVersion` the row no longer has.
 *
 * THIS ONE PAGES. The server's page is 50 and its ceiling 100, so a
 * much-edited item would otherwise show a truncated past with nothing saying
 * so. A successful restore returns the reader to the first page deliberately:
 * the history it was reading has changed underneath it.
 */
async function renderItemHistory(
  item: OpenedItem,
  opts?: { readonly cursor?: string; readonly loaded?: readonly OpenedVersion[] },
  notice?: { readonly text: string; readonly tone?: 'ok' | 'warn' | 'error' },
): Promise<void> {
  try {
    session.requireVaultToken();
  } catch {
    await renderUnlock();
    return;
  }

  const note = el('div');
  const page = await session.itemVersions(item.id, opts?.cursor);
  if (!page.ok) {
    replaceChildren(
      main(),
      el('h1', {}, ['History']),
      status(`We could not load this item's history. ${messageFor(page.code)}`, 'error'),
      el('p', {}, [quietButton('Back', () => void renderVault())]),
    );
    return;
  }

  const versions = [...(opts?.loaded ?? []), ...page.data.versions];
  const rows = versions.map((version) =>
    el('li', { class: 'item' }, [
      el('span', {}, [titleOf(version, 'version')]),
      el('span', { class: 'item-type' }, [
        // The separator belongs to the time, not to the type: an unparseable
        // `versionedAt` must not leave a row reading "Password · ".
        labelFor(version.itemType) +
          (captureTime(version.versionedAt) === '' ? '' : ` · ${captureTime(version.versionedAt)}`),
      ]),
      // A VERSION THIS CLIENT CANNOT OPEN IS NEVER OFFERED. Restoring it would
      // write ciphertext nobody can read over live content — the one action on
      // this screen that destroys something. The row still shows, so the owner
      // can see the past exists; only the button is withheld.
      ...(version.unreadable
        ? []
        : [
            quietButton('Put this version back', () => {
              void (async () => {
                // `item.revision` is the LIVE row's — the concurrency token.
                // `version.revision` names the image. Different jobs, and the
                // spec pins both against a fixture where they differ.
                const restored = await session.restoreVersion(
                  item.id,
                  version.revision,
                  item.revision,
                );
                if (!restored.ok) {
                  replaceChildren(note, status(messageFor(restored.code), 'error'));
                  return;
                }
                // The FRESH item is adopted. Re-rendering against the old one
                // would leave a later edit sealing under a stale blobVersion.
                const when = captureTime(version.versionedAt);
                await renderItemHistory(restored.data, undefined, {
                  text:
                    (when === ''
                      ? 'Put back the version you chose.'
                      : `Put back the version from ${when}.`) +
                    ' The version you replaced is still in this history.',
                });
              })();
            }),
          ]),
    ]),
  );

  const next = page.data.nextCursor;
  replaceChildren(
    main(),
    el('h1', {}, ['History']),
    el('p', { class: 'field-hint' }, [titleOf(item, 'item')]),
    versions.length === 0
      ? status('This item has not been changed since you created it.')
      : el('ul', { class: 'items' }, rows),
    el('p', {}, [
      quietButton('Back', () => void renderVault()),
      ...(next === null
        ? []
        : [
            ' ',
            quietButton('Show older', () => {
              // The cursor goes back VERBATIM — never parsed, never built.
              void renderItemHistory(item, { cursor: next, loaded: versions });
            }),
          ]),
    ]),
    note,
    ...(notice ? [status(notice.text, notice.tone ?? 'ok')] : []),
  );
}

// ------------------------------------------------- emergency access (PR3)

/**
 * THE OWNER'S SIDE.
 *
 * Reading order matters here: what is arranged now, then who could be added,
 * then the arming action. A screen that led with "add a grantee" would make the
 * destructive part of a reconfiguration (it retires every existing share) the
 * easiest thing on the page.
 */
async function renderEmergency(notice?: {
  readonly text: string;
  readonly tone?: 'ok' | 'warn' | 'error';
}): Promise<void> {
  // Every read on this screen needs the vault OPEN — the idle lock can have
  // fired while it was on screen, and a thrown accessor would leave a blank
  // page rather than the unlock form.
  let vaultToken: string;
  try {
    vaultToken = session.requireVaultToken();
  } catch {
    await renderUnlock();
    return;
  }

  // A MESSAGE HAS TO SURVIVE THE RE-RENDER THAT FOLLOWS IT. Every action here
  // re-reads the screen afterwards, and a note written before that read is
  // destroyed by it — so what an action wants to say is carried IN, not left
  // behind. Without this a grantee pressed "Request access", started a waiting
  // period, and was told nothing at all.
  const note = el('div');
  const [escrow, candidates, granted, own] = await Promise.all([
    describeEscrow(),
    granteeCandidates(),
    grantedToMe(),
    ownRecoveryKey(vaultToken),
  ]);

  /**
   * A policy's grantee, by name where we can and by account id where we cannot.
   *
   * The candidate list is the ONLY place a name exists on this origin — the
   * vault service stores account ids, deliberately, because the vault cluster
   * cannot dereference a core-cluster contact. A contact deleted since the
   * arrangement was made therefore falls back to the id rather than
   * disappearing: the arrangement is still live and the owner still needs to
   * see it.
   */
  const namesByUser = new Map(
    (candidates.ok ? candidates.data : []).map((candidate) => [candidate.userId, candidate.name]),
  );
  const nameFor = (policy: PolicyDto): string =>
    namesByUser.get(policy.granteeUserId) ?? policy.granteeUserId;

  const children: HTMLElement[] = [
    el('h1', {}, ['Emergency access']),
    ...(notice ? [status(notice.text, notice.tone ?? 'ok')] : []),
    el('p', { class: 'status' }, [
      'People you choose can open this vault if you cannot — but never quietly. Every request starts a waiting period, you are told, and one tap stops it.',
    ]),
  ];

  // --- what is arranged now ---
  children.push(el('h2', {}, ['Your arrangement']));
  if (!escrow.ok) {
    children.push(status(messageFor(escrow.code), 'error'));
  } else if (!escrow.data.configured) {
    children.push(status('Nobody can open this vault but you.'));
  } else {
    children.push(
      status(
        `${escrow.data.policies.length} contact(s) named; ${escrow.data.threshold ?? 1} needed together to open it.`,
      ),
      el(
        'ul',
        { class: 'items' },
        escrow.data.policies.map((policy) => policyRow(policy, note, nameFor)),
      ),
    );
  }

  // --- who could be added ---
  children.push(el('h2', {}, ['Choose who can open it']));
  if (!candidates.ok) {
    children.push(status('We could not load your contacts just now.', 'error'));
  } else if (candidates.data.length === 0) {
    children.push(
      status(
        'None of your contacts has an Estate account linked yet. Link one in Estate first — emergency access seals a share to a specific account.',
        'warn',
      ),
    );
  } else {
    children.push(granteePicker(candidates.data, note));
  }

  // --- the other side: what others have named you for ---
  children.push(el('h2', {}, ['Granted to you']));
  if (own.ok) {
    /*
     * THE GRANTEE HALF OF THE FINGERPRINT CEREMONY (M15 review).
     *
     * The owner's side shows the fingerprint of the key it is about to seal a
     * share to and says "check this with them by phone or in person". Until
     * this block existed the person on the other end of that call had NOWHERE
     * to read their own — so the comparison could not be performed, and the
     * only defence against a malicious server substituting its own key for a
     * grantee's was a ceremony nobody could complete. `grantee_public_key_sha256`
     * cannot help: it is derived client-side from whatever key the client was
     * handed, so it binds to a substituted key just as happily.
     *
     * Computed from the key the SERVER just served back, deliberately — that is
     * the value an owner would be shown, so if the two agree the substitution
     * did not happen on either leg.
     */
    // `fromBase64` throws SYNCHRONOUSLY, so a trailing `.catch()` on the
    // promise does not catch it and the whole screen fails to render — the same
    // defect `offerFor` had in PR3, reintroduced here and caught by its test.
    // Zone A treats the server as hostile, so a malformed key is expected input.
    const fingerprint = await Promise.resolve()
      .then(() => publicKeyFingerprint(fromBase64(own.data.publicKey)))
      .catch(() => null);
    children.push(
      status('Others can name you for emergency access. Your key is published.'),
      ...(fingerprint
        ? [
            el('p', { class: 'field-hint' }, [
              'If someone names you, they will read a short code back to you. Check it against yours — by phone or in person, not through this platform:',
            ]),
            el('p', { class: 'secret-key' }, [fingerprint]),
          ]
        : [
            // Refusing to display SOMETHING is the right answer here: a wrong
            // fingerprint compared against a right one would confirm a
            // substitution as legitimate.
            status(
              'We could not read your key’s fingerprint back. Reload before confirming it with anyone.',
              'warn',
            ),
          ]),
    );
  } else if (own.code === 'NOT_FOUND') {
    // ORDERING IS THE POINT: nobody can seal a share to you until this exists,
    // so it is stated as a precondition rather than buried in a failure later.
    children.push(
      status('Nobody can name you for emergency access yet.', 'warn'),
      el('p', { class: 'field-hint' }, [
        'Publishing a key lets others seal a share of their recovery key to you. The half that opens it never leaves this vault.',
      ]),
      el('p', {}, [
        quietButton('Let others name me', () => {
          void (async () => {
            if (!account) return;
            replaceChildren(note, status('Publishing…'));
            const published = await withStepUp(note, 'Publishing your key', () =>
              Promise.resolve()
                .then(() => publishRecoveryKey(account?.userId ?? '', session.requireMasterKey()))
                .catch(() => ({ ok: false as const, code: 'UNKNOWN' as const })),
            );
            if (!published.ok) {
              replaceChildren(note, status(messageFor(published.code ?? 'UNKNOWN'), 'error'));
              return;
            }
            await renderEmergency();
          })();
        }),
      ]),
    );
  } else {
    children.push(status('We could not check whether your key is published.', 'error'));
  }
  if (!granted.ok) {
    children.push(status('We could not check what others have named you for.', 'error'));
  } else if (granted.data.length === 0) {
    children.push(status('Nobody has named you for emergency access.'));
  } else {
    children.push(
      el(
        'ul',
        { class: 'items' },
        granted.data.map((policy) =>
          el('li', { class: 'item' }, [
            el('span', {}, [`Vault of ${policy.ownerUserId}`]),
            el('span', { class: 'item-type' }, [describeGranteeStatus(policy)]),
            ...granteeActions(policy, note),
          ]),
        ),
      ),
    );
  }

  children.push(el('p', {}, [quietButton('Back', () => void renderVault())]), note);
  replaceChildren(main(), ...children);
}

/**
 * A policy status in words, not in the service's vocabulary.
 *
 * `configured` is what the DDL calls an arrangement nobody has acted on; to an
 * owner reading their own page that is "ready if you cannot", and printing the
 * column value would have shipped a schema enum onto the one screen where
 * somebody decides whether their arrangement is what they meant. Driving the
 * live stack is what surfaced it — every unit fixture used the words a test
 * author chose rather than the ones Postgres stores.
 */
const POLICY_STATUS_WORDS: Readonly<Record<string, string>> = {
  configured: 'ready if you cannot',
  requested: 'requested',
  waiting: 'waiting period running',
  denied_by_owner: 'stopped by you',
  released: 'opened',
  revoked: 'removed',
};

function describePolicyStatus(status: string): string {
  // An UNKNOWN status still renders — a service deployed ahead of this origin
  // must not blank the row (the M12 rule), and the raw token is at least true.
  return POLICY_STATUS_WORDS[status] ?? status.replace(/_/g, ' ');
}

function describeGranteeStatus(policy: { status: string; releasesAt: string | null }): string {
  if (policy.status === 'waiting' && policy.releasesAt) {
    const remainingMs = Date.parse(policy.releasesAt) - Date.now();
    if (remainingMs > 0) {
      const hours = Math.ceil(remainingMs / 3_600_000);
      return `waiting — about ${hours}h left`;
    }
    return 'ready to open';
  }
  return describePolicyStatus(policy.status);
}

function granteeActions(
  policy: { id: string; status: string; releasesAt: string | null },
  note: HTMLElement,
): HTMLElement[] {
  const ready =
    policy.status === 'waiting' && policy.releasesAt && Date.parse(policy.releasesAt) <= Date.now();
  // WHAT THE SERVICE ACTUALLY ALLOWS, not a status invented here. `blockReason`
  // refuses a request only for revoked / released / waiting / denied_by_owner,
  // so `configured` and `requested` are the two a grantee may act on. An
  // earlier version gated this on `armed` — a status the DDL does not have —
  // and so would never have offered the button at all. Every unit fixture used
  // the same invented word, which is why only the live stack found it.
  if (policy.status === 'configured' || policy.status === 'requested') {
    return [
      quietButton('Request access', () => {
        void (async () => {
          const result = await requestAccess(policy.id);
          if (!result.ok) {
            replaceChildren(note, status(messageFor(result.code), 'error'));
            return;
          }
          await renderEmergency({
            text: 'The waiting period has started and the owner has been told. You can open the vault when it ends — unless they stop it.',
          });
        })();
      }),
    ];
  }
  if (ready) {
    return [quietButton('Open the vault', () => renderRelease(policy.id))];
  }
  return [];
}

/** One arranged grantee, with the owner's controls. */
function policyRow(
  policy: PolicyDto,
  note: HTMLElement,
  nameFor: (policy: PolicyDto) => string,
): HTMLElement {
  const act = (
    label: string,
    done: string,
    run: () => Promise<{ ok: boolean; code?: ApiFailure }>,
  ): HTMLElement =>
    quietButton(label, () => {
      void (async () => {
        // `rearm` and `revoke` are step-up gated; `deny` is deliberately not
        // (the M6 rule that the protective action must never be harder). Wrapping
        // all three is harmless: `withStepUp` only prompts on a refusal.
        const result = await withStepUp(note, label, run);
        if (!result.ok) {
          replaceChildren(note, status(messageFor(result.code ?? 'UNKNOWN'), 'error'));
          return;
        }
        await renderEmergency({ text: done });
      })();
    });

  const controls: HTMLElement[] = [];
  if (policy.status === 'waiting') {
    // DENY IS ONE TAP AND NEVER STEP-UP GATED (docs/03 §5.2). A challenge
    // between an owner and "stop this" is a control that argues with itself.
    controls.push(
      act(
        'Stop this',
        'Stopped. That request cannot proceed, and it stays stopped until you allow it again.',
        () => denyPolicy(policy.id),
      ),
    );
  }
  if (policy.status === 'denied_by_owner') {
    controls.push(
      act('Allow again', 'Allowed again. A new request would start a fresh waiting period.', () =>
        rearmPolicy(policy.id),
      ),
    );
  }
  if (policy.status !== 'released') {
    controls.push(
      act('Remove', 'Removed. That person can no longer open this vault.', () =>
        revokePolicy(policy.id),
      ),
    );
  }

  return el('li', { class: 'item' }, [
    // THE PERSON, not their account id. An owner reviewing an arrangement has
    // to be able to recognise who they named — a row of UUIDs cannot be checked
    // against what they intended, which is the whole point of reading it back.
    el('span', {}, [nameFor(policy)]),
    el('span', { class: 'item-type' }, [
      `${describePolicyStatus(policy.status)} · ${policy.waitingPeriodHours}h wait` +
        (policy.requestCount > 0 ? ` · ${policy.requestCount} request(s)` : ''),
    ]),
    ...controls,
  ]);
}

/**
 * The picker, and the FINGERPRINT CEREMONY.
 *
 * Each candidate must be confirmed individually, and the confirmation shows the
 * fingerprint of the key that will actually be sealed to. This is the only
 * defence against a malicious server substituting its own key — nothing
 * server-side can detect it, because the digest recorded alongside the share is
 * derived from whatever key the client was handed.
 */
function granteePicker(candidates: readonly GranteeCandidate[], note: HTMLElement): HTMLElement {
  const confirmed = new Map<string, GranteeKeyOffer>();
  const list = el('ul', { class: 'items' });
  const waiting = field({
    id: 'waiting-hours',
    label: 'Waiting period (hours)',
    type: 'number',
    value: '48',
    hint: 'At least 24. This is how long you have to stop a request before it succeeds.',
  });
  const threshold = field({
    id: 'threshold',
    label: 'How many must act together',
    type: 'number',
    value: '1',
    // ONLY 1 IS SUPPORTED BY THIS CLIENT (M15 review). The service and
    // `packages/vault-crypto` both do arbitrary M-of-N — `createEscrow` splits
    // Shamir over the grantees exactly as M6 designed — but `releaseAndRecover`
    // hands `recoverMasterKey` a SINGLE share, because release is one-shot per
    // policy and there is no way yet for one grantee to collect another's.
    // Arming 2-of-3 would therefore create an arrangement nobody could ever
    // open, and the first grantee to try would spend their own policy finding
    // out. Offering the field and refusing the value is the honest shape: the
    // capability exists in the protocol and not yet in this client.
    hint: 'This client can only complete a release with 1 — collecting several people’s shares is not built yet.',
  });
  const arm = el('button', { class: 'button', type: 'button' }, ['Arm emergency access']);

  for (const candidate of candidates) {
    const state = el('span', { class: 'item-type' }, ['not confirmed']);
    const confirm = quietButton('Confirm key', () => {
      void (async () => {
        const offer = await offerFor(candidate);
        if (!offer.ok) {
          replaceChildren(
            note,
            status(
              offer.code === 'NOT_FOUND'
                ? `${candidate.name} has not set up a vault yet, so there is no key to seal a share to.`
                : messageFor(offer.code),
              'warn',
            ),
          );
          return;
        }
        // The owner reads this to the grantee out of band and they agree it
        // matches. Only then does the share get sealed to that key.
        replaceChildren(
          note,
          el('p', { class: 'status status-warn' }, [
            `Check this with ${candidate.name} by phone or in person before arming — not by email or message on this platform:`,
          ]),
          el('p', { class: 'secret-key' }, [offer.data.fingerprint]),
        );
        confirmed.set(candidate.userId, offer.data);
        replaceChildren(state, 'key confirmed');
      })();
    });
    list.append(el('li', { class: 'item' }, [el('span', {}, [candidate.name]), state, confirm]));
  }

  onClick(arm, () => {
    void (async () => {
      if (confirmed.size === 0) {
        replaceChildren(
          note,
          status('Confirm at least one contact’s key fingerprint first.', 'warn'),
        );
        return;
      }
      const hours = Number(waiting.input.value);
      const needed = Number(threshold.input.value);
      if (!Number.isInteger(hours) || hours < 24) {
        replaceChildren(note, status('The waiting period must be at least 24 hours.', 'error'));
        return;
      }
      if (!Number.isInteger(needed) || needed < 1 || needed > confirmed.size) {
        replaceChildren(note, status(`Choose between 1 and ${confirmed.size}.`, 'error'));
        return;
      }
      arm.setAttribute('disabled', '');
      replaceChildren(note, status('Splitting your recovery key on this device…'));

      const masterKeyBytes = await session.exportMasterKey().catch(() => null);
      if (!masterKeyBytes) {
        arm.removeAttribute('disabled');
        replaceChildren(note, status(messageFor('VAULT_LOCKED'), 'error'));
        return;
      }
      try {
        const armed = await withStepUp(note, 'Arming emergency access', () =>
          configureEscrow({
            ownerUserId: account?.userId ?? '',
            masterKeyBytes,
            confirmed: [...confirmed.values()],
            threshold: needed,
            waitingPeriodHours: hours,
          }).catch(() => ({ ok: false as const, code: 'UNKNOWN' as const })),
        );
        if (!armed.ok) {
          arm.removeAttribute('disabled');
          // `api.ts` narrows both 503 refusals to their own codes, so the M14
          // arming gate and a real outage stay distinguishable here.
          replaceChildren(note, status(messageFor(armed.code), 'error'));
          return;
        }
        await renderEmergency();
      } finally {
        wipe(masterKeyBytes);
      }
    })();
  });

  return el('div', {}, [
    el('p', { class: 'field-hint' }, [
      'Confirm each person’s key fingerprint with them directly. It is the only way to be sure a share is sealed to them and not to somebody else.',
    ]),
    list,
    waiting.row,
    threshold.row,
    el('p', {}, [arm]),
  ]);
}

/**
 * The grantee opening someone else's vault.
 *
 * Needs the grantee's OWN vault open, because their recovery private key is
 * wrapped under their own master key. A session alone achieves nothing, which
 * is the property that makes the release meaningful.
 */
function renderRelease(policyId: string): void {
  const note = el('div');
  replaceChildren(
    main(),
    el('h1', {}, ['Open the vault you were trusted with']),
    el('p', { class: 'status status-warn' }, [
      'This spends the arrangement: it can be done once, and the owner is told. Only continue if they genuinely cannot do this themselves.',
    ]),
    /*
     * SAY WHAT THIS DOES AND DOES NOT DO (M15 review).
     *
     * Release is ONE-SHOT, and this client reconstructs the owner's recovery
     * key and then wipes it — there is no screen yet that reads their items
     * with it. Until that ships, pressing the button spends the only chance the
     * arrangement had and returns nothing usable, so the person doing it in a
     * real emergency has to be told that BEFORE they press it rather than
     * discovering it afterwards. Withholding the warning while keeping the
     * button is the shape this repo calls offering what the server would
     * refuse; here the server would not refuse, which makes it worse.
     */
    el('p', { class: 'status status-warn' }, [
      'Reading the owner’s items is not built yet. This confirms the pieces fit and that you could open the vault — it does not show you what is inside, and the arrangement cannot be used a second time once you continue.',
    ]),
    el('p', {}, [
      buttonEl('Open it now', () => {
        void (async () => {
          if (!account) return;
          replaceChildren(note, status('Collecting the pieces…'));
          let vaultToken: string;
          let granteeMasterKey: CryptoKey;
          try {
            vaultToken = session.requireVaultToken();
            granteeMasterKey = session.requireMasterKey();
          } catch {
            replaceChildren(
              note,
              status(
                'Unlock your own vault first — the key that opens your share is inside it.',
                'warn',
              ),
            );
            return;
          }
          const own = await ownRecoveryKey(vaultToken);
          if (!own.ok) {
            replaceChildren(
              note,
              status(
                own.code === 'VAULT_LOCKED'
                  ? 'Unlock your own vault first — the key that opens your share is inside it.'
                  : messageFor(own.code),
                'warn',
              ),
            );
            return;
          }
          const recovered = await releaseAndRecover({
            policyId,
            granteeUserId: account.userId,
            granteeMasterKey,
            granteePublicKey: own.data.publicKey,
            wrappedPrivateKey: own.data.wrappedPrivateKey,
          }).catch(() => ({ ok: false as const, code: 'UNKNOWN' as const }));
          if (!recovered.ok) {
            replaceChildren(note, status(messageFor(recovered.code), 'error'));
            return;
          }
          // The recovered key is NOT retained and NOT sent anywhere. What this
          // release proves is that the reconstruction works; reading the
          // owner's items with it is the next screen's job and is deliberately
          // not part of the one-shot action.
          wipe(recovered.data.masterKeyBytes);
          replaceChildren(
            note,
            status(
              'The recovery key was reconstructed on this device, and the owner has been told. It was not kept: reading their items with it is not built yet, and this arrangement is now spent.',
              'ok',
            ),
          );
        })();
      }),
      ' ',
      quietButton('Back', () => void renderEmergency()),
    ]),
    note,
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
    // `note` is deliberately NOT here — see `renderSetup`. Deleting an item is
    // step-up gated, so this node hosts a prompt that is itself a `<form>`.
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
  // Same DOM order as when `note` sat inside the form — after the save row,
  // before the delete control — without the nesting.
  const children: Array<HTMLElement | string> = [el('h1', {}, [heading]), form, note];
  if (existing) {
    children.push(
      el('p', {}, [
        quietButton('Delete this item', () => {
          void (async () => {
            const removed = await withStepUp(note, 'Deleting this item', () =>
              session.remove(existing.id),
            );
            if (!removed.ok) {
              replaceChildren(note, status(messageFor(removed.code ?? 'UNKNOWN'), 'error'));
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
  const currentPassword = field({
    id: 'change-current',
    label: 'Current vault password',
    type: 'password',
    hint: 'Checked on this device before anything changes.',
  });
  const current = field({
    id: 'change-secret',
    label: 'Secret Key',
    // The M15 review found this hint was a claim the code did not keep: a
    // different well-formed key was accepted and the vault rebound to it. It is
    // verified now, so the sentence is true.
    hint: 'Unchanged by this — only the password half of the derivation moves.',
  });
  const next = field({ id: 'change-new', label: 'New vault password', type: 'password' });
  const changeButton = el('button', { class: 'button', type: 'submit' }, ['Change password']);
  const changeForm = el('form', {}, [
    currentPassword.row,
    current.row,
    next.row,
    el('p', {}, [changeButton]),
  ]);

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
      const changed = await withStepUp(note, 'Changing your vault password', () =>
        session
          .changePassword(currentPassword.input.value, next.input.value, current.input.value.trim())
          .catch(() => ({ ok: false as const, code: 'INVALID_REQUEST' as const })),
      );
      next.input.value = '';
      current.input.value = '';
      currentPassword.input.value = '';
      changeButton.removeAttribute('disabled');
      replaceChildren(
        note,
        changed.ok
          ? status('Your vault password has changed. Other devices were signed out.', 'ok')
          : status(
              // UNAUTHENTICATED is the local verification refusing; the other
              // two are a malformed key or a server conflict. One sentence for
              // all three, because naming which half was wrong is what the
              // unlock screen already refuses to do.
              changed.code === 'UNAUTHENTICATED' ||
                changed.code === 'CONFLICT' ||
                changed.code === 'INVALID_REQUEST'
                ? 'That vault password and Secret Key did not open this vault, so nothing was changed.'
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
      // Captured: `account` is module state and the closure below runs again
      // after a step-up, by which time narrowing has been lost.
      const { userId } = account;
      reset.setAttribute('disabled', '');
      replaceChildren(note, status('Resetting…'));
      const done = await withStepUp(note, 'Resetting the vault', () =>
        session
          .reset(userId, resetPassword.input.value)
          .catch(() => ({ ok: false as const, code: 'UNAVAILABLE' as const })),
      );
      resetPassword.input.value = '';
      confirm.input.value = '';
      if (!done.ok) {
        reset.removeAttribute('disabled');
        replaceChildren(note, status(messageFor(done.code ?? 'UNKNOWN'), 'error'));
        return;
      }
      // The old Secret Key opens nothing now, so this device must forget it and
      // the user must save the new one.
      await forgetSecretKey(userId);
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
