import { request, type ApiResult } from './api.js';
import { messageFor } from './copy.js';
import { el, render } from './dom.js';
import { mountVaultScreens } from './vault-screens.js';
import {
  disconnect,
  forgetSession,
  loadSession,
  pair,
  withSession,
  type PairedSession,
} from './session.js';

/**
 * THE WHOLE VISIBLE SURFACE OF PR2a.
 *
 * Connect this browser with a pairing code, and then report one fact: whether
 * this account has a vault set up. That single sentence is the point of the PR
 * — it exercises pairing → token storage → refresh → the vault origin's edge →
 * the vault service's per-handler audience admission, end to end, with nothing
 * cryptographic anywhere in the path.
 *
 * IT DELIBERATELY CANNOT OPEN A VAULT, and the popup says so. Unlocking needs
 * an SRP handshake, a step-up, the vault password and the device Secret Key,
 * and none of that exists here yet (PR2b). Saying it plainly is the M16 PR1
 * habit applied to a half-built feature: a surface that looks like it should
 * work and does not is worse than one that states its own boundary.
 */

/** Server shape of `GET /v1/vault/keyset`, proxied through the edge. */
interface KeysetStatus {
  enrolled?: unknown;
}

type View =
  | { kind: 'loading' }
  | { kind: 'unpaired'; error?: string }
  | { kind: 'pairing' }
  | { kind: 'paired'; session: PairedSession; status: VaultStatus; error?: string }
  | { kind: 'working'; session: PairedSession };

/**
 * THREE STATES, NOT TWO. "We could not ask" is a fact about the platform and
 * must not render as "no vault" — the M10 PR4 rule, and on this surface the
 * wrong collapse would tell someone their vault does not exist.
 */
type VaultStatus = 'enrolled' | 'none' | 'unknown';

export interface PopupDeps {
  readonly root: HTMLElement;
}

export async function mountPopup({ root }: PopupDeps): Promise<void> {
  let view: View = { kind: 'loading' };

  function show(next: View): void {
    view = next;
    draw();
  }

  /**
   * Read the one fact this PR exists to display, and decide what a failure
   * means for the PAIRING rather than just for the request.
   *
   * `UNAUTHENTICATED` here has survived a refresh attempt (see
   * `session.withSession`, which reports a transport failure as itself rather
   * than as a 401), so it means the credential is genuinely gone — revoked from
   * the owner's paired-devices list, or expired. The honest screen for that is
   * the one offering a new code, not a paired view with a banner. Anything else
   * is an outage: the pairing stands and only this read failed.
   */
  async function refreshStatus(session: PairedSession): Promise<void> {
    const { result, session: current } = await withSession(session, (bearer) =>
      request<KeysetStatus>('/api/vault/keyset', { bearer }),
    );
    if (result.ok) {
      show({
        kind: 'paired',
        session: current,
        status: result.data.enrolled === true ? 'enrolled' : 'none',
      });
      return;
    }
    if (result.code === 'UNAUTHENTICATED') {
      await forgetSession();
      show({ kind: 'unpaired', error: messageFor(result.code) });
      return;
    }
    show({
      kind: 'paired',
      session: current,
      status: 'unknown',
      error: messageFor(result.code),
    });
  }

  async function onConnect(code: string): Promise<void> {
    show({ kind: 'pairing' });
    const result: ApiResult<PairedSession> = await pair(code);
    if (!result.ok) {
      show({ kind: 'unpaired', error: messageFor(result.code) });
      return;
    }
    await refreshStatus(result.data);
  }

  async function onDisconnect(session: PairedSession): Promise<void> {
    show({ kind: 'working', session });
    const result = await disconnect(session);
    if (!result.ok) {
      show({ kind: 'paired', session, status: 'unknown', error: messageFor(result.code) });
      return;
    }
    show({ kind: 'unpaired' });
  }

  function drawUnpaired(error: string | undefined): void {
    const input = el('input', {
      id: 'pairing-code',
      type: 'text',
      placeholder: 'EP1-…',
      class: 'code',
    });
    const label = el('label', { class: 'label' }, 'Pairing code');
    label.htmlFor = 'pairing-code';
    const button = el('button', { class: 'primary' }, 'Connect this browser');
    button.addEventListener('click', () => {
      void onConnect(input.value);
    });
    render(
      root,
      el('h1', {}, 'Connect to Estate'),
      el(
        'p',
        { class: 'hint' },
        'In Estate, open Security and create a pairing code. Type it here — it works once and expires after ten minutes.',
      ),
      label,
      input,
      button,
      ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
    );
  }

  /**
   * The vault half mounts into its own element, and is mounted ONCE rather than
   * on every redraw: it owns its own state machine — and possibly a half-typed
   * vault password — so re-mounting it under the paired view would discard what
   * somebody was in the middle of entering.
   */
  const vaultHost = el('div', { class: 'vault' });
  let vaultMounted = false;

  function drawPaired(
    session: PairedSession,
    status: VaultStatus,
    error: string | undefined,
  ): void {
    const disconnectButton = el('button', { class: 'secondary' }, 'Disconnect this browser');
    disconnectButton.addEventListener('click', () => {
      void onDisconnect(session);
    });
    const statusLine =
      status === 'enrolled'
        ? 'This account has a vault.'
        : status === 'none'
          ? 'This account has no vault yet. You can set one up in Estate.'
          : 'We couldn’t check your vault just now.';
    render(
      root,
      el('h1', {}, 'Connected to Estate'),
      el('p', { class: 'status' }, statusLine),
      el(
        'p',
        { class: 'hint' },
        'This browser can look up vault items and nothing else. It cannot reset your vault, change your emergency contacts, or reach the rest of your estate.',
      ),
      vaultHost,
      disconnectButton,
      ...(error === undefined ? [] : [el('p', { class: 'error' }, error)]),
    );
    if (!vaultMounted) {
      vaultMounted = true;
      void mountVaultScreens({
        host: vaultHost,
        userId: session.userId,
        bearer: session.accessToken,
      });
    }
  }

  function draw(): void {
    if (view.kind === 'loading') {
      render(root, el('p', { class: 'hint' }, 'Loading…'));
      return;
    }
    if (view.kind === 'pairing') {
      render(root, el('p', { class: 'hint' }, 'Connecting…'));
      return;
    }
    if (view.kind === 'working') {
      render(root, el('p', { class: 'hint' }, 'Disconnecting…'));
      return;
    }
    if (view.kind === 'unpaired') {
      drawUnpaired(view.error);
      return;
    }
    drawPaired(view.session, view.status, view.error);
  }

  draw();
  const existing = await loadSession();
  if (!existing) {
    show({ kind: 'unpaired' });
    return;
  }
  await refreshStatus(existing);
}
