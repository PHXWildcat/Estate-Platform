import { request } from './api.js';
import { el, onClick, replaceChildren, requireElement } from './dom.js';

/**
 * The vault origin's client — PR1's version, which deliberately holds NO KEYS.
 *
 * This milestone's PR1 exists to prove the boundary before anything valuable
 * sits behind it: the origin, the handoff, the cookie, the CSP, the proxy and
 * the fences. So this screen does exactly three things — say who is signed in,
 * say whether a vault has been enrolled, and sign out — and every one of them
 * goes through the same allowlisted edge the real surface will.
 *
 * Note the imports: relative, with explicit `.js`, because these are NATIVE ES
 * MODULES served as written. There is no bundler (see tsconfig.client.json) and
 * @estate/vault-crypto will arrive in PR2 by ABSOLUTE PATH from this origin,
 * never as a bare specifier — which is what lets `script-src 'self'` stay
 * exactly that, with no inline import map to hash.
 */

interface SessionInfo {
  userId: string;
  mfaLevel: string;
  audience: string;
}

interface KeysetStatus {
  enrolled: boolean;
  updatedAt: string | null;
}

function statusLine(message: string, tone: 'ok' | 'warn' | 'error' = 'ok'): HTMLElement {
  return el('p', { class: `status status-${tone}`, role: 'status', 'aria-live': 'polite' }, [
    message,
  ]);
}

export async function render(): Promise<void> {
  const main = requireElement('app');

  // The arrival ceremony refused. One message for every reason the edge could
  // have had — expired, unknown, already spent, raced — because it does not
  // know which, by design.
  if (new URLSearchParams(window.location.search).get('open') === 'refused') {
    replaceChildren(
      main,
      el('h1', {}, ['This vault link has expired']),
      statusLine(
        'Vault links are valid for about a minute and can be used once. Go back to Estate and open the vault again.',
        'warn',
      ),
      el('p', {}, [el('a', { class: 'link', id: 'back' }, ['Back to Estate'])]),
    );
    wireBackLink();
    return;
  }

  const session = await request<SessionInfo>('/api/auth/session');
  if (!session.ok) {
    replaceChildren(
      main,
      el('h1', {}, ['Not signed in']),
      statusLine(
        session.code === 'NETWORK' || session.code === 'UNAVAILABLE'
          ? 'The vault is temporarily unreachable. Try again shortly.'
          : 'Open the vault from Estate to continue.',
        session.code === 'NETWORK' || session.code === 'UNAVAILABLE' ? 'error' : 'warn',
      ),
      el('p', {}, [el('a', { class: 'link', id: 'back' }, ['Back to Estate'])]),
    );
    wireBackLink();
    return;
  }

  const keyset = await request<KeysetStatus>('/api/vault/keyset');

  const signOut = el('button', { class: 'button', type: 'button' }, ['Sign out of the vault']);
  onClick(signOut, () => {
    void (async (): Promise<void> => {
      signOut.setAttribute('disabled', '');
      // Revoke FIRST; the edge clears the cookie only on a 2xx. A "signed out"
      // screen over a live session is the worse outcome (M8 PR5).
      const result = await request('/api/auth/logout', { method: 'POST' });
      if (result.ok) {
        window.location.assign('/');
        return;
      }
      signOut.removeAttribute('disabled');
      main.append(statusLine('Could not sign out. Your session is still open.', 'error'));
    })();
  });

  replaceChildren(
    main,
    el('h1', {}, ['Vault']),
    statusLine(
      keyset.ok
        ? keyset.data.enrolled
          ? 'A vault is set up on this account. Unlocking arrives in the next release.'
          : 'No vault has been set up on this account yet.'
        : 'Could not read the vault status.',
      keyset.ok ? 'ok' : 'error',
    ),
    el('dl', { class: 'facts' }, [
      el('dt', {}, ['Signed in as']),
      // The user id, never an email: this origin has no reason to hold one, and
      // M9's notification doctrine keeps addresses out of everything that does
      // not need to reach somebody.
      el('dd', {}, [session.data.userId]),
      el('dt', {}, ['Session type']),
      el('dd', {}, [session.data.audience]),
    ]),
    el('p', {}, [signOut]),
    el('p', {}, [el('a', { class: 'link', id: 'back' }, ['Back to Estate'])]),
  );
  wireBackLink();
}

/**
 * The link home.
 *
 * The app origin is CONFIGURATION, so it cannot be baked into the static shell
 * — and it is deliberately not interpolated into the served HTML either, since
 * building markup from a string is the one thing this origin has organised
 * itself never to do. The edge serves it as `/app/config.js`, a generated
 * JavaScript module whose only statement assigns a `JSON.stringify`-encoded
 * string. No HTML templating, no parser, nothing for the CSP to exempt.
 *
 * `dom.ts` deliberately has no `href` attribute to set, so navigation happens
 * through `location.assign` with a value the edge validated as a URL.
 */
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
