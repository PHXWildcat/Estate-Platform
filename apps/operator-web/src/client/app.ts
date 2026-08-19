import { request, type ApiFailure } from './api.js';
import { el, onClick, replaceChildren, requireElement } from './dom.js';

/**
 * THE OPERATOR CONSOLE, at the boundary stage (M21 PR3a).
 *
 * What it can do is one sentence: tell you which credential you are holding on
 * this origin, and let you put it down. There is no settlement surface here yet
 * — that is PR3b, and it lands with the proxy routes and the audit event that
 * makes an operator's read visible. Shipping the boundary first is the M15 PR1
 * precedent: prove the origin, the handoff and the fences with nothing valuable
 * behind them, so the review of the boundary is not tangled up with the review
 * of the surface.
 *
 * THE SCREEN'S ONE JOB BESIDES THAT is to be honest about what arriving here
 * proves, which is NOTHING. An `operator` audience is a RESTRICTION on where a
 * credential may be spent, not a claim about who is spending it: minting is
 * role-blind by design, so any signed-in account can reach this origin, and
 * whether they may approve a death case is decided by `settlement_operators`
 * inside the transaction that would act on it. A console that implied otherwise
 * would be teaching its own users a false model of the control.
 */

interface SessionView {
  readonly userId: string;
  readonly sessionId: string;
  readonly audience: string;
  readonly stepupExpiresAt: string | null;
}

/**
 * A response missing its fields is NO DATA, never data (M11/M12/M15).
 *
 * The realistic failure is a version skew — this origin's client deployed ahead
 * of identity, or behind it — and the direction that matters is that a missing
 * `audience` must not render as an empty one. An empty audience would read on
 * screen as "your session type is blank", which is a claim about a credential
 * rather than an admission that we could not ask.
 */
function parseSession(payload: unknown): SessionView | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const { userId, sessionId, audience, stepupExpiresAt } = payload as Record<string, unknown>;
  if (typeof userId !== 'string' || userId.length === 0) return null;
  if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
  if (typeof audience !== 'string' || audience.length === 0) return null;
  if (stepupExpiresAt !== null && typeof stepupExpiresAt !== 'string') return null;
  return { userId, sessionId, audience, stepupExpiresAt };
}

function appOrigin(): string {
  // Set by `/app/config.js`, which the edge generates from a zod-validated URL.
  const value = (globalThis as { ESTATE_APP_ORIGIN?: unknown }).ESTATE_APP_ORIGIN;
  return typeof value === 'string' ? value : '';
}

function link(href: string, label: string): HTMLAnchorElement {
  // `href` is deliberately absent from `dom.ts`'s attribute allowlist, so the
  // one place a URL becomes an attribute is here, over a value the edge
  // validated as a URL before it ever reached the browser.
  const anchor = el('a', { class: 'link' }, [label]);
  anchor.setAttribute('href', href);
  return anchor;
}

/**
 * What went wrong, in the operator's vocabulary rather than the wire's.
 *
 * `UNAVAILABLE` and `NETWORK` deliberately do NOT say the session ended. An
 * outage must not wear the face of a revocation (M16 PR2a): telling somebody to
 * sign in again during an identity outage sends them to a ceremony that cannot
 * run, and on this origin the ceremony starts on a different origin entirely.
 */
function messageFor(code: ApiFailure): string {
  switch (code) {
    case 'NETWORK':
      return 'We could not reach Estate just now. Your session has not ended — try again in a moment.';
    case 'UNAVAILABLE':
      return 'Estate is not answering just now. Your session has not ended — try again in a moment.';
    case 'TOO_MANY_ATTEMPTS':
      return 'Too many attempts. Wait a few minutes and try again.';
    default:
      return 'Something went wrong. Try again in a moment.';
  }
}

function signedOutScreen(reason: string | null): readonly Node[] {
  const origin = appOrigin();
  return [
    el('h1', { class: 'title' }, ['Operator console']),
    ...(reason ? [el('p', { class: 'notice', role: 'alert' }, [reason])] : []),
    el('p', { class: 'lede' }, [
      'You are not signed in on this origin. The console is opened from Estate: sign in there, confirm it is you, and open the operator console from your security settings.',
    ]),
    ...(origin ? [el('p', {}, [link(origin, 'Go to Estate')])] : []),
  ];
}

function signedInScreen(session: SessionView, onSignOut: () => void): readonly Node[] {
  const origin = appOrigin();
  const signOut = el('button', { type: 'button', class: 'button', id: 'sign-out' }, ['Sign out']);
  onClick(signOut, onSignOut);
  return [
    el('h1', { class: 'title' }, ['Operator console']),
    el('dl', { class: 'facts' }, [
      el('dt', {}, ['Session type']),
      el('dd', { 'data-testid': 'audience' }, [session.audience]),
      el('dt', {}, ['Identity check']),
      el('dd', {}, [session.stepupExpiresAt ? 'Recently confirmed' : 'Not recently confirmed']),
    ]),
    /*
     * THE SENTENCE THAT KEEPS THE MODEL HONEST, and it is not decoration.
     *
     * Minting an operator handoff is role-blind — any signed-in account can
     * arrive here — so a console that opened with "welcome, operator" would
     * teach every user who reached it that arriving is the permission. It is
     * not. The allowlist decides, in settlement, inside the transaction.
     */
    el('p', { class: 'lede' }, [
      'This credential is restricted to this origin. It reaches none of your own estate — not your assets, documents, people or vault — and it grants no authority on its own: whether you may act on a settlement case is decided when you try, against the operator allowlist.',
    ]),
    el('p', { class: 'lede' }, [
      'It expires on its own after 15 minutes and cannot be renewed. To come back, open the console from Estate again.',
    ]),
    el('p', { class: 'actions' }, [signOut, ...(origin ? [link(origin, 'Back to Estate')] : [])]),
  ];
}

let signingOut = false;

export async function render(): Promise<void> {
  const app = requireElement('app');
  const refused = new URL(globalThis.location.href).searchParams.get('open') === 'refused';
  const arrivalNotice = refused
    ? // ONE ANSWER FOR EVERY ARRIVAL FAILURE — unknown code, expired, already
      // spent, lost a race, identity unreachable. The edge distinguishes none
      // of them and neither does this, or the landing page becomes an oracle
      // for whether a guessed code named something real.
      'That link could not be opened. Codes are single-use and expire quickly — open the console from Estate again.'
    : null;

  const result = await request<unknown>('/api/auth/session');
  if (!result.ok) {
    if (result.code === 'UNAUTHENTICATED') {
      replaceChildren(app, ...signedOutScreen(arrivalNotice));
      return;
    }
    replaceChildren(
      app,
      el('h1', { class: 'title' }, ['Operator console']),
      el('p', { class: 'notice', role: 'alert' }, [messageFor(result.code)]),
    );
    return;
  }

  const session = parseSession(result.data);
  if (!session) {
    replaceChildren(
      app,
      el('h1', { class: 'title' }, ['Operator console']),
      el('p', { class: 'notice', role: 'alert' }, [
        'We could not read your session. Try again in a moment.',
      ]),
    );
    return;
  }

  replaceChildren(
    app,
    ...signedInScreen(session, () => {
      void signOut();
    }),
  );
}

/**
 * Sign out: REVOKE FIRST, and only then believe it (M8 PR5).
 *
 * The edge clears the cookie when — and only when — identity actually revoked
 * the session, so a failed revocation leaves the browser holding a credential
 * that still works and a screen that still says so. A "signed out" message over
 * a live session is the worse outcome of the two.
 */
async function signOut(): Promise<void> {
  if (signingOut) return;
  signingOut = true;
  try {
    const result = await request<unknown>('/api/auth/logout', { method: 'POST' });
    if (!result.ok) {
      const app = requireElement('app');
      const notice = el('p', { class: 'notice', role: 'alert' }, [
        'We could not sign you out. You are still signed in on this origin — try again in a moment.',
      ]);
      app.append(notice);
      return;
    }
    await render();
  } finally {
    signingOut = false;
  }
}
