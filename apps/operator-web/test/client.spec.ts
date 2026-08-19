/**
 * @jest-environment jsdom
 */

/**
 * The operator console's browser client (M21 PR3a).
 *
 * jsdom cannot enforce a CSP or Trusted Types, so what those buy is measured in
 * a real browser rather than here. What IS testable here is the thing the
 * screen is for: that it says which credential you are holding, that it never
 * implies arriving proved anything, and that an outage does not wear the face
 * of a revocation.
 */
import { render } from '../src/client/app';

const SESSION = {
  userId: 'u-ada',
  sessionId: 's-1',
  audience: 'operator',
  mfaLevel: 'stepup',
  stepupExpiresAt: '2026-08-18T12:00:00.000Z',
};

interface Reply {
  status: number;
  body: unknown;
}

let calls: Array<{ path: string; method: string; headers: Record<string, string> }>;

function transport(replies: Record<string, Reply | (() => Reply)>): void {
  calls = [];
  (globalThis as { fetch?: unknown }).fetch = (path: string, init?: RequestInit) => {
    calls.push({
      path,
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    const entry = replies[path];
    if (entry === undefined) return Promise.reject(new Error('unrouted'));
    const reply = typeof entry === 'function' ? entry() : entry;
    return Promise.resolve({
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      text: () => Promise.resolve(reply.body === undefined ? '' : JSON.stringify(reply.body)),
    });
  };
}

function setUrl(search: string): void {
  window.history.replaceState({}, '', `/${search}`);
}

beforeEach(() => {
  document.body.replaceChildren();
  const main = document.createElement('main');
  main.id = 'app';
  document.body.append(main);
  (globalThis as { ESTATE_APP_ORIGIN?: string }).ESTATE_APP_ORIGIN = 'http://localhost:3000';
  setUrl('');
});

const app = (): HTMLElement => document.getElementById('app') as HTMLElement;

/** Two drains: the logout round trip and the re-render that follows it. */
const settle = async (): Promise<void> => {
  await new Promise((r) => setTimeout(r, 0));
  await new Promise((r) => setTimeout(r, 0));
};

describe('the operator console', () => {
  it('names the credential it is holding, and says arriving proves nothing', async () => {
    transport({ '/api/auth/session': { status: 200, body: SESSION } });
    await render();

    expect(app().querySelector('[data-testid="audience"]')?.textContent).toBe('operator');
    const copy = app().textContent ?? '';
    // The sentence that keeps the model honest: minting is role-blind, so a
    // console implying otherwise would teach every user who reached it that
    // arriving is the permission.
    expect(copy).toMatch(/grants no authority on its own/i);
    expect(copy).toMatch(/operator allowlist/i);
    expect(copy).toMatch(/reaches none of your own estate/i);
    expect(copy).toMatch(/15 minutes/);
    expect(copy).toMatch(/cannot be renewed/i);
  });

  it('SHOWS the audience it actually received, so a misdirected code is visible', async () => {
    // The edge deliberately does not check which audience a redeemed code
    // carried — the callee enforces it, and a second copy of the audience table
    // here would drift. What makes that safe to say is that the screen reports
    // what it is holding rather than assuming.
    transport({
      '/api/auth/session': { status: 200, body: { ...SESSION, audience: 'vault' } },
    });
    await render();
    expect(app().querySelector('[data-testid="audience"]')?.textContent).toBe('vault');
  });

  it('reads a response missing its fields as NO DATA, never as data', async () => {
    // A version skew must not render a blank session type, which would read as
    // a claim about a credential rather than as an admission (M11/M12/M15).
    for (const body of [{}, { userId: 'u' }, { ...SESSION, audience: '' }, 'nope']) {
      transport({ '/api/auth/session': { status: 200, body } });
      await render();
      expect(app().textContent).toMatch(/could not read your session/i);
      expect(app().querySelector('[data-testid="audience"]')).toBeNull();
    }
  });

  it('sends people back to the app when there is no session here', async () => {
    transport({ '/api/auth/session': { status: 401, body: { error: 'unauthorized' } } });
    await render();
    expect(app().textContent).toMatch(/not signed in on this origin/i);
    expect(app().querySelector('a.link')?.getAttribute('href')).toBe('http://localhost:3000');
  });

  it('renders no link at all when the origin module did not load', async () => {
    // `/app/config.js` is a separate request, so it can fail on its own. A
    // half-built link (`href=""`, or the literal `undefined`) would be a
    // control that looks like a way out and is not — so there is simply no
    // link, on both screens.
    delete (globalThis as { ESTATE_APP_ORIGIN?: string }).ESTATE_APP_ORIGIN;
    transport({ '/api/auth/session': { status: 401, body: { error: 'unauthorized' } } });
    await render();
    expect(app().querySelector('a')).toBeNull();
    expect(app().textContent).toMatch(/not signed in on this origin/i);

    transport({ '/api/auth/session': { status: 200, body: SESSION } });
    await render();
    expect(app().querySelector('a')).toBeNull();
    // …and the session facts are still there: the missing link costs the page
    // a way out, never the thing it exists to say.
    expect(app().querySelector('[data-testid="audience"]')?.textContent).toBe('operator');
  });

  it('does NOT say the session ended when the platform is simply unreachable', async () => {
    // An outage must not wear the face of a revocation (M16 PR2a): telling
    // somebody to sign in again during an identity outage sends them to a
    // ceremony that cannot run, on a different origin.
    for (const reply of [
      { status: 503, body: { error: 'unavailable' } },
      { status: 502, body: { error: 'upstream_unavailable' } },
    ]) {
      transport({ '/api/auth/session': reply });
      await render();
      expect(app().textContent).toMatch(/has not ended/i);
      expect(app().textContent).not.toMatch(/not signed in/i);
    }
  });

  it('answers every arrival failure with one sentence', async () => {
    setUrl('?open=refused');
    transport({ '/api/auth/session': { status: 401, body: { error: 'unauthorized' } } });
    await render();
    const copy = app().textContent ?? '';
    expect(copy).toMatch(/could not be opened/i);
    // Single-use and short-lived is the whole explanation. Which of unknown,
    // expired, spent or raced applied is deliberately not said — the edge does
    // not distinguish them either.
    expect(copy).toMatch(/single-use/i);
    expect(copy).not.toMatch(/expired code|already used|unknown code/i);
  });

  it('signs out through the edge, and re-renders as signed out', async () => {
    let signedIn = true;
    transport({
      '/api/auth/session': () =>
        signedIn
          ? { status: 200, body: SESSION }
          : { status: 401, body: { error: 'unauthorized' } },
      '/api/auth/logout': () => {
        signedIn = false;
        return { status: 204, body: undefined };
      },
    });
    await render();
    (document.getElementById('sign-out') as HTMLButtonElement).click();
    await settle();

    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'GET /api/auth/session',
      'POST /api/auth/logout',
      'GET /api/auth/session',
    ]);
    expect(app().textContent).toMatch(/not signed in on this origin/i);
  });

  it('SAYS YOU ARE STILL SIGNED IN when the sign-out failed', async () => {
    // Revoke first, and only then believe it (M8 PR5): a "signed out" message
    // over a live session is the worse of the two outcomes.
    transport({
      '/api/auth/session': { status: 200, body: SESSION },
      '/api/auth/logout': { status: 500, body: {} },
    });
    await render();
    (document.getElementById('sign-out') as HTMLButtonElement).click();
    await settle();

    expect(app().textContent).toMatch(/still signed in/i);
    // And it is still true: the audience row is still on screen.
    expect(app().querySelector('[data-testid="audience"]')?.textContent).toBe('operator');
  });

  it('carries the CSRF header on every call', async () => {
    transport({
      '/api/auth/session': { status: 200, body: SESSION },
      '/api/auth/logout': { status: 204, body: undefined },
    });
    await render();
    (document.getElementById('sign-out') as HTMLButtonElement).click();
    await settle();
    expect(calls.length).toBeGreaterThan(1);
    for (const call of calls) {
      expect(call.headers['x-estate-operator-csrf']).toBe('1');
    }
  });

  it('renders text as TEXT, with no markup path into the document', async () => {
    // The Trusted-Types policy is `'none'`, so a browser throws on any parse.
    // jsdom cannot enforce that, but it can prove the client never asks: an
    // audience carrying markup arrives as characters.
    transport({
      '/api/auth/session': {
        status: 200,
        body: { ...SESSION, audience: '<img src=x onerror=alert(1)>' },
      },
    });
    await render();
    const cell = app().querySelector('[data-testid="audience"]');
    expect(cell?.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(cell?.querySelector('img')).toBeNull();
  });
});
