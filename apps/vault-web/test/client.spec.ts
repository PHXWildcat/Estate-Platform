/**
 * @jest-environment jsdom
 */

/**
 * The browser client.
 *
 * jsdom cannot enforce a CSP or Trusted Types, so what those buy is measured in
 * a REAL browser instead (and was: `trustedTypes.createPolicy` refused,
 * `innerHTML` threw a TypeError producing zero child nodes, and `new Function`
 * and `eval` both threw EvalError from page context). What jsdom is good for is
 * the half a browser cannot easily assert — that the DOM helper produces TEXT
 * for text, that a failure never renders as a success, and that the status
 * mapping is what the UI thinks it is.
 */
import { el, replaceChildren, text } from '../src/client/dom';
import { request } from '../src/client/api';
import { render } from '../src/client/app';

type FetchArgs = [string, RequestInit | undefined];

/**
 * A response DOUBLE rather than a real `Response`.
 *
 * jsdom provides no `fetch` and no `Response` global, so constructing one threw
 * — and `request` dutifully reported NETWORK, which is the correct behaviour
 * for a transport that blew up and a completely misleading test result. The
 * double exposes exactly the three members `request` reads.
 */
function response(status: number, body: string | null): unknown {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(body ?? ''),
  };
}

function stubFetch(handler: (path: string, init?: RequestInit) => unknown): FetchArgs[] {
  const calls: FetchArgs[] = [];
  globalThis.fetch = ((path: string, init?: RequestInit) => {
    calls.push([path, init]);
    return Promise.resolve(handler(path, init));
  }) as unknown as typeof fetch;
  return calls;
}

const json = (status: number, body: unknown): unknown => response(status, JSON.stringify(body));

describe('dom helpers build text, never markup', () => {
  it('renders a script-shaped title as characters', () => {
    // The property the whole renderer exists for. A vault item's title is
    // attacker-influencable in the general case (someone else named the
    // account), so it must never be parsed.
    const node = el('p', {}, ['<img src=x onerror=alert(1)>']);
    expect(node.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(node.querySelector('img')).toBeNull();
    expect(node.childNodes).toHaveLength(1);
    expect(node.childNodes[0]?.nodeType).toBe(3); // TEXT_NODE
  });

  it('replaceChildren also produces text nodes, not parsed markup', () => {
    const host = el('div');
    replaceChildren(host, '<b>bold?</b>', text('plain'));
    expect(host.querySelector('b')).toBeNull();
    expect(host.textContent).toBe('<b>bold?</b>plain');
  });

  it('sets only the attributes it was given, and drops false/undefined', () => {
    const node = el('button', { class: 'button', disabled: false, hidden: true });
    expect(node.getAttribute('class')).toBe('button');
    expect(node.hasAttribute('disabled')).toBe(false);
    expect(node.hasAttribute('hidden')).toBe(true);
  });
});

describe('api failure mapping', () => {
  it.each([
    [401, 'unauthorized', 'UNAUTHENTICATED'],
    [403, 'stepup_required', 'STEPUP_REQUIRED'],
    [403, 'vault_locked', 'VAULT_LOCKED'],
    [403, 'something_else', 'UNKNOWN'],
    [404, 'not_found', 'NOT_FOUND'],
    [409, 'version_conflict', 'CONFLICT'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
    [502, 'upstream_unavailable', 'UNAVAILABLE'],
    [500, 'internal_error', 'UNKNOWN'],
  ])('maps %s/%s to %s', async (status, token, expected) => {
    stubFetch(() => json(status, { error: token }));
    const result = await request('/api/vault/keyset');
    expect(result).toEqual({ ok: false, code: expected });
  });

  it('never surfaces server error text', async () => {
    stubFetch(() => json(500, { error: 'internal_error', message: 'pg: relation does not exist' }));
    const result = await request('/api/vault/keyset');
    expect(JSON.stringify(result)).not.toContain('relation does not exist');
  });

  it('carries the CSRF header and same-origin credentials on every call', async () => {
    const calls = stubFetch(() => json(200, {}));
    await request('/api/vault/keyset');
    const init = calls[0]?.[1];
    expect((init?.headers as Record<string, string>)['x-estate-vault-csrf']).toBe('1');
    // Never 'include': there is no other origin this app should credential.
    expect(init?.credentials).toBe('same-origin');
  });

  it('treats a network failure as a failure, not as empty data', async () => {
    globalThis.fetch = () => Promise.reject(new Error('offline'));
    expect(await request('/api/vault/keyset')).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('accepts a 204 with no body', async () => {
    stubFetch(() => response(204, null));
    expect(await request('/api/vault/lock')).toEqual({ ok: true, data: {} });
  });
});

describe('the screen', () => {
  // Stubbing `window.location` is unavoidable for the sign-out tests (jsdom
  // refuses a real navigation), and a stub that outlives its test silently
  // pins `location.search` for every later one — which is exactly what
  // happened: the expired-link case stopped seeing its own query string and
  // rendered the signed-in screen instead. Restore it every time.
  const originalLocation = Object.getOwnPropertyDescriptor(window, 'location');

  afterEach(() => {
    if (originalLocation) {
      Object.defineProperty(window, 'location', originalLocation);
    }
  });

  beforeEach(() => {
    document.body.replaceChildren(el('main', { id: 'app' }));
    window.ESTATE_APP_ORIGIN = 'http://localhost:3000';
  });

  it('says not signed in when the session call is refused', async () => {
    stubFetch(() => json(401, { error: 'unauthorized' }));
    await render();
    expect(document.body.textContent).toContain('Not signed in');
    expect(document.body.textContent).toContain('Open the vault from Estate');
  });

  it('distinguishes an OUTAGE from being signed out', async () => {
    // The M10 PR4 rule: a failed read must never render as an answer, and two
    // different failures must not collapse into one message the user cannot act
    // on. "Sign in again" during an outage sends someone somewhere pointless.
    stubFetch(() => json(502, { error: 'upstream_unavailable' }));
    await render();
    expect(document.body.textContent).toContain('temporarily unreachable');
    expect(document.body.textContent).not.toContain('Open the vault from Estate');
  });

  it('shows the enrolled state and the session audience', async () => {
    stubFetch((path) =>
      path === '/api/auth/session'
        ? json(200, { userId: 'user-uuid', mfaLevel: 'stepup', audience: 'vault' })
        : json(200, { enrolled: true, updatedAt: '2026-08-08T00:00:00.000Z' }),
    );
    await render();
    expect(document.body.textContent).toContain('A vault is set up on this account');
    expect(document.body.textContent).toContain('user-uuid');
    expect(document.body.textContent).toContain('vault');
  });

  it('says so plainly when no vault exists yet', async () => {
    stubFetch((path) =>
      path === '/api/auth/session'
        ? json(200, { userId: 'user-uuid', mfaLevel: 'stepup', audience: 'vault' })
        : json(200, { enrolled: false, updatedAt: null }),
    );
    await render();
    expect(document.body.textContent).toContain('No vault has been set up');
  });

  it('does not claim an empty vault when the keyset read FAILS', async () => {
    stubFetch((path) =>
      path === '/api/auth/session'
        ? json(200, { userId: 'user-uuid', mfaLevel: 'stepup', audience: 'vault' })
        : json(502, { error: 'upstream_unavailable' }),
    );
    await render();
    expect(document.body.textContent).toContain('Could not read the vault status');
    expect(document.body.textContent).not.toContain('No vault has been set up');
  });

  /**
   * Sign-out, which is the one place this screen can do harm by being
   * optimistic: a "signed out" message over a still-live session is strictly
   * worse than an honest failure (the M8 PR5 logout lesson, where reading
   * identity's 401 as success cleared the cookies while a 30-day refresh token
   * stayed alive).
   */
  describe('sign out', () => {
    async function renderSignedIn(
      logout: (calls: number) => unknown,
    ): Promise<{ calls: FetchArgs[]; assign: jest.Mock }> {
      let logoutCalls = 0;
      const calls = stubFetch((path) => {
        if (path === '/api/auth/session') {
          return json(200, { userId: 'user-uuid', mfaLevel: 'stepup', audience: 'vault' });
        }
        if (path === '/api/auth/logout') {
          logoutCalls += 1;
          return logout(logoutCalls);
        }
        return json(200, { enrolled: true, updatedAt: null });
      });
      const assign = jest.fn();
      Object.defineProperty(window, 'location', {
        value: { search: '', assign },
        writable: true,
        configurable: true,
      });
      await render();
      return { calls, assign };
    }

    it('revokes upstream FIRST, then navigates away', async () => {
      const { calls, assign } = await renderSignedIn(() => json(200, { status: 'ok' }));
      const button = [...document.querySelectorAll('button')].find((b) =>
        b.textContent?.includes('Sign out'),
      );
      button?.click();
      await new Promise((resolve) => setTimeout(resolve, 0));

      const logout = calls.find(([path]) => path === '/api/auth/logout');
      expect(logout?.[1]?.method).toBe('POST');
      expect(assign).toHaveBeenCalledWith('/');
    });

    it('does NOT claim to have signed out when the revocation fails', async () => {
      const { assign } = await renderSignedIn(() => json(502, { error: 'upstream_unavailable' }));
      const button = [...document.querySelectorAll('button')].find((b) =>
        b.textContent?.includes('Sign out'),
      );
      button?.click();
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(assign).not.toHaveBeenCalled();
      expect(document.body.textContent).toContain('Your session is still open');
      // And the control is usable again rather than stuck disabled.
      expect(button?.hasAttribute('disabled')).toBe(false);
    });
  });

  it('renders the expired-link message without asking anything upstream', async () => {
    const calls = stubFetch(() => json(200, {}));
    window.history.replaceState({}, '', '/?open=refused');
    await render();
    expect(document.body.textContent).toContain('This vault link has expired');
    // One message for every reason, and no round trip to discover which.
    expect(calls).toHaveLength(0);
    window.history.replaceState({}, '', '/');
  });
});
