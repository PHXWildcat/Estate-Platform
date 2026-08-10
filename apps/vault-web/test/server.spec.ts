/**
 * The vault edge, driven over a real HTTP socket.
 *
 * Not supertest and not a handler unit test: this is the origin whose whole
 * job is what the BROWSER sees — cookie attributes, redirect codes, headers —
 * and every one of those is a property of a real response rather than of a
 * function's return value.
 */
import { once } from 'node:events';
import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { loadConfig } from '../src/config';
import { createVaultWebServer, projectGranteeCandidates } from '../src/server';
import { Upstream, type FetchLike } from '../src/upstream';
import { VAULT_CSP } from '../src/security-headers';

const APP_ORIGIN = 'http://localhost:3000';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string | undefined;
}

/** Records what the edge said upstream and replies with a script. */
function transport(reply: (call: Call) => { status: number; body: string }): {
  calls: Call[];
  fetchImpl: FetchLike;
} {
  const calls: Call[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    const call: Call = { url, method: init.method, headers: init.headers, body: init.body };
    calls.push(call);
    const { status, body } = reply(call);
    return Promise.resolve({
      status,
      text: () => Promise.resolve(body),
      headers: { get: (): string | null => 'application/json' },
    });
  };
  return { calls, fetchImpl };
}

async function start(fetchImpl: FetchLike): Promise<{ server: Server; base: string }> {
  const config = loadConfig({
    NODE_ENV: 'test',
    VAULT_URL: 'http://vault:3006',
    IDENTITY_URL: 'http://identity:3001',
    PROFILE_URL: 'http://profile:3002',
    APP_ORIGIN,
  });
  const server = createVaultWebServer({
    config,
    upstream: new Upstream({ identityUrl: config.identityUrl, fetchImpl }),
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  return { server, base: `http://127.0.0.1:${port}` };
}

describe('the vault edge', () => {
  let server: Server;
  let base: string;
  let calls: Call[];

  const REDEEMED = JSON.stringify({ accessToken: 'vault-access-token', userId: 'u-1' });

  async function boot(
    reply: (call: Call) => { status: number; body: string } = () => ({
      status: 200,
      body: REDEEMED,
    }),
  ): Promise<void> {
    const t = transport(reply);
    calls = t.calls;
    ({ server, base } = await start(t.fetchImpl));
  }

  afterEach(async () => {
    server?.close();
    await once(server, 'close').catch(() => undefined);
  });

  const openForm = (code: string, origin: string | null = APP_ORIGIN): Promise<Response> =>
    fetch(`${base}/open`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(origin === null ? {} : { origin }),
      },
      body: `code=${encodeURIComponent(code)}`,
    });

  describe('security headers', () => {
    it('serves the strict CSP on every response', async () => {
      await boot();
      const shell = await fetch(`${base}/`);
      expect(shell.headers.get('content-security-policy')).toBe(VAULT_CSP);
      // Including on an error, which is where a header is most often forgotten.
      const missing = await fetch(`${base}/nope.js`);
      expect(missing.status).toBe(404);
      expect(missing.headers.get('content-security-policy')).toBe(VAULT_CSP);
    });

    it('refuses framing and leaks no referrer', async () => {
      await boot();
      const res = await fetch(`${base}/`);
      expect(res.headers.get('x-frame-options')).toBe('DENY');
      expect(res.headers.get('referrer-policy')).toBe('no-referrer');
      expect(res.headers.get('cache-control')).toBe('no-store');
    });
  });

  describe('the arrival handoff', () => {
    it('redeems a code and sets a __Host- cookie with the exact attributes', async () => {
      await boot();
      const res = await openForm('a-single-use-code');

      expect(res.status).toBe(303);
      expect(res.headers.get('location')).toBe('/');
      const cookie = res.headers.getSetCookie().join('\n');
      // The prefix is the control: the browser itself then enforces host-only,
      // Path=/ and no Domain.
      expect(cookie).toContain('__Host-estate_vault=vault-access-token');
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('Secure');
      expect(cookie).toContain('Path=/');
      expect(cookie).toContain('SameSite=Lax');
      expect(cookie).not.toContain('Domain');

      expect(calls[0]?.url).toBe('http://identity:3001/v1/auth/handoff/redeem');
      expect(calls[0]?.body).toBe(JSON.stringify({ code: 'a-single-use-code' }));
    });

    it('never puts the code in the redirect URL', async () => {
      await boot();
      const res = await openForm('secret-code-value');
      expect(res.headers.get('location')).not.toContain('secret-code-value');
    });

    it('refuses a POST from any origin but the app', async () => {
      await boot();
      for (const origin of ['http://evil.example', null]) {
        const res = await openForm('a-code', origin);
        expect(res.status).toBe(403);
        // Nothing was even asked upstream.
        expect(calls).toHaveLength(0);
      }
    });

    it('answers a refused redemption identically to a missing code', async () => {
      await boot(() => ({ status: 401, body: JSON.stringify({ error: 'invalid_code' }) }));
      const refused = await openForm('wrong');
      expect(refused.status).toBe(303);
      expect(refused.headers.get('location')).toBe('/?open=refused');
      expect(refused.headers.getSetCookie()).toEqual([]);
    });

    it('sets no cookie when identity answers a malformed body', async () => {
      // A response missing its fields is NO DATA, never data (the M11 rule).
      await boot(() => ({ status: 200, body: JSON.stringify({ userId: 'u-1' }) }));
      const res = await openForm('a-code');
      expect(res.headers.getSetCookie()).toEqual([]);
      expect(res.headers.get('location')).toBe('/?open=refused');
    });
  });

  describe('the proxy', () => {
    const withSession = (path: string, init: RequestInit = {}): Promise<Response> =>
      fetch(`${base}${path}`, {
        ...init,
        headers: {
          cookie: '__Host-estate_vault=vault-access-token',
          'x-estate-vault-csrf': '1',
          ...(init.headers ?? {}),
        },
      });

    it('forwards the CALLER’S OWN bearer and nothing else', async () => {
      await boot(() => ({ status: 200, body: JSON.stringify({ enrolled: false }) }));
      const res = await withSession('/api/vault/keyset');
      expect(res.status).toBe(200);
      expect(calls[0]?.url).toBe('http://vault:3006/v1/vault/keyset');
      expect(calls[0]?.headers['authorization']).toBe('Bearer vault-access-token');
      // No service credential exists to be sent.
      expect(JSON.stringify(calls[0]?.headers)).not.toMatch(/INTERNAL_TOKEN/i);
    });

    it('carries the query string, so a paginated list is not silently re-scoped', async () => {
      await boot(() => ({ status: 200, body: '{}' }));
      await withSession('/api/vault/items?limit=25&cursor=abc');
      expect(calls[0]?.url).toBe('http://vault:3006/v1/vault/items?limit=25&cursor=abc');
    });

    it('refuses without the CSRF header', async () => {
      await boot();
      const res = await fetch(`${base}/api/vault/keyset`, {
        headers: { cookie: '__Host-estate_vault=vault-access-token' },
      });
      expect(res.status).toBe(403);
      expect(calls).toHaveLength(0);
    });

    it('refuses without the session cookie', async () => {
      await boot();
      const res = await fetch(`${base}/api/vault/keyset`, {
        headers: { 'x-estate-vault-csrf': '1' },
      });
      expect(res.status).toBe(401);
      expect(calls).toHaveLength(0);
    });

    it('reaches ONLY the allowlisted routes — an unlisted path never leaves', async () => {
      await boot();
      for (const path of [
        // The one that matters: this edge must not help a vault session mint
        // another handoff.
        '/api/auth/handoff',
        '/api/auth/totp/enroll',
        // identity's UNAUTHENTICATED refresh-token revocation route, which a
        // `startsWith('/api/auth/logout')` rule would have admitted.
        '/api/auth/logout/refresh',
        // A suffix on an exact-match route must not slip through either.
        '/api/auth/sessionx',
        '/api/internal/v1/legal-hold',
        '/api/profile/v1/profile',
      ]) {
        const res = await withSession(path);
        expect({ path, status: res.status }).toEqual({ path, status: 404 });
      }
      expect(calls).toHaveLength(0);
    });

    it('answers 502 rather than an empty vault when the upstream is unreachable', async () => {
      const fetchImpl: FetchLike = () => Promise.reject(new Error('ECONNREFUSED'));
      ({ server, base } = await start(fetchImpl));
      const res = await withSession('/api/vault/keyset');
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: 'upstream_unavailable' });
    });

    it('clears the cookie when sign-out succeeds upstream', async () => {
      await boot(() => ({ status: 200, body: JSON.stringify({ status: 'ok' }) }));
      const res = await withSession('/api/auth/logout', { method: 'POST' });
      expect(res.headers.getSetCookie().join('\n')).toContain('Max-Age=0');
    });

    it('does NOT clear the cookie when sign-out fails upstream', async () => {
      // A "signed out" screen over a live session is the worse outcome (M8 PR5).
      await boot(() => ({ status: 401, body: JSON.stringify({ error: 'unauthorized' }) }));
      const res = await withSession('/api/auth/logout', { method: 'POST' });
      expect(res.headers.getSetCookie()).toEqual([]);
    });
  });

  describe('static serving', () => {
    it('serves the shell', async () => {
      await boot();
      const res = await fetch(`${base}/`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/html');
      expect(await res.text()).toContain('Vault · Zone A');
    });

    it('serves the app origin as generated JS, not as templated HTML', async () => {
      await boot();
      const res = await fetch(`${base}/app/config.js`);
      expect(res.headers.get('content-type')).toContain('text/javascript');
      expect(await res.text()).toBe(`window.ESTATE_APP_ORIGIN = "${APP_ORIGIN}";\n`);
    });

    /**
     * NO REQUEST LINE READS A FILE OUTSIDE `public/`.
     *
     * Two corrections are baked into this test, and both are the M13 lesson
     * about a test named for a property it never touched.
     *
     * FIRST, it uses a RAW SOCKET. The original used `fetch`, which NORMALISES
     * `/../../x` to `/x` before it ever reaches the server — measured, the
     * request line the server saw was `/package.json` — so the 404 came from
     * the extension allowlist and no traversal was ever attempted. An attacker
     * does not use `fetch`.
     *
     * SECOND, it asserts the PROPERTY, not a particular guard. Deleting the
     * `startsWith(publicDir)` check leaves this green, because the WHATWG `URL`
     * parse upstream of it collapses `..` (and decodes `%2e%2e` to `..` first).
     * That check is unreachable and is documented as such in `server.ts`;
     * claiming here that it is what stops traversal would be false.
     *
     * The targets are `.css` files in ANOTHER app, so the extension allowlist
     * cannot mask a real escape: a regression serves `apps/web`'s stylesheet
     * from the Zone A origin, and the assertion looks for its actual contents.
     */
    it.each([
      '/../../web/src/app/globals.css',
      '/%2e%2e/%2e%2e/web/src/app/globals.css',
      '/..%2f..%2fweb/src/app/globals.css',
      '/app/../../../web/src/app/globals.css',
    ])('serves nothing outside public for %s', async (rawPath) => {
      await boot();
      const port = Number(new URL(base).port);
      const response = await new Promise<string>((resolve) => {
        const socket = connect(port, '127.0.0.1', () => {
          socket.write(`GET ${rawPath} HTTP/1.1\r\nHost: vault\r\nConnection: close\r\n\r\n`);
        });
        let buffer = '';
        socket.on('data', (chunk) => {
          buffer += chunk.toString('utf8');
        });
        socket.on('close', () => resolve(buffer));
        socket.on('error', () => resolve(buffer));
      });
      expect(response).toContain('404');
      // A token that appears in apps/web's stylesheet and nowhere here.
      expect(response).not.toContain('--rail');
    });

    it('refuses paths whose extension is not on the allowlist', async () => {
      await boot();
      expect((await fetch(`${base}/package.json`)).status).toBe(404);
    });
  });

  /**
   * THE ONE ZONE B READ ON THIS ORIGIN (M15 PR3).
   *
   * Contact NAMES cross onto the vault origin so an owner can choose grantees
   * and confirm each one's key fingerprint. Nothing else does, and the
   * subtraction is asserted here rather than trusted to a screen.
   */
  describe('grantee candidates', () => {
    // What profile's dedicated route serves. The extra fields are NOT part of
    // that contract — they are here because the edge's own projection must hold
    // if the upstream shape ever widens, which is the whole reason it survives
    // now that profile projects too.
    const CONTACTS = JSON.stringify([
      {
        contactId: 'c-1',
        userId: 'u-ada',
        name: 'Ada',
        relationship: 'sibling',
        professionalKind: 'attorney',
        hasNotes: true,
      },
    ]);

    const ask = (headers: Record<string, string> = {}): Promise<Response> =>
      fetch(`${base}/api/grantee-candidates`, {
        headers: { cookie: '__Host-estate_vault=t', 'x-estate-vault-csrf': '1', ...headers },
      });

    it('keeps exactly three fields, and only from linked contacts', () => {
      expect(projectGranteeCandidates(JSON.parse(CONTACTS))).toEqual([
        { contactId: 'c-1', userId: 'u-ada', name: 'Ada' },
      ]);
    });

    it('drops a row that is missing what a grantee needs', () => {
      // `linked: true` with no `linkedUserId` cannot be sealed a share, so
      // surfacing it would render a row the owner can never choose.
      expect(projectGranteeCandidates([{ id: 'c-3', name: 'Half', linked: true }])).toEqual([]);
      expect(projectGranteeCandidates('not an array')).toEqual([]);
    });

    it('serves the projection, and nothing else profile said', async () => {
      await boot(() => ({ status: 200, body: CONTACTS }));
      const response = await ask();
      expect(response.status).toBe(200);
      const text = await response.text();
      expect(JSON.parse(text)).toEqual({
        candidates: [{ contactId: 'c-1', userId: 'u-ada', name: 'Ada' }],
      });
      // Anything profile might add later stays in Zone B.
      expect(text).not.toContain('sibling');
      expect(text).not.toContain('attorney');
      expect(text).not.toContain('hasNotes');
      // Forwarded on the caller's OWN bearer — this edge holds no credential.
      expect(calls[0]?.headers['authorization']).toBe('Bearer t');
      // The DEDICATED route, not the general contacts list: that one is
      // `account`-only at profile and would 401 a vault session anyway.
      expect(calls[0]?.url).toContain('/v1/contacts/grantee-candidates');
    });

    it('refuses without the CSRF header, and without a session', async () => {
      await boot(() => ({ status: 200, body: CONTACTS }));
      expect((await ask({ 'x-estate-vault-csrf': '' })).status).toBe(403);
      const noCookie = await fetch(`${base}/api/grantee-candidates`, {
        headers: { 'x-estate-vault-csrf': '1' },
      });
      expect(noCookie.status).toBe(401);
      expect(calls).toHaveLength(0);
    });

    it('never passes profile’s failure body through', async () => {
      await boot(() => ({ status: 500, body: '{"error":"pg: relation contacts does not exist"}' }));
      const response = await ask();
      expect(response.status).toBe(502);
      expect(await response.text()).toBe(JSON.stringify({ error: 'contacts_unavailable' }));
    });

    it('reports an unparseable upstream body as an outage, not as no contacts', async () => {
      await boot(() => ({ status: 200, body: '<html>gateway</html>' }));
      expect((await ask()).status).toBe(502);
    });
  });
});
