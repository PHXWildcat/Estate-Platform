/**
 * The operator edge, driven over a real HTTP socket.
 *
 * Not supertest and not a handler unit test: this is an origin whose whole job
 * is what the BROWSER sees — cookie attributes, redirect codes, headers — and
 * every one of those is a property of a real response rather than of a
 * function's return value.
 */
import { once } from 'node:events';
import { connect } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { loadConfig } from '../src/config';
import { createOperatorWebServer } from '../src/server';
import { Upstream, type FetchLike } from '../src/upstream';
import { OPERATOR_CSP } from '../src/security-headers';
import { OPERATOR_SESSION_COOKIE } from '../src/cookies';

const APP_ORIGIN = 'http://localhost:3000';
const CSRF = { 'x-estate-operator-csrf': '1' };

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
    IDENTITY_URL: 'http://identity:3001',
    SETTLEMENT_URL: 'http://settlement:3007',
    APP_ORIGIN,
  });
  const server = createOperatorWebServer({
    config,
    upstream: new Upstream({ identityUrl: config.identityUrl, fetchImpl }),
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address() as AddressInfo;
  return { server, base: `http://127.0.0.1:${port}` };
}

describe('the operator edge', () => {
  let server: Server;
  let base: string;
  let calls: Call[];

  const REDEEMED = JSON.stringify({ accessToken: 'operator-access-token', userId: 'u-1' });

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

  const cookieHeader = (token: string): string => `${OPERATOR_SESSION_COOKIE}=${token}`;

  describe('the arrival ceremony', () => {
    it('spends the code server-side and sets a __Host- cookie the page cannot read', async () => {
      await boot();
      const res = await openForm('EH1-ABCD');

      expect(res.status).toBe(303);
      expect(res.headers.get('location')).toBe('/');
      const setCookie = res.headers.get('set-cookie') ?? '';
      expect(setCookie).toContain(`${OPERATOR_SESSION_COOKIE}=operator-access-token`);
      // Every one of these is what `__Host-` means: the browser refuses the
      // cookie without Secure and Path=/, and refuses it WITH a Domain.
      expect(setCookie).toContain('HttpOnly');
      expect(setCookie).toContain('Secure');
      expect(setCookie).toContain('Path=/');
      expect(setCookie).toContain('SameSite=Lax');
      expect(setCookie).not.toContain('Domain=');

      // The code went to identity, not into a URL, a log, or the page.
      expect(calls).toHaveLength(1);
      expect(calls[0]?.url).toBe('http://identity:3001/v1/auth/handoff/redeem');
      expect(JSON.parse(calls[0]?.body ?? '{}')).toEqual({ code: 'EH1-ABCD' });
    });

    it('answers EVERY arrival failure identically, and sets no cookie', async () => {
      // Unknown, expired, spent, raced and identity-unreachable are one answer
      // here exactly as they are one answer at identity: a landing page that
      // distinguished them would be an oracle for whether a guessed code named
      // something real.
      const outcomes: Array<{ label: string; status: number; body: string }> = [
        { label: 'refused', status: 401, body: JSON.stringify({ error: 'invalid_code' }) },
        { label: 'malformed', status: 200, body: '{"accessToken":""}' },
        { label: 'not-json', status: 200, body: 'not json' },
        // A well-formed JSON document that is not an object at all. Shape is
        // checked rather than trusted, or a malformed body produces a session
        // cookie carrying `undefined` (M11: a response missing its fields is NO
        // DATA, never data).
        { label: 'json-scalar', status: 200, body: '"a-string"' },
        { label: 'json-null', status: 200, body: 'null' },
        { label: 'no-userId', status: 200, body: JSON.stringify({ accessToken: 'a' }) },
      ];
      for (const outcome of outcomes) {
        await boot(() => ({ status: outcome.status, body: outcome.body }));
        const res = await openForm('EH1-ABCD');
        expect({
          label: outcome.label,
          status: res.status,
          at: res.headers.get('location'),
        }).toEqual({ label: outcome.label, status: 303, at: '/?open=refused' });
        expect(res.headers.get('set-cookie')).toBeNull();
        server.close();
      }

      // And an identity that is not answering at all lands on the same page.
      // FAIL CLOSED: an unreachable identity is a refusal here, never an
      // arrival — the alternative would be a cookie carrying nothing.
      ({ server, base } = await start(() => Promise.reject(new Error('ECONNREFUSED'))));
      const unreachable = await openForm('EH1-ABCD');
      expect(unreachable.status).toBe(303);
      expect(unreachable.headers.get('location')).toBe('/?open=refused');
      expect(unreachable.headers.get('set-cookie')).toBeNull();
    });

    it('refuses a POST that did not come from the app origin', async () => {
      await boot();
      for (const origin of ['http://evil.example', null]) {
        const res = await openForm('EH1-ABCD', origin);
        expect(res.status).toBe(403);
      }
      // The code was never spent: an arbitrary page holding one cannot even
      // cause this edge to try it.
      expect(calls).toHaveLength(0);
    });

    it('answers a missing code the same way as a bad one', async () => {
      await boot();
      const res = await fetch(`${base}/open`, {
        method: 'POST',
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded', origin: APP_ORIGIN },
        body: 'nothing=here',
      });
      expect(res.status).toBe(303);
      expect(res.headers.get('location')).toBe('/?open=refused');
      expect(calls).toHaveLength(0);
    });
  });

  describe('the proxy allowlist', () => {
    it('reaches identity on the CALLER’S OWN bearer, and holds none of its own', async () => {
      await boot(() => ({ status: 200, body: '{"audience":"operator"}' }));
      const res = await fetch(`${base}/api/auth/session`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });

      expect(res.status).toBe(200);
      expect(calls[0]?.url).toBe('http://identity:3001/v1/auth/session');
      expect(calls[0]?.headers['authorization']).toBe('Bearer caller-token');
      // Nothing else. No service credential exists on this origin to add.
      expect(Object.keys(calls[0]?.headers ?? {})).toEqual(['authorization']);
    });

    it('REFUSES EVERY PATH THAT IS NOT ON THE LIST, without leaving the process', async () => {
      await boot();
      const refused = [
        // Identity's mint routes: this edge must not help an operator session
        // mint another credential.
        '/api/auth/handoff',
        '/api/auth/handoff/operator',
        '/api/auth/extension/pairing',
        // The suffix that a `startsWith('/api/auth/logout')` rule would have
        // admitted — identity's UNAUTHENTICATED refresh-token revocation route.
        '/api/auth/logout/refresh',
        // An operator session has no refresh token by construction, so there is
        // nothing here to refresh.
        '/api/auth/refresh',
        // Settlement routes this origin proxies neighbours of, and does not
        // proxy: `cases` is the REPORTER's listing (one segment short of
        // `cases/:caseId`), and the other two are the executor and
        // owner-facing halves of the surface.
        '/api/settlement/cases',
        '/api/settlement/cases/case-1/tasks',
        '/api/settlement/settings',
        '/api/settlement/cases/case-1/void',
        // Other people's estates, reachable from nowhere here.
        '/api/vault/items',
        '/api/contacts',
        // Path traversal on the rewrite, which an exact match cannot express.
        '/api/auth/session/../../internal/v1/settlement-lock/victim',
      ];
      for (const path of refused) {
        const res = await fetch(`${base}${path}`, {
          headers: { ...CSRF, cookie: cookieHeader('caller-token') },
        });
        expect({ path, status: res.status }).toEqual({ path, status: 404 });
      }
      expect(calls).toHaveLength(0);
    });

    it('reaches SETTLEMENT for its own routes, and identity for identity’s', async () => {
      // Two upstreams, one credential. The row names which base URL a path
      // resolves against, so a settlement path can never be answered by
      // identity or the reverse.
      await boot(() => ({ status: 200, body: '[]' }));
      await fetch(`${base}/api/settlement/queue`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      await fetch(`${base}/api/auth/session`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });

      expect(calls.map((c) => c.url)).toEqual([
        'http://settlement:3007/v1/settlement/queue',
        'http://identity:3001/v1/auth/session',
      ]);
      // Still the caller's own bearer, and still nothing else.
      expect(Object.keys(calls[0]?.headers ?? {})).toEqual(['authorization']);
      expect(calls[0]?.headers['authorization']).toBe('Bearer caller-token');
    });

    it('SUBSTITUTES A CAPTURED SEGMENT into the template, and nothing else', async () => {
      await boot(() => ({ status: 200, body: '{}' }));
      const caseId = '11111111-2222-3333-4444-555555555555';
      await fetch(`${base}/api/settlement/cases/${caseId}/timeline`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(calls[0]?.url).toBe(`http://settlement:3007/v1/settlement/cases/${caseId}/timeline`);
    });

    it('THE METHOD IS PART OF THE ROW: a shared path grants one verb, not both', async () => {
      /*
       * `GET cases/:caseId/stages` is the operator's read and is proxied;
       * `POST cases/:caseId/stages` is the EXECUTOR's request and is not. The
       * audience table would refuse the POST anyway — this asserts the edge
       * does not claim a capability it has not been given, so the table says
       * what it grants without a reader reconstructing the audience list.
       */
      await boot(() => ({ status: 200, body: '[]' }));
      const stages = `${base}/api/settlement/cases/case-1/stages`;
      const read = await fetch(stages, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      const write = await fetch(stages, {
        method: 'POST',
        headers: {
          ...CSRF,
          cookie: cookieHeader('caller-token'),
          'content-type': 'application/json',
        },
        body: '{"stage":"vault"}',
      });

      expect({ read: read.status, write: write.status }).toEqual({ read: 200, write: 404 });
      expect(calls).toHaveLength(1);
      // The same shape at the other colliding pair.
      const distributions = `${base}/api/settlement/cases/case-1/distributions`;
      const recorded = await fetch(distributions, {
        method: 'POST',
        headers: {
          ...CSRF,
          cookie: cookieHeader('caller-token'),
          'content-type': 'application/json',
        },
        body: '{}',
      });
      expect(recorded.status).toBe(404);
      // …and a method this edge proxies nowhere is refused on a path it does
      // proxy, with the same answer an unknown path gets.
      const deleted = await fetch(`${base}/api/settlement/queue`, {
        method: 'DELETE',
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(deleted.status).toBe(404);
      expect(calls).toHaveLength(1);
    });

    it('A PARAMETER CANNOT SPAN A SEPARATOR, and an empty one is not a parameter', async () => {
      await boot(() => ({ status: 200, body: '{}' }));
      // `%2F` survives `URL.pathname` percent-encoded, so it arrives as ONE
      // opaque segment and is forwarded still encoded — it never becomes a
      // separator, here or at the callee.
      await fetch(`${base}/api/settlement/cases/a%2Fb/timeline`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(calls[0]?.url).toBe('http://settlement:3007/v1/settlement/cases/a%2Fb/timeline');

      // `..` and `%2e%2e` are collapsed by the WHATWG parse BEFORE the table is
      // consulted, so neither can reach a parameter at all — measured here
      // rather than assumed, because the whole traversal argument rests on it.
      for (const smuggled of [
        '/api/settlement/cases/../../v1/auth/handoff',
        '/api/settlement/cases/%2e%2e/%2e%2e/v1/auth/handoff',
        // An empty parameter would otherwise forward `cases//timeline`.
        '/api/settlement/cases//timeline',
      ]) {
        const res = await fetch(`${base}${smuggled}`, {
          headers: { ...CSRF, cookie: cookieHeader('caller-token') },
        });
        expect({ smuggled, status: res.status }).toEqual({ smuggled, status: 404 });
      }
      expect(calls).toHaveLength(1);
    });

    it('DROPS THE QUERY STRING rather than forwarding it', async () => {
      // None of the sixteen routes takes one, so forwarding would only be a way
      // to smuggle a parameter into an internal service.
      await boot(() => ({ status: 200, body: '[]' }));
      await fetch(`${base}/api/settlement/queue?status=verified&limit=9999`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(calls[0]?.url).toBe('http://settlement:3007/v1/settlement/queue');
    });

    it('READS THE COOKIE AND ONLY THE COOKIE — a bearer header is not a credential here', async () => {
      // The vault origin accepts an `Authorization` header because the browser
      // EXTENSION cannot hold a cookie. There is no extension on this origin,
      // so a header-only request is unauthenticated and never reaches identity.
      await boot();
      const res = await fetch(`${base}/api/auth/session`, {
        headers: { ...CSRF, authorization: 'Bearer smuggled-token' },
      });
      expect(res.status).toBe(401);
      expect(calls).toHaveLength(0);
    });

    it('requires the custom header, which a cross-site request cannot set', async () => {
      await boot();
      const res = await fetch(`${base}/api/auth/session`, {
        headers: { cookie: cookieHeader('caller-token') },
      });
      expect(res.status).toBe(403);
      expect(calls).toHaveLength(0);
    });

    it('clears the cookie when identity actually revoked, and not before', async () => {
      await boot(() => ({ status: 204, body: '' }));
      const ok = await fetch(`${base}/api/auth/logout`, {
        method: 'POST',
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(ok.headers.get('set-cookie')).toContain(`${OPERATOR_SESSION_COOKIE}=;`);
      expect(ok.headers.get('set-cookie')).toContain('Max-Age=0');
      // The SAME attributes it was set with, or some browsers keep the cookie.
      expect(ok.headers.get('set-cookie')).toContain('Path=/; HttpOnly; SameSite=Lax; Secure');
      server.close();

      await boot(() => ({ status: 500, body: '{}' }));
      const failed = await fetch(`${base}/api/auth/logout`, {
        method: 'POST',
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      // A "signed out" browser over a live session is the worse outcome (M8
      // PR5), so a failed revocation clears nothing.
      expect(failed.headers.get('set-cookie')).toBeNull();
    });

    it('forwards an empty POST as NO body rather than as an empty JSON document', async () => {
      await boot(() => ({ status: 204, body: '' }));
      await fetch(`${base}/api/auth/logout`, {
        method: 'POST',
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(calls[0]?.body).toBeUndefined();
      expect(calls[0]?.headers['content-type']).toBeUndefined();
    });

    it('forwards a step-up code to identity as a JSON body, on the caller’s cookie', async () => {
      // The one route of the three that carries a payload. Proving a body
      // crosses matters because a step-up on this origin is what an operator
      // will have to pass before acting on a case in PR3b — a forwarded body
      // that arrived empty would be a refusal nobody could place.
      await boot(() => ({ status: 200, body: '{"ok":true}' }));
      const res = await fetch(`${base}/api/auth/stepup`, {
        method: 'POST',
        headers: {
          ...CSRF,
          cookie: cookieHeader('caller-token'),
          'content-type': 'application/json',
        },
        body: JSON.stringify({ code: '123456' }),
      });

      expect(res.status).toBe(200);
      expect(calls[0]?.url).toBe('http://identity:3001/v1/auth/stepup');
      expect(calls[0]?.method).toBe('POST');
      expect(calls[0]?.body).toBe(JSON.stringify({ code: '123456' }));
      expect(calls[0]?.headers['content-type']).toBe('application/json');
      expect(calls[0]?.headers['authorization']).toBe('Bearer caller-token');
    });

    it('does NOT forward the caller’s own headers, only the ones it constructs', async () => {
      // An allowlist by CONSTRUCTION rather than by filter: `proxy` builds its
      // header map from scratch, so there is no list to forget to prune. A
      // client cannot smuggle a header into an internal service through here.
      await boot(() => ({ status: 200, body: '{}' }));
      await fetch(`${base}/api/auth/session`, {
        headers: {
          ...CSRF,
          cookie: cookieHeader('caller-token'),
          'x-estate-user-id': 'somebody-else',
          'x-forwarded-for': '10.0.0.1',
          'if-match': '7',
        },
      });
      expect(Object.keys(calls[0]?.headers ?? {})).toEqual(['authorization']);
    });

    it('answers an unreachable identity as an outage, never as an empty answer', async () => {
      const fetchImpl: FetchLike = () => Promise.reject(new Error('ECONNREFUSED'));
      ({ server, base } = await start(fetchImpl));
      const res = await fetch(`${base}/api/auth/session`, {
        headers: { ...CSRF, cookie: cookieHeader('caller-token') },
      });
      expect(res.status).toBe(502);
      expect(await res.json()).toEqual({ error: 'upstream_unavailable' });
    });

    it('refuses a body larger than the cap', async () => {
      await boot();
      const res = await fetch(`${base}/api/auth/stepup`, {
        method: 'POST',
        headers: {
          ...CSRF,
          cookie: cookieHeader('caller-token'),
          'content-type': 'application/json',
        },
        body: JSON.stringify({ code: 'x'.repeat(300 * 1024) }),
      });
      expect(res.status).toBe(413);
      expect(calls).toHaveLength(0);
    });
  });

  describe('what every response carries', () => {
    it('applies the strict CSP and the isolation headers to everything', async () => {
      await boot();
      for (const path of ['/', '/api/nope', '/does-not-exist']) {
        const res = await fetch(`${base}${path}`);
        expect(res.headers.get('content-security-policy')).toBe(OPERATOR_CSP);
        expect(res.headers.get('x-frame-options')).toBe('DENY');
        expect(res.headers.get('referrer-policy')).toBe('no-referrer');
        expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin');
        expect(res.headers.get('cache-control')).toBe('no-store');
      }
    });

    it('has no unsafe-inline, no unsafe-eval and no Trusted-Types policy, in EVERY environment', () => {
      // The exact strings, because the VALUE is the security parameter: a CSP
      // containing `'unsafe-inline'` still contains `script-src 'self'`.
      expect(OPERATOR_CSP).toContain("script-src 'self'");
      expect(OPERATOR_CSP).not.toContain('unsafe-inline');
      expect(OPERATOR_CSP).not.toContain('unsafe-eval');
      expect(OPERATOR_CSP).toContain("require-trusted-types-for 'script'");
      expect(OPERATOR_CSP).toContain("trusted-types 'none'");
      expect(OPERATOR_CSP).toContain("connect-src 'self'");
    });

    it('answers no CORS header, so a hostile page cannot read anything it provokes', async () => {
      await boot();
      const res = await fetch(`${base}/api/auth/session`, {
        headers: { ...CSRF, origin: 'http://evil.example', cookie: cookieHeader('t') },
      });
      expect(res.headers.get('access-control-allow-origin')).toBeNull();
      expect(res.headers.get('access-control-allow-credentials')).toBeNull();
    });
  });

  describe('the static client', () => {
    it('serves the shell and the generated origin module, and nothing else', async () => {
      await boot();
      const shell = await fetch(`${base}/`);
      expect(shell.status).toBe(200);
      expect(shell.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(await shell.text()).toContain('Operator · TB7');

      const config = await fetch(`${base}/app/config.js`);
      expect(config.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
      // A JS STRING LITERAL produced by JSON.stringify over a zod-validated
      // URL — no markup, no parser, nothing for `script-src 'self'` to exempt.
      expect(await config.text()).toBe(`window.ESTATE_APP_ORIGIN = "${APP_ORIGIN}";\n`);
    });

    /**
     * NO REQUEST LINE READS A FILE OUTSIDE `public/`.
     *
     * Two properties of this test are the M15 PR1 corrections rather than
     * style, and both are the M13 lesson about a test named for a property it
     * never touched.
     *
     * FIRST, it uses a RAW SOCKET. `fetch` NORMALISES `/../../x` to `/x` before
     * it ever reaches the server — measured on the vault origin, where the
     * request line the server saw was `/package.json` — so a 404 came from the
     * extension allowlist and no traversal was ever attempted. An attacker does
     * not use `fetch`.
     *
     * SECOND, it asserts the PROPERTY, not a particular guard. Deleting the
     * `startsWith(publicDir)` check leaves this green, because the WHATWG `URL`
     * parse upstream of it collapses `..` (and decodes `%2e%2e` to `..` first).
     * That check is unreachable and is documented as such in `server.ts`;
     * claiming here that it is what stops traversal would be false.
     *
     * The targets are a `.css` file in ANOTHER app, so the extension allowlist
     * cannot mask a real escape: a regression serves `apps/web`'s stylesheet
     * from this origin, and the assertion looks for its actual contents.
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
          socket.write(`GET ${rawPath} HTTP/1.1\r\nHost: operator\r\nConnection: close\r\n\r\n`);
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
      expect(response).not.toContain('--color-rail-active');
    });

    it('serves only the four allowlisted extensions', async () => {
      await boot();
      for (const path of ['/package.json', '/tsconfig.json', '/app/main.js.map']) {
        const res = await fetch(`${base}${path}`);
        expect({ path, status: res.status }).toEqual({ path, status: 404 });
      }
    });

    it('answers a non-GET on an unknown path with a 404, never a method error', async () => {
      await boot();
      const res = await fetch(`${base}/whatever`, { method: 'PUT' });
      expect(res.status).toBe(404);
    });
  });
});
