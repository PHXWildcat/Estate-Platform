import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import type { OperatorWebConfig } from './config';
import { CSRF_HEADER, clearSessionCookie, sessionTokenFrom, setSessionCookie } from './cookies';
import { SECURITY_HEADERS } from './security-headers';
import { Upstream } from './upstream';

/** Bodies are small by construction: a handoff code, or a short JSON document. */
const MAX_BODY_BYTES = 256 * 1024;

const MIME_BY_EXTENSION: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

/**
 * Which upstream a proxied path may reach, and NOTHING ELSE.
 *
 * An allowlist rather than a prefix rewrite, because a proxy that forwards
 * whatever path it is given is an SSRF primitive pointed at the internal
 * network — and this one carries a live bearer token. Each entry names the
 * service and the exact route; anything unmatched is a 404 that never leaves
 * the process.
 *
 * TODAY THAT IS IDENTITY'S THREE ROUTES AND NOTHING ELSE — the three an
 * `operator`-audience session is admitted to at all
 * (`AUDIENCE_ROUTE_ADMITTERS.operator`). Settlement's operator surface joins
 * this table in M21 PR3b, in the same change as the screens that call it: an
 * upstream reachable before anything reaches it is the zero-callers shape this
 * milestone exists to close, and an allowlist entry is a capability like any
 * other.
 *
 * EXACT MATCHES, no tree, and that distinction is load-bearing rather than
 * tidy: a `startsWith('/api/auth/logout')` rule also matches
 * `/api/auth/logout/refresh`, which is identity's UNAUTHENTICATED
 * refresh-token revocation route, and nothing on this origin has any business
 * reaching it. `/v1/auth/` as a prefix would be worse still — it contains
 * `handoff`, and this edge must not be able to help an operator session mint
 * another credential.
 */
const PROXY_ROUTES: ReadonlyArray<{
  readonly path: string;
  readonly upstream: 'identity';
  readonly rewriteTo: string;
}> = [
  { path: '/api/auth/session', upstream: 'identity', rewriteTo: '/v1/auth/session' },
  { path: '/api/auth/stepup', upstream: 'identity', rewriteTo: '/v1/auth/stepup' },
  { path: '/api/auth/logout', upstream: 'identity', rewriteTo: '/v1/auth/logout' },
];

/**
 * WHICH CREDENTIAL A PROXIED REQUEST TRAVELS ON: the cookie, and only the
 * cookie.
 *
 * The vault edge reads an `Authorization: Bearer` header in preference to its
 * cookie, and that exists for exactly one caller — the browser EXTENSION, which
 * lives on `chrome-extension://…` and can never receive a cookie this origin
 * sets. There is no extension here and there is not going to be one: an
 * operator console is a screen a person sits in front of, and a stored
 * credential that reaches docs/03 §5.1's review surface is the opposite of what
 * TB7 wants.
 *
 * So this edge reads one credential from one place. An `Authorization` header
 * is not preferred, not merged, and not consulted — a request carrying one and
 * no cookie is unauthenticated here, which `test/server.spec.ts` pins. Adding
 * the bearer path later would be adding a way to drive this origin from
 * something other than a browser, which is a design decision and not a
 * convenience.
 *
 * WHAT THIS DOES NOT DO: it does not re-implement the audience table. Which
 * routes an `operator` session may reach is decided by the services
 * (`AUDIENCE_ROUTE_ADMITTERS` and the per-handler decorators). This edge
 * forwards; the callee decides.
 */
function credentialFrom(req: IncomingMessage): string | null {
  return sessionTokenFrom(req.headers['cookie']);
}

function applySecurityHeaders(res: ServerResponse): void {
  for (const [name, value] of SECURITY_HEADERS) {
    res.setHeader(name, value);
  }
}

function send(res: ServerResponse, status: number, body: string, contentType: string): void {
  res.statusCode = status;
  res.setHeader('content-type', contentType);
  res.end(body);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  send(res, status, JSON.stringify(payload), 'application/json');
}

async function readBody(req: IncomingMessage): Promise<string | null> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.byteLength;
    if (size > MAX_BODY_BYTES) {
      return null;
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** `code=…` out of an application/x-www-form-urlencoded body. */
function formField(body: string, field: string): string | null {
  for (const pair of body.split('&')) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    if (decodeURIComponent(pair.slice(0, eq).replace(/\+/g, ' ')) !== field) continue;
    return decodeURIComponent(pair.slice(eq + 1).replace(/\+/g, ' '));
  }
  return null;
}

export interface OperatorWebServerOptions {
  readonly config: OperatorWebConfig;
  readonly upstream: Upstream;
  /** Root of the served client bundle; defaults to this package's `public`. */
  readonly publicDir?: string;
}

/**
 * THE OPERATOR ORIGIN'S EDGE.
 *
 * Small on purpose. Everything it does is one of four things:
 *
 *   1. serve a static, framework-free client under a strict CSP,
 *   2. redeem the arrival handoff once and set a `__Host-` cookie,
 *   3. forward the caller's own bearer to an allowlisted upstream, and
 *   4. clear the cookie on sign-out.
 *
 * It holds no service credential and takes no authorization decision. In
 * particular it does not decide who is an OPERATOR: that is
 * `settlement_operators`, read by settlement's own `OperatorGate` inside the
 * transaction it guards (M21 PR2). An operator-audience session is a
 * RESTRICTION on where a credential may be spent, never a claim about who is
 * holding it — so arriving here proves nothing and is meant to prove nothing.
 */
export function createOperatorWebServer(options: OperatorWebServerOptions): Server {
  const { config, upstream } = options;
  const publicDir = options.publicDir ?? join(__dirname, '..', 'public');
  const upstreamUrl = {
    identity: config.identityUrl,
  } as const;

  async function serveStatic(res: ServerResponse, pathname: string): Promise<void> {
    const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
    /*
     * Path traversal, and the vault origin's measurement of the same code
     * applies here unchanged — including which line is actually doing the work.
     *
     * WHAT ACTUALLY CLOSES IT is the WHATWG `URL` parse in the request handler
     * below: it collapses `..` segments, and it decodes `%2e%2e` to `..` FIRST
     * and then collapses those too, so `pathname` can never contain an
     * ascending segment by the time it arrives here. `..%2f` survives the
     * parse, but `%2f` is not a separator on disk — it is one literal directory
     * name that does not exist.
     *
     * The check below is therefore UNREACHABLE, which was measured on the vault
     * origin rather than reasoned about (deleting it left every traversal test
     * green). It stays as defence in depth against a future refactor that stops
     * routing through `new URL` — but it is recorded as unreachable rather than
     * credited as the control, because a guard nobody can trigger is a guard
     * nobody has tested.
     */
    const resolved = join(publicDir, normalize(relative));
    if (!resolved.startsWith(publicDir + sep)) {
      sendJson(res, 404, { error: 'not_found' });
      return;
    }
    const mime = MIME_BY_EXTENSION[extname(resolved)];
    if (!mime) {
      // An allowlist of extensions, so a stray file in `public/` cannot be
      // served as something the browser will interpret unpredictably.
      sendJson(res, 404, { error: 'not_found' });
      return;
    }
    try {
      send(res, 200, await readFile(resolved, 'utf8'), mime);
    } catch {
      sendJson(res, 404, { error: 'not_found' });
    }
  }

  /**
   * The arrival ceremony: a cross-site TOP-LEVEL FORM POST from the app origin
   * carrying a single-use code.
   *
   * A form POST rather than a redirect with the code in the URL, and that
   * choice is the reason the code never lands in browser history, in a
   * `Referer`, or in an intermediary's access log — the same reasoning that
   * moved M12's document search off the query string.
   *
   * The `Origin` header is checked against the configured app origin. It is NOT
   * the authorization — the code is — but it costs nothing and means an
   * arbitrary page cannot drive this endpoint even while holding a code.
   */
  async function handleOpen(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const origin = req.headers['origin'];
    if (typeof origin !== 'string' || origin !== config.appOrigin) {
      sendJson(res, 403, { error: 'forbidden' });
      return;
    }
    const body = await readBody(req);
    const code = body === null ? null : formField(body, 'code');
    if (!code) {
      // Same answer as a bad code: this endpoint distinguishes nothing.
      res.statusCode = 303;
      res.setHeader('location', '/?open=refused');
      res.end();
      return;
    }
    const redeemed = await upstream.redeemHandoff(code);
    if (!redeemed) {
      res.statusCode = 303;
      res.setHeader('location', '/?open=refused');
      res.end();
      return;
    }
    setSessionCookie(res, redeemed.accessToken);
    // 303 so the browser follows with a GET: the code is spent, and a reload of
    // the landing URL must not repost it.
    res.statusCode = 303;
    res.setHeader('location', '/');
    res.end();
  }

  async function handleProxy(
    req: IncomingMessage,
    res: ServerResponse,
    pathname: string,
  ): Promise<void> {
    const route = PROXY_ROUTES.find((r) => r.path === pathname);
    if (!route) {
      sendJson(res, 404, { error: 'not_found' });
      return;
    }
    if (req.headers[CSRF_HEADER] !== '1') {
      // Every client call carries it; a cross-site request cannot set it
      // without a preflight this edge never answers.
      sendJson(res, 403, { error: 'forbidden' });
      return;
    }
    const bearer = credentialFrom(req);
    if (!bearer) {
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const raw = req.method === 'GET' || req.method === 'DELETE' ? undefined : await readBody(req);
    if (raw === null) {
      sendJson(res, 413, { error: 'payload_too_large' });
      return;
    }
    // An empty POST (identity's logout takes none) must forward as NO body, not
    // as an empty JSON document — a zero-length body with `content-type:
    // application/json` is a parse error at the callee.
    const body = raw === undefined || raw.length === 0 ? undefined : raw;
    const result = await upstream.proxy({
      baseUrl: upstreamUrl[route.upstream],
      path: route.rewriteTo,
      method: req.method ?? 'GET',
      bearer,
      body,
    });
    // Signing out upstream must also clear the cookie here, or the browser
    // keeps presenting a revoked token and the UI says "signed in" — the M8 PR5
    // logout lesson, whose worst outcome is the other order: a cleared cookie
    // over a session that is still live.
    if (pathname === '/api/auth/logout' && result.status >= 200 && result.status < 300) {
      clearSessionCookie(res);
    }
    send(res, result.status, result.body, result.contentType);
  }

  return createServer((req, res) => {
    void (async (): Promise<void> => {
      applySecurityHeaders(res);
      const url = new URL(req.url ?? '/', `http://${req.headers['host'] ?? 'operator'}`);
      const { pathname } = url;

      if (req.method === 'POST' && pathname === '/open') {
        await handleOpen(req, res);
        return;
      }
      if (pathname.startsWith('/api/')) {
        await handleProxy(req, res, pathname);
        return;
      }
      /**
       * The one piece of generated JavaScript on this origin, and the reason it
       * is generated rather than templated into the shell: the app origin is
       * configuration, and building HTML from a string is precisely what this
       * app has organised itself never to do. `JSON.stringify` of a value zod
       * already validated as a URL produces a JS string literal — no markup, no
       * parser, and nothing for `script-src 'self'` to exempt.
       */
      if (req.method === 'GET' && pathname === '/app/config.js') {
        send(
          res,
          200,
          `window.ESTATE_APP_ORIGIN = ${JSON.stringify(config.appOrigin)};\n`,
          'text/javascript; charset=utf-8',
        );
        return;
      }
      if (req.method === 'GET') {
        await serveStatic(res, pathname);
        return;
      }
      sendJson(res, 404, { error: 'not_found' });
    })().catch(() => {
      // Nothing internal reaches the client: no message, no stack. This
      // origin's error surface is one token.
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'internal_error' });
      } else {
        res.end();
      }
    });
  });
}
