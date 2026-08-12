import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import type { VaultWebConfig } from './config';
import {
  CSRF_HEADER,
  bearerFrom,
  clearSessionCookie,
  sessionTokenFrom,
  setSessionCookie,
} from './cookies';
import { SECURITY_HEADERS } from './security-headers';
import { Upstream } from './upstream';

/** Bodies are small by construction: a handoff code, or an opaque blob. */
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
 * service and the exact route prefix; anything unmatched is a 404 that never
 * leaves the process.
 */
const PROXY_ROUTES: ReadonlyArray<{
  readonly prefix: string;
  readonly upstream: 'vault' | 'identity' | 'profile';
  readonly rewriteTo: string;
  /**
   * Whether a path SUFFIX may follow. True only where the upstream route is
   * genuinely a tree — the vault's `/items/:id`. Every identity route is an
   * exact match, and that distinction is load-bearing rather than tidy: a
   * `startsWith('/api/auth/logout')` rule also matches `/api/auth/logout/refresh`,
   * which is identity's UNAUTHENTICATED refresh-token revocation route, and
   * nothing on this origin has any business reaching it.
   */
  readonly tree: boolean;
}> = [
  // The vault service's owner-facing surface. Opaque in both directions.
  { prefix: '/api/vault/', upstream: 'vault', rewriteTo: '/v1/vault/', tree: true },
  // Identity, and ONLY the three routes a vault session is admitted to
  // (`session-audience.decorator.ts`). Enumerated rather than prefixed:
  // `/v1/auth/` would include `handoff`, and this edge must not be able to help
  // a vault session mint another one.
  { prefix: '/api/auth/session', upstream: 'identity', rewriteTo: '/v1/auth/session', tree: false },
  { prefix: '/api/auth/stepup', upstream: 'identity', rewriteTo: '/v1/auth/stepup', tree: false },
  { prefix: '/api/auth/logout', upstream: 'identity', rewriteTo: '/v1/auth/logout', tree: false },
];

/**
 * THE TWO ROUTES THAT CARRY NO CREDENTIAL (M16 PR2a).
 *
 * The extension's single front door is this origin — one `host_permission`, one
 * origin — and two of the things it must do have no bearer to forward, by the
 * design of the routes themselves:
 *
 *   · redeeming a pairing code, which is unauthenticated BECAUSE the code is
 *     the authority and there is no field in the request that could name an
 *     account (the §6g anti-enumeration shape), and
 *   · refreshing, whose authority is the refresh token in the body.
 *
 * A SEPARATE TABLE rather than entries in `PROXY_ROUTES`, because that table's
 * handler requires a credential and admitting these would mean weakening the
 * requirement for every route in it. These reach `Upstream.passThrough`, which
 * has no bearer parameter to pass.
 *
 * EXACT paths, no suffix, no tree — the `logout`/`logout/refresh` lesson.
 * Identity's `POST /v1/auth/logout/refresh` remains unreachable from here, and
 * `/v1/auth/refresh` being reachable is not a route to it: they are different
 * routes with different bodies and different effects.
 */
const PASS_THROUGH_ROUTES: ReadonlyArray<{
  readonly path: string;
  readonly upstreamPath: string;
}> = [
  { path: '/api/auth/extension/pairing/redeem', upstreamPath: '/v1/auth/extension/pairing/redeem' },
  { path: '/api/auth/refresh', upstreamPath: '/v1/auth/refresh' },
];

/**
 * WHICH CREDENTIAL A PROXIED REQUEST TRAVELS ON, and in which order.
 *
 * `Authorization: Bearer` WINS when present; the cookie is read only in its
 * absence. One rule, no fallback chain, no merging — a request carrying both
 * uses the header and never looks at the cookie, which `test/server.spec.ts`
 * pins. The alternative (cookie first, bearer as fallback) would mean a
 * paired extension's request could silently travel on a browser session that
 * happened to be present, and "which credential did that actually use" is not
 * a question this edge should ever be ambiguous about.
 *
 * Both are the CALLER'S OWN token. Neither is a service credential, this edge
 * still holds none, and it still cannot reach anything the caller could not.
 *
 * WHAT THIS DOES NOT DO: it does not re-implement the audience table. Which
 * routes an `extension` session may reach is decided by the services
 * (`AUDIENCE_ROUTE_ADMITTERS` and the per-handler decorators), was measured
 * end to end in PR1, and a second copy here is a second copy that drifts. This
 * edge forwards; the callee decides.
 */
function credentialFrom(req: IncomingMessage): string | null {
  // THE PRESENCE OF THE HEADER DECIDES, not its parseability (M16 review).
  //
  // `bearerFrom` is deliberately strict (`/^Bearer (\S+)$/i`), so `Basic …`, a
  // bare `Bearer`, or `Bearer  two-spaces` all yield null — and the `??` then
  // fell through to the cookie. A request that WAS carrying an Authorization
  // header therefore travelled on a browser session instead, which is exactly
  // the ambiguity the paragraph above says this edge must never have. Both are
  // the caller's own credential so nothing is escalated, but "never looks at
  // the cookie" was true only of a well-formed header, and a rule that holds
  // only for correct input is not the rule that was written down.
  if (req.headers['authorization'] !== undefined) {
    return bearerFrom(req.headers['authorization']);
  }
  return sessionTokenFrom(req.headers['cookie']);
}

/**
 * THE ONE ZONE B READ ON THIS ORIGIN (M15 PR3).
 *
 * Emergency access needs the owner to choose grantees and confirm each one's
 * key fingerprint out of band — which is impossible without knowing WHO they
 * are choosing. So contact NAMES cross onto the vault origin, and nothing else
 * does.
 *
 * TWO INDEPENDENT NARROWINGS, and the first is the one that matters. Profile
 * serves this edge a DEDICATED route (`/v1/contacts/grantee-candidates`) whose
 * whole response is three fields, and that route is the only one in the service
 * a `vault`-audience session may reach at all. Found by driving the stack: the
 * obvious version of this — read `/v1/contacts` and project here — could never
 * have worked, because profile refuses a vault session, and the shortcut that
 * would have made it work is widening profile SERVICE-WIDE, which hands a
 * leaked handoff the owner's PII, every contact's decrypted detail, the family
 * tree and the role assignments.
 *
 * The projection below is then the SECOND narrowing, kept even though the
 * upstream is already minimal: it is the only upstream response this edge
 * parses, and a future widening of profile's shape must not reach Zone A
 * because nobody remembered this edge exists. Belt and braces, cheap, and with
 * its own test.
 *
 * Filtered to LINKED contacts for the same reason profile filters them: an
 * unlinked contact has no platform account, so it cannot hold a recovery
 * keypair and cannot be a grantee.
 */
const GRANTEE_CANDIDATES_PATH = '/api/grantee-candidates';

interface ProfileGranteeCandidate {
  contactId?: unknown;
  userId?: unknown;
  name?: unknown;
}

export interface GranteeCandidate {
  readonly contactId: string;
  readonly userId: string;
  readonly name: string;
}

/** Keep exactly three fields, whatever else the upstream sends. For its test. */
export function projectGranteeCandidates(payload: unknown): GranteeCandidate[] {
  if (!Array.isArray(payload)) {
    return [];
  }
  const out: GranteeCandidate[] = [];
  for (const row of payload as ProfileGranteeCandidate[]) {
    const { contactId, userId, name } = row ?? {};
    if (typeof contactId !== 'string' || typeof userId !== 'string' || typeof name !== 'string') {
      // A row missing what a grantee needs is dropped rather than passed
      // through half-formed — the client would otherwise render a row it
      // cannot seal a share to.
      continue;
    }
    out.push({ contactId, userId, name });
  }
  return out;
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

export interface VaultWebServerOptions {
  readonly config: VaultWebConfig;
  readonly upstream: Upstream;
  /** Root of the served client bundle; defaults to this package's `public`. */
  readonly publicDir?: string;
}

/**
 * THE VAULT ORIGIN'S EDGE.
 *
 * Small on purpose. Everything it does is one of four things:
 *
 *   1. serve a static, framework-free client under a strict CSP,
 *   2. redeem the arrival handoff once and set a `__Host-` cookie,
 *   3. forward the caller's own bearer to an allowlisted upstream, and
 *   4. clear the cookie on sign-out.
 *
 * It parses no vault payload, holds no service credential, and decrypts
 * nothing — it structurally cannot, because Zone A's keys never leave the
 * browser.
 */
export function createVaultWebServer(options: VaultWebServerOptions): Server {
  const { config, upstream } = options;
  const publicDir = options.publicDir ?? join(__dirname, '..', 'public');
  const upstreamUrl = {
    vault: config.vaultUrl,
    identity: config.identityUrl,
    profile: config.profileUrl,
  } as const;

  async function serveStatic(res: ServerResponse, pathname: string): Promise<void> {
    const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
    /*
     * Path traversal. A file served from here is JavaScript that runs on the
     * Zone A origin, so this is worth being precise about — including about
     * which line is actually doing the work.
     *
     * WHAT ACTUALLY CLOSES IT is the WHATWG `URL` parse in the request handler
     * above: it collapses `..` segments, and it decodes `%2e%2e` to `..` FIRST
     * and then collapses those too, so `pathname` can never contain an
     * ascending segment by the time it arrives here. `..%2f` survives the
     * parse, but `%2f` is not a separator on disk — it is one literal
     * directory name that does not exist.
     *
     * MEASURED, not reasoned about: deleting the check below leaves every
     * traversal test green, because the check is UNREACHABLE. It stays anyway,
     * as defence in depth against a future refactor that stops routing through
     * `new URL` — but it is recorded as unreachable rather than credited as the
     * control, because a guard nobody can trigger is a guard nobody has tested.
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
   * The `Origin` header is checked against the configured app origin. It is
   * NOT the authorization — the code is — but it costs nothing and means an
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
    search: string,
  ): Promise<void> {
    const route = PROXY_ROUTES.find((r) =>
      r.tree ? pathname.startsWith(r.prefix) : pathname === r.prefix,
    );
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
    // Only headers the vault protocol actually needs. An allowlist, so a
    // client cannot smuggle an arbitrary header into an internal service.
    const forwarded: Record<string, string> = {};
    for (const name of ['if-match', 'x-estate-vault-session']) {
      const value = req.headers[name];
      if (typeof value === 'string') forwarded[name] = value;
    }
    const suffix = pathname.slice(route.prefix.length);
    const result = await upstream.proxy({
      baseUrl: upstreamUrl[route.upstream],
      // The query string travels too: the vault's item list is paginated by
      // `?limit=&cursor=`, and dropping it silently changes the request.
      path: `${route.rewriteTo}${suffix}${search}`,
      method: req.method ?? 'GET',
      bearer,
      body,
      headers: forwarded,
    });
    // Signing out upstream must also clear the cookie here, or the browser
    // keeps presenting a revoked token and the UI says "signed in". Only when
    // the request actually CARRIED one: the extension logs out on a bearer and
    // has no cookie to clear, and answering it with a Set-Cookie would be a
    // header about a credential it does not have.
    if (
      pathname === '/api/auth/logout' &&
      result.status >= 200 &&
      result.status < 300 &&
      sessionTokenFrom(req.headers['cookie']) !== null
    ) {
      clearSessionCookie(res);
    }
    send(res, result.status, result.body, result.contentType);
  }

  /**
   * The extension's two credential-free identity calls (see PASS_THROUGH_ROUTES).
   *
   * THE CSRF HEADER IS STILL REQUIRED, and the comment matters more than the
   * check: for these two routes it is NOT the control, because neither carries
   * an ambient credential and therefore neither is CSRF-able in the first
   * place. It stays because every other `/api/` route has it, one rule is
   * easier to keep than two, and it costs the extension nothing — extension
   * contexts bypass CORS for hosts in `host_permissions`, so no preflight is
   * involved and this edge still answers none.
   */
  async function handlePassThrough(
    req: IncomingMessage,
    res: ServerResponse,
    upstreamPath: string,
  ): Promise<void> {
    if (req.headers[CSRF_HEADER] !== '1') {
      sendJson(res, 403, { error: 'forbidden' });
      return;
    }
    const body = await readBody(req);
    if (body === null) {
      sendJson(res, 413, { error: 'payload_too_large' });
      return;
    }
    const result = await upstream.passThrough({
      baseUrl: upstreamUrl.identity,
      path: upstreamPath,
      body: body.length === 0 ? undefined : body,
    });
    send(res, result.status, result.body, result.contentType);
  }

  /**
   * Profile's contact summary, narrowed to what a grantee picker needs.
   *
   * COOKIE ONLY, deliberately — this is the one route on the edge that does NOT
   * accept a bearer. The Zone B read on this origin belongs to the interactive
   * vault session that a person is sitting in front of choosing grantees, not to
   * a credential stored on a device. Defence in depth rather than the control:
   * profile admits only the `vault` audience on that route, so an extension
   * session would be refused upstream anyway — but the edge should not be the
   * thing that has to be asked.
   */
  async function handleGranteeCandidates(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.headers[CSRF_HEADER] !== '1') {
      sendJson(res, 403, { error: 'forbidden' });
      return;
    }
    const bearer = sessionTokenFrom(req.headers['cookie']);
    if (!bearer) {
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }
    const result = await upstream.proxy({
      baseUrl: upstreamUrl.profile,
      path: '/v1/contacts/grantee-candidates',
      method: 'GET',
      bearer,
    });
    if (result.status !== 200) {
      // Passed through as a status, never as profile's body: the client needs
      // to distinguish "no contacts" from "could not ask", and nothing profile
      // says about the failure belongs on this origin.
      sendJson(res, result.status === 401 ? 401 : 502, { error: 'contacts_unavailable' });
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(result.body);
    } catch {
      sendJson(res, 502, { error: 'contacts_unavailable' });
      return;
    }
    sendJson(res, 200, { candidates: projectGranteeCandidates(parsed) });
  }

  return createServer((req, res) => {
    void (async (): Promise<void> => {
      applySecurityHeaders(res);
      const url = new URL(req.url ?? '/', `http://${req.headers['host'] ?? 'vault'}`);
      const { pathname } = url;

      if (req.method === 'POST' && pathname === '/open') {
        await handleOpen(req, res);
        return;
      }
      if (req.method === 'GET' && pathname === GRANTEE_CANDIDATES_PATH) {
        await handleGranteeCandidates(req, res);
        return;
      }
      // BEFORE the `/api/` proxy, because that handler requires a credential
      // and these two routes have none to require.
      const passThrough =
        req.method === 'POST' ? PASS_THROUGH_ROUTES.find((r) => r.path === pathname) : undefined;
      if (passThrough) {
        await handlePassThrough(req, res, passThrough.upstreamPath);
        return;
      }
      if (pathname.startsWith('/api/')) {
        await handleProxy(req, res, pathname, url.search);
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
      // Nothing internal reaches the client: no message, no stack. The vault
      // origin's error surface is one token.
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'internal_error' });
      } else {
        res.end();
      }
    });
  });
}
