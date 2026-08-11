/**
 * Everything this edge says to another service.
 *
 * There are exactly three shapes, and the difference between them is the whole
 * trust story of this origin:
 *
 *   · `redeemHandoff` — the ONE call made with no user credential, because the
 *     code IS the credential. It happens once, server-side, on arrival.
 *   · `proxy` — every other call, made by FORWARDING THE CALLER'S OWN BEARER.
 *     This edge holds no service credential (see `config.ts`), so it cannot
 *     reach anything the calling user could not reach themselves. A compromised
 *     vault edge replays the sessions it is currently serving; it cannot mint
 *     one.
 *   · `passThrough` — the extension's two unauthenticated identity routes
 *     (M16 PR2a). It TAKES NO BEARER PARAMETER AT ALL, which is the point: an
 *     optional credential on `proxy` would be a fail-open shape, where the next
 *     caller forgets the argument and the request silently goes out anonymous.
 *     Here anonymity is the contract, so it is expressed in the type.
 */

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
  },
) => Promise<{
  status: number;
  text(): Promise<string>;
  headers: { get(n: string): string | null };
}>;

export interface RedeemedSession {
  readonly accessToken: string;
  readonly userId: string;
}

export interface UpstreamOptions {
  readonly identityUrl: string;
  readonly fetchImpl?: FetchLike;
}

/** What a proxied call returns: status and body, passed through verbatim. */
export interface ProxyResult {
  readonly status: number;
  readonly body: string;
  readonly contentType: string;
}

export class Upstream {
  private readonly identityUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: UpstreamOptions) {
    this.identityUrl = options.identityUrl.replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /**
   * Spend a handoff code for a vault-audience session.
   *
   * Returns null for EVERY failure — unknown code, expired, already spent, lost
   * a race, identity unreachable. The caller has one thing to say to the user
   * and one thing to record, which is what keeps the arrival page from becoming
   * an oracle for whether a guessed code named something real.
   */
  async redeemHandoff(code: string): Promise<RedeemedSession | null> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.identityUrl}/v1/auth/handoff/redeem`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code }),
      });
    } catch {
      return null; // network/DNS ⇒ fail closed, same as a refusal
    }
    if (response.status !== 200) {
      return null;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(await response.text());
    } catch {
      return null;
    }
    // Shape-checked rather than trusted: a malformed body must not produce a
    // session cookie carrying `undefined` (the M11 browser-only lesson —
    // a response missing its fields is NO DATA, never data).
    if (typeof parsed !== 'object' || parsed === null) {
      return null;
    }
    const { accessToken, userId } = parsed as Record<string, unknown>;
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      return null;
    }
    if (typeof userId !== 'string' || userId.length === 0) {
      return null;
    }
    return { accessToken, userId };
  }

  /**
   * Forward one request upstream on the caller's own bearer.
   *
   * The response body is passed through VERBATIM and unparsed. That is the
   * point of this edge existing at all: the vault service's payloads are opaque
   * ciphertext, and code that does not parse them is code that cannot leak
   * their plaintext — there is none to leak here, and there never will be,
   * because the keys live in the browser.
   */
  async proxy(input: {
    baseUrl: string;
    path: string;
    method: string;
    bearer: string;
    body?: string | undefined;
    /** Forwarded verbatim; the vault session token and If-Match live here. */
    headers?: Record<string, string>;
  }): Promise<ProxyResult> {
    const base = input.baseUrl.replace(/\/$/, '');
    const headers: Record<string, string> = {
      ...input.headers,
      authorization: `Bearer ${input.bearer}`,
    };
    if (input.body !== undefined) {
      headers['content-type'] = 'application/json';
    }
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${base}${input.path}`, {
        method: input.method,
        headers,
        ...(input.body === undefined ? {} : { body: input.body }),
      });
    } catch {
      // 502 rather than a fabricated answer: an unreachable vault must never
      // look like an empty one.
      return {
        status: 502,
        body: JSON.stringify({ error: 'upstream_unavailable' }),
        contentType: 'application/json',
      };
    }
    return {
      status: response.status,
      body: await response.text(),
      contentType: response.headers.get('content-type') ?? 'application/json',
    };
  }

  /**
   * Forward one request to an upstream route that is UNAUTHENTICATED BY
   * CONSTRUCTION (M16 PR2a): extension pairing redemption, and token refresh.
   *
   * Both are identity routes with no bearer to forward — the pairing code is
   * the authority for one and the refresh token in the body is the authority
   * for the other. Neither is reachable through `PROXY_ROUTES`, which requires
   * a credential and would have to be weakened to carry them.
   *
   * NO BEARER PARAMETER EXISTS on this method. That is deliberate and is the
   * only reason it is a separate method rather than `proxy` with an optional
   * argument: a credential you can forget to pass is a credential that gets
   * forgotten, and the direction that fails there is silent.
   *
   * The response is passed back VERBATIM, exactly as `proxy` does. It carries
   * the tokens the extension needs, and identity's own uniform refusals — this
   * edge distinguishes nothing that identity chose not to.
   */
  async passThrough(input: {
    baseUrl: string;
    path: string;
    body: string | undefined;
  }): Promise<ProxyResult> {
    const base = input.baseUrl.replace(/\/$/, '');
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${base}${input.path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: input.body ?? '{}',
      });
    } catch {
      return {
        status: 502,
        body: JSON.stringify({ error: 'upstream_unavailable' }),
        contentType: 'application/json',
      };
    }
    return {
      status: response.status,
      body: await response.text(),
      contentType: response.headers.get('content-type') ?? 'application/json',
    };
  }
}
