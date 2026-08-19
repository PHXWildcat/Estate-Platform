/**
 * Everything this edge says to another service.
 *
 * There are exactly TWO shapes, and the difference between them is the whole
 * trust story of this origin:
 *
 *   · `redeemHandoff` — the ONE call made with no user credential, because the
 *     code IS the credential. It happens once, server-side, on arrival.
 *   · `proxy` — every other call, made by FORWARDING THE CALLER'S OWN BEARER.
 *     This edge holds no service credential (see `config.ts`), so it cannot
 *     reach anything the calling operator could not reach themselves. A
 *     compromised operator edge replays the sessions it is currently serving;
 *     it cannot mint one.
 *
 * WHAT IS NOT HERE is the vault edge's third shape. `Upstream.passThrough`
 * exists there to carry two identity routes that are UNAUTHENTICATED BY
 * CONSTRUCTION — extension pairing redemption, and token refresh. Neither has a
 * counterpart here: there is no extension on this origin, and an operator
 * session HAS NO REFRESH TOKEN AT ALL. That is a property of the handoff
 * ceremony rather than a policy this edge enforces — `redeem` writes the digest
 * of a value generated and discarded in the same expression, so no refresh
 * token for that session exists anywhere to be presented. A `/api/auth/refresh`
 * route here would forward a credential the caller cannot have.
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
   * Spend a handoff code for the session it was minted for.
   *
   * THE AUDIENCE IS NOT AN ARGUMENT, here or at identity: it travels on the
   * `auth_handoffs` row, written by whichever mint route was called, and
   * `redeem` has no way to re-choose it. So this edge cannot ask for an
   * operator session — it can only spend a code that already is one.
   *
   * WHICH MEANS THIS EDGE DOES NOT CHECK THE AUDIENCE IT RECEIVED, and that is
   * a decision rather than an omission. Posting a VAULT code here would set an
   * operator-origin cookie holding a vault session; posting an OPERATOR code at
   * the vault origin would do the mirror image. Neither buys anything, because
   * an audience is a RESTRICTION and the callee is what enforces it: the vault
   * service refuses an operator session, settlement will refuse a vault one,
   * and identity's three routes admit both by design. Re-deciding it here would
   * be a second copy of the audience table, free to drift from the one that
   * actually decides — which is the mistake the vault edge's `credentialFrom`
   * comment already refuses to make. The client SHOWS the audience it is
   * holding, so a misdirected code is visible rather than silently wrong.
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
    // session cookie carrying `undefined` (the M11 browser-only lesson — a
    // response missing its fields is NO DATA, never data).
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
   * The response body is passed through VERBATIM and unparsed. This edge takes
   * no view of what an upstream said: it holds no credential, so it adds no
   * authority, and parsing would only create a second place for an answer about
   * somebody's death case to be reshaped.
   */
  async proxy(input: {
    baseUrl: string;
    path: string;
    method: string;
    bearer: string;
    body?: string | undefined;
  }): Promise<ProxyResult> {
    const base = input.baseUrl.replace(/\/$/, '');
    const headers: Record<string, string> = {
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
      // 502 rather than a fabricated answer: an unreachable upstream must never
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
}
