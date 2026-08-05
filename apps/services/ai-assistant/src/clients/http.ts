import type { z } from 'zod';

/**
 * The one transport the assistant's peer-read clients share.
 *
 * Minimal fetch shape so tests inject a transport double instead of a network
 * (the @estate/settlement-client precedent). The response type deliberately
 * exposes `ok` and nothing else — no `status`, no headers, no body text. That
 * is not an oversight: the flat taxonomy below refuses to discriminate on a
 * status code, and a type that cannot see one is a rule the next edit cannot
 * quietly break.
 */
export type FetchLike = (
  url: string,
  init: { method: 'GET'; headers: Record<string, string> },
) => Promise<{ ok: boolean; json(): Promise<unknown> }>;

/** Real transport. Injected by default; every client accepts an override. */
export const defaultFetch: FetchLike = (url, init) => fetch(url, init);

/**
 * GET `url` on the CALLER'S OWN bearer, validate the body, or answer null.
 *
 * Two properties, and both of them are the design rather than convenience.
 *
 * FIRST, THE CREDENTIAL. This service holds no internal service credential in
 * either direction (see src/di-tokens.ts). Every peer read forwards the bearer
 * the caller presented, so the assistant can only ever see what that user could
 * already see for themselves, and a compromised assistant replays the sessions
 * it is currently serving rather than minting new authority (the M8 PR5 BFF
 * pattern). That matters more here than anywhere else in the product: this is
 * the one process an attacker can address in natural language, through the
 * document text and OCR output it is asked to read (docs/03 §4 TB5, risk #6).
 * An empty bearer therefore short-circuits to the refusal WITHOUT a round trip
 * — an unauthenticated read is not a read worth attempting, and asking anyway
 * would only teach a caller which peers are reachable.
 *
 * SECOND, THE FLAT TAXONOMY. A network failure, a non-2xx, a body that is not
 * JSON and a body that fails its schema all collapse to the SAME answer: null.
 * No status discrimination, no retry, no cache. These reads feed a MODEL, and
 * a partially-understood response must read as "no data" rather than as data —
 * a half-parsed asset list becomes a confidently wrong sentence about someone's
 * estate, and a 403 that leaked through as an empty list becomes "you have no
 * documents" said to a user who has several. Refusing uniformly means the tool
 * layer has exactly one thing to say (this read did not happen) and no way to
 * accidentally narrate a failure as a fact. Nothing about the downstream
 * response — status, message, or body — reaches the caller or the prompt.
 */
export async function readJson<T extends z.ZodTypeAny>(
  fetchImpl: FetchLike,
  url: string,
  bearer: string,
  schema: T,
): Promise<z.infer<T> | null> {
  const result = await readJsonOrAbsent(fetchImpl, url, bearer, schema);
  // Callers of THIS function have no absent case, so the peer's "no such row"
  // collapses back into the uniform refusal — exactly the pre-M10-PR3 shape.
  return result === ABSENT ? null : result;
}

/**
 * The peer answered, in its own application vocabulary, that the resource does
 * not exist. A DISTINCT value from null because the two mean opposite things:
 * null is "this read did not happen" and must fail closed; ABSENT is a real
 * answer ("there is no profile row") that a caller may legitimately render as
 * an empty view.
 */
export const ABSENT: unique symbol = Symbol('peer answered: no such resource');

/**
 * `readJson`, except the peer's own not-found token is surfaced as `ABSENT`
 * instead of being folded into the refusal.
 *
 * THE DISCRIMINATOR IS THE PEER'S APPLICATION-LEVEL BODY TOKEN, NOT A STATUS
 * CODE. `FetchLike` deliberately cannot see a status (the type is the rule), and
 * that stays true here: what this matches is a non-ok response whose body is the
 * `{error: 'not_found'}` object this repo's services throw for a row that does
 * not exist. A route-level 404 — a wrong URL, a misdeployed peer — carries
 * Nest's default body instead, does not match, and stays a fail-closed null.
 * That asymmetry is the point: "the peer looked and found nothing" is a real
 * answer, while "something answered 404" is not evidence of anything.
 *
 * Exists for exactly one consumer today (`ProfileClient.facts` — a user who
 * never completed profile onboarding has no row, and the M10 PR3 stack run
 * proved that reading that as an outage turns three analyses and one tool into
 * a permanent 503 for them). Every other read keeps the flat taxonomy.
 */
export async function readJsonOrAbsent<T extends z.ZodTypeAny>(
  fetchImpl: FetchLike,
  url: string,
  bearer: string,
  schema: T,
): Promise<z.infer<T> | typeof ABSENT | null> {
  if (!bearer) {
    return null;
  }
  let response: Awaited<ReturnType<FetchLike>>;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers: { authorization: `Bearer ${bearer}` },
    });
  } catch {
    return null; // network/DNS failure ⇒ no data
  }
  if (!response.ok) {
    // 401, 403, 5xx and unfamiliar 404s all stay the same answer, deliberately.
    // Only the peer's own "no such row" token is allowed to mean more.
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return null;
    }
    const isNotFoundToken =
      typeof body === 'object' &&
      body !== null &&
      (body as Record<string, unknown>)['error'] === 'not_found';
    return isNotFoundToken ? ABSENT : null;
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return null;
  }
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return null; // contract drift ⇒ no data, never a guess
  }
  return parsed.data as z.infer<T>;
}

/**
 * Percent-encode a value destined for a URL path segment.
 *
 * Ordinary defensive hygiene everywhere else in the repo; load-bearing here.
 * The ids these clients interpolate arrive as TOOL ARGUMENTS chosen by a model,
 * and the model's context contains user-supplied document text and OCR output
 * (docs/03 §4 TB5, risk #6) — so this is the one place in the product where a
 * path segment is attacker-influencable through prose. An id carrying `../` or
 * `?` must not become a different route on a peer service.
 */
export function pathSegment(value: string | number): string {
  return encodeURIComponent(String(value));
}
