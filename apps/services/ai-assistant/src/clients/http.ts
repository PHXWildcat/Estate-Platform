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
    return null; // 401, 403, 404, 5xx — all the same answer, deliberately
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
