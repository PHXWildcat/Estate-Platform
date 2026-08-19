/**
 * THE ONLY PLACE THIS ORIGIN TALKS TO THE NETWORK.
 *
 * One module, one `fetch`, and `test/fences.spec.ts` asserts that no other
 * client file calls `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket` or
 * `EventSource`. On the vault origin that fence makes a claim about key
 * material; here it makes one about ESTATE CONTENT — the case detail an
 * operator reads has exactly one route off this page, and it is this file.
 *
 * The CSP is the second layer under it: `connect-src 'self'` means the browser
 * refuses a request to any other origin even if this module regressed.
 *
 * Requests are same-origin, credentialed by the `__Host-` cookie the edge set —
 * this code never sees a token, never stores one, and has no way to read one.
 */

/** Every way a call can fail, as the UI sees it. A closed set. */
export type ApiFailure =
  | 'UNAUTHENTICATED'
  | 'STEPUP_REQUIRED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'INVALID_REQUEST'
  | 'TOO_MANY_ATTEMPTS'
  | 'UNAVAILABLE'
  | 'NETWORK'
  | 'UNKNOWN';

export type ApiResult<T> = { ok: true; data: T } | { ok: false; code: ApiFailure };

const CSRF_HEADER = 'x-estate-operator-csrf';

/** Server error TEXT is never surfaced; statuses narrow to the set above. */
function failureFor(status: number, token: string | null): ApiFailure {
  if (status === 401) return 'UNAUTHENTICATED';
  if (status === 403) {
    if (token === 'stepup_required') return 'STEPUP_REQUIRED';
    return 'FORBIDDEN';
  }
  if (status === 404) return 'NOT_FOUND';
  if (status === 400) return 'INVALID_REQUEST';
  // A control firing, never an outage (the M9 rule): identity's step-up cap
  // answers 429, and "wait" is a different remedy from every other refusal in
  // this union.
  if (status === 429) return 'TOO_MANY_ATTEMPTS';
  if (status === 502 || status === 503) return 'UNAVAILABLE';
  return 'UNKNOWN';
}

export interface RequestOptions {
  readonly method?: string;
  readonly body?: unknown;
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { [CSRF_HEADER]: '1' };
  if (options.body !== undefined) headers['content-type'] = 'application/json';

  let response: Response;
  try {
    response = await fetch(path, {
      method: options.method ?? 'GET',
      headers,
      // Same-origin only. Never 'include': there is no other origin this app
      // should ever send a credential to, and 'same-origin' makes a future
      // absolute URL fail closed rather than leak the cookie.
      credentials: 'same-origin',
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    });
  } catch {
    return { ok: false, code: 'NETWORK' };
  }

  const raw = await response.text().catch(() => '');
  let payload: unknown = null;
  if (raw.length > 0) {
    try {
      payload = JSON.parse(raw);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const token =
      typeof payload === 'object' && payload !== null
        ? ((payload as { error?: unknown }).error ?? null)
        : null;
    return {
      ok: false,
      code: failureFor(response.status, typeof token === 'string' ? token : null),
    };
  }
  // 204 and friends: a successful call with no document.
  return { ok: true, data: (payload ?? {}) as T };
}
