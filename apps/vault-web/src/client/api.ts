/**
 * THE ONLY PLACE THIS ORIGIN TALKS TO THE NETWORK.
 *
 * One module, one `fetch`, and `test/no-key-material-egress.spec.ts` asserts
 * that no other client file calls `fetch`, `XMLHttpRequest`, `sendBeacon`,
 * `WebSocket` or `EventSource`. That is the fence that makes the milestone's
 * central claim checkable: nothing derived from the vault password or the
 * Secret Key ever leaves the device. Key material cannot leak through a call
 * site that does not exist, and there is exactly one call site to audit.
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
  | 'VAULT_LOCKED'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'INVALID_REQUEST'
  | 'UNAVAILABLE'
  // M14's arming gate and M9's capability gate. Both arrive as 503 and BOTH
  // ARE CONTROLS FIRING, not outages — so they are named here rather than
  // folded into UNAVAILABLE. "We cannot notify anyone right now" and "you have
  // never confirmed your address" have completely different remedies, and a
  // screen that cannot tell them apart must give the wrong one to somebody.
  | 'RECIPIENT_UNVERIFIED'
  | 'NOTIFICATIONS_UNAVAILABLE'
  | 'NETWORK'
  | 'UNKNOWN';

export type ApiResult<T> = { ok: true; data: T } | { ok: false; code: ApiFailure };

const CSRF_HEADER = 'x-estate-vault-csrf';

/** Server error TEXT is never surfaced; statuses narrow to the set above. */
function failureFor(status: number, token: string | null): ApiFailure {
  if (status === 401) return 'UNAUTHENTICATED';
  if (status === 403) {
    if (token === 'stepup_required') return 'STEPUP_REQUIRED';
    if (token === 'vault_locked') return 'VAULT_LOCKED';
    return 'UNKNOWN';
  }
  if (status === 404) return 'NOT_FOUND';
  if (status === 409 || status === 412) return 'CONFLICT';
  if (status === 400) return 'INVALID_REQUEST';
  if (status === 502 || status === 503) {
    if (token === 'recipient_unverified') return 'RECIPIENT_UNVERIFIED';
    if (token === 'notifications_unavailable') return 'NOTIFICATIONS_UNAVAILABLE';
    return 'UNAVAILABLE';
  }
  return 'UNKNOWN';
}

export interface RequestOptions {
  readonly method?: string;
  readonly body?: unknown;
  /** The opaque vault-session token from a completed SRP unlock (PR2). */
  readonly vaultSession?: string;
  readonly ifMatch?: number;
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { [CSRF_HEADER]: '1' };
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (options.vaultSession) headers['x-estate-vault-session'] = options.vaultSession;
  if (options.ifMatch !== undefined) headers['if-match'] = String(options.ifMatch);

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
