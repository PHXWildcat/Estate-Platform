import { vaultOrigin } from './config.js';

/**
 * THE ONLY PLACE THIS EXTENSION TALKS TO THE NETWORK.
 *
 * One module, one `fetch`, and `test/fences.spec.ts` asserts that no other file
 * in the package calls `fetch`, `XMLHttpRequest`, `sendBeacon`, `WebSocket`,
 * `EventSource` or `new Image`. That fence is what will make PR2b's central
 * claim checkable — key material cannot leak through a call site that does not
 * exist — and it is cheaper to establish now, while there is no key material,
 * than to retrofit around code that already handles some.
 *
 * EVERY REQUEST GOES TO THE VAULT ORIGIN'S EDGE, which is the extension's
 * single front door (docs/04): one `host_permission`, one origin, reusing an
 * allowlist and a holds-no-credential property that already exist rather than
 * teaching this artifact to address internal services.
 *
 * NO CORS DANCE, and it is worth saying why the edge needs no
 * `Access-Control-Allow-Origin` for this: extension pages and service workers
 * bypass CORS for hosts in `host_permissions` (chromium.org, "extension
 * content script fetches"), so no preflight is involved and the edge continues
 * to answer none — which is exactly the property its CSRF defence rests on.
 * Content scripts do NOT bypass CORS, and this package deliberately has none.
 */

/** Every way a call can fail, as this extension sees it. A closed set. */
export type ApiFailure =
  | 'UNAUTHENTICATED'
  | 'INVALID_CODE'
  | 'STEPUP_REQUIRED'
  | 'VAULT_LOCKED'
  | 'NOT_FOUND'
  | 'UNAVAILABLE'
  | 'NETWORK'
  | 'UNKNOWN';

export type ApiResult<T> = { ok: true; data: T } | { ok: false; code: ApiFailure };

const CSRF_HEADER = 'x-estate-vault-csrf';

/**
 * Server error TEXT is never surfaced; statuses narrow to the set above.
 *
 * `invalid_code` is identity's ONE answer for every way a pairing code can be
 * refused — unknown, expired, already spent, revoked, mis-shaped, raced. It is
 * carried through as one code here for the same reason it is one there: telling
 * them apart would tell whoever is holding a guess that it named something
 * real.
 */
function failureFor(status: number, token: string | null): ApiFailure {
  if (status === 401) return token === 'invalid_code' ? 'INVALID_CODE' : 'UNAUTHENTICATED';
  if (status === 403) {
    if (token === 'stepup_required') return 'STEPUP_REQUIRED';
    if (token === 'vault_locked') return 'VAULT_LOCKED';
    return 'UNKNOWN';
  }
  if (status === 404) return 'NOT_FOUND';
  if (status === 502 || status === 503) return 'UNAVAILABLE';
  return 'UNKNOWN';
}

export interface RequestOptions {
  readonly method?: string;
  readonly body?: unknown;
  /**
   * The caller's own access token. Absent for the two credential-free routes
   * (pairing redemption and refresh), whose authority is in the body.
   */
  readonly bearer?: string | undefined;
  /**
   * The opaque vault-session token from a completed SRP unlock (M16 PR2b).
   *
   * A SECOND, NARROWER authority on top of the bearer: the bearer says which
   * account is calling, and this says that this device has actually opened the
   * vault. Item reads require both, which is why a stolen extension credential
   * reaches the API and still decrypts nothing.
   */
  readonly vaultSession?: string | undefined;
}

export async function request<T>(
  path: string,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { [CSRF_HEADER]: '1' };
  if (options.body !== undefined) headers['content-type'] = 'application/json';
  if (options.bearer !== undefined) headers['authorization'] = `Bearer ${options.bearer}`;
  if (options.vaultSession !== undefined) {
    headers['x-estate-vault-session'] = options.vaultSession;
  }

  let response: Response;
  try {
    response = await fetch(`${vaultOrigin()}${path}`, {
      method: options.method ?? 'GET',
      headers,
      /*
       * `omit`, not `include` and not `same-origin`.
       *
       * This is a cross-origin request from an extension context, and the ONLY
       * credential it should ever carry is the bearer set above — a token this
       * extension was handed by the pairing ceremony and stores itself. Sending
       * cookies would mean a request travelling on whatever session the user's
       * browser happens to hold for the vault origin, which is a different
       * user's-browser-state-dependent authority than the one this artifact was
       * granted. `omit` makes that impossible rather than unlikely.
       */
      credentials: 'omit',
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
