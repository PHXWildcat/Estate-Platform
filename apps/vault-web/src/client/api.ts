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
  // M27 PR2's restore surface, and the same reasoning one milestone later. The
  // four restore routes answer FIVE distinct refusals across two status codes,
  // and until this PR three of them collapsed into `CONFLICT` and `NOT_FOUND` —
  // which is not a naming problem, it is a WRONG REMEDY reaching the user:
  //
  //   · `item_unrestorable` means a reset destroyed the key that opened this
  //     blob. It rendered as CONFLICT's "Reload and try again", which is advice
  //     that can never succeed. A control firing wearing an outage's face.
  //   · `version_conflict` is the one of the three where reloading DOES work,
  //     so it must not share copy with the one where nothing does. It is ALSO
  //     the one that is not restore-only: `updateItem` throws it for the same
  //     stale `If-Match`, so its message stays surface-neutral. The first draft
  //     named the history screen and was therefore false on the edit form —
  //     this list's own defect, committed while writing the list.
  //   · `version_not_found` rendered as NOT_FOUND's "That item is no longer
  //     there" on a screen where the item is plainly present — a false
  //     sentence, and the wrong thing to do about it.
  | 'VERSION_CONFLICT'
  | 'ITEM_UNRESTORABLE'
  | 'VERSION_NOT_FOUND'
  // A Cedar denial. It arrives as 403 with `forbidden` and fell through to
  // UNKNOWN's "Something went wrong" — an authz control reading as a fault, on
  // the first surface to name three new Cedar actions (`read_history`,
  // `undelete`, `restore`). Unreachable while the owner is the only principal;
  // named now because PR3 introduces one who is not.
  | 'FORBIDDEN'
  // M27 PR3b review. The grantee's READING screen answers four refusals that
  // had no name here, so every one of them reached the reader as `UNKNOWN`'s
  // "Something went wrong. Try again." or — worse — as item-shaped copy on a
  // screen showing a whole vault. Three of them are the owner's own controls
  // firing, which is the M9 rule pointed straight at the surface it protects:
  // a stop and a settlement hold are not faults, they have different
  // remedies, and "try again" is the wrong advice for either. A third,
  // `policy_revoked`, was named here until the coverage floor showed the
  // service arm producing it was dead — a revoked policy is soft-deleted and
  // answers the uniform 404 — so the code went with it rather than becoming a
  // zero-caller surface.
  // They are named rather than folded together for the same reason
  // `RECIPIENT_UNVERIFIED` and `NOTIFICATIONS_UNAVAILABLE` are.
  | 'ACCESS_STOPPED'
  | 'SETTLEMENT_HOLD'
  | 'NOT_COLLECTED'
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
    if (token === 'forbidden') return 'FORBIDDEN';
    // Two controls, two remedies, and neither is a fault.
    if (token === 'denied_by_owner') return 'ACCESS_STOPPED';
    if (token === 'settlement_stage_not_reached') return 'SETTLEMENT_HOLD';
    return 'UNKNOWN';
  }
  if (status === 404) {
    // The ITEM is missing versus THAT VERSION is missing. Different sentences
    // and different remedies — one sends the reader back to the vault, the
    // other leaves them on a screen whose item is still there.
    if (token === 'version_not_found') return 'VERSION_NOT_FOUND';
    return 'NOT_FOUND';
  }
  if (status === 409) {
    // NOT restore-only, and the copy must not pretend otherwise: `updateItem`
    // and `restoreItemVersion` both throw this for the same stale `If-Match`.
    // It stays a DISTINCT code from `CONFLICT` — which covers `item_exists`,
    // `keyset_exists` and 412, genuinely different conditions — but its message
    // is surface-neutral. See `messageFor` and apps/web's M19 precedent.
    if (token === 'version_conflict') return 'VERSION_CONFLICT';
    if (token === 'item_unrestorable') return 'ITEM_UNRESTORABLE';
    // The arrangement was rebuilt under the grantee, so the release they are
    // holding is no longer the current one. CONFLICT's "this item changed"
    // names an item on a screen that is showing a vault, and its "reload"
    // never works — the remedy is to request and open again.
    if (token === 'not_collected') return 'NOT_COLLECTED';
    // `invalid_cursor` lands here deliberately. It can only fire if this client
    // mangles a cursor the server handed it, which is a bug rather than a user
    // condition — so it gets no name and no copy, and the spec asserts a cursor
    // is round-tripped VERBATIM instead. Prefer the absence to the filter.
    return 'CONFLICT';
  }
  if (status === 412) return 'CONFLICT';
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
