import { request, type ApiResult } from './api.js';
import { forgetSecretKey } from './secret-key-store.js';

/**
 * THE PAIRED SESSION: what this device was granted, and how it is given back.
 *
 * WHAT IS STORED, exhaustively: an access token, a refresh token, and the ids
 * they belong to. NO KEY MATERIAL, now or in PR2b — the master key will live as
 * a non-extractable `CryptoKey` in an offscreen document and will never be
 * serialisable into here. `chrome.storage.local` is typed in `chrome.d.ts` to
 * make that a statement rather than a convention.
 *
 * WHY `local` AND NOT `session`. `chrome.storage.session` is memory-backed and
 * cleared when the browser closes, which is the better home for anything
 * short-lived — but the pairing ceremony is deliberately once per browser and
 * requires a step-up on the APP origin to repeat. A device that forgot its
 * pairing on every browser restart would send users back through that ceremony
 * daily, and the predictable result is people leaving the extension unpaired.
 *
 * SO THE REFRESH TOKEN IS ON DISK, for up to its 30-day life, and that is a
 * real residual rather than an oversight (docs/03 §6j). What bounds it is the
 * AUDIENCE, not the storage: the credential reaches five vault routes and three
 * identity ones and NOTHING else — it cannot reset a vault, replace a keyset,
 * delete an item, touch emergency access, mint another handoff, or enumerate
 * the owner's other devices — and it still decrypts nothing, because every item
 * read is behind a vault session that only a completed SRP unlock produces, and
 * that needs the vault password and the device Secret Key. What it costs an
 * attacker who has it is visible in the owner's paired-devices list (M16 PR1),
 * revocable from there in one click.
 */

const STORAGE_KEY = 'estate.session';

export interface PairedSession {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly userId: string;
  readonly sessionId: string;
}

/** What identity returns from redemption and from refresh. */
interface IssuedTokens {
  accessToken?: unknown;
  refreshToken?: unknown;
  userId?: unknown;
  sessionId?: unknown;
}

/**
 * A response missing its fields is NO DATA, never data (M11/M12/M15 — three
 * milestones running found the same shape in a browser). Here the consequence
 * of getting it wrong is a stored session whose `accessToken` is the literal
 * string "undefined", which then fails every request with an error that names
 * nothing.
 */
function toSession(payload: IssuedTokens): PairedSession | null {
  const { accessToken, refreshToken, userId, sessionId } = payload;
  if (typeof accessToken !== 'string' || accessToken.length === 0) return null;
  if (typeof refreshToken !== 'string' || refreshToken.length === 0) return null;
  if (typeof userId !== 'string' || userId.length === 0) return null;
  if (typeof sessionId !== 'string' || sessionId.length === 0) return null;
  return { accessToken, refreshToken, userId, sessionId };
}

export async function loadSession(): Promise<PairedSession | null> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const value = stored[STORAGE_KEY];
  // Storage is shape-checked exactly like a network response: a partially
  // written record from an interrupted update must not present as a session.
  return typeof value === 'object' && value !== null ? toSession(value) : null;
}

async function store(session: PairedSession): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_KEY]: session });
}

export async function forgetSession(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY);
}

/**
 * Spend a pairing code for a session.
 *
 * THE TYPED CODE IS SENT VERBATIM. Identity folds it onto the minting alphabet
 * (`canonicalCode`) before hashing, which is what lets a person retype it in
 * lower case with the dashes dropped — and a client-side fold here would be a
 * second copy of a matching rule, free to disagree with the one that decides.
 * That is the M12 upload-client rule: never a client-side second opinion on a
 * server-side gate.
 */
export async function pair(code: string): Promise<ApiResult<PairedSession>> {
  const result = await request<IssuedTokens>('/api/auth/extension/pairing/redeem', {
    method: 'POST',
    body: { code },
  });
  if (!result.ok) return result;
  const session = toSession(result.data);
  if (!session) return { ok: false, code: 'UNKNOWN' };
  await store(session);
  return { ok: true, data: session };
}

/**
 * Exchange the refresh token for a fresh pair, and persist it.
 *
 * Refresh ROTATES IN PLACE at identity — it updates the same session row rather
 * than minting a new one — so the audience survives and a refreshed extension
 * session cannot become something more powerful than it was. That property was
 * true by accident of an UPDATE's SET list until M16 PR1 pinned it with a test.
 */
export async function refresh(session: PairedSession): Promise<ApiResult<PairedSession>> {
  const result = await request<IssuedTokens>('/api/auth/refresh', {
    method: 'POST',
    body: { refreshToken: session.refreshToken },
  });
  if (!result.ok) return result;
  const next = toSession(result.data);
  if (!next) return { ok: false, code: 'UNKNOWN' };
  await store(next);
  return { ok: true, data: next };
}

/**
 * Make a call on this device's own credential, refreshing ONCE if the access
 * token has expired.
 *
 * The access token lives 15 minutes and the session lives 30 days, so an
 * extension that did not refresh would be useless within the hour and the only
 * remedy would be re-pairing — which needs a step-up on the app origin. Reactive
 * rather than scheduled: identity returns the SESSION's expiry from redemption,
 * not the access token's, so there is no clock here to trust and a 401 is the
 * honest signal.
 *
 * EXACTLY ONE retry. A loop on repeated 401s would hammer identity with a dead
 * refresh token; one attempt distinguishes "the access token expired" from "the
 * session is gone", which are the only two cases and want opposite responses.
 */
export async function withSession<T>(
  session: PairedSession,
  call: (bearer: string) => Promise<ApiResult<T>>,
): Promise<{ result: ApiResult<T>; session: PairedSession }> {
  const first = await call(session.accessToken);
  if (first.ok || first.code !== 'UNAUTHENTICATED') {
    return { result: first, session };
  }
  const refreshed = await refresh(session);
  if (!refreshed.ok) {
    /*
     * AN OUTAGE MUST NOT READ AS A REVOCATION.
     *
     * If the refresh was REFUSED, the session is genuinely gone — revoked from
     * the owner's paired-devices list, or expired — and the original 401 is the
     * truth to report; the caller will forget the credential on it.
     *
     * If the refresh could not be MADE (no network, the edge or identity down),
     * reporting that same 401 would tell a user their device had been
     * disconnected because their wifi dropped, and un-pair a perfectly good
     * credential — sending them back through a step-up ceremony on the app
     * origin for nothing. So the transport failure is what surfaces. This is
     * the M9 rule pointed the other way: an outage must not wear the face of a
     * control.
     */
    const revoked = refreshed.code === 'UNAUTHENTICATED' || refreshed.code === 'INVALID_CODE';
    return { result: revoked ? first : { ok: false, code: refreshed.code }, session };
  }
  return { result: await call(refreshed.data.accessToken), session: refreshed.data };
}

/**
 * Give the credential back, then forget it.
 *
 * REVOCATION FIRST, and storage cleared only if something was actually revoked
 * — the M8 PR5 logout rule, where a browser that looks signed out over a live
 * session is the worst outcome. Here the equivalent is an extension that shows
 * "not connected" while a live 30-day credential for this account still exists
 * somewhere.
 *
 * REFRESH BEFORE LOGOUT, deliberately. Identity's `POST /v1/auth/logout`
 * requires a live ACCESS token, and the unauthenticated
 * `/v1/auth/logout/refresh` that M8 added for exactly this case is one the
 * vault edge REFUSES to proxy (its `/api/auth/logout` entry is an exact match
 * precisely so the `/refresh` sibling stays unreachable). So a stale access
 * token is refreshed first and then spent. If refresh fails, the session is
 * already dead and forgetting it locally is correct rather than premature.
 */
export async function disconnect(session: PairedSession): Promise<ApiResult<{ ok: true }>> {
  const { result } = await withSession(session, (bearer) =>
    request<unknown>('/api/auth/logout', { method: 'POST', bearer }),
  );
  if (!result.ok && result.code !== 'UNAUTHENTICATED') {
    // A transport failure or an outage: the credential may well still be live,
    // so it is not forgotten. Saying so is better than a reassuring lie.
    return { ok: false, code: result.code };
  }
  await forgetSession();
  // A device that is no longer paired has no business holding half the key
  // material for an account it can no longer reach.
  await forgetSecretKey(session.userId);
  return { ok: true, data: { ok: true } };
}
