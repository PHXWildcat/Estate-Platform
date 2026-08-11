/**
 * The paired session: what it stores, what it refuses to store, and the one
 * distinction that decides whether a user gets un-paired by a wifi blip.
 */
import { assertExactOrigin, vaultOrigin, ExtensionConfigError } from '../src/config';
import { PACKAGED_VAULT_ORIGIN } from '../src/origin';
import {
  disconnect,
  forgetSession,
  loadSession,
  pair,
  refresh,
  withSession,
  type PairedSession,
} from '../src/session';
import { clearChromeDouble, installChromeDouble, TEST_ORIGIN } from './chrome-double';

interface Recorded {
  url: string;
  init: RequestInit;
}

function transport(replies: Array<{ status: number; body: unknown }>): {
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const queue = [...replies];
  (globalThis as { fetch?: unknown }).fetch = (
    url: unknown,
    init: RequestInit,
  ): Promise<Response> => {
    calls.push({ url: String(url), init });
    const next = queue.shift() ?? { status: 500, body: {} };
    return Promise.resolve({
      ok: next.status >= 200 && next.status < 300,
      status: next.status,
      text: () => Promise.resolve(JSON.stringify(next.body)),
    } as unknown as Response);
  };
  return { calls };
}

const TOKENS = {
  accessToken: 'access-1',
  refreshToken: 'refresh-1',
  userId: 'u-1',
  sessionId: 's-1',
};

const SESSION: PairedSession = TOKENS;

describe('the vault origin is packaged, not read back from the manifest', () => {
  /*
   * REWRITTEN, not deleted. This describe was named "comes from the manifest"
   * and asserted exactly that, which was the right design and did not work: an
   * OFFSCREEN DOCUMENT gets only `chrome.runtime`'s messaging surface — no
   * `getManifest` — and the key holder lives in one, so `vaultOrigin()` threw on
   * every vault request and `api.ts` reported it as `NETWORK`. Measured in
   * Chrome 151, with the popup as the control; jsdom could never have shown it,
   * because the chrome double supplies `getManifest` unconditionally.
   *
   * The value is written into `origin.ts` by the build now, from the same
   * `VAULT_ORIGIN` the manifest gets. That is two places holding one value, so
   * `manifest.spec.ts` asserts they agree in a REAL build.
   */
  afterEach(clearChromeDouble);

  it('returns the packaged origin', () => {
    expect(vaultOrigin()).toBe(PACKAGED_VAULT_ORIGIN);
  });

  it('does not consult the manifest at all, so an offscreen context can call it', () => {
    // No chrome double installed: `chrome` is undefined here, which is stricter
    // than the offscreen document (where it exists but is nearly empty). If
    // this throws, the regression is back.
    expect(() => vaultOrigin()).not.toThrow();
    expect(vaultOrigin()).toBe(PACKAGED_VAULT_ORIGIN);
  });

  it.each(['https://*.estate.test', 'not-a-url', '', 'https://vault.estate.test/some/path'])(
    'refuses %s as a packaged origin',
    (value) => {
      // Exercised through the exported validator rather than by mocking the
      // constant: a mocked constant would prove that a mock throws.
      expect(() => assertExactOrigin(value)).toThrow(ExtensionConfigError);
    },
  );

  it('accepts an exact origin, with or without the manifest match suffix', () => {
    expect(assertExactOrigin('https://vault.estate.test')).toBe('https://vault.estate.test');
    expect(assertExactOrigin('https://vault.estate.test/*')).toBe('https://vault.estate.test');
  });
});

describe('pairing', () => {
  afterEach(clearChromeDouble);

  it('sends the typed code VERBATIM and stores what comes back', async () => {
    installChromeDouble();
    const { calls } = transport([{ status: 200, body: TOKENS }]);
    // Lower case with the dashes dropped: identity folds it (`canonicalCode`),
    // and a client-side fold here would be a second copy of a matching rule.
    const result = await pair('ep1 abcd efgh');

    expect(result.ok).toBe(true);
    expect(calls[0]?.url).toBe(`${TEST_ORIGIN}/api/auth/extension/pairing/redeem`);
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({ code: 'ep1 abcd efgh' });
    expect(await loadSession()).toEqual(SESSION);
  });

  it('carries the CSRF header and NO credential', async () => {
    installChromeDouble();
    const { calls } = transport([{ status: 200, body: TOKENS }]);
    await pair('EP1-CODE');
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers['x-estate-vault-csrf']).toBe('1');
    expect(headers['authorization']).toBeUndefined();
    expect(calls[0]?.init.credentials).toBe('omit');
  });

  it('stores nothing when the response is missing a field', async () => {
    // A response missing its fields is NO DATA, never data. Storing a session
    // whose accessToken is the string "undefined" fails every later request
    // with an error that names nothing.
    installChromeDouble();
    transport([{ status: 200, body: { accessToken: 'a', userId: 'u-1' } }]);
    const result = await pair('EP1-CODE');
    expect(result).toEqual({ ok: false, code: 'UNKNOWN' });
    expect(await loadSession()).toBeNull();
  });

  it('surfaces identity’s uniform refusal as one code', async () => {
    installChromeDouble();
    transport([{ status: 401, body: { error: 'invalid_code' } }]);
    expect(await pair('EP1-NOPE')).toEqual({ ok: false, code: 'INVALID_CODE' });
    expect(await loadSession()).toBeNull();
  });

  it('rejects a partially written record on read, like a network response', async () => {
    const double = installChromeDouble();
    double.store.set('estate.session', { accessToken: 'a', refreshToken: 'r' });
    expect(await loadSession()).toBeNull();
  });

  it('stores NOTHING that is not a token', async () => {
    installChromeDouble();
    const double = installChromeDouble();
    transport([{ status: 200, body: { ...TOKENS, masterKey: 'should-not-be-kept' } }]);
    await pair('EP1-CODE');
    expect(JSON.stringify([...double.store.values()])).not.toContain('should-not-be-kept');
    expect(Object.keys(double.store.get('estate.session') as object).sort()).toEqual([
      'accessToken',
      'refreshToken',
      'sessionId',
      'userId',
    ]);
  });
});

describe('refreshing', () => {
  afterEach(clearChromeDouble);

  it('retries a 401 ONCE with a refreshed token, then succeeds', async () => {
    installChromeDouble();
    const { calls } = transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 200, body: { ...TOKENS, accessToken: 'access-2', refreshToken: 'refresh-2' } },
      { status: 200, body: { enrolled: true } },
    ]);

    const { result, session } = await withSession(SESSION, (bearer) =>
      import('../src/api').then((m) => m.request('/api/vault/keyset', { bearer })),
    );

    expect(result).toEqual({ ok: true, data: { enrolled: true } });
    expect(session.accessToken).toBe('access-2');
    // The refresh went to the edge with no credential attached.
    expect(calls[1]?.url).toBe(`${TEST_ORIGIN}/api/auth/refresh`);
    expect((calls[1]?.init.headers as Record<string, string>)['authorization']).toBeUndefined();
    // ...and the retry carried the NEW token, not the old one.
    expect((calls[2]?.init.headers as Record<string, string>)['authorization']).toBe(
      'Bearer access-2',
    );
    expect(await loadSession()).toMatchObject({ accessToken: 'access-2' });
  });

  it('does not loop: a second 401 is reported, not retried again', async () => {
    installChromeDouble();
    const { calls } = transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 200, body: { ...TOKENS, accessToken: 'access-2' } },
      { status: 401, body: { error: 'unauthorized' } },
    ]);
    const { result } = await withSession(SESSION, (bearer) =>
      import('../src/api').then((m) => m.request('/api/vault/keyset', { bearer })),
    );
    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
    expect(calls).toHaveLength(3);
  });

  it('reports a REFUSED refresh as unauthenticated — the session really is gone', async () => {
    installChromeDouble();
    transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 401, body: { error: 'unauthorized' } },
    ]);
    const { result } = await withSession(SESSION, (bearer) =>
      import('../src/api').then((m) => m.request('/api/vault/keyset', { bearer })),
    );
    expect(result).toEqual({ ok: false, code: 'UNAUTHENTICATED' });
  });

  it('reports an UNREACHABLE refresh as an outage, NOT as a revocation', async () => {
    /*
     * The distinction that decides whether a wifi blip un-pairs a device. The
     * popup forgets the credential on UNAUTHENTICATED — so if a network failure
     * arrived wearing that code, a user would be sent back through a step-up
     * ceremony on the app origin because their connection dropped for a second.
     * The M9 rule pointed the other way: an outage must not wear the face of a
     * control.
     */
    installChromeDouble();
    transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 503, body: { error: 'upstream_unavailable' } },
    ]);
    const { result } = await withSession(SESSION, (bearer) =>
      import('../src/api').then((m) => m.request('/api/vault/keyset', { bearer })),
    );
    expect(result).toEqual({ ok: false, code: 'UNAVAILABLE' });
  });

  it('leaves the stored session alone when the refresh fails', async () => {
    installChromeDouble();
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    transport([{ status: 503, body: {} }]);
    await refresh(SESSION);
    expect(await loadSession()).toEqual(SESSION);
  });
});

describe('disconnecting', () => {
  afterEach(clearChromeDouble);

  it('revokes upstream FIRST, then forgets the credential', async () => {
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    const { calls } = transport([{ status: 200, body: { status: 'ok' } }]);

    expect(await disconnect(SESSION)).toEqual({ ok: true, data: { ok: true } });
    expect(calls[0]?.url).toBe(`${TEST_ORIGIN}/api/auth/logout`);
    expect((calls[0]?.init.headers as Record<string, string>)['authorization']).toBe(
      'Bearer access-1',
    );
    expect(await loadSession()).toBeNull();
  });

  it('refreshes a stale access token before spending it', async () => {
    // Identity's logout needs a LIVE access token, and the unauthenticated
    // `logout/refresh` route that M8 added for this case is one the vault edge
    // deliberately refuses to proxy. So the stale token is refreshed first.
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    const { calls } = transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 200, body: { ...TOKENS, accessToken: 'access-2' } },
      { status: 200, body: { status: 'ok' } },
    ]);

    expect((await disconnect(SESSION)).ok).toBe(true);
    expect(calls.map((c) => c.url)).toEqual([
      `${TEST_ORIGIN}/api/auth/logout`,
      `${TEST_ORIGIN}/api/auth/refresh`,
      `${TEST_ORIGIN}/api/auth/logout`,
    ]);
    expect(await loadSession()).toBeNull();
  });

  it('KEEPS the credential when revocation could not be attempted', async () => {
    // The M8 PR5 logout rule: "disconnected" over a live 30-day credential is
    // the worst outcome, so an outage does not clear storage.
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    transport([
      { status: 503, body: { error: 'upstream_unavailable' } },
      { status: 503, body: { error: 'upstream_unavailable' } },
    ]);

    expect(await disconnect(SESSION)).toEqual({ ok: false, code: 'UNAVAILABLE' });
    expect(await loadSession()).toEqual(SESSION);
  });

  it('forgets it when the session was ALREADY gone', async () => {
    // Revoked from the owner's paired-devices list. There is nothing to give
    // back, and keeping a dead credential on disk helps nobody.
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    transport([
      { status: 401, body: { error: 'unauthorized' } },
      { status: 401, body: { error: 'unauthorized' } },
    ]);
    expect((await disconnect(SESSION)).ok).toBe(true);
    expect(await loadSession()).toBeNull();
  });

  it('forgetSession removes the record outright', async () => {
    const double = installChromeDouble();
    double.store.set('estate.session', SESSION);
    await forgetSession();
    expect(double.store.size).toBe(0);
  });
});
