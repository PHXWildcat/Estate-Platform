import { randomUUID } from 'node:crypto';
import { HttpSessionVerifier, type FetchLike } from '../src/verifier';

const USER = randomUUID();
const SESSION = randomUUID();

function sessionBody(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    userId: USER,
    sessionId: SESSION,
    mfaLevel: 'stepup',
    stepupExpiresAt: '2026-07-23T12:05:00.000Z',
    ...over,
  };
}

/** Records calls and returns a scripted response. */
function transport(response: { ok: boolean; status: number; body: unknown } | 'throw'): {
  calls: Array<{ url: string; headers: Record<string, string> }>;
  fetchImpl: FetchLike;
} {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({ url, headers: init.headers });
    if (response === 'throw') {
      return Promise.reject(new Error('ECONNREFUSED'));
    }
    return Promise.resolve({
      ok: response.ok,
      status: response.status,
      json: () => Promise.resolve(response.body),
    });
  };
  return { calls, fetchImpl };
}

describe('HttpSessionVerifier (introspection against identity)', () => {
  const opts = { identityUrl: 'http://identity:3001/' };

  it('verifies a valid token → SessionContext with a parsed Date', async () => {
    const { calls, fetchImpl } = transport({ ok: true, status: 200, body: sessionBody() });
    const verifier = new HttpSessionVerifier({ ...opts, fetchImpl });
    const ctx = await verifier.verify('opaque-token');
    expect(ctx).toEqual({
      userId: USER,
      sessionId: SESSION,
      mfaLevel: 'stepup',
      stepupExpiresAt: new Date('2026-07-23T12:05:00.000Z'),
    });
    // Trailing slash trimmed; token presented as a bearer, never in the URL.
    expect(calls[0]!.url).toBe('http://identity:3001/v1/auth/session');
    expect(calls[0]!.headers['authorization']).toBe('Bearer opaque-token');
  });

  it('maps null stepupExpiresAt correctly', async () => {
    const { fetchImpl } = transport({
      ok: true,
      status: 200,
      body: sessionBody({ mfaLevel: 'mfa', stepupExpiresAt: null }),
    });
    const ctx = await new HttpSessionVerifier({ ...opts, fetchImpl }).verify('t');
    expect(ctx?.stepupExpiresAt).toBeNull();
  });

  it('returns null on an empty token without calling identity', async () => {
    const { calls, fetchImpl } = transport({ ok: true, status: 200, body: sessionBody() });
    expect(await new HttpSessionVerifier({ ...opts, fetchImpl }).verify('')).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('fails closed on 401 (invalid/expired/revoked)', async () => {
    const { fetchImpl } = transport({ ok: false, status: 401, body: { error: 'unauthorized' } });
    expect(await new HttpSessionVerifier({ ...opts, fetchImpl }).verify('t')).toBeNull();
  });

  it('fails closed on a network error', async () => {
    const { fetchImpl } = transport('throw');
    expect(await new HttpSessionVerifier({ ...opts, fetchImpl }).verify('t')).toBeNull();
  });

  it('fails closed on a malformed body (identity contract drift)', async () => {
    const { fetchImpl } = transport({
      ok: true,
      status: 200,
      body: sessionBody({ userId: 'not-a-uuid' }),
    });
    expect(await new HttpSessionVerifier({ ...opts, fetchImpl }).verify('t')).toBeNull();
  });

  it('positive-caches by token: a second verify within the TTL does not re-call identity', async () => {
    const { calls, fetchImpl } = transport({ ok: true, status: 200, body: sessionBody() });
    const verifier = new HttpSessionVerifier({ ...opts, fetchImpl, cacheTtlMs: 10_000 });
    await verifier.verify('cached-token');
    await verifier.verify('cached-token');
    expect(calls).toHaveLength(1);
  });

  it('does NOT cache negatives (a transient failure cannot lock out the token)', async () => {
    let ok = false;
    const calls: string[] = [];
    const fetchImpl: FetchLike = (_url, init) => {
      calls.push(init.headers['authorization'] ?? '');
      return Promise.resolve({
        ok,
        status: ok ? 200 : 503,
        json: () => Promise.resolve(sessionBody()),
      });
    };
    const verifier = new HttpSessionVerifier({ ...opts, fetchImpl, cacheTtlMs: 10_000 });
    expect(await verifier.verify('t')).toBeNull(); // first: identity 503
    ok = true;
    expect(await verifier.verify('t')).not.toBeNull(); // recovers on the next call
    expect(calls).toHaveLength(2);
  });

  it('uses the global fetch when no transport is injected', async () => {
    const spy = jest.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve(sessionBody()),
    } as Response);
    try {
      const ctx = await new HttpSessionVerifier({ identityUrl: 'http://identity:3001' }).verify(
        't',
      );
      expect(ctx).not.toBeNull();
      expect(spy).toHaveBeenCalledWith(
        'http://identity:3001/v1/auth/session',
        expect.objectContaining({ method: 'GET' }),
      );
    } finally {
      spy.mockRestore();
    }
  });

  it('re-calls identity once the cache entry expires (bounded revocation latency)', async () => {
    let now = 1_000_000;
    const { calls, fetchImpl } = transport({ ok: true, status: 200, body: sessionBody() });
    const verifier = new HttpSessionVerifier(
      { ...opts, fetchImpl, cacheTtlMs: 30_000 },
      () => new Date(now),
    );
    await verifier.verify('t');
    now += 31_000;
    await verifier.verify('t');
    expect(calls).toHaveLength(2);
  });
});
