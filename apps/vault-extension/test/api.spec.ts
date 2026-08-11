/**
 * The one network module, and the error firewall it is.
 *
 * Server error TEXT never reaches a screen: statuses and identity's own
 * machine-readable tokens narrow to a closed set, and everything else becomes
 * UNKNOWN. That matters more here than on an ordinary client, because this
 * artifact runs inside a browser extension where a leaked upstream message
 * would be readable by anything with devtools access.
 */
import { request } from '../src/api';
import { clearChromeDouble, installChromeDouble, TEST_ORIGIN } from './chrome-double';

function replyWith(reply: { status: number; body?: string; throws?: boolean }): {
  calls: Array<{ url: string; init: RequestInit }>;
} {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  (globalThis as { fetch?: unknown }).fetch = (
    url: unknown,
    init: RequestInit,
  ): Promise<Response> => {
    calls.push({ url: String(url), init });
    if (reply.throws) return Promise.reject(new Error('ECONNREFUSED'));
    return Promise.resolve({
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      text: () => Promise.resolve(reply.body ?? ''),
    } as unknown as Response);
  };
  return { calls };
}

describe('every request', () => {
  afterEach(clearChromeDouble);

  it('goes to the vault origin from the manifest, and nowhere else', async () => {
    installChromeDouble();
    const { calls } = replyWith({ status: 200, body: '{}' });
    await request('/api/vault/keyset');
    expect(calls[0]?.url).toBe(`${TEST_ORIGIN}/api/vault/keyset`);
  });

  it('carries the CSRF header and omits cookies', async () => {
    // `omit`, not `include`: the only credential this artifact should ever send
    // is the bearer it was granted, never whatever session the user's browser
    // happens to hold for the vault origin.
    installChromeDouble();
    const { calls } = replyWith({ status: 200, body: '{}' });
    await request('/api/vault/keyset', { bearer: 'tok' });
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers['x-estate-vault-csrf']).toBe('1');
    expect(headers['authorization']).toBe('Bearer tok');
    expect(calls[0]?.init.credentials).toBe('omit');
  });

  it('sets no content-type when there is no body', async () => {
    installChromeDouble();
    const { calls } = replyWith({ status: 200, body: '{}' });
    await request('/api/vault/keyset');
    expect((calls[0]?.init.headers as Record<string, string>)['content-type']).toBeUndefined();
  });
});

describe('failures narrow to a closed set', () => {
  afterEach(clearChromeDouble);

  it.each([
    [401, 'invalid_code', 'INVALID_CODE'],
    [401, 'unauthorized', 'UNAUTHENTICATED'],
    [401, null, 'UNAUTHENTICATED'],
    [403, 'stepup_required', 'STEPUP_REQUIRED'],
    [403, 'vault_locked', 'VAULT_LOCKED'],
    [403, 'something_else', 'UNKNOWN'],
    [404, null, 'NOT_FOUND'],
    [502, null, 'UNAVAILABLE'],
    [503, null, 'UNAVAILABLE'],
    [418, null, 'UNKNOWN'],
    [500, 'pg: relation does not exist', 'UNKNOWN'],
  ])('maps %s/%s to %s', async (status, token, expected) => {
    installChromeDouble();
    replyWith({ status, body: token === null ? '{}' : JSON.stringify({ error: token }) });
    const result = await request('/api/vault/keyset');
    expect(result).toEqual({ ok: false, code: expected });
  });

  it('never surfaces the server’s own text', async () => {
    installChromeDouble();
    replyWith({ status: 500, body: JSON.stringify({ error: 'pg: relation does not exist' }) });
    const result = await request('/api/vault/keyset');
    expect(JSON.stringify(result)).not.toContain('relation does not exist');
  });

  it('treats an unreachable edge as NETWORK, not as an answer', async () => {
    installChromeDouble();
    replyWith({ status: 0, throws: true });
    expect(await request('/api/vault/keyset')).toEqual({ ok: false, code: 'NETWORK' });
  });

  it('treats an unparseable body as no document rather than crashing', async () => {
    installChromeDouble();
    replyWith({ status: 200, body: 'not json at all' });
    expect(await request('/api/vault/keyset')).toEqual({ ok: true, data: {} });
  });

  it('treats an empty 204 as a successful call with no document', async () => {
    installChromeDouble();
    replyWith({ status: 204, body: '' });
    expect(await request('/api/vault/lock', { method: 'POST' })).toEqual({ ok: true, data: {} });
  });
});
