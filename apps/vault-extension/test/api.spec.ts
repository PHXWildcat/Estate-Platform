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

  it('survives a body that cannot be read at all', async () => {
    // A truncated or aborted response: `text()` rejects rather than resolving.
    // Treated as no document, not as a crash — this module is the extension's
    // error firewall and must not let a transport failure become an exception
    // somewhere with no handler.
    installChromeDouble();
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: true,
        status: 200,
        text: () => Promise.reject(new Error('aborted')),
      } as unknown as Response);
    expect(await request('/api/vault/keyset')).toEqual({ ok: true, data: {} });
  });

  it('treats an empty 204 as a successful call with no document', async () => {
    installChromeDouble();
    replyWith({ status: 204, body: '' });
    expect(await request('/api/vault/lock', { method: 'POST' })).toEqual({ ok: true, data: {} });
  });
});

describe('writing an item (M16 PR4a)', () => {
  afterEach(clearChromeDouble);

  it('sends If-Match as the version the caller READ, because update requires it', async () => {
    // The vault service refuses an update with no `If-Match` as
    // `invalid_request`, so this is an explicit option rather than something a
    // caller can forget into a 400.
    installChromeDouble();
    const { calls } = replyWith({ status: 200, body: '{}' });
    await request('/api/vault/items/i-1', {
      method: 'PUT',
      body: { itemType: 'password', blob: 'AAAA' },
      bearer: 'b',
      vaultSession: 'vs',
      ifMatch: 3,
    });
    expect((calls[0]?.init.headers as Record<string, string>)['if-match']).toBe('3');
  });

  it('omits If-Match entirely when there is none, rather than sending a blank', async () => {
    // A create has no version to match on, and `If-Match: ` would be a header
    // the service has to interpret rather than one it never sees.
    installChromeDouble();
    const { calls } = replyWith({ status: 201, body: '{}' });
    await request('/api/vault/items', { method: 'POST', body: {}, bearer: 'b' });
    expect(Object.keys(calls[0]?.init.headers as Record<string, string>)).not.toContain('if-match');
  });

  it('keeps the two 409s apart, because their remedies differ', async () => {
    installChromeDouble();
    replyWith({ status: 409, body: JSON.stringify({ error: 'version_conflict' }) });
    expect(await request('/api/vault/items/i-1', { method: 'PUT' })).toEqual({
      ok: false,
      code: 'VERSION_CONFLICT',
    });

    replyWith({ status: 409, body: JSON.stringify({ error: 'item_exists' }) });
    expect(await request('/api/vault/items', { method: 'POST' })).toEqual({
      ok: false,
      code: 'ITEM_EXISTS',
    });
  });

  it('does not invent a code for a 409 it does not recognise', async () => {
    // The closed set is the point: an unknown token becomes UNKNOWN rather than
    // being guessed into one of the two that carry advice.
    installChromeDouble();
    replyWith({ status: 409, body: JSON.stringify({ error: 'something_new' }) });
    expect(await request('/api/vault/items', { method: 'POST' })).toEqual({
      ok: false,
      code: 'UNKNOWN',
    });
  });
});
