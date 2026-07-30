import { FetchAssetsClient } from '../src/assets-client';

/**
 * The REAL client against a stubbed transport (the identity-client pattern).
 * What matters here is the wire contract and the error firewall: the bearer
 * goes out on every call, downstream response text never comes back, and a
 * malformed downstream answer is refused rather than half-trusted.
 */

const TOKEN = 'access-token-value-123';
const BASE = 'http://assets.test';

function response(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

const ASSET = {
  assetId: 'a2c2e6a4-0000-4000-8000-00000000000a',
  category: 'cash',
  title: 'Checking',
  estValue: '10.00',
  valuationAsOf: '2026-07-01',
  ownershipPct: 100,
  inTrust: false,
  version: '2',
};

describe('FetchAssetsClient', () => {
  it('sends the bearer on list, and parses the array', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, [ASSET]));
    const client = new FetchAssetsClient(BASE, fetchFn);
    await expect(client.list(TOKEN)).resolves.toEqual([ASSET]);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/v1/assets`);
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    expect(init.method).toBe('GET');
  });

  it('sends the bearer on net worth', async () => {
    const netWorth = {
      totalValue: '10.00',
      assetCount: 1,
      valuedAssetCount: 1,
      inTrustValue: '0',
    };
    const fetchFn = jest.fn().mockResolvedValue(response(200, netWorth));
    await expect(new FetchAssetsClient(BASE, fetchFn).netWorth(TOKEN)).resolves.toEqual(netWorth);
    expect((fetchFn.mock.calls[0] as [string, RequestInit])[0]).toBe(`${BASE}/v1/net-worth`);
  });

  it('POSTs a create with the whole valuation triple flattened onto the body', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(201, { assetId: 'x', version: '1' }));
    await new FetchAssetsClient(BASE, fetchFn).create(TOKEN, {
      category: 'cash',
      title: 'Savings',
      valuation: {
        estValue: '99.10',
        valuationAsOf: '2026-07-01',
        valuationSource: 'owner_estimate',
      },
    });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({
      category: 'cash',
      title: 'Savings',
      estValue: '99.10',
      valuationAsOf: '2026-07-01',
      valuationSource: 'owner_estimate',
    });
  });

  it('omits valuation keys entirely when there is no valuation', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(201, { assetId: 'x', version: '1' }));
    await new FetchAssetsClient(BASE, fetchFn).create(TOKEN, {
      category: 'cash',
      title: 'Wallet',
    });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ category: 'cash', title: 'Wallet' });
  });

  it.each([
    [401, 'unauthorized', 'UNAUTHENTICATED'],
    [400, 'invalid_request', 'INVALID_REQUEST'],
    [422, 'invalid_request', 'INVALID_REQUEST'],
  ])('maps %i to the %s code', async (status, token, code) => {
    const fetchFn = jest.fn().mockResolvedValue(response(status, { error: token }));
    await expect(new FetchAssetsClient(BASE, fetchFn).list(TOKEN)).rejects.toMatchObject({
      extensions: { code },
    });
  });

  it('maps a step-up refusal to STEPUP_REQUIRED', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(403, { error: 'stepup_required' }));
    await expect(new FetchAssetsClient(BASE, fetchFn).list(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'STEPUP_REQUIRED' },
    });
  });

  it('never forwards downstream text for an unmapped status', async () => {
    const fetchFn = jest
      .fn()
      .mockResolvedValue(response(500, { error: 'stack trace and internals' }));
    const attempt = new FetchAssetsClient(BASE, fetchFn).list(TOKEN);
    await expect(attempt).rejects.toThrow(/status 500/);
    await expect(attempt).rejects.not.toThrow(/internals/);
  });

  it('turns a network failure into a message with no cause attached', async () => {
    const fetchFn = jest.fn().mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:3003'));
    const attempt = new FetchAssetsClient(BASE, fetchFn).list(TOKEN);
    await expect(attempt).rejects.toThrow('assets service unreachable');
    await expect(attempt).rejects.not.toThrow(/10\.0\.0\.5/);
  });

  it('refuses a response whose shape does not match, rather than half-trusting it', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, [{ assetId: 'x' }]));
    await expect(new FetchAssetsClient(BASE, fetchFn).list(TOKEN)).rejects.toThrow(
      'assets response failed validation',
    );
  });

  it('refuses a non-JSON response', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.reject(new Error('not json')),
    });
    await expect(new FetchAssetsClient(BASE, fetchFn).list(TOKEN)).rejects.toThrow(
      'assets response was not JSON',
    );
  });

  it('tolerates a non-JSON error body and still maps by status', async () => {
    const fetchFn = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.reject(new Error('not json')),
    });
    await expect(new FetchAssetsClient(BASE, fetchFn).list(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'UNAUTHENTICATED' },
    });
  });

  it('builds a real fetch-backed client when no transport is injected', () => {
    expect(() => new FetchAssetsClient(BASE)).not.toThrow();
  });
});
