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
  valuationSource: 'owner_estimate',
  ownershipPct: 100,
  inTrust: false,
  fundingStatus: null,
  status: 'live',
  retiredAt: null,
  version: '2',
};

const DETAIL = {
  ...ASSET,
  costBasis: null,
  location: 'safe',
  notes: 'gate code',
};

const ACK = {
  assetId: 'a2c2e6a4-0000-4000-8000-00000000000a',
  eventId: 'e2c2e6a4-0000-4000-8000-00000000000e',
  version: '3',
  occurredAt: '2026-08-13T00:00:00.000Z',
  replayed: false,
};

/** The decedent whose estate an executor reads — never the caller. */
const OWNER = '9f9f9f9f-0000-4000-8000-00000000000b';

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

  it('asks for retired rows only when told to', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, []));
    await new FetchAssetsClient(BASE, fetchFn).list(TOKEN, true);
    expect((fetchFn.mock.calls[0] as [string, RequestInit])[0]).toBe(
      `${BASE}/v1/assets?includeRetired=true`,
    );
  });

  /**
   * ANOTHER PERSON'S ESTATE, under a settlement staged grant (M23 PR2).
   *
   * A separate METHOD for a separate ROUTE, and the separation is the point:
   * `/v1/estates/:ownerUserId/assets` carries its own authorization model
   * (assets asks settlement for an approved `inventory` stage) and its own
   * audit action naming the case that authorised the read. Merging it into
   * `list` would have put a non-owner branch inside the owner's hot path.
   */
  it('GETs the ESTATE route, and never the owner’s own list', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, [ASSET]));
    const client = new FetchAssetsClient(BASE, fetchFn);
    await expect(client.listEstate(TOKEN, OWNER)).resolves.toEqual([ASSET]);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/v1/estates/${OWNER}/assets`);
    expect(url).not.toContain('/v1/assets');
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    // The BFF adds nothing to settlement's decision and cannot: it forwards
    // the caller's own bearer and holds no credential of its own.
    expect(Object.keys(init.headers as Record<string, string>).join(',')).not.toMatch(
      /internal|x-estate-service|api-key/i,
    );
  });

  it('encodes the owner id rather than interpolating it into the path', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, []));
    await new FetchAssetsClient(BASE, fetchFn).listEstate(TOKEN, '../../assets');
    const [url] = fetchFn.mock.calls[0] as [string];
    expect(url).toContain('%2F');
    expect(url).not.toContain('/../');
  });

  it('refuses a malformed estate list rather than half-trusting it', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, [{ assetId: ASSET.assetId }]));
    await expect(
      new FetchAssetsClient(BASE, fetchFn).listEstate(TOKEN, OWNER),
    ).rejects.toBeDefined();
  });

  it('maps a refused stage to a refusal, not to an empty estate', async () => {
    // Assets answers 403 when settlement says no approved `inventory` stage.
    // An empty array here would render as "this estate holds nothing", which is
    // a statement about a dead person's affairs made on no evidence at all.
    const fetchFn = jest.fn().mockResolvedValue(response(403, { error: 'forbidden' }));
    await expect(
      new FetchAssetsClient(BASE, fetchFn).listEstate(TOKEN, OWNER),
    ).rejects.toBeDefined();
  });

  it('GETs the detail and parses the full shape (list shape is refused there)', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, DETAIL));
    const client = new FetchAssetsClient(BASE, fetchFn);
    await expect(client.get(TOKEN, ASSET.assetId)).resolves.toEqual(DETAIL);
    expect((fetchFn.mock.calls[0] as [string, RequestInit])[0]).toBe(
      `${BASE}/v1/assets/${ASSET.assetId}`,
    );
    // A LIST row is not a detail: the detail schema requires the fields the
    // list deliberately lacks, so a version-skewed response is NO DATA.
    const skewed = jest.fn().mockResolvedValue(response(200, ASSET));
    await expect(new FetchAssetsClient(BASE, skewed).get(TOKEN, ASSET.assetId)).rejects.toThrow(
      'assets response failed validation',
    );
  });

  it('GETs history entries with their payloads', async () => {
    const entry = {
      version: '1',
      eventId: 'e2c2e6a4-0000-4000-8000-00000000000e',
      eventType: 'AssetCreated',
      occurredAt: '2026-08-01T00:00:00.000Z',
      actorId: 'a2c2e6a4-0000-4000-8000-00000000000b',
      payload: { v: 1, type: 'AssetCreated', category: 'cash', title: 'Checking' },
    };
    const fetchFn = jest.fn().mockResolvedValue(response(200, [entry]));
    await expect(
      new FetchAssetsClient(BASE, fetchFn).history(TOKEN, ASSET.assetId),
    ).resolves.toEqual([entry]);
    expect((fetchFn.mock.calls[0] as [string, RequestInit])[0]).toBe(
      `${BASE}/v1/assets/${ASSET.assetId}/events`,
    );
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
    const fetchFn = jest.fn().mockResolvedValue(response(201, ACK));
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
    const fetchFn = jest.fn().mockResolvedValue(response(201, ACK));
    await new FetchAssetsClient(BASE, fetchFn).create(TOKEN, {
      category: 'cash',
      title: 'Wallet',
    });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ category: 'cash', title: 'Wallet' });
  });

  it('forwards clientEventId as the wire eventId — the idempotency key', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(201, ACK));
    await new FetchAssetsClient(BASE, fetchFn).create(TOKEN, {
      category: 'cash',
      title: 'Wallet',
      clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
    });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({
      category: 'cash',
      title: 'Wallet',
      eventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
    });
  });

  it('PATCHes an update with If-Match, keeping nulls (clear) and dropping absents', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, ACK));
    await new FetchAssetsClient(BASE, fetchFn).updateDetails(
      TOKEN,
      ASSET.assetId,
      { title: 'Renamed', notes: null, clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c' },
      '2',
    );
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE}/v1/assets/${ASSET.assetId}`);
    expect(init.method).toBe('PATCH');
    expect((init.headers as Record<string, string>)['if-match']).toBe('2');
    // notes:null survives (the CLEAR); location is absent (unchanged); the
    // clientEventId travels as eventId.
    expect(JSON.parse(init.body as string)).toEqual({
      title: 'Renamed',
      notes: null,
      eventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
    });
  });

  it('POSTs valuations / ownership / retire to their command routes', async () => {
    const fetchFn = jest.fn().mockResolvedValue(response(200, ACK));
    const client = new FetchAssetsClient(BASE, fetchFn);
    await client.recordValuation(
      TOKEN,
      ASSET.assetId,
      { estValue: '1.00', valuationAsOf: '2026-08-01', valuationSource: 'market' },
      '2',
    );
    await client.changeOwnership(TOKEN, ASSET.assetId, { ownershipPct: 50, costBasis: null }, '3');
    await client.retire(TOKEN, ASSET.assetId, { reason: 'sold' }, '4');
    const urls = fetchFn.mock.calls.map((c) => (c as [string, RequestInit])[0]);
    expect(urls).toEqual([
      `${BASE}/v1/assets/${ASSET.assetId}/valuations`,
      `${BASE}/v1/assets/${ASSET.assetId}/ownership`,
      `${BASE}/v1/assets/${ASSET.assetId}/retire`,
    ]);
    const ownershipBody = JSON.parse(
      (fetchFn.mock.calls[1] as [string, RequestInit])[1].body as string,
    ) as Record<string, unknown>;
    expect(ownershipBody).toEqual({ ownershipPct: 50, costBasis: null });
    const versions = fetchFn.mock.calls.map(
      (c) => ((c as [string, RequestInit])[1].headers as Record<string, string>)['if-match'],
    );
    expect(versions).toEqual(['2', '3', '4']);
  });

  it('reads beneficiaries, designates with If-Match, and removes via query-string DELETE', async () => {
    const beneficiaries = {
      assetId: ASSET.assetId,
      beneficiaries: [
        { contactId: 'f0000000-0000-4000-8000-000000000001', designation: 'primary', sharePct: 60 },
      ],
      totals: [{ designation: 'primary', sharePct: 60, designationComplete: false }],
    };
    const readFn = jest.fn().mockResolvedValue(response(200, beneficiaries));
    await expect(
      new FetchAssetsClient(BASE, readFn).beneficiaries(TOKEN, ASSET.assetId),
    ).resolves.toEqual(beneficiaries);
    expect((readFn.mock.calls[0] as [string, RequestInit])[0]).toBe(
      `${BASE}/v1/assets/${ASSET.assetId}/beneficiaries`,
    );

    const designateFn = jest.fn().mockResolvedValue(response(201, ACK));
    await new FetchAssetsClient(BASE, designateFn).designateBeneficiary(
      TOKEN,
      ASSET.assetId,
      {
        contactId: 'f0000000-0000-4000-8000-000000000001',
        designation: 'primary',
        sharePct: 60,
        clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
      },
      '3',
    );
    const [designateUrl, designateInit] = designateFn.mock.calls[0] as [string, RequestInit];
    expect(designateUrl).toBe(`${BASE}/v1/assets/${ASSET.assetId}/beneficiaries`);
    expect((designateInit.headers as Record<string, string>)['if-match']).toBe('3');
    expect(JSON.parse(designateInit.body as string)).toEqual({
      contactId: 'f0000000-0000-4000-8000-000000000001',
      designation: 'primary',
      sharePct: 60,
      eventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
    });

    // A DELETE carries no body: designation AND the idempotency key ride the
    // query string, which is what the service route reads.
    const removeFn = jest.fn().mockResolvedValue(response(200, ACK));
    await new FetchAssetsClient(BASE, removeFn).removeBeneficiary(
      TOKEN,
      ASSET.assetId,
      'f0000000-0000-4000-8000-000000000001',
      'primary',
      'c1c2e6a4-0000-4000-8000-00000000000d',
      '4',
    );
    const [removeUrl, removeInit] = removeFn.mock.calls[0] as [string, RequestInit];
    expect(removeUrl).toBe(
      `${BASE}/v1/assets/${ASSET.assetId}/beneficiaries/f0000000-0000-4000-8000-000000000001?designation=primary&eventId=c1c2e6a4-0000-4000-8000-00000000000d`,
    );
    expect(removeInit.method).toBe('DELETE');
    expect((removeInit.headers as Record<string, string>)['if-match']).toBe('4');
    expect(removeInit.body).toBeUndefined();
  });

  it('remove without an eventId leaves it off the query string entirely', async () => {
    const removeFn = jest.fn().mockResolvedValue(response(200, ACK));
    await new FetchAssetsClient(BASE, removeFn).removeBeneficiary(
      TOKEN,
      ASSET.assetId,
      'f0000000-0000-4000-8000-000000000001',
      'primary',
    );
    const [removeUrl, removeInit] = removeFn.mock.calls[0] as [string, RequestInit];
    expect(removeUrl).toBe(
      `${BASE}/v1/assets/${ASSET.assetId}/beneficiaries/f0000000-0000-4000-8000-000000000001?designation=primary`,
    );
    expect((removeInit.headers as Record<string, string>)['if-match']).toBeUndefined();
  });

  it('share_sum_exceeded is its own code; a plain 422 stays INVALID_REQUEST', async () => {
    const overFn = jest.fn().mockResolvedValue(response(422, { error: 'share_sum_exceeded' }));
    await expect(
      new FetchAssetsClient(BASE, overFn).designateBeneficiary(
        TOKEN,
        ASSET.assetId,
        { contactId: 'f0000000-0000-4000-8000-000000000001', designation: 'primary', sharePct: 90 },
        '3',
      ),
    ).rejects.toMatchObject({ extensions: { code: 'SHARE_SUM_EXCEEDED' } });
    const plainFn = jest.fn().mockResolvedValue(response(422, { error: 'invalid_request' }));
    await expect(new FetchAssetsClient(BASE, plainFn).list(TOKEN)).rejects.toMatchObject({
      extensions: { code: 'INVALID_REQUEST' },
    });
  });

  it('maps errors on every read path, not only the list', async () => {
    const boom = () => jest.fn().mockResolvedValue(response(500, { error: 'internals' }));
    await expect(new FetchAssetsClient(BASE, boom()).netWorth(TOKEN)).rejects.toThrow(/status 500/);
    await expect(new FetchAssetsClient(BASE, boom()).history(TOKEN, ASSET.assetId)).rejects.toThrow(
      /status 500/,
    );
    await expect(new FetchAssetsClient(BASE, boom()).get(TOKEN, ASSET.assetId)).rejects.toThrow(
      /status 500/,
    );
  });

  it('maps the uniform 404 to NOT_FOUND and a stale If-Match to VERSION_CONFLICT', async () => {
    const notFound = jest.fn().mockResolvedValue(response(404, { error: 'not_found' }));
    await expect(
      new FetchAssetsClient(BASE, notFound).get(TOKEN, ASSET.assetId),
    ).rejects.toMatchObject({ extensions: { code: 'NOT_FOUND' } });
    const conflict = jest.fn().mockResolvedValue(response(409, { error: 'version_conflict' }));
    await expect(
      new FetchAssetsClient(BASE, conflict).retire(TOKEN, ASSET.assetId, {}, '1'),
    ).rejects.toMatchObject({ extensions: { code: 'VERSION_CONFLICT' } });
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
