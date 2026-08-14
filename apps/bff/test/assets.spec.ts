import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE, REFRESH_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  ASSET,
  FakeAssetsClient,
  FakeIdentityClient,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The first non-identity resolvers, and the 2026-07-23 decision's stated
 * end-state made real: the BFF FORWARDS THE CALLER'S OWN BEARER downstream.
 * The assertions here pin the exact token flow — cookie in, same value out —
 * because that is the security property; the data mapping is incidental.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;
const BOTH_COOKIES = `${COOKIE}; ${REFRESH_COOKIE}=${encodeURIComponent(TOKENS.refreshToken)}`;

/**
 * HAND-COPIES of the web app's asset documents (helpers.ts's Session copy
 * carries the full hazard note): the BFF does not depend on apps/web, so a
 * field added to the real documents and forgotten here leaves this suite
 * exercising a query no client sends. Keep in step with
 * apps/web/src/graphql/operations.ts.
 */
const ASSETS_QUERY =
  'query Assets($includeRetired: Boolean) { assets(includeRetired: $includeRetired) { assetId category title estValue valuationAsOf valuationSource ownershipPct inTrust fundingStatus status retiredAt version } }';
const ASSET_QUERY =
  'query Asset($assetId: ID!) { asset(assetId: $assetId) { assetId category title estValue valuationAsOf valuationSource ownershipPct costBasis location notes inTrust fundingStatus status retiredAt version } }';
const ASSET_HISTORY_QUERY =
  'query AssetHistory($assetId: ID!) { assetHistory(assetId: $assetId) { version eventId eventType occurredAt payload } }';
const NET_WORTH_QUERY =
  'query NetWorth { netWorth { totalValue assetCount valuedAssetCount inTrustValue } }';
const CREATE_ASSET_MUTATION =
  'mutation CreateAsset($input: CreateAssetInput!) { createAsset(input: $input) { assetId eventId version replayed } }';
const UPDATE_ASSET_MUTATION =
  'mutation UpdateAsset($assetId: ID!, $expectedVersion: String!, $title: String, $location: String, $notes: String, $inTrust: Boolean, $fundingStatus: String, $clientEventId: ID) { updateAsset(assetId: $assetId, expectedVersion: $expectedVersion, title: $title, location: $location, notes: $notes, inTrust: $inTrust, fundingStatus: $fundingStatus, clientEventId: $clientEventId) { assetId eventId version replayed } }';
const RETIRE_ASSET_MUTATION =
  'mutation RetireAsset($assetId: ID!, $expectedVersion: String!, $reason: String, $clientEventId: ID) { retireAsset(assetId: $assetId, expectedVersion: $expectedVersion, reason: $reason, clientEventId: $clientEventId) { assetId eventId version replayed } }';
const LOGOUT_MUTATION = 'mutation Logout { logout { ok } }';

describe('assets resolvers', () => {
  let app: INestApplication;
  let assets: FakeAssetsClient;

  beforeEach(async () => {
    assets = new FakeAssetsClient();
    app = await makeApp({ assets });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the CALLER’S bearer token, never anything the BFF minted', async () => {
    const res = await gql(app, { query: ASSETS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors).toBeUndefined();
    // The exact value from the httpOnly cookie — the whole trust model.
    expect(assets.listCalls).toEqual([{ accessToken: TOKENS.accessToken, includeRetired: false }]);
    expect(gqlBody(res).data?.['assets']).toEqual([
      {
        assetId: ASSET.assetId,
        category: 'cash',
        title: 'Checking account',
        estValue: '1200.50',
        valuationAsOf: '2026-07-01',
        valuationSource: 'owner_estimate',
        ownershipPct: 100,
        inTrust: false,
        fundingStatus: null,
        status: 'live',
        retiredAt: null,
        version: '3',
      },
    ]);
  });

  it('passes includeRetired through only when asked', async () => {
    await gql(
      app,
      { query: ASSETS_QUERY, variables: { includeRetired: true } },
      { cookie: COOKIE },
    );
    expect(assets.listCalls).toEqual([{ accessToken: TOKENS.accessToken, includeRetired: true }]);
  });

  it('refuses without a session cookie, before any downstream call', async () => {
    const res = await gql(app, { query: ASSETS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(assets.listCalls).toEqual([]);
  });

  it('serves the detail with the fields the list deliberately lacks', async () => {
    const res = await gql(
      app,
      { query: ASSET_QUERY, variables: { assetId: ASSET.assetId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.getCalls).toEqual([{ accessToken: TOKENS.accessToken, assetId: ASSET.assetId }]);
    const detail = gqlBody(res).data?.['asset'] as Record<string, unknown>;
    expect(detail['location']).toBe('top drawer of the desk');
    expect(detail['notes']).toBe('joint with Sam');
  });

  it('serves history entries with their validated payloads', async () => {
    const res = await gql(
      app,
      { query: ASSET_HISTORY_QUERY, variables: { assetId: ASSET.assetId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    const entries = gqlBody(res).data?.['assetHistory'] as Array<Record<string, unknown>>;
    expect(entries).toHaveLength(1);
    expect(entries[0]?.['eventType']).toBe('AssetCreated');
    expect(entries[0]?.['payload']).toEqual({
      v: 1,
      type: 'AssetCreated',
      category: 'cash',
      title: 'Checking account',
    });
  });

  it('updateAsset keeps NULL (clear) and ABSENT (unchanged) apart end to end', async () => {
    // The one distinction that must never blur: a blank field the user did
    // not touch stays untouched; an explicit clear travels as null.
    const res = await gql(
      app,
      {
        query: UPDATE_ASSET_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          title: 'Renamed',
          notes: null,
          // location deliberately NOT provided
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.commandCalls).toEqual([
      {
        method: 'updateDetails',
        accessToken: TOKENS.accessToken,
        assetId: ASSET.assetId,
        input: { title: 'Renamed', notes: null },
        expectedVersion: '3',
      },
    ]);
    expect(assets.commandCalls[0]?.input).not.toHaveProperty('location');

    // The other arms: a trust flip, an explicit fundingStatus CLEAR, and a
    // client-minted idempotency key all travel.
    const second = await gql(
      app,
      {
        query: UPDATE_ASSET_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '4',
          inTrust: true,
          fundingStatus: null,
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(second).errors).toBeUndefined();
    expect(assets.commandCalls[1]).toMatchObject({
      method: 'updateDetails',
      input: {
        inTrust: true,
        fundingStatus: null,
        clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
      },
      expectedVersion: '4',
    });
  });

  it('recordValuation and changeOwnership forward their commands intact', async () => {
    const VALUATION_MUTATION =
      'mutation RecordValuation($assetId: ID!, $expectedVersion: String!, $estValue: String!, $valuationAsOf: String!, $valuationSource: String!, $clientEventId: ID) { recordValuation(assetId: $assetId, expectedVersion: $expectedVersion, estValue: $estValue, valuationAsOf: $valuationAsOf, valuationSource: $valuationSource, clientEventId: $clientEventId) { assetId eventId version replayed } }';
    const OWNERSHIP_MUTATION =
      'mutation ChangeOwnership($assetId: ID!, $expectedVersion: String!, $ownershipPct: Float!, $costBasis: String, $clientEventId: ID) { changeOwnership(assetId: $assetId, expectedVersion: $expectedVersion, ownershipPct: $ownershipPct, costBasis: $costBasis, clientEventId: $clientEventId) { assetId eventId version replayed } }';

    const valuation = await gql(
      app,
      {
        query: VALUATION_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '3',
          estValue: '900000.00',
          valuationAsOf: '2026-08-13',
          valuationSource: 'appraisal',
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(valuation).errors).toBeUndefined();
    // costBasis: null travels as the explicit CLEAR; no clientEventId here so
    // none is invented for the wire.
    const ownership = await gql(
      app,
      {
        query: OWNERSHIP_MUTATION,
        variables: {
          assetId: ASSET.assetId,
          expectedVersion: '4',
          ownershipPct: 50,
          costBasis: null,
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(ownership).errors).toBeUndefined();
    expect(assets.commandCalls).toEqual([
      {
        method: 'recordValuation',
        accessToken: TOKENS.accessToken,
        assetId: ASSET.assetId,
        input: {
          estValue: '900000.00',
          valuationAsOf: '2026-08-13',
          valuationSource: 'appraisal',
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
        },
        expectedVersion: '3',
      },
      {
        method: 'changeOwnership',
        accessToken: TOKENS.accessToken,
        assetId: ASSET.assetId,
        input: { ownershipPct: 50, costBasis: null },
        expectedVersion: '4',
      },
    ]);
  });

  it('retireAsset forwards the expectedVersion and surfaces VERSION_CONFLICT', async () => {
    const first = await gql(
      app,
      {
        query: RETIRE_ASSET_MUTATION,
        variables: { assetId: ASSET.assetId, expectedVersion: '3', reason: 'sold' },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(first).errors).toBeUndefined();
    expect(assets.commandCalls[0]).toMatchObject({
      method: 'retire',
      input: { reason: 'sold' },
      expectedVersion: '3',
    });

    assets.commandError = bffError('VERSION_CONFLICT');
    const stale = await gql(
      app,
      {
        query: RETIRE_ASSET_MUTATION,
        variables: { assetId: ASSET.assetId, expectedVersion: '1' },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(stale).errors?.[0]?.extensions?.code).toBe('VERSION_CONFLICT');
  });

  it('serves net worth with money as decimal strings', async () => {
    const res = await gql(app, { query: NET_WORTH_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).data?.['netWorth']).toEqual({
      totalValue: '1200.50',
      assetCount: 1,
      valuedAssetCount: 1,
      inTrustValue: '0',
    });
    expect(assets.netWorthCalls).toEqual([TOKENS.accessToken]);
  });

  it('creates an asset with the FULL input, forwarding the bearer untouched', async () => {
    const res = await gql(
      app,
      {
        query: CREATE_ASSET_MUTATION,
        variables: {
          input: {
            category: 'real_estate',
            title: 'Lake house',
            ownershipPct: 50,
            inTrust: true,
            fundingStatus: 'funded',
            estValue: '99.10',
            valuationAsOf: '2026-07-01',
            valuationSource: 'owner_estimate',
            costBasis: '50.00',
            location: 'deed drawer',
            notes: 'shared with Sam',
            clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
          },
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(gqlBody(res).data?.['createAsset']).toMatchObject({ replayed: false });
    expect(assets.createCalls).toEqual([
      {
        accessToken: TOKENS.accessToken,
        input: {
          category: 'real_estate',
          title: 'Lake house',
          ownershipPct: 50,
          inTrust: true,
          fundingStatus: 'funded',
          costBasis: '50.00',
          location: 'deed drawer',
          notes: 'shared with Sam',
          clientEventId: 'c1c2e6a4-0000-4000-8000-00000000000c',
          valuation: {
            estValue: '99.10',
            valuationAsOf: '2026-07-01',
            valuationSource: 'owner_estimate',
          },
        },
      },
    ]);
  });

  it('REFUSES a partial valuation instead of forwarding one the ledger rejects', async () => {
    // estValue/valuationAsOf/valuationSource are all-or-nothing: an amount with
    // no date and no provenance is not an auditable claim, so the ledger
    // refuses it. Answering INVALID_REQUEST here beats a masked downstream 400.
    const res = await gql(
      app,
      {
        query: CREATE_ASSET_MUTATION,
        variables: { input: { category: 'cash', title: 'Partial', estValue: '10.00' } },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(assets.createCalls).toEqual([]);
  });

  it('omits the valuation entirely when no amount is given', async () => {
    await gql(
      app,
      { query: CREATE_ASSET_MUTATION, variables: { input: { category: 'cash', title: 'Wallet' } } },
      { cookie: COOKIE },
    );
    expect(assets.createCalls[0]?.input).toEqual({ category: 'cash', title: 'Wallet' });
  });

  it('surfaces downstream auth failures as stable codes, nothing else', async () => {
    assets.listError = bffError('UNAUTHENTICATED');
    const res = await gql(app, { query: ASSETS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
  });

  it('masks non-mapped downstream failures', async () => {
    assets.listError = new Error('assets responded with status 500: secret internals');
    const res = await gql(app, { query: ASSETS_QUERY }, { cookie: COOKIE });
    const message = gqlBody(res).errors?.[0]?.message ?? '';
    expect(message).not.toContain('secret internals');
  });
});

describe('logout', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  function expiredCookies(res: { headers: Record<string, unknown> }): string[] {
    const setCookie: unknown = res.headers['set-cookie'];
    const values: string[] = Array.isArray(setCookie) ? (setCookie as string[]) : [];
    return values.filter((cookie) => cookie.includes('Max-Age=0'));
  }

  it('revokes server-side FIRST, then expires both cookies', async () => {
    const res = await gql(app, { query: LOGOUT_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).data?.['logout']).toEqual({ ok: true });
    expect(identity.logoutCalls).toEqual([TOKENS.accessToken]);
    const cleared = expiredCookies(res);
    expect(cleared.some((c) => c.startsWith(`${ACCESS_COOKIE}=`))).toBe(true);
    expect(cleared.some((c) => c.startsWith(`${REFRESH_COOKIE}=`))).toBe(true);
    // Same attributes as the set path, or some browsers keep the cookie.
    for (const cookie of cleared) {
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('SameSite=Strict');
      expect(cookie).toContain('Path=/');
    }
  });

  it('clears cookies even with no session (idempotent from the browser’s view)', async () => {
    const res = await gql(app, { query: LOGOUT_MUTATION });
    expect(gqlBody(res).data?.['logout']).toEqual({ ok: true });
    expect(identity.logoutCalls).toEqual([]);
    expect(expiredCookies(res).length).toBe(2);
  });

  it('falls back to the REFRESH credential when the access token has expired', async () => {
    // The M8-review finding. identity's guarded logout route needs a live
    // ACCESS token (15 min) but the session and its refresh token live 30 days,
    // so a tab older than the access TTL gets a 401 — which used to be read as
    // "already logged out", revoking nothing while reporting success.
    identity.logoutResult = false;
    const res = await gql(app, { query: LOGOUT_MUTATION }, { cookie: BOTH_COOKIES });
    expect(gqlBody(res).data?.['logout']).toEqual({ ok: true });
    expect(identity.logoutCalls).toEqual([TOKENS.accessToken]);
    // The session IS revoked, through the credential that still resolves it.
    expect(identity.logoutByRefreshCalls).toEqual([TOKENS.refreshToken]);
    expect(expiredCookies(res)).toHaveLength(2);
  });

  it('does NOT clear cookies when the refresh fallback itself fails', async () => {
    identity.logoutResult = false;
    identity.logoutByRefreshError = new Error('identity unreachable');
    const res = await gql(app, { query: LOGOUT_MUTATION }, { cookie: BOTH_COOKIES });
    expect(gqlBody(res).errors?.length).toBeGreaterThan(0);
    expect(expiredCookies(res)).toEqual([]);
  });

  it('does not reach for the refresh credential when the access token worked', async () => {
    await gql(app, { query: LOGOUT_MUTATION }, { cookie: BOTH_COOKIES });
    expect(identity.logoutByRefreshCalls).toEqual([]);
  });
  it('does NOT clear cookies when revocation fails — no fake logouts', async () => {
    // The cookies are the only copies of the tokens. Clearing them after a
    // failed revocation would strand a live session only a thief could use,
    // while telling the user they are safely logged out.
    identity.logoutError = new Error('identity unreachable');
    const res = await gql(app, { query: LOGOUT_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.length).toBeGreaterThan(0);
    expect(expiredCookies(res)).toEqual([]);
  });
});
