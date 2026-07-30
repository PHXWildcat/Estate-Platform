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

const ASSETS_QUERY =
  'query Assets { assets { assetId category title estValue ownershipPct inTrust version } }';
const NET_WORTH_QUERY =
  'query NetWorth { netWorth { totalValue assetCount valuedAssetCount inTrustValue } }';
const CREATE_ASSET_MUTATION =
  'mutation CreateAsset($category: String!, $title: String!, $estValue: String, $valuationAsOf: String, $valuationSource: String) { createAsset(category: $category, title: $title, estValue: $estValue, valuationAsOf: $valuationAsOf, valuationSource: $valuationSource) { assetId version } }';
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
    expect(assets.listCalls).toEqual([TOKENS.accessToken]);
    expect(gqlBody(res).data?.['assets']).toEqual([
      {
        assetId: ASSET.assetId,
        category: 'cash',
        title: 'Checking account',
        estValue: '1200.50',
        ownershipPct: 100,
        inTrust: false,
        version: '3',
      },
    ]);
  });

  it('refuses without a session cookie, before any downstream call', async () => {
    const res = await gql(app, { query: ASSETS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(assets.listCalls).toEqual([]);
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

  it('creates an asset, forwarding the bearer and passing estValue through untouched', async () => {
    const res = await gql(
      app,
      {
        query: CREATE_ASSET_MUTATION,
        variables: {
          category: 'cash',
          title: 'Savings',
          estValue: '99.10',
          valuationAsOf: '2026-07-01',
          valuationSource: 'owner_estimate',
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(assets.createCalls).toEqual([
      {
        accessToken: TOKENS.accessToken,
        input: {
          category: 'cash',
          title: 'Savings',
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
        variables: { category: 'cash', title: 'Partial', estValue: '10.00' },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(assets.createCalls).toEqual([]);
  });

  it('omits the valuation entirely when no amount is given', async () => {
    await gql(
      app,
      { query: CREATE_ASSET_MUTATION, variables: { category: 'cash', title: 'Wallet' } },
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
