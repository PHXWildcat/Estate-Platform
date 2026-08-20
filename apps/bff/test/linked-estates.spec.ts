import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { FakeProfileClient, TOKENS, gql, gqlBody, makeApp } from './helpers';

/**
 * The linked-estates resolver (M22 PR4a).
 *
 * This edge forwards and does nothing else, which is itself the assertion
 * worth making: the disclosure decision, the audit record and the decrypt all
 * belong to profile, and a BFF that started coalescing a null name or caching
 * the answer would be making a call about somebody else's PII in the layer
 * with no key and no audit trail.
 */
describe('linkedEstates', () => {
  const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;
  const QUERY = 'query LinkedEstates { linkedEstates { ownerUserId contactId ownerName roles } }';

  let app: INestApplication;
  let profile: FakeProfileClient;

  beforeEach(async () => {
    profile = new FakeProfileClient();
    app = await makeApp({ profile });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the caller’s own bearer and returns what profile said', async () => {
    const res = await gql(app, { query: QUERY }, { cookie: COOKIE });
    expect(profile.linkedEstatesCalls).toEqual([TOKENS.accessToken]);
    expect(gqlBody(res).data?.['linkedEstates']).toEqual(profile.linkedEstatesResult);
  });

  it('passes a null owner name through instead of coalescing it', async () => {
    // The null is profile saying "this owner has no name on file". A default
    // invented here would be the BFF asserting what the key holder declined to.
    profile.linkedEstatesResult = [
      { ownerUserId: 'o1', contactId: 'c1', ownerName: null, roles: [] },
    ];
    const res = await gql(app, { query: QUERY }, { cookie: COOKIE });
    const [row] = gqlBody(res).data?.['linkedEstates'] as Array<Record<string, unknown>>;
    expect(row?.['ownerName']).toBeNull();
  });

  it('requires a session', async () => {
    const res = await gql(app, { query: QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(profile.linkedEstatesCalls).toEqual([]);
  });

  it('surfaces a downstream refusal as a code, never as an empty list', async () => {
    const { bffError } = await import('../src/identity-client');
    profile.profileError = bffError('UNAUTHENTICATED');
    const res = await gql(app, { query: QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(gqlBody(res).data?.['linkedEstates']).toBeFalsy();
  });
});
