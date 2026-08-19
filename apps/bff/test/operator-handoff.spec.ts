import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';

const OPERATOR_MUTATION =
  'mutation StartOperatorHandoff { startOperatorHandoff { code expiresAt operatorOrigin } }';
const VAULT_MUTATION =
  'mutation StartVaultHandoff { startVaultHandoff { code expiresAt vaultOrigin } }';

/**
 * `startOperatorHandoff` (M21 PR3a).
 *
 * The BFF adds no authority here — identity's SessionGuard and StepUpGuard
 * decide, and this resolver forwards the caller's own bearer like every other
 * one. What it CONTRIBUTES is the operator origin, which only the deployment
 * knows.
 *
 * The load-bearing assertion is the LAST one: the two ceremonies must not share
 * a call path, because "the route is the selector" is the whole reason there
 * are two mint routes at identity instead of one taking an audience. A resolver
 * that reached the vault mint would put an operator user on a vault origin, and
 * one that took an audience from the wire would let a client choose.
 */
describe('startOperatorHandoff', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('mints on the caller’s own bearer and returns the operator origin', async () => {
    const res = await gql(app, { query: OPERATOR_MUTATION }, { cookie: COOKIE });

    expect(gqlBody(res)).toEqual({
      data: {
        startOperatorHandoff: {
          code: 'operator-handoff-code',
          expiresAt: '2026-08-08T00:01:00.000Z',
          operatorOrigin: 'http://operator.localhost:3011',
        },
      },
    });
    // The CALLER's token, forwarded. The BFF holds no credential for identity,
    // none for the operator origin, and none for settlement — so it could not
    // ask whether this caller is an operator even if it should.
    expect(identity.mintOperatorHandoffCalls).toEqual(['the-access-token']);
  });

  it('requires a session, and asks identity nothing without one', async () => {
    const res = await gql(app, { query: OPERATOR_MUTATION });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.mintOperatorHandoffCalls).toEqual([]);
  });

  it('surfaces STEPUP_REQUIRED so the UI prompts rather than fails', async () => {
    identity.operatorHandoffError = bffError('STEPUP_REQUIRED');
    const res = await gql(app, { query: OPERATOR_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
    expect(gqlBody(res).data?.startOperatorHandoff).toBeFalsy();
  });

  it('hands over NO origin when the mint failed', async () => {
    // The origin must never travel without a code. A page that received one
    // alone could render a form it cannot fill and post `code=` at the operator
    // origin — refused there, but a confusing way to arrive.
    identity.operatorHandoffError = bffError('OPERATOR_UNAVAILABLE');
    const res = await gql(app, { query: OPERATOR_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res).data?.startOperatorHandoff).toBeFalsy();
    expect(JSON.stringify(gqlBody(res))).not.toContain('operator.localhost');
  });

  it('puts the code in the body and in no header', async () => {
    const res = await gql(app, { query: OPERATOR_MUTATION }, { cookie: COOKIE });
    // No Set-Cookie, no Location, nothing. The app origin's only job is to put
    // it in a hidden field and submit a top-level POST.
    expect(JSON.stringify(res.headers)).not.toContain('operator-handoff-code');
  });

  it(`IS A DIFFERENT CEREMONY FROM THE VAULT'S, all the way down`, async () => {
    // Two mutations, two client methods, two identity routes, two audiences.
    // Nothing on the wire names an audience, so there is no field in which a
    // client could ask for the wrong one — which is only true while the two
    // paths stay separate.
    await gql(app, { query: OPERATOR_MUTATION }, { cookie: COOKIE });
    expect(identity.mintOperatorHandoffCalls).toHaveLength(1);
    expect(identity.mintVaultHandoffCalls).toHaveLength(0);

    await gql(app, { query: VAULT_MUTATION }, { cookie: COOKIE });
    expect(identity.mintOperatorHandoffCalls).toHaveLength(1);
    expect(identity.mintVaultHandoffCalls).toHaveLength(1);
  });

  it('carries no audience field a client could set', async () => {
    // Asking for one is a GraphQL validation error, not a silently ignored
    // argument: the schema has nowhere to put it.
    const res = await gql(
      app,
      { query: 'mutation { startOperatorHandoff(audience: "vault") { code } }' },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.message).toMatch(/Unknown argument "audience"/);
    expect(identity.mintOperatorHandoffCalls).toEqual([]);
  });
});
