import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const REQUEST_MUTATION =
  'mutation RequestPasswordReset($email: String!) { requestPasswordReset(email: $email) { ok } }';
const COMPLETE_MUTATION =
  'mutation CompletePasswordReset($code: String!, $newPassword: String!) { ' +
  'completePasswordReset(code: $code, newPassword: $newPassword) { ok } }';

/**
 * The M20 PR3 password reset at the EDGE — the first ceremony in the product a
 * signed-OUT caller drives, which inverts the property every other new
 * mutation asserts: these two must work WITHOUT a session, because the caller
 * by definition has none, and they must never mint one, because identity
 * returns no tokens to mint it from.
 */
describe('password reset at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the request with NO session and the address unchanged', async () => {
    // No cookie header at all — the signed-out caller is the designed one.
    const res = await gql(app, {
      query: REQUEST_MUTATION,
      variables: { email: '  Mixed.Case@Example.TEST ' },
    });

    expect(gqlBody(res)).toEqual({ data: { requestPasswordReset: { ok: true } } });
    // UNCHANGED: identity normalizes and blind-indexes the address itself, and
    // a second normalizer here could resolve a different account than the one
    // this surface echoed back (the requestEmailChange rule).
    expect(identity.requestPasswordResetCalls).toEqual(['  Mixed.Case@Example.TEST ']);
  });

  it('forwards the completion with NO session, code and password unchanged', async () => {
    const res = await gql(app, {
      query: COMPLETE_MUTATION,
      variables: { code: 'pr1 abcd-efgh', newPassword: 'a-brand-new-passphrase' },
    });

    expect(gqlBody(res)).toEqual({ data: { completePasswordReset: { ok: true } } });
    // The canonical fold lives in identity; the password minimum is identity's
    // schema. Neither is re-derived at the edge.
    expect(identity.completePasswordResetCalls).toEqual([
      { code: 'pr1 abcd-efgh', newPassword: 'a-brand-new-passphrase' },
    ]);
  });

  it('sets NO cookie on completion — a reset signs you in nowhere', async () => {
    // Identity revoked every session and returned no tokens; a Set-Cookie here
    // would be the edge inventing a credential identity refused to mint (the
    // M15 PR4 lesson — an unauthenticated redemption must not confer
    // authority).
    const res = await gql(app, {
      query: COMPLETE_MUTATION,
      variables: { code: 'PR1-ABCD', newPassword: 'a-brand-new-passphrase' },
    });

    expect(gqlBody(res)).toEqual({ data: { completePasswordReset: { ok: true } } });
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('a stale cookie neither helps nor hurts either leg', async () => {
    // A browser mid-reset may well carry cookies for a session the reset (or a
    // hijacker) already revoked. The resolvers read no session, so a cookie's
    // presence must change nothing — asserted with junk that would fail any
    // introspection.
    const res = await gql(
      app,
      { query: REQUEST_MUTATION, variables: { email: 'reader@example.test' } },
      { cookie: 'estate_access=long-dead-token' },
    );

    expect(gqlBody(res)).toEqual({ data: { requestPasswordReset: { ok: true } } });
    expect(identity.requestPasswordResetCalls).toEqual(['reader@example.test']);
  });

  it('surfaces INVALID_VERIFICATION_CODE and INVALID_REQUEST apart on completion', async () => {
    // One is "the code is dead — ask for a new one", the other is "the new
    // password was refused". Different fields, different remedies.
    identity.completePasswordResetError = bffError('INVALID_VERIFICATION_CODE');
    const refused = await gql(app, {
      query: COMPLETE_MUTATION,
      variables: { code: 'PR1-WRONG', newPassword: 'a-brand-new-passphrase' },
    });
    expect(gqlBody(refused).errors?.[0]?.extensions?.code).toBe('INVALID_VERIFICATION_CODE');

    identity.completePasswordResetError = bffError('INVALID_REQUEST');
    const short = await gql(app, {
      query: COMPLETE_MUTATION,
      variables: { code: 'PR1-ABCD', newPassword: 'shrt' },
    });
    expect(gqlBody(short).errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
  });
});
