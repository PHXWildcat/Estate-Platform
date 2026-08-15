import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';

const REQUEST_MUTATION =
  'mutation RequestEmailChange($currentPassword: String!, $newEmail: String!) { ' +
  'requestEmailChange(currentPassword: $currentPassword, newEmail: $newEmail) { ok } }';
const COMPLETE_MUTATION =
  'mutation CompleteEmailChange($code: String!) { completeEmailChange(code: $code) { ok } }';
const CANCEL_MUTATION = 'mutation CancelEmailChange { cancelEmailChange { ok } }';

const REQUEST_VARS = { currentPassword: 'the-passphrase', newEmail: 'new@example.test' };

/**
 * The M20 PR2 address change at the EDGE.
 *
 * The client spec pins the wire to identity; what belongs here is what only the
 * edge can get wrong — that each leg travels on the caller's own bearer with
 * its values unchanged, that nothing is re-validated on the way through, and
 * that refusals with different remedies stay different codes.
 *
 * THE THREE LEGS ARE THREE MUTATIONS, deliberately, rather than one with a
 * mode: they take different arguments, they are gated differently at identity
 * (asking is step-up gated, finishing and cancelling are not), and a single
 * mutation would have to accept the union of their inputs — which is how a
 * cancel arrives carrying a password nobody checked.
 */
describe('address change at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the request on the caller’s own bearer, values unchanged', async () => {
    const res = await gql(
      app,
      { query: REQUEST_MUTATION, variables: REQUEST_VARS },
      { cookie: COOKIE },
    );

    expect(gqlBody(res)).toEqual({ data: { requestEmailChange: { ok: true } } });
    // The BFF holds no credential of its own: whatever authority this call had
    // is the session the browser presented.
    expect(identity.requestEmailChangeCalls).toEqual([
      {
        accessToken: 'the-access-token',
        currentPassword: 'the-passphrase',
        newEmail: 'new@example.test',
      },
    ]);
  });

  it('does NOT re-validate or normalize the address — identity owns both', async () => {
    // A second copy of a validation rule at the edge is a copy free to drift
    // from the one that decides (the M12 upload-client rule), and normalizing
    // here would be worse still: identity lower-cases and blind-indexes the
    // address itself, so a second normalizer could stage a DIFFERENT address
    // than the one this surface echoed back to the user.
    const res = await gql(
      app,
      {
        query: REQUEST_MUTATION,
        variables: { currentPassword: 'p', newEmail: '  Mixed.Case@Example.TEST ' },
      },
      { cookie: COOKIE },
    );

    expect(gqlBody(res)).toEqual({ data: { requestEmailChange: { ok: true } } });
    expect(identity.requestEmailChangeCalls[0]?.newEmail).toBe('  Mixed.Case@Example.TEST ');
  });

  it('forwards the code on the caller’s own bearer, exactly as typed', async () => {
    // The canonical fold — case, separators, the confusable alphabet — lives in
    // identity and decides the digest compare. A fold here would be a second
    // matching rule free to disagree with the one that matters.
    const res = await gql(
      app,
      { query: COMPLETE_MUTATION, variables: { code: 'ec1 abcd-efgh' } },
      { cookie: COOKIE },
    );

    expect(gqlBody(res)).toEqual({ data: { completeEmailChange: { ok: true } } });
    expect(identity.completeEmailChangeCalls).toEqual([
      { accessToken: 'the-access-token', code: 'ec1 abcd-efgh' },
    ]);
  });

  it('forwards the cancel on the caller’s own bearer', async () => {
    const res = await gql(app, { query: CANCEL_MUTATION }, { cookie: COOKIE });

    expect(gqlBody(res)).toEqual({ data: { cancelEmailChange: { ok: true } } });
    expect(identity.cancelEmailChangeCalls).toEqual(['the-access-token']);
  });

  it.each([
    ['request', REQUEST_MUTATION, REQUEST_VARS, 'requestEmailChangeCalls'],
    ['complete', COMPLETE_MUTATION, { code: 'EC1-ABCD' }, 'completeEmailChangeCalls'],
    ['cancel', CANCEL_MUTATION, {}, 'cancelEmailChangeCalls'],
  ] as const)('the %s leg requires a session', async (_leg, query, variables, calls) => {
    const res = await gql(app, { query, variables });

    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity[calls]).toEqual([]);
  });

  it.each([
    ['INVALID_CREDENTIALS', 'the account password was wrong'],
    ['STEPUP_REQUIRED', 'a fresh factor is needed — conditional at identity'],
    ['CODE_REQUESTED_RECENTLY', 'the re-issue floor or the destination bound fired'],
    ['INVALID_REQUEST', 'the address was malformed, or is already this account’s'],
  ] as const)('surfaces %s (%s) on the request leg as its own code', async (code, _why) => {
    // Four remedies — re-check the password, find your authenticator, wait,
    // type a different address. Collapsing any pair sends somebody to do the
    // wrong thing, and CODE_REQUESTED_RECENTLY in particular is a control
    // firing, which the M9 rule says must not read as an outage.
    identity.requestEmailChangeError = bffError(code);

    const res = await gql(
      app,
      { query: REQUEST_MUTATION, variables: REQUEST_VARS },
      { cookie: COOKIE },
    );

    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe(code);
  });

  it('keeps identity’s UNIFORM refusal uniform on the completion leg', async () => {
    // Identity answers ONE `invalid_code` for a code that is unknown, expired,
    // spent, cancelled, attempt-exhausted, or whose address was registered by
    // somebody else during the window — deliberately, so that whoever is
    // guessing at an owner's pending change gets no progress meter, and so
    // "taken" never leaks another account's existence. The edge's job is to
    // carry that uniformity through, not to re-derive distinctions from it.
    identity.completeEmailChangeError = bffError('INVALID_VERIFICATION_CODE');

    const res = await gql(
      app,
      { query: COMPLETE_MUTATION, variables: { code: 'EC1-WRONG' } },
      { cookie: COOKIE },
    );

    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_VERIFICATION_CODE');
  });
});
