import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const COOKIE = 'estate_access=the-access-token';

const STATUS_QUERY = 'query EmailVerification { emailVerification }';
const RESEND_MUTATION = 'mutation ResendEmailVerification { resendEmailVerification }';
const VERIFY_MUTATION = 'mutation VerifyEmail($code: String!) { verifyEmail(code: $code) { ok } }';

/**
 * The M14 surface at the edge.
 *
 * Two properties are worth pinning here rather than in the client: that the
 * enum crosses GraphQL as the THREE states the service reports (a boolean
 * would erase the one that is about the platform rather than the user), and
 * that the code reaches identity unchanged — canonicalizing at the edge would
 * be a second copy of a matching rule, which is how two copies drift.
 */
describe('email verification at the edge', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it.each([
    ['verified', 'VERIFIED'],
    ['unverified', 'UNVERIFIED'],
    ['unavailable', 'UNAVAILABLE'],
  ] as const)('carries the %s state across as %s', async (service, wire) => {
    identity.emailVerificationResult = service;
    const res = await gql(app, { query: STATUS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res)).toEqual({ data: { emailVerification: wire } });
    expect(identity.emailVerificationCalls).toEqual(['the-access-token']);
  });

  it('requires a session — it is a question about the caller', async () => {
    const res = await gql(app, { query: STATUS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.emailVerificationCalls).toHaveLength(0);
  });

  it.each([
    ['sent', 'SENT'],
    ['too_soon', 'TOO_SOON'],
    ['already_verified', 'ALREADY_VERIFIED'],
    ['unavailable', 'UNAVAILABLE'],
  ] as const)('reports the %s resend outcome as %s', async (service, wire) => {
    // Reported rather than flattened to a boolean: TOO_SOON is the re-issue
    // floor, the only rate limit on this path, and a caller told "sent" who
    // receives nothing keeps pressing.
    identity.resendEmailVerificationResult = service;
    const res = await gql(app, { query: RESEND_MUTATION }, { cookie: COOKIE });
    expect(gqlBody(res)).toEqual({ data: { resendEmailVerification: wire } });
  });

  it('passes the code through EXACTLY as submitted', async () => {
    // Identity measures and hashes the canonical form. A fold here would be a
    // second implementation of the same rule, free to disagree with the one
    // that decides.
    const res = await gql(
      app,
      { query: VERIFY_MUTATION, variables: { code: '  ev1-k7mn  ' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res)).toEqual({ data: { verifyEmail: { ok: true } } });
    expect(identity.verifyEmailCalls).toEqual([
      { accessToken: 'the-access-token', code: '  ev1-k7mn  ' },
    ]);
  });

  it('surfaces a refused code under its OWN code, not INVALID_CREDENTIALS', async () => {
    // INVALID_CREDENTIALS already means "email and password" on the login
    // surface. The M12 review's finding was exactly that collision: one token
    // changing meaning with the surface produced copy about a password on a
    // form that has none.
    identity.verifyEmailError = bffError('INVALID_VERIFICATION_CODE');
    const res = await gql(
      app,
      { query: VERIFY_MUTATION, variables: { code: 'nope' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_VERIFICATION_CODE');
  });

  it('keeps "could not complete" apart from "wrong code"', async () => {
    // The code was fine and there is nothing for the user to re-check, so the
    // remedies differ — which is the whole reason these are two tokens.
    identity.verifyEmailError = bffError('VERIFICATION_UNAVAILABLE');
    const res = await gql(
      app,
      { query: VERIFY_MUTATION, variables: { code: 'EV1-K7MN' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('VERIFICATION_UNAVAILABLE');
  });
});
