/**
 * The paired-devices operations at the edge (M16).
 *
 * The BFF adds no authority on any of these: identity decides, and the edge
 * forwards THE CALLER'S OWN bearer. So the assertions are the four this repo
 * makes of every resolver — the caller's token really was the one forwarded, a
 * cookie-less request calls nothing, a peer refusal arrives as a code the client
 * can act on, and no response leaks a value.
 */
import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp } from './helpers';
import { bffError } from '../src/identity-client';

const SESSIONS_QUERY =
  'query Sessions { sessions { sessionId audience createdAt expiresAt current } }';
const REVOKE =
  'mutation RevokeSession($sessionId: ID!) { revokeSession(sessionId: $sessionId) { ok } }';
const PAIR = 'mutation StartExtensionPairing { startExtensionPairing { code expiresAt } }';

const ACCESS_TOKEN = 'the-access-token';
const COOKIE = { cookie: `estate_access=${ACCESS_TOKEN}` };

describe('paired devices', () => {
  let identity: FakeIdentityClient;
  let app: INestApplication;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('names an audience it does not recognise UNKNOWN, and keeps the other rows', async () => {
    /*
     * THE ROWS SURVIVE, which is the whole finding: before this, a strict row
     * inside a `z.array` failed the entire parse, so one audience minted by an
     * identity deployed ahead of this build blanked the page a user opens to
     * revoke a credential they do not recognise.
     *
     * Three rows so the assertion can distinguish "kept the unknown one" from
     * "kept everything regardless", and `UNKNOWN` rather than `ACCOUNT` because
     * the failure mode that matters is telling somebody an unrecognised
     * credential is their own browser.
     */
    identity.sessionsResult = [
      { sessionId: 's-1', audience: 'account', createdAt: 'a', expiresAt: 'b', current: true },
      {
        sessionId: 's-2',
        audience: 'a-fifth-audience',
        createdAt: 'c',
        expiresAt: 'd',
        current: false,
      },
      { sessionId: 's-3', audience: 'operator', createdAt: 'e', expiresAt: 'f', current: false },
    ];
    const res = await gql(app, { query: SESSIONS_QUERY }, COOKIE);
    expect(gqlBody(res).data?.sessions).toEqual([
      expect.objectContaining({ sessionId: 's-1', audience: 'ACCOUNT' }),
      expect.objectContaining({ sessionId: 's-2', audience: 'UNKNOWN' }),
      expect.objectContaining({ sessionId: 's-3', audience: 'OPERATOR' }),
    ]);
    expect(gqlBody(res).errors).toBeUndefined();
  });

  it('lists sessions on the CALLER’S OWN bearer, carrying the audience', async () => {
    identity.sessionsResult = [
      {
        sessionId: 's-1',
        audience: 'extension',
        createdAt: '2026-08-10T12:00:00.000Z',
        expiresAt: '2026-09-09T12:00:00.000Z',
        current: false,
      },
    ];
    const res = await gql(app, { query: SESSIONS_QUERY }, COOKIE);
    expect(identity.sessionsCalls).toEqual([ACCESS_TOKEN]);
    // Mapped to the GraphQL enum, not passed through as the wire value — the
    // exhaustive Record is what makes a fourth audience a compile error.
    expect(gqlBody(res).data).toEqual({
      sessions: [
        {
          sessionId: 's-1',
          audience: 'EXTENSION',
          createdAt: '2026-08-10T12:00:00.000Z',
          expiresAt: '2026-09-09T12:00:00.000Z',
          current: false,
        },
      ],
    });
  });

  it('answers UNAUTHENTICATED without a cookie, and calls nothing', async () => {
    const res = await gql(app, { query: SESSIONS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(identity.sessionsCalls).toEqual([]);
  });

  it('surfaces a revoke refusal as NOT_FOUND — unknown and not-yours alike', async () => {
    // Identity answers a uniform 404 because the owner predicate is in its
    // UPDATE; the edge must not invent a distinction the service refused to
    // make, so both cases arrive here as one code.
    identity.revokeSessionError = bffError('NOT_FOUND');
    const res = await gql(app, { query: REVOKE, variables: { sessionId: 'nope' } }, COOKIE);
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('NOT_FOUND');
    expect(identity.revokeSessionCalls).toEqual([{ accessToken: ACCESS_TOKEN, sessionId: 'nope' }]);
  });

  it('revokes and returns ok', async () => {
    const res = await gql(app, { query: REVOKE, variables: { sessionId: 's-1' } }, COOKIE);
    expect(gqlBody(res).data).toEqual({ revokeSession: { ok: true } });
  });

  it('mints a pairing code, and a step-up refusal arrives as a code the UI can act on', async () => {
    const ok = await gql(app, { query: PAIR }, COOKIE);
    expect(identity.startExtensionPairingCalls).toEqual([ACCESS_TOKEN]);
    expect(gqlBody(ok).data).toEqual({
      startExtensionPairing: { code: 'EP1-TEST', expiresAt: '2026-08-10T12:10:00.000Z' },
    });

    identity.extensionPairingError = bffError('STEPUP_REQUIRED');
    const refused = await gql(app, { query: PAIR }, COOKIE);
    expect(gqlBody(refused).errors?.[0]?.extensions?.['code']).toBe('STEPUP_REQUIRED');
    expect(gqlBody(refused).data?.['startExtensionPairing']).toBeFalsy();
    // The refusal carries no pairing code anywhere in the response.
    expect(JSON.stringify(refused.body)).not.toContain('EP1-');
  });
});
