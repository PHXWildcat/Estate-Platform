import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, gqlBody, makeApp, SESSION_QUERY, TOKENS } from './helpers';

describe('session query', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('returns null without a cookie and never calls identity', async () => {
    const res = await gql(app, { query: SESSION_QUERY });
    expect(res.body).toEqual({ data: { session: null } });
    expect(identity.sessionCalls).toHaveLength(0);
  });

  it('forwards the access cookie as Bearer and maps a fresh step-up session', async () => {
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'stepup',
      stepupExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    const res = await gql(
      app,
      { query: SESSION_QUERY },
      { cookie: 'estate_access=the-access-token' },
    );
    expect(identity.sessionCalls).toEqual(['the-access-token']);
    expect(res.body).toEqual({
      data: {
        session: { userId: TOKENS.userId, mfaLevel: 'STEPUP', stepUpFresh: true },
      },
    });
    // sessionId is deliberately not exposed.
    expect(JSON.stringify(res.body)).not.toContain(TOKENS.sessionId);
  });

  it('computes stepUpFresh=false for an expired step-up window', async () => {
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'mfa',
      stepupExpiresAt: new Date(Date.now() - 1_000).toISOString(),
    };
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=tok' });
    expect(gqlBody(res).data?.session).toEqual({
      userId: TOKENS.userId,
      mfaLevel: 'MFA',
      stepUpFresh: false,
    });
  });

  it('computes stepUpFresh=false when identity reports no step-up at all', async () => {
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'none',
      stepupExpiresAt: null,
    };
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=tok' });
    expect(gqlBody(res).data?.session).toEqual({
      userId: TOKENS.userId,
      mfaLevel: 'NONE',
      stepUpFresh: false,
    });
  });

  it('returns null when identity rejects the token (401 → null)', async () => {
    identity.sessionResult = null;
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=stale' });
    expect(res.body).toEqual({ data: { session: null } });
    expect(identity.sessionCalls).toEqual(['stale']);
  });

  it('authenticated mutations forward the cookie token to identity', async () => {
    const res = await gql(
      app,
      { query: 'mutation Enroll { totpEnroll { otpauthUri } }' },
      { cookie: 'estate_access=enroll-tok' },
    );
    expect(gqlBody(res).data).toEqual({
      totpEnroll: { otpauthUri: identity.totpEnrollResult.otpauthUri },
    });
    expect(identity.totpEnrollCalls).toEqual(['enroll-tok']);
  });

  it('authenticated mutations without a cookie are UNAUTHENTICATED', async () => {
    const res = await gql(app, { query: 'mutation Demo { exportDemo { ok } }' });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.exportDemoCalls).toHaveLength(0);
  });
});
