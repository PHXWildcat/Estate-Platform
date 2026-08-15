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
      audience: 'account',
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
        session: {
          userId: TOKENS.userId,
          mfaLevel: 'STEPUP',
          stepUpFresh: true,
          // M16: identity has always sent this; the BFF used to strip it.
          audience: 'ACCOUNT',
        },
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
      audience: 'account',
      stepupExpiresAt: new Date(Date.now() - 1_000).toISOString(),
    };
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=tok' });
    expect(gqlBody(res).data?.session).toEqual({
      userId: TOKENS.userId,
      mfaLevel: 'MFA',
      stepUpFresh: false,
      audience: 'ACCOUNT',
    });
  });

  it('computes stepUpFresh=false when identity reports no step-up at all', async () => {
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'none',
      audience: 'account',
      stepupExpiresAt: null,
    };
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=tok' });
    expect(gqlBody(res).data?.session).toEqual({
      userId: TOKENS.userId,
      mfaLevel: 'NONE',
      stepUpFresh: false,
      audience: 'ACCOUNT',
    });
  });

  it('returns null when identity rejects the token and there is NOTHING to refresh with', async () => {
    identity.sessionResult = null;
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_access=stale' });
    expect(res.body).toEqual({ data: { session: null } });
    expect(identity.sessionCalls).toEqual(['stale']);
  });

  // SESSION CONTINUITY (M20 PR4): null and "refreshable" are different facts.
  // Returning null for a dead access token WITH a refresh cookie behind it is
  // what made the app render signed-out at the 15-minute access TTL while a
  // 30-day refresh token sat in the jar.
  it('throws UNAUTHENTICATED — not null — when only a refresh cookie is present', async () => {
    const res = await gql(app, { query: SESSION_QUERY }, { cookie: 'estate_refresh=long-lived' });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    // `session` is a NULLABLE field, so GraphQL nulls the FIELD and keeps
    // `data` an object — the web client keys on `errors` before `data`, which
    // is what makes this error win over the null and trigger the refresh.
    expect(gqlBody(res).data).toEqual({ session: null });
    // No access token to introspect: identity is never consulted.
    expect(identity.sessionCalls).toHaveLength(0);
  });

  it('throws UNAUTHENTICATED — not null — when identity rejects the access token but a refresh cookie remains', async () => {
    identity.sessionResult = null;
    const res = await gql(
      app,
      { query: SESSION_QUERY },
      { cookie: 'estate_access=stale; estate_refresh=long-lived' },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    // The dead token WAS presented first — the throw is the fallback, not a
    // shortcut past introspection (a live access token must keep winning).
    expect(identity.sessionCalls).toEqual(['stale']);
  });

  it('a live access token still answers normally when both cookies are present', async () => {
    identity.sessionResult = {
      userId: TOKENS.userId,
      sessionId: TOKENS.sessionId,
      mfaLevel: 'mfa',
      audience: 'account',
      stepupExpiresAt: null,
    };
    const res = await gql(
      app,
      { query: SESSION_QUERY },
      { cookie: 'estate_access=live; estate_refresh=long-lived' },
    );
    expect(gqlBody(res).data?.session).toMatchObject({ userId: TOKENS.userId });
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
