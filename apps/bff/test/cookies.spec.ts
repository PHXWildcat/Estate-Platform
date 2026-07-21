import type { INestApplication } from '@nestjs/common';
import { parseCookies, serializeSessionCookie } from '../src/cookies';
import {
  FakeIdentityClient,
  gql,
  gqlBody,
  LOGIN_MUTATION,
  makeApp,
  sha256Hex,
  testConfig,
  TOKENS,
} from './helpers';

describe('cookie parser/serializer', () => {
  it('parses a cookie header, first occurrence winning', () => {
    const cookies = parseCookies('a=1; b=two; a=shadowed; c="quoted"');
    expect(cookies.get('a')).toBe('1');
    expect(cookies.get('b')).toBe('two');
    expect(cookies.get('c')).toBe('quoted');
  });

  it('handles missing/malformed headers', () => {
    expect(parseCookies(undefined).size).toBe(0);
    expect(parseCookies('garbage-without-equals').size).toBe(0);
    expect(parseCookies('=novalue; x=1').get('x')).toBe('1');
  });

  it('serializes httpOnly SameSite=Strict cookies, Secure only when asked', () => {
    expect(serializeSessionCookie('estate_access', 'v', false)).toBe(
      'estate_access=v; Path=/; HttpOnly; SameSite=Strict',
    );
    expect(serializeSessionCookie('estate_access', 'v', true)).toBe(
      'estate_access=v; Path=/; HttpOnly; SameSite=Strict; Secure',
    );
  });
});

function setCookieHeaders(res: { headers: Record<string, unknown> }): string[] {
  const header = res.headers['set-cookie'];
  if (Array.isArray(header)) {
    return header as string[];
  }
  return typeof header === 'string' ? [header] : [];
}

describe('login/refresh cookie behavior (dev-configured instance)', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeEach(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterEach(async () => {
    await app.close();
  });

  it('login sets httpOnly SameSite=Strict cookies and returns no token material', async () => {
    const res = await gql(app, {
      query: LOGIN_MUTATION,
      variables: { email: 'user@example.com', password: 'correct-horse-battery' },
    });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { login: { ok: true } } });

    const cookies = setCookieHeaders(res);
    const access = cookies.find((c) => c.startsWith('estate_access='));
    const refresh = cookies.find((c) => c.startsWith('estate_refresh='));
    expect(access).toBeDefined();
    expect(refresh).toBeDefined();
    for (const cookie of [access as string, refresh as string]) {
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('SameSite=Strict');
      expect(cookie).toContain('Path=/');
      expect(cookie).not.toContain('Secure');
    }

    // No token material anywhere in the response body.
    const bodyText = JSON.stringify(res.body);
    expect(bodyText).not.toContain(TOKENS.accessToken);
    expect(bodyText).not.toContain(TOKENS.refreshToken);
    expect(bodyText).not.toContain(TOKENS.sessionId);
  });

  it('refresh reads the estate_refresh cookie and re-sets both cookies', async () => {
    const res = await gql(
      app,
      { query: 'mutation Refresh { refresh { ok } }' },
      { cookie: 'estate_refresh=my-refresh-cookie-value' },
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { refresh: { ok: true } } });
    expect(identity.refreshCalls).toEqual(['my-refresh-cookie-value']);

    const cookies = setCookieHeaders(res);
    expect(cookies.some((c) => c.startsWith('estate_access='))).toBe(true);
    expect(cookies.some((c) => c.startsWith('estate_refresh='))).toBe(true);
  });

  it('refresh without the cookie is UNAUTHENTICATED and never calls identity', async () => {
    const res = await gql(app, { query: 'mutation Refresh { refresh { ok } }' });
    expect(gqlBody(res).data).toBeNull();
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(identity.refreshCalls).toHaveLength(0);
  });
});

describe('production-configured instance', () => {
  it('login cookies carry the Secure attribute', async () => {
    const identity = new FakeIdentityClient();
    const manifest = new Map([[sha256Hex(LOGIN_MUTATION), LOGIN_MUTATION]]);
    const app = await makeApp({
      identity,
      manifest,
      config: testConfig({ nodeEnv: 'production', persistedManifestPath: 'unused-in-test' }),
    });
    try {
      const res = await gql(app, {
        extensions: { persistedQuery: { version: 1, sha256Hash: sha256Hex(LOGIN_MUTATION) } },
        variables: { email: 'user@example.com', password: 'correct-horse-battery' },
      });
      expect(res.body).toEqual({ data: { login: { ok: true } } });
      const cookies = setCookieHeaders(res);
      expect(cookies.length).toBeGreaterThanOrEqual(2);
      for (const cookie of cookies) {
        expect(cookie).toContain('Secure');
        expect(cookie).toContain('HttpOnly');
        expect(cookie).toContain('SameSite=Strict');
      }
    } finally {
      await app.close();
    }
  });
});
