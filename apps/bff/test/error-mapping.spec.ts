import type { INestApplication } from '@nestjs/common';
import { GraphQLError } from 'graphql';
import { FetchIdentityClient, type FetchFn } from '../src/identity-client';
import { gql, gqlBody, makeApp } from './helpers';

const RAW_TEXT = 'RAW_IDENTITY_INTERNAL_DETAIL_do_not_leak';

interface RecordedCall {
  url: string;
  init: RequestInit;
}

function stubFetch(status: number, body: unknown): { fetchFn: FetchFn; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetchFn: FetchFn = (url, init) => {
    calls.push({ url, init });
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
      }),
    );
  };
  return { fetchFn, calls };
}

async function appWith(status: number, body: unknown): Promise<INestApplication> {
  const { fetchFn } = stubFetch(status, body);
  return makeApp({ identity: new FetchIdentityClient('http://identity.test', fetchFn) });
}

describe('identity error mapping through the GraphQL surface', () => {
  it('maps identity 401 to UNAUTHENTICATED without leaking response text', async () => {
    const app = await appWith(401, { error: 'unauthorized', detail: RAW_TEXT });
    try {
      const res = await gql(
        app,
        { query: 'mutation Enroll { totpEnroll { otpauthUri } }' },
        { cookie: 'estate_access=tok' },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
      expect(JSON.stringify(res.body)).not.toContain(RAW_TEXT);
      expect(JSON.stringify(res.body)).not.toContain('unauthorized');
    } finally {
      await app.close();
    }
  });

  it('maps identity 403 stepup_required to STEPUP_REQUIRED', async () => {
    const app = await appWith(403, { error: 'stepup_required', detail: RAW_TEXT });
    try {
      const res = await gql(
        app,
        { query: 'mutation Demo { exportDemo { ok } }' },
        { cookie: 'estate_access=tok' },
      );
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
      expect(JSON.stringify(res.body)).not.toContain(RAW_TEXT);
    } finally {
      await app.close();
    }
  });

  it('maps login 401 invalid_credentials to INVALID_CREDENTIALS', async () => {
    const app = await appWith(401, { error: 'invalid_credentials' });
    try {
      const res = await gql(app, {
        query: 'mutation L { login(email: "a@b.c", password: "x") { ok } }',
      });
      expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('INVALID_CREDENTIALS');
    } finally {
      await app.close();
    }
  });

  it('masks unexpected identity failures (5xx) into a generic message', async () => {
    const app = await appWith(500, { error: 'internal_error', detail: RAW_TEXT });
    try {
      const res = await gql(app, {
        query: 'mutation L { login(email: "a@b.c", password: "x") { ok } }',
      });
      const text = JSON.stringify(res.body);
      expect(gqlBody(res).errors?.length).toBe(1);
      expect(text).not.toContain(RAW_TEXT);
      expect(text).not.toContain('internal_error');
      expect(text).not.toContain('500');
    } finally {
      await app.close();
    }
  });
});

describe('FetchIdentityClient unit behavior', () => {
  it('posts JSON credentials to /v1/auth/login and returns parsed tokens', async () => {
    const tokens = {
      accessToken: 'a',
      refreshToken: 'r',
      sessionId: 's',
      userId: 'u',
    };
    const { fetchFn, calls } = stubFetch(200, tokens);
    const client = new FetchIdentityClient('http://identity.test', fetchFn);
    await expect(client.login('a@b.c', 'pw')).resolves.toEqual(tokens);
    expect(calls[0]?.url).toBe('http://identity.test/v1/auth/login');
    expect(calls[0]?.init.method).toBe('POST');
    expect(JSON.parse(calls[0]?.init.body as string)).toEqual({ email: 'a@b.c', password: 'pw' });
  });

  it('forwards the access token as a Bearer header and treats 401 as null session', async () => {
    const { fetchFn, calls } = stubFetch(401, { error: 'unauthorized' });
    const client = new FetchIdentityClient('http://identity.test', fetchFn);
    await expect(client.session('tok-123')).resolves.toBeNull();
    const headers = calls[0]?.init.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tok-123');
    expect(calls[0]?.url).toBe('http://identity.test/v1/auth/session');
    expect(calls[0]?.init.method).toBe('GET');
  });

  it('maps identity 400 to INVALID_REQUEST', async () => {
    const { fetchFn } = stubFetch(400, { error: 'invalid_request' });
    const client = new FetchIdentityClient('http://identity.test', fetchFn);
    const err = await client.register('bad', 'pw').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GraphQLError);
    expect((err as GraphQLError).extensions.code).toBe('INVALID_REQUEST');
  });

  it('maps invalid_code on TOTP verification to INVALID_CREDENTIALS', async () => {
    const { fetchFn } = stubFetch(401, { error: 'invalid_code' });
    const client = new FetchIdentityClient('http://identity.test', fetchFn);
    const err = await client.totpVerify('tok', '000000').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GraphQLError);
    expect((err as GraphQLError).extensions.code).toBe('INVALID_CREDENTIALS');
  });

  it('turns network failures into a generic non-GraphQL error (masked by yoga)', async () => {
    const fetchFn: FetchFn = () => Promise.reject(new Error(`ECONNREFUSED ${RAW_TEXT}`));
    const client = new FetchIdentityClient('http://identity.test', fetchFn);
    const err = await client.login('a@b.c', 'pw').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(GraphQLError);
    expect((err as Error).message).toBe('identity service unreachable');
  });
});
