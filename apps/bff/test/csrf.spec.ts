import type { INestApplication } from '@nestjs/common';
import { FakeIdentityClient, gql, makeApp, SESSION_QUERY } from './helpers';

describe('CSRF header enforcement', () => {
  let app: INestApplication;
  let identity: FakeIdentityClient;

  beforeAll(async () => {
    identity = new FakeIdentityClient();
    app = await makeApp({ identity });
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects requests without x-estate-csrf before any resolver runs', async () => {
    const res = await gql(
      app,
      { query: SESSION_QUERY },
      { omitCsrf: true, cookie: 'estate_access=tok' },
    );
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'forbidden' });
    expect(identity.sessionCalls).toHaveLength(0);
  });

  it('rejects requests with a wrong header value', async () => {
    const res = await gql(app, { query: SESSION_QUERY }, { csrfValue: 'yes' });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'forbidden' });
    expect(identity.sessionCalls).toHaveLength(0);
  });

  it('lets requests with x-estate-csrf: 1 through to GraphQL', async () => {
    const res = await gql(app, { query: SESSION_QUERY });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ data: { session: null } });
  });
});
