import type { INestApplication } from '@nestjs/common';
import {
  FakeIdentityClient,
  gql,
  gqlBody,
  makeApp,
  SESSION_QUERY,
  sha256Hex,
  testConfig,
} from './helpers';

const SESSION_HASH = sha256Hex(SESSION_QUERY);

function persistedBody(hash: string): Record<string, unknown> {
  return { extensions: { persistedQuery: { version: 1, sha256Hash: hash } } };
}

describe('persisted operations in production mode', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await makeApp({
      identity: new FakeIdentityClient(),
      manifest: new Map([[SESSION_HASH, SESSION_QUERY]]),
      config: testConfig({ nodeEnv: 'production', persistedManifestPath: 'unused-in-test' }),
    });
  });

  afterAll(async () => {
    await app.close();
  });

  it('rejects arbitrary operations with a generic error', async () => {
    const res = await gql(app, { query: SESSION_QUERY });
    expect(gqlBody(res).data).toBeUndefined();
    expect(gqlBody(res).errors?.[0]?.message).toBe('Operation not allowed');
  });

  it('executes an operation from the manifest by hash', async () => {
    const res = await gql(app, persistedBody(SESSION_HASH));
    expect(res.body).toEqual({ data: { session: null } });
  });

  it('rejects an unknown hash with a generic error', async () => {
    const res = await gql(app, persistedBody(sha256Hex('query Nope { session { userId } }')));
    expect(gqlBody(res).data).toBeUndefined();
    expect(gqlBody(res).errors?.[0]?.message).toBe('Operation not allowed');
  });

  it('blocks introspection even if an introspection document sneaks into the manifest', async () => {
    const introspection = 'query Introspect { __schema { queryType { name } } }';
    const manifest = new Map([[sha256Hex(introspection), introspection]]);
    const prodApp = await makeApp({
      manifest,
      config: testConfig({ nodeEnv: 'production', persistedManifestPath: 'unused-in-test' }),
    });
    try {
      const res = await gql(prodApp, persistedBody(sha256Hex(introspection)));
      expect(gqlBody(res).data).toBeUndefined();
      expect(gqlBody(res).errors?.[0]?.message).toBe('GraphQL introspection is disabled');
    } finally {
      await prodApp.close();
    }
  });
});

describe('persisted operations in dev mode', () => {
  it('allows arbitrary operations and still serves manifest hashes', async () => {
    const app = await makeApp({ manifest: new Map([[SESSION_HASH, SESSION_QUERY]]) });
    try {
      const arbitrary = await gql(app, { query: '{ session { userId } }' });
      expect(arbitrary.body).toEqual({ data: { session: null } });

      const persisted = await gql(app, persistedBody(SESSION_HASH));
      expect(persisted.body).toEqual({ data: { session: null } });
    } finally {
      await app.close();
    }
  });
});
