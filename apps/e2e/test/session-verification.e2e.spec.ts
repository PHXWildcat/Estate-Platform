/**
 * Cross-service session-verification acceptance E2E: proves that a downstream
 * service (assets) accepts a caller ONLY after REAL verification of their
 * bearer token against the identity service — the upgrade that retires the M2
 * `x-estate-user-id` / `x-estate-stepup-verified` header trust.
 *
 * The assets app's SessionVerifier is a real `HttpSessionVerifier` whose
 * transport dispatches to identity's actual in-process `/v1/auth/session`
 * handler (SessionGuard → SQL session lookup). So a token minted by identity
 * login is verified by assets through identity introspection — the network hop
 * is bridged in-process, the same deliberate convention as the Kafka bridge in
 * the other E2Es. cacheTtlMs is 0 so a mid-test step-up is observed at once.
 *
 * Deep `dist` imports are sanctioned HERE ONLY: this is a test-only package;
 * runtime services never import each other (docs/04 boundary rule 4).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import supertest from 'supertest';
import { Client } from 'pg';
import { Migrator } from '@estate/db';
import { HttpSessionVerifier, SESSION_VERIFIER, type FetchLike } from '@estate/auth-guard';
import { AppModule as IdentityAppModule } from '@estate/service-identity/dist/app.module';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { AppModule as AssetsAppModule } from '@estate/service-assets/dist/app.module';
import { PG_POOL_CONFIG } from '@estate/service-assets/dist/di-tokens';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

function schemaScopedUrl(base: string, schema: string): string {
  const url = new URL(base);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

describeIfPg('cross-service session verification: assets ⟶ identity introspection', () => {
  const stamp = Date.now();
  const authSchema = `e2e_sv_auth_${stamp}`;
  const financialSchema = `e2e_sv_fin_${stamp}`;
  let admin: Client;
  let identityApp: ReturnType<TestingModule['createNestApplication']>;
  let assetsApp: ReturnType<TestingModule['createNestApplication']>;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${authSchema}`);
    await admin.query(`CREATE SCHEMA ${financialSchema}`);

    for (const [pkg, schema] of [
      ['@estate/service-identity', authSchema],
      ['@estate/service-assets', financialSchema],
    ] as const) {
      const client = new Client({ connectionString: schemaScopedUrl(baseUrl, schema) });
      await client.connect();
      await new Migrator(client, migrationsDirOf(pkg)).migrate();
      await client.end();
    }

    // --- identity (the session authority) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, authSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];
    const identityRef = await Test.createTestingModule({ imports: [IdentityAppModule] }).compile();
    identityApp = identityRef.createNestApplication({ logger: false });
    await identityApp.init();
    const identityHttp = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);

    // Real introspection transport: dispatch the verifier's HTTP call to
    // identity's in-process /v1/auth/session handler.
    const fetchImpl: FetchLike = async (url, init) => {
      const res = await identityHttp
        .get(new URL(url).pathname)
        .set('authorization', init.headers['authorization'] ?? '');
      return {
        ok: res.status >= 200 && res.status < 300,
        status: res.status,
        json: () => Promise.resolve(res.body as unknown),
      };
    };
    const verifier = new HttpSessionVerifier({
      identityUrl: 'http://identity.internal',
      cacheTtlMs: 0, // re-introspect every call so a mid-test step-up is seen at once
      fetchImpl,
    });

    // --- assets (the downstream verifier) ---
    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, financialSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];
    const assetsRef = await Test.createTestingModule({ imports: [AssetsAppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(verifier)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: schemaScopedUrl(baseUrl, financialSchema) })
      .compile();
    assetsApp = assetsRef.createNestApplication({ logger: false });
    await assetsApp.init();
  });

  afterAll(async () => {
    await assetsApp?.close();
    await identityApp?.close();
    await admin.query(`DROP SCHEMA ${authSchema} CASCADE`);
    await admin.query(`DROP SCHEMA ${financialSchema} CASCADE`);
    await admin.end();
  });

  it('assets accepts a caller only after verifying their identity-minted token', async () => {
    const identity = supertest(identityApp.getHttpServer() as Parameters<typeof supertest>[0]);
    const assets = supertest(assetsApp.getHttpServer() as Parameters<typeof supertest>[0]);

    const email = `sv-${randomUUID()}@example.com`;
    const password = `Pw-${randomBytes(18).toString('base64url')}`;
    await identity.post('/v1/auth/register').send({ email, password }).expect(201);
    const login = await identity.post('/v1/auth/login').send({ email, password }).expect(200);
    const { accessToken } = login.body as { accessToken: string };
    const bearer = { authorization: `Bearer ${accessToken}` };

    // No token and a forged token are both rejected — the header is gone; only a
    // real, identity-verified session gets in.
    await assets.get('/v1/assets').expect(401, { error: 'unauthorized' });
    await assets.get('/v1/assets').set('authorization', 'Bearer forged').expect(401);

    // A genuine identity-minted token is verified across the service boundary.
    const created = await assets
      .post('/v1/assets')
      .set(bearer)
      .send({ category: 'cash', title: 'Verified Checking' })
      .expect(201);
    const assetId = (created.body as { assetId: string }).assetId;
    const list = await assets.get('/v1/assets').set(bearer).expect(200);
    expect((list.body as unknown[]).length).toBe(1);

    // The step-up-gated beneficiary route is refused: the session exists but is
    // not stepped up (mfa_level != 'stepup').
    await assets
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(bearer)
      .send({ contactId: randomUUID(), designation: 'primary', sharePct: 100 })
      .expect(403, { error: 'stepup_required' });

    // Perform a REAL step-up on identity (TOTP enroll → verify → step-up)…
    const enroll = await identity.post('/v1/auth/totp/enroll').set(bearer).expect(201);
    const secret = new URL((enroll.body as { otpauthUri: string }).otpauthUri).searchParams.get(
      'secret',
    )!;
    await identity
      .post('/v1/auth/totp/verify')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);
    await identity
      .post('/v1/auth/stepup')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);

    // …and the SAME token now clears the gate, because assets re-introspects and
    // sees the fresh step-up on the session. Real cross-service freshness — no
    // boolean header could have carried this.
    await assets
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(bearer)
      .send({ contactId: randomUUID(), designation: 'primary', sharePct: 100 })
      .expect(201);
  });
});
