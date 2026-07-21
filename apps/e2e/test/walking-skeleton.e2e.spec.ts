/**
 * Milestone 1 acceptance E2E: register → login → TOTP → step-up → gated
 * action → refresh, with every emitted audit event ingested into the audit
 * service's hash-chained store and the chain cryptographically verified.
 *
 * Transport note: identity's producer and audit's ingestor are bridged
 * in-process (the exact bytes identity hands to Kafka are handed to the
 * ingestor). The Kafka broker hop itself is exercised once local/CI Redpanda
 * exists — tracked in docs/04 follow-ups.
 *
 * Deep `dist` imports are sanctioned HERE ONLY: this is a test-only package;
 * runtime services never import each other (docs/04 boundary rule 4).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import supertest from 'supertest';
import { Client } from 'pg';
import { TOPICS } from '@estate/contracts';
import { checkConventions, Migrator } from '@estate/db';
import { AppModule } from '@estate/service-identity/dist/app.module';
import { InMemoryAuditProducer } from '@estate/service-identity/dist/audit-producer';
import { AUDIT_PRODUCER } from '@estate/service-identity/dist/di-tokens';
import { currentTotpCode } from '@estate/service-identity/dist/totp';
import { AuditIngestor } from '@estate/service-audit/dist/ingestor';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

function schemaScopedUrl(base: string, schema: string): string {
  const url = new URL(base);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

describeIfPg('walking skeleton: identity → audit chain', () => {
  const stamp = Date.now();
  const authSchema = `e2e_auth_${stamp}`;
  const auditSchema = `e2e_audit_${stamp}`;
  let admin: Client;
  let auditDb: Client;
  // Typed via @nestjs/testing to avoid a direct @nestjs/common dependency in
  // this test-only package (it resolves to INestApplication).
  let app: ReturnType<TestingModule['createNestApplication']>;
  let producer: InMemoryAuditProducer;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${authSchema}`);
    await admin.query(`CREATE SCHEMA ${auditSchema}`);

    // --- identity side: migrate, then boot the real Nest module ---
    const authClient = new Client({ connectionString: schemaScopedUrl(baseUrl, authSchema) });
    await authClient.connect();
    await new Migrator(authClient, migrationsDirOf('@estate/service-identity')).migrate();
    await authClient.end();

    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, authSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['EMAIL_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS']; // NODE_ENV=test ⇒ in-memory producer

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    await app.init();
    producer = app.get<InMemoryAuditProducer>(AUDIT_PRODUCER);
    expect(producer).toBeInstanceOf(InMemoryAuditProducer);

    // --- audit side: migrate on its own schema-scoped session ---
    auditDb = new Client({ connectionString: schemaScopedUrl(baseUrl, auditSchema) });
    await auditDb.connect();
    await new Migrator(auditDb, migrationsDirOf('@estate/service-audit')).migrate();
  });

  afterAll(async () => {
    await app?.close();
    await auditDb?.end();
    await admin.query(`DROP SCHEMA ${authSchema} CASCADE`);
    await admin.query(`DROP SCHEMA ${auditSchema} CASCADE`);
    await admin.end();
  });

  it('runs the full auth flow and produces a verifiable audit chain', async () => {
    // getHttpServer() is typed `any` by Nest; assert to supertest's input type.
    const http = supertest(app.getHttpServer() as Parameters<typeof supertest>[0]);
    const email = `e2e-${randomUUID()}@example.com`;
    const password = 'correct-horse-battery-staple-9';

    await http.post('/v1/auth/register').send({ email, password }).expect(201);

    const login = await http.post('/v1/auth/login').send({ email, password }).expect(200);
    const { accessToken, refreshToken } = login.body as {
      accessToken: string;
      refreshToken: string;
    };
    const bearer = { Authorization: `Bearer ${accessToken}` };

    // step-up-gated action must be refused before step-up…
    await http.post('/v1/auth/export-demo').set(bearer).expect(403);

    const enroll = await http.post('/v1/auth/totp/enroll').set(bearer).expect(201);
    const otpauthUri = (enroll.body as { otpauthUri: string }).otpauthUri;
    expect(otpauthUri).not.toContain(email); // provisioning URI carries no PII
    const secret = new URL(otpauthUri).searchParams.get('secret')!;

    await http
      .post('/v1/auth/totp/verify')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);
    await http
      .post('/v1/auth/stepup')
      .set(bearer)
      .send({ code: currentTotpCode(secret) })
      .expect(200);

    // …and allowed within the fresh 5-minute window.
    await http.post('/v1/auth/export-demo').set(bearer).expect(204);

    // refresh rotation still works end to end
    await http.post('/v1/auth/refresh').send({ refreshToken }).expect(200);

    // --- bridge: exact produced bytes → audit ingestor ---
    const auditMessages = producer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    expect(auditMessages.length).toBeGreaterThanOrEqual(4);

    const ingestor = new AuditIngestor(auditDb);
    for (const message of auditMessages) {
      const result = await ingestor.ingest(message.value);
      expect(result.status).toBe('appended');
    }

    const verdict = await new ChainVerifier(auditDb).verify();
    expect(verdict).toEqual({ ok: true, count: auditMessages.length });

    const actions = new Set(
      auditMessages.map((m) => (JSON.parse(m.value) as { action: string }).action),
    );
    for (const required of [
      'auth.user.registered',
      'auth.login.succeeded',
      'crypto.field.decrypted',
      'auth.stepup.granted',
    ]) {
      expect(actions).toContain(required);
    }

    // no token material or PII ever crosses the audit bus
    const allPayloads = auditMessages.map((m) => m.value).join('\n');
    expect(allPayloads).not.toContain(email);
    expect(allPayloads).not.toContain(accessToken);
    expect(allPayloads).not.toContain(refreshToken);
  });

  it('both migrated schemas satisfy the docs/02 conventions', async () => {
    const authCheck = new Client({
      connectionString: schemaScopedUrl(process.env['PG_TEST_URL']!, authSchema),
    });
    await authCheck.connect();
    try {
      await expect(
        checkConventions(authCheck, {
          schema: authSchema,
          businessTables: ['users'],
          appendOnlyTables: ['auth_events'],
        }),
      ).resolves.toEqual([]);
    } finally {
      await authCheck.end();
    }

    await expect(
      checkConventions(auditDb, { schema: auditSchema, appendOnlyTables: ['audit_events'] }),
    ).resolves.toEqual([]);
  });
});
