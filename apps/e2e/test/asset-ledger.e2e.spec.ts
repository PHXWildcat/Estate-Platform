/**
 * Milestone 3 acceptance E2E: create asset → step-up-gated beneficiary
 * designation → decrypted read → as-of temporal query, with every emitted
 * audit event ingested into the audit service's hash-chained store and the
 * chain cryptographically verified, and every domain event validated as
 * IDs/enums-only against the shared contract.
 *
 * Transport note: the assets producer and audit ingestor are bridged
 * in-process (the exact bytes assets hands to Kafka are handed to the
 * ingestor) — same deliberate M1 bridge, Kafka broker hop tracked in docs/04.
 *
 * Deep `dist` imports are sanctioned HERE ONLY: this is a test-only package;
 * runtime services never import each other (docs/04 boundary rule 4).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { Test, type TestingModule } from '@nestjs/testing';
import supertest from 'supertest';
import { Client } from 'pg';
import {
  AssetLedgerAppendedEvent,
  AuditEventSchema,
  TOPICS,
  type MfaLevel,
} from '@estate/contracts';
import { checkConventions, Migrator } from '@estate/db';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { AppModule } from '@estate/service-assets/dist/app.module';
import { InMemoryAuditProducer } from '@estate/service-assets/dist/audit-producer';
import { AUDIT_PRODUCER } from '@estate/service-assets/dist/di-tokens';
import { AuditIngestor } from '@estate/service-audit/dist/ingestor';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';

/**
 * A downstream service now VERIFIES the caller's bearer token instead of
 * trusting a header. This fake stands in for identity introspection: a token
 * `<level>:<userId>` verifies to that session (the real cross-service path is
 * covered by session-verification.e2e.spec.ts).
 */
const fakeVerifier: SessionVerifier = {
  verify: (token) => {
    const m = /^(mfa|stepup):([0-9a-f-]{36})$/.exec(token);
    if (!m) {
      return Promise.resolve(null);
    }
    const [, level, userId] = m;
    const ctx: SessionContext = {
      userId: userId!,
      sessionId: '00000000-0000-4000-8000-000000000000',
      mfaLevel: level as MfaLevel,
      stepupExpiresAt: level === 'stepup' ? new Date(Date.now() + 5 * 60 * 1000) : null,
    };
    return Promise.resolve(ctx);
  },
};
const bearer = (level: 'mfa' | 'stepup', userId: string): Record<string, string> => ({
  authorization: `Bearer ${level}:${userId}`,
});

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

function schemaScopedUrl(base: string, schema: string): string {
  const url = new URL(base);
  url.searchParams.set('options', `-c search_path=${schema}`);
  return url.toString();
}

describeIfPg('asset ledger: event-sourced commands → audit chain + domain topic', () => {
  const stamp = Date.now();
  const financialSchema = `e2e_financial_${stamp}`;
  const auditSchema = `e2e_fin_audit_${stamp}`;
  const OWNER = randomUUID();
  const CONTACT = randomUUID();
  const TITLE = 'Cabin at Bear Lake';
  const NOTES = 'deed stored with attorney';
  let admin: Client;
  let auditDb: Client;
  let app: ReturnType<TestingModule['createNestApplication']>;
  let producer: InMemoryAuditProducer;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${financialSchema}`);
    await admin.query(`CREATE SCHEMA ${auditSchema}`);

    // --- assets side: migrate, then boot the real Nest module ---
    const financialClient = new Client({
      connectionString: schemaScopedUrl(baseUrl, financialSchema),
    });
    await financialClient.connect();
    await new Migrator(financialClient, migrationsDirOf('@estate/service-assets')).migrate();
    await financialClient.end();

    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, financialSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS']; // NODE_ENV=test ⇒ in-memory producer

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
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
    await admin.query(`DROP SCHEMA ${financialSchema} CASCADE`);
    await admin.query(`DROP SCHEMA ${auditSchema} CASCADE`);
    await admin.end();
  });

  it('runs the ledger flow and produces a verifiable audit chain + valid domain events', async () => {
    const http = supertest(app.getHttpServer() as Parameters<typeof supertest>[0]);
    const owner = bearer('mfa', OWNER);
    const stepUp = bearer('stepup', OWNER);

    // create (encrypted payload + projection in one transaction)
    const created = await http
      .post('/v1/assets')
      .set(owner)
      .send({
        category: 'real_estate',
        title: TITLE,
        estValue: '325000.00',
        valuationAsOf: '2026-07-01',
        valuationSource: 'appraisal',
        notes: NOTES,
        inTrust: true,
      })
      .expect(201);
    const assetId = (created.body as { assetId: string }).assetId;

    // beneficiary change is a step-up action (docs/01 §5): refused without…
    await http
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(owner)
      .send({ contactId: CONTACT, designation: 'primary', sharePct: 100 })
      .expect(403, { error: 'stepup_required' });
    // …allowed with the gateway step-up assertion
    await http
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(stepUp)
      .send({ contactId: CONTACT, designation: 'primary', sharePct: 100 })
      .expect(201);

    // decrypted read for the owner; deny-by-default for anyone else
    const read = await http.get(`/v1/assets/${assetId}`).set(owner).expect(200);
    expect((read.body as { estValue: string }).estValue).toBe('325000.00');
    await http.get(`/v1/assets/${assetId}`).set(bearer('mfa', randomUUID())).expect(403);

    // temporal query: nothing held before the ledger began
    const empty = await http.get('/v1/assets?asOf=2020-01-01').set(owner).expect(200);
    expect(empty.body).toEqual([]);

    // --- bridge: exact produced audit bytes → audit ingestor ---
    const auditMessages = producer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    expect(auditMessages.length).toBeGreaterThanOrEqual(3);

    const ingestor = new AuditIngestor(auditDb);
    for (const message of auditMessages) {
      const result = await ingestor.ingest(message.value);
      expect(result.status).toBe('appended');
    }
    const verdict = await new ChainVerifier(auditDb).verify();
    expect(verdict).toEqual({ ok: true, count: auditMessages.length });

    const actions = new Set(
      auditMessages.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
    );
    for (const required of [
      'asset.created',
      'asset.beneficiary.designated',
      'crypto.field.decrypted',
    ]) {
      expect(actions).toContain(required);
    }

    // --- domain topic: every envelope parses and carries IDs/enums only ---
    const domainMessages = producer.messages.filter((m) => m.topic === TOPICS.assetEvents);
    expect(domainMessages.length).toBe(2); // AssetCreated + BeneficiaryDesignated
    for (const message of domainMessages) {
      const envelope = AssetLedgerAppendedEvent.parse(JSON.parse(message.value));
      expect(envelope.payload.assetId).toBe(assetId);
      expect(message.key).toBe(assetId);
    }

    // no values, titles, or notes ever cross the bus — audit OR domain topic
    const allPayloads = producer.messages.map((m) => m.value).join('\n');
    expect(allPayloads).not.toContain(TITLE);
    expect(allPayloads).not.toContain(NOTES);
    expect(allPayloads).not.toContain('325000');
  });

  it('the migrated financial schema satisfies the docs/02 conventions', async () => {
    const check = new Client({
      connectionString: schemaScopedUrl(process.env['PG_TEST_URL']!, financialSchema),
    });
    await check.connect();
    try {
      await expect(
        checkConventions(check, {
          schema: financialSchema,
          businessTables: ['asset_beneficiaries'],
          appendOnlyTables: ['asset_events'],
        }),
      ).resolves.toEqual([]);
    } finally {
      await check.end();
    }
  });
});
