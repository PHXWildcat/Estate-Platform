/**
 * Milestone 3 (second half) acceptance E2E: Plaid link → sync → signed
 * webhook → step-up-gated revocation, with every emitted audit event ingested
 * into the audit service's hash-chained store and the chain cryptographically
 * verified, every domain event validated as IDs/enums-only, and the TB5 token
 * firewall asserted across the bus.
 *
 * Transport note: the plaid producer and audit ingestor are bridged
 * in-process (the exact bytes plaid hands to Kafka are handed to the
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
  AuditEventSchema,
  PlaidItemLinkedEvent,
  PlaidItemStatusChangedEvent,
  PlaidItemSyncedEvent,
  TOPICS,
  type MfaLevel,
} from '@estate/contracts';
import { Migrator } from '@estate/db';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { AppModule } from '@estate/service-plaid/dist/app.module';
import { InMemoryAuditProducer } from '@estate/service-plaid/dist/audit-producer';
import { AUDIT_PRODUCER, PLAID_GATEWAY } from '@estate/service-plaid/dist/di-tokens';
import type { StubPlaidGateway } from '@estate/service-plaid/dist/stub-plaid-gateway';
import { AuditIngestor } from '@estate/service-audit/dist/ingestor';
import { ChainVerifier } from '@estate/service-audit/dist/verifier';

/**
 * A downstream service now VERIFIES the caller's bearer token instead of
 * trusting a header. This fake stands in for identity introspection (the real
 * cross-service path is covered by session-verification.e2e.spec.ts).
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

describeIfPg('plaid isolate: link/sync/webhook/revoke → audit chain + domain topic', () => {
  const stamp = Date.now();
  const financialSchema = `e2e_plaid_${stamp}`;
  const auditSchema = `e2e_plaid_audit_${stamp}`;
  const OWNER = randomUUID();
  let admin: Client;
  let auditDb: Client;
  let app: ReturnType<TestingModule['createNestApplication']>;
  let producer: InMemoryAuditProducer;
  let gateway: StubPlaidGateway;

  beforeAll(async () => {
    const baseUrl = process.env['PG_TEST_URL']!;
    admin = new Client({ connectionString: baseUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${financialSchema}`);
    await admin.query(`CREATE SCHEMA ${auditSchema}`);

    // --- plaid side: migrate, then boot the real Nest module ---
    const financialClient = new Client({
      connectionString: schemaScopedUrl(baseUrl, financialSchema),
    });
    await financialClient.connect();
    await new Migrator(financialClient, migrationsDirOf('@estate/service-plaid')).migrate();
    await financialClient.end();

    process.env['DATABASE_URL'] = schemaScopedUrl(baseUrl, financialSchema);
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['ITEM_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS']; // NODE_ENV=test ⇒ in-memory producer
    delete process.env['PLAID_MODE']; // ⇒ stub gateway

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
    // rawBody: webhook signature verification hashes the exact request bytes.
    app = moduleRef.createNestApplication({ rawBody: true });
    await app.init();
    producer = app.get<InMemoryAuditProducer>(AUDIT_PRODUCER);
    expect(producer).toBeInstanceOf(InMemoryAuditProducer);
    gateway = app.get<StubPlaidGateway>(PLAID_GATEWAY);

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

  it('runs the TB5 flow and produces a verifiable audit chain + valid domain events', async () => {
    const http = supertest(app.getHttpServer() as Parameters<typeof supertest>[0]);
    const owner = bearer('mfa', OWNER);
    const stepUp = bearer('stepup', OWNER);

    // link (capture the raw token so the firewall can hunt for it)
    const exchangeSpy = jest.spyOn(gateway, 'exchangePublicToken');
    const linked = await http
      .post('/v1/plaid/items')
      .set(owner)
      .send({ publicToken: 'public-stub-e2e' })
      .expect(201);
    const itemId = (linked.body as { id: string }).id;
    const exchanged = (await exchangeSpy.mock.results[0]!.value) as {
      accessToken: string;
      itemId: string;
    };

    // owner-initiated sync, then decrypted account read
    await http.post(`/v1/plaid/items/${itemId}/sync`).set(owner).expect(200);
    const accounts = await http.get('/v1/accounts').set(owner).expect(200);
    expect((accounts.body as unknown[]).length).toBe(2);

    // signed webhook flips the item to login_required; unsigned is rejected
    const webhookBody = JSON.stringify({
      webhook_type: 'ITEM',
      webhook_code: 'ITEM_LOGIN_REQUIRED',
      item_id: exchanged.itemId,
    });
    await http
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .send(webhookBody)
      .expect(401);
    await http
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .set('plaid-verification', gateway.signWebhook(webhookBody))
      .send(webhookBody)
      .expect(204);

    // revocation is a step-up action: refused without, allowed with
    await http.delete(`/v1/plaid/items/${itemId}`).set(owner).expect(403, {
      error: 'stepup_required',
    });
    await http.delete(`/v1/plaid/items/${itemId}`).set(stepUp).expect(204);
    await http.get('/v1/accounts').set(owner).expect(200, []);

    // --- bridge: exact produced audit bytes → audit ingestor ---
    const auditMessages = producer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    expect(auditMessages.length).toBeGreaterThanOrEqual(5);

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
      'plaid.item.linked',
      'plaid.item.synced',
      'plaid.item.login_required',
      'plaid.item.revoked',
      'plaid.webhook.rejected',
      'crypto.field.decrypted',
    ]) {
      expect(actions).toContain(required);
    }

    // --- domain topic: every envelope parses and carries IDs/enums only ---
    const domainMessages = producer.messages.filter((m) => m.topic === TOPICS.plaidEvents);
    expect(domainMessages.length).toBeGreaterThanOrEqual(3);
    for (const message of domainMessages) {
      const parsed = JSON.parse(message.value) as { type: string };
      const schema =
        parsed.type === 'plaid.item.linked'
          ? PlaidItemLinkedEvent
          : parsed.type === 'plaid.item.synced'
            ? PlaidItemSyncedEvent
            : PlaidItemStatusChangedEvent;
      const envelope = schema.parse(JSON.parse(message.value));
      expect(envelope.payload.itemId).toBe(itemId);
      expect(message.key).toBe(itemId);
    }

    // --- TB5 token firewall: nothing secret ever crosses the bus ---
    const allPayloads = producer.messages.map((m) => m.value).join('\n');
    expect(allPayloads).not.toContain(exchanged.accessToken);
    expect(allPayloads).not.toContain(exchanged.itemId);
    expect(allPayloads).not.toContain('First Stub Platypus Bank');
    expect(allPayloads).not.toContain('1240.55');
    expect(allPayloads).not.toContain('98230.10');
  });
});
