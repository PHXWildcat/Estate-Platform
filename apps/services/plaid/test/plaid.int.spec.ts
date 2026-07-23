/**
 * End-to-end integration test against a real Postgres, gated exactly like the
 * other services: set PG_TEST_URL to run (CI service container). Runs the
 * service's real migrations into a scratch schema, boots the Nest app over it
 * with the stub gateway + in-memory audit producer, and drives the full TB5
 * flow: link → sync → read accounts → signed webhook → step-up-gated revoke —
 * with the token firewall asserted at every layer.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { checkConventions, Migrator } from '@estate/db';
import { TOPICS, AuditEventSchema, type MfaLevel } from '@estate/contracts';
import { DekConflictError, type FieldCrypto } from '@estate/crypto';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { PgDekRepository } from '../src/dek.repository';
import { AUDIT_PRODUCER, FIELD_CRYPTO, PG_POOL_CONFIG, PLAID_GATEWAY } from '../src/di-tokens';
import type { StubPlaidGateway } from '../src/stub-plaid-gateway';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const STRANGER = randomUUID();

/**
 * Stands in for real identity introspection: a bearer token `<level>:<userId>`
 * verifies to that session (what CallerGuard would get from HttpSessionVerifier
 * → identity's /v1/auth/session); a malformed token verifies to null (⇒ 401).
 * The real cross-service path is proven in the session-verification e2e.
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

describeIfPg('plaid isolating service end to end', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `plaidsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;
  let gateway: StubPlaidGateway;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Version-capture triggers INSERT into unqualified *_versions names; the
    // admin connection needs the scratch schema on its search_path too.
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_plaid_schema.sql');
    } finally {
      await migrClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    process.env['ITEM_INDEX_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];
    delete process.env['PLAID_MODE'];

    producer = new InMemoryAuditProducer();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
    // rawBody: webhook signature verification hashes the exact request bytes.
    app = moduleRef.createNestApplication({ logger: false, rawBody: true });
    await app.init();
    server = app.getHttpServer() as Server;
    gateway = app.get<StubPlaidGateway>(PLAID_GATEWAY);
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  const asOwner = (): Record<string, string> => bearer('mfa', OWNER);

  let itemId: string;
  let plaidItemId: string;
  let rawAccessToken: string;

  it('rejects a request with no bearer token, and one with a forged token (401)', async () => {
    await request(server).get('/v1/plaid/items').expect(401);
    await request(server).get('/v1/plaid/items').set('authorization', 'Bearer forged').expect(401);
  });

  it('issues a link token for the caller', async () => {
    const res = await request(server).post('/v1/plaid/link-token').set(asOwner()).expect(201);
    expect((res.body as { linkToken: string }).linkToken).toContain('link-stub-');
  });

  it('links an item: access token is ciphertext at rest, blind-indexed item id', async () => {
    // Capture what the stub hands the service so the firewall can hunt for it.
    const spy = jest.spyOn(gateway, 'exchangePublicToken');
    const res = await request(server)
      .post('/v1/plaid/items')
      .set(asOwner())
      .send({ publicToken: 'public-stub-int' })
      .expect(201);
    const view = res.body as { id: string; institutionId: string; status: string };
    itemId = view.id;
    expect(view.status).toBe('healthy');

    const exchanged = (await spy.mock.results[0]!.value) as {
      accessToken: string;
      itemId: string;
    };
    rawAccessToken = exchanged.accessToken;
    plaidItemId = exchanged.itemId;
    expect(rawAccessToken).toContain('access-stub-');

    const { rows } = await admin.query(
      `SELECT access_token_ct, item_id_ct, item_bidx FROM ${schema}.plaid_items WHERE id = $1`,
      [itemId],
    );
    const row = rows[0] as { access_token_ct: Buffer; item_id_ct: Buffer; item_bidx: Buffer };
    expect(row.access_token_ct.toString('utf8')).not.toContain(rawAccessToken);
    expect(row.item_id_ct.toString('utf8')).not.toContain(plaidItemId);
    expect(row.item_bidx.length).toBe(32);
  });

  it('duplicate link of the same Plaid item is refused by the blind-index unique guard', async () => {
    // The stub maps the same public token to the same Plaid item_id.
    await request(server)
      .post('/v1/plaid/items')
      .set(asOwner())
      .send({ publicToken: 'public-stub-int' })
      .expect(409);
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.plaid_items WHERE deleted_at IS NULL`,
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('syncs accounts: balances encrypted at rest, decrypted only for the owner', async () => {
    const res = await request(server)
      .post(`/v1/plaid/items/${itemId}/sync`)
      .set(asOwner())
      .expect(200);
    expect((res.body as { accountsUpserted: number }).accountsUpserted).toBe(2);

    const { rows } = await admin.query(
      `SELECT current_balance_ct FROM ${schema}.accounts WHERE deleted_at IS NULL`,
    );
    expect(rows).toHaveLength(2);
    for (const row of rows as Array<{ current_balance_ct: Buffer }>) {
      expect(row.current_balance_ct.toString('utf8')).not.toContain('1240.55');
      expect(row.current_balance_ct.toString('utf8')).not.toContain('98230.10');
    }

    const accounts = await request(server).get('/v1/accounts').set(asOwner()).expect(200);
    const balances = (accounts.body as Array<{ currentBalance: string }>)
      .map((a) => a.currentBalance)
      .sort();
    expect(balances).toEqual(['1240.55', '98230.10']);
  });

  it('a stranger cannot see, sync, or revoke the item (Cedar deny-by-default)', async () => {
    const asStranger = bearer('mfa', STRANGER);
    const list = await request(server).get('/v1/plaid/items').set(asStranger).expect(200);
    expect(list.body).toEqual([]);
    await request(server).post(`/v1/plaid/items/${itemId}/sync`).set(asStranger).expect(403);
    await request(server)
      .delete(`/v1/plaid/items/${itemId}`)
      .set(bearer('stepup', STRANGER))
      .expect(403);
  });

  it('accepts only a correctly signed webhook and flips status on ITEM_LOGIN_REQUIRED', async () => {
    const body = JSON.stringify({
      webhook_type: 'ITEM',
      webhook_code: 'ITEM_LOGIN_REQUIRED',
      item_id: plaidItemId,
    });
    // Unsigned → 401 + audited rejection, nothing changes.
    await request(server)
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .send(body)
      .expect(401);
    // Tampered body under a valid signature → 401.
    await request(server)
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .set('plaid-verification', gateway.signWebhook('{}'))
      .send(body)
      .expect(401);
    // Correctly signed → 204 and the item flips to login_required.
    await request(server)
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .set('plaid-verification', gateway.signWebhook(body))
      .send(body)
      .expect(204);
    const { rows } = await admin.query(`SELECT status FROM ${schema}.plaid_items WHERE id = $1`, [
      itemId,
    ]);
    expect((rows[0] as { status: string }).status).toBe('login_required');
  });

  it('a signed SYNC_UPDATES_AVAILABLE webhook re-syncs and heals the item', async () => {
    const body = JSON.stringify({
      webhook_type: 'TRANSACTIONS',
      webhook_code: 'SYNC_UPDATES_AVAILABLE',
      item_id: plaidItemId,
    });
    await request(server)
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .set('plaid-verification', gateway.signWebhook(body))
      .send(body)
      .expect(204);
    const { rows } = await admin.query(`SELECT status FROM ${schema}.plaid_items WHERE id = $1`, [
      itemId,
    ]);
    expect((rows[0] as { status: string }).status).toBe('healthy');
  });

  it('revocation requires step-up, then soft-deletes item and accounts (never rows)', async () => {
    await request(server).delete(`/v1/plaid/items/${itemId}`).set(asOwner()).expect(403);
    await request(server)
      .delete(`/v1/plaid/items/${itemId}`)
      .set(bearer('stepup', OWNER))
      .expect(204);

    const items = await admin.query(
      `SELECT status, deleted_at FROM ${schema}.plaid_items WHERE id = $1`,
      [itemId],
    );
    const item = items.rows[0] as { status: string; deleted_at: Date | null };
    expect(item.status).toBe('revoked');
    expect(item.deleted_at).not.toBeNull();
    const accounts = await admin.query(
      `SELECT count(*)::int AS live FROM ${schema}.accounts WHERE deleted_at IS NULL`,
    );
    expect((accounts.rows[0] as { live: number }).live).toBe(0);
    await request(server).get('/v1/accounts').set(asOwner()).expect(200, []);
  });

  it('concurrent first-writes cannot mint two active plaid DEKs (unique index + adoption)', async () => {
    const fieldCrypto = app.get<FieldCrypto>(FIELD_CRYPTO);
    const newUser = randomUUID();
    const dekIds = await Promise.all([1, 2, 3, 4].map(() => fieldCrypto.getOrCreateDek(newUser)));
    expect(new Set(dekIds).size).toBe(1);
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.plaid_deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [newUser],
    );
    expect((rows[0] as { n: number }).n).toBe(1);
  });

  it('translates a duplicate active-DEK insert to DekConflictError (23505)', async () => {
    const repo = app.get(PgDekRepository);
    const userId = randomUUID();
    const record = {
      userId,
      kekAlias: 'plaid/kek',
      wrappedKey: randomBytes(32),
      createdAt: new Date(),
      destroyedAt: null,
    };
    await repo.insert({ ...record, dekId: randomUUID() });
    await expect(repo.insert({ ...record, dekId: randomUUID() })).rejects.toBeInstanceOf(
      DekConflictError,
    );
  });

  it('token firewall: the raw access token appears NOWHERE — DB, events, or audit', async () => {
    expect(rawAccessToken).toContain('access-stub-'); // sanity: we really hold it
    // Every column of every row in this service's tables.
    for (const table of ['plaid_items', 'accounts', 'plaid_items_versions', 'accounts_versions']) {
      const { rows } = await admin.query(`SELECT to_jsonb(t)::text AS j FROM ${schema}.${table} t`);
      for (const row of rows as Array<{ j: string }>) {
        expect(row.j).not.toContain(rawAccessToken);
        expect(row.j).not.toContain(plaidItemId);
      }
    }
    // Every message this service ever produced.
    expect(producer.messages.length).toBeGreaterThan(0);
    for (const message of producer.messages) {
      expect(message.value).not.toContain(rawAccessToken);
      expect(message.value).not.toContain(plaidItemId);
      expect(message.value).not.toContain('First Stub Platypus Bank');
      expect(message.value).not.toContain('1240.55');
      if (message.topic === TOPICS.auditEvents) {
        AuditEventSchema.parse(JSON.parse(message.value)); // shape-valid, enum-only
      }
    }
    const actions = new Set(
      producer.messages
        .filter((m) => m.topic === TOPICS.auditEvents)
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
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
  });

  it('the migrated plaid schema satisfies the docs/02 conventions (checkConventions)', async () => {
    const violations = await checkConventions(
      { query: (text: string, values?: unknown[]) => admin.query(text, values) },
      {
        schema,
        businessTables: ['plaid_items', 'accounts'],
        appendOnlyTables: ['plaid_items_versions', 'accounts_versions'],
      },
    );
    expect(violations).toEqual([]);
  });
});
