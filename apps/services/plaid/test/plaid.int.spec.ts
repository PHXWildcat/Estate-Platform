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
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import {
  blindIndexCaptureCorpus,
  blindIndexCaptureGaps,
  checkConventions,
  Migrator,
} from '@estate/db';
import { TOPICS, AuditEventSchema, type MfaLevel } from '@estate/contracts';
import { DekConflictError, type FieldCrypto } from '@estate/crypto';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client, type QueryResultRow } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { InMemoryAuditProducer } from '@estate/kafka';
import { AccountsRepo } from '../src/accounts.repo';
import { Db, type Queryable } from '../src/db';
import { PgDekRepository } from '../src/dek.repository';
import { AUDIT_PRODUCER, FIELD_CRYPTO, PG_POOL_CONFIG, PLAID_GATEWAY } from '../src/di-tokens';
import { ItemsRepo } from '../src/items.repo';
import { PlaidGatewayError } from '../src/plaid-gateway';
import type { StubPlaidGateway } from '../src/stub-plaid-gateway';

/**
 * The status vocabulary, from the DDL rather than from memory: every `from`
 * the ladder drives below record must be a member. Pinned to the table so a
 * CHECK on some other table cannot be mistaken for this one's.
 */
function ddlItemStatuses(): string[] {
  // EVERY migration, in order, and the LAST definition wins — as it does in the
  // database. Migrations are append-only, so a widened vocabulary arrives as an
  // `ALTER TABLE … CHECK` in a new file, and a reader of 001's `CREATE TABLE`
  // alone reads the one statement that can never change. The ladder fence
  // learned this in M49 PR6's review; two spellings of one reading is how the
  // narrower one survives.
  const dir = join(__dirname, '..', 'migrations');
  const definitions: string[][] = [];
  for (const file of readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()) {
    const sql = readFileSync(join(dir, file), 'utf8');
    const scopes: string[] = [];
    const created = /CREATE TABLE\s+plaid_items\s*\(([\s\S]*?)\n\);/i.exec(sql);
    if (created) scopes.push(created[1] as string);
    for (const alter of sql.matchAll(/ALTER TABLE\s+plaid_items\b[\s\S]*?;/gi)) {
      scopes.push(alter[0]);
    }
    for (const scope of scopes) {
      for (const check of scope.matchAll(/CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)/gi)) {
        definitions.push(
          (check[1] as string).split(',').map((v) => v.trim().replace(/^'|'$/g, '')),
        );
      }
    }
  }
  expect(definitions.length).toBeGreaterThan(0);
  return definitions[definitions.length - 1] as string[];
}

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
      audience: 'account',
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

  // -------------------------------------------------------------------------
  // THE LADDER'S TWELVE EDGES, ON THE TRAIL WITH THE STATUS EACH WRITE FOUND
  // (M49 PR6, docs/03 §6ppp). Three live priors, four targets, and every
  // write admits every prior — so every event carries `from`, and the drives
  // below reach each of the twelve. Four are already behind us on this item:
  // `healthy → healthy` (the first sync), `healthy → login_required` (the
  // first webhook), `login_required → healthy` (the heal), and the revoke
  // below adds `healthy → revoked`. The rest are driven here, and the SET
  // assertion after the revoke is what proves nothing else was recorded.
  // -------------------------------------------------------------------------

  const audited = (): Array<ReturnType<typeof AuditEventSchema.parse>> =>
    producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)));

  const lastOf = (action: string): ReturnType<typeof AuditEventSchema.parse> => {
    const hits = audited().filter((e) => e.action === action);
    expect(hits.length).toBeGreaterThan(0);
    return hits[hits.length - 1]!;
  };

  const statusOf = async (id: string): Promise<string> => {
    const { rows } = await admin.query(`SELECT status FROM ${schema}.plaid_items WHERE id = $1`, [
      id,
    ]);
    return (rows[0] as { status: string }).status;
  };

  const signedWebhook = (code: string, forPlaidItemId: string): Promise<unknown> => {
    const body = JSON.stringify({
      webhook_type: 'ITEM',
      webhook_code: code,
      item_id: forPlaidItemId,
    });
    return request(server)
      .post('/v1/plaid/webhook')
      .set('content-type', 'application/json')
      .set('plaid-verification', gateway.signWebhook(body))
      .send(body);
  };

  /**
   * The next `syncAccounts` answers `invalid_access_token`, then the stub is
   * itself again. A spy rather than the stub's own revocation hook, because
   * that hook is one-way — a removed token cannot be re-armed — and the
   * recovery edge needs the sync AFTER the failure to succeed.
   */
  let armedFailure: jest.SpyInstance | null = null;
  const failNextSync = (): void => {
    armedFailure = jest
      .spyOn(gateway, 'syncAccounts')
      .mockRejectedValueOnce(new PlaidGatewayError('invalid_access_token'));
  };

  // AN ARMED REJECTION THAT NOBODY SPENT IS A TRAP FOR THE NEXT TEST. `jest`
  // is configured with `clearMocks`, which clears recorded calls but not a
  // queued one-time implementation, so a drive that fails before it reaches
  // `syncAccounts` leaves the rejection loaded and the NEXT drive fails for a
  // reason its name does not mention — one red test presenting as five. This
  // reds the drive that actually armed it instead.
  afterEach(() => {
    if (armedFailure === null) return;
    const spent = armedFailure.mock.calls.length > 0;
    armedFailure.mockRestore();
    armedFailure = null;
    expect({ armedFailureSpent: spent }).toEqual({ armedFailureSpent: true });
  });

  it('the token dies under a sync: `healthy → error` is recorded, under the actor who asked (M49 PR6)', async () => {
    failNextSync();
    // The rethrown gateway error is not an HttpException, so the owner sees
    // `internal_error` for a link that needs re-authorising — an outage face on
    // a remediable condition, which §6ppp records rather than fixes here.
    await request(server).post(`/v1/plaid/items/${itemId}/sync`).set(asOwner()).expect(500);
    expect(await statusOf(itemId)).toBe('error');
    const errored = lastOf('plaid.item.errored');
    expect(errored).toMatchObject({
      actorId: OWNER,
      actorType: 'user',
      resourceType: 'plaid_item',
      resourceId: itemId,
      detail: { from: 'healthy' },
    });
  });

  it('a second failure is an edge too: `error → error`', async () => {
    failNextSync();
    await request(server).post(`/v1/plaid/items/${itemId}/sync`).set(asOwner()).expect(500);
    expect(lastOf('plaid.item.errored').detail).toEqual({ from: 'error' });
  });

  it('Plaid asks for a re-login on an item the platform had written off: `error → login_required`, then a repeat: `login_required → login_required`', async () => {
    await signedWebhook('ITEM_LOGIN_REQUIRED', plaidItemId).then((r) =>
      expect((r as { status: number }).status).toBe(204),
    );
    expect(lastOf('plaid.item.login_required')).toMatchObject({
      actorId: null,
      actorType: 'system',
      onBehalfOf: OWNER,
      detail: { from: 'error' },
    });
    // The other webhook code that lands on the same status — and the event
    // still cannot say which of the two it was (§6ppp).
    await signedWebhook('ERROR', plaidItemId).then((r) =>
      expect((r as { status: number }).status).toBe(204),
    );
    expect(lastOf('plaid.item.login_required').detail).toEqual({ from: 'login_required' });
    expect(await statusOf(itemId)).toBe('login_required');
  });

  it('a webhook-driven sync that fails: `login_required → error`, attributed to the platform, not the owner', async () => {
    failNextSync();
    // The throw propagates out of the webhook route too, so Plaid is answered
    // 500 and will retry — each retry a fresh `error → error` (§6ppp).
    await signedWebhook('SYNC_UPDATES_AVAILABLE', plaidItemId).then((r) =>
      expect((r as { status: number }).status).toBe(500),
    );
    expect(await statusOf(itemId)).toBe('error');
    // The platform acted, and the row still names whose item it was.
    expect(lastOf('plaid.item.errored')).toMatchObject({
      actorId: null,
      actorType: 'system',
      onBehalfOf: OWNER,
      detail: { from: 'login_required' },
    });
  });

  it('the recovery is on the trail as an EDGE, not an inference: `error → healthy`', async () => {
    await request(server).post(`/v1/plaid/items/${itemId}/sync`).set(asOwner()).expect(200);
    expect(await statusOf(itemId)).toBe('healthy');
    // `from: 'error'` on the sync that healed it. Before M49 PR6 this row was
    // indistinguishable from the routine sync two drives up — both `synced`,
    // both `detail: { accounts: 2 }`.
    expect(lastOf('plaid.item.synced').detail).toEqual({ accounts: 2, from: 'error' });
  });

  /**
   * Two more items, so that `revoked` can be reached from the two dead priors
   * — a revoked item is terminal, and the shared item above is revoked from
   * `healthy` in the next drive.
   */
  const linkAnother = async (publicToken: string): Promise<{ id: string; plaidItemId: string }> => {
    const spy = jest.spyOn(gateway, 'exchangePublicToken');
    const res = await request(server)
      .post('/v1/plaid/items')
      .set(asOwner())
      .send({ publicToken })
      .expect(201);
    const exchanged = (await spy.mock.results[spy.mock.results.length - 1]!.value) as {
      itemId: string;
    };
    spy.mockRestore();
    return { id: (res.body as { id: string }).id, plaidItemId: exchanged.itemId };
  };

  it('revoking a dead link records where it was: `login_required → revoked` and `error → revoked`', async () => {
    const b = await linkAnother('public-stub-ladder-b');
    await signedWebhook('ITEM_LOGIN_REQUIRED', b.plaidItemId);
    expect(await statusOf(b.id)).toBe('login_required');
    await request(server)
      .delete(`/v1/plaid/items/${b.id}`)
      .set(bearer('stepup', OWNER))
      .expect(204);
    expect(lastOf('plaid.item.revoked')).toMatchObject({
      resourceId: b.id,
      detail: { from: 'login_required' },
    });

    const c = await linkAnother('public-stub-ladder-c');
    failNextSync();
    await request(server).post(`/v1/plaid/items/${c.id}/sync`).set(asOwner()).expect(500);
    expect(await statusOf(c.id)).toBe('error');
    await request(server)
      .delete(`/v1/plaid/items/${c.id}`)
      .set(bearer('stepup', OWNER))
      .expect(204);
    expect(lastOf('plaid.item.revoked')).toMatchObject({
      resourceId: c.id,
      detail: { from: 'error' },
    });
  });

  it('a sync that meets a revoke UNDER THE LOCK writes nothing and resurrects nothing — two connections (M49 PR6)', async () => {
    const e = await linkAnother('public-stub-ladder-e');
    await request(server).post(`/v1/plaid/items/${e.id}/sync`).set(asOwner()).expect(200);
    const live = async (): Promise<number> => {
      const { rows } = await admin.query(
        `SELECT count(*)::int AS n FROM ${schema}.accounts WHERE plaid_item_id = $1 AND deleted_at IS NULL`,
        [e.id],
      );
      return (rows[0] as { n: number }).n;
    };
    expect(await live()).toBe(2);

    // CONNECTION B: a revoke in flight — the item row locked and tombstoned,
    // its accounts retired, NOT yet committed. `revoke()`'s own transaction,
    // statement for statement, run by hand so that the commit can be timed.
    const rival = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await rival.connect();
    const b: Queryable = {
      query: async <T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> =>
        (await rival.query<T>(text, values)).rows,
    };
    // try/finally around everything between BEGIN and the disconnect: an
    // assertion that throws in that window leaves a transaction holding the
    // item lock, and every later drive in this file blocks on it until jest's
    // timeout — one red test presenting as a hung suite and a leaked schema.
    try {
      await rival.query('BEGIN');
      expect(await app.get(ItemsRepo).markRevoked(b, e.id, new Date())).toBe('healthy');
      await app.get(AccountsRepo).softDeleteByItem(b, e.id, new Date());

      // THE OWNER'S SYNC, fired while B holds the item lock. Its decrypt, its
      // gateway call and its encryption run; then its transaction's FIRST
      // statement — the `healthy` write — waits on B. Whatever the timing, that
      // statement runs after B commits and finds no live row: the wait is what
      // B's lock guarantees, and the answer is what the tombstone guarantees.
      const mark = producer.messages.length;
      const sync = request(server)
        .post(`/v1/plaid/items/${e.id}/sync`)
        .set(asOwner())
        .then((r) => r);

      // THE WAIT IS OBSERVED, not assumed from a timer. Without this the drive
      // passes identically with zero contention — the sync simply arriving
      // after the commit and finding a tombstoned row, which is the weaker
      // "already revoked" case wearing this test's name. `pg_locks` is asked
      // until the sync's backend is actually blocked on the rival's row lock.
      const blocked = async (): Promise<boolean> => {
        const { rows } = await admin.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM pg_stat_activity
            WHERE wait_event_type = 'Lock' AND state = 'active' AND datname = current_database()`,
        );
        return Number(rows[0]?.n ?? '0') > 0;
      };
      let waited = 0;
      while (!(await blocked()) && waited < 4000) {
        await new Promise((resolve) => setTimeout(resolve, 50));
        waited += 50;
      }
      expect({ sawTheSyncWaitOnTheLock: await blocked() }).toEqual({
        sawTheSyncWaitOnTheLock: true,
      });

      await rival.query('COMMIT');
      const res = await sync;
      expect({ status: res.status, body: res.body as { accountsUpserted: number } }).toEqual({
        status: 200,
        body: { accountsUpserted: 0 },
      });

      // Nothing resurrected, nothing filed. Under the statement order this PR
      // replaced — accounts first, item last — this same drive ends with both
      // accounts live again under a revoked item, which is docs/03 §6ppp's
      // resurrection finding driven rather than described; and with B's locks
      // taken in the interleaved order it ends in 40P01, which the PR's review
      // drove. Same fix for both: the item lock first, on both sides — and the
      // ladder fence reads that order out of BOTH methods, because this drive
      // hand-rolls revoke's half and so cannot notice it changing.
      expect(await live()).toBe(0);
      expect(await statusOf(e.id)).toBe('revoked');
      expect(
        producer.messages
          .slice(mark)
          .filter((m) => m.topic === TOPICS.auditEvents)
          .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action)
          .filter((a) => a.startsWith('plaid.item.')),
      ).toEqual([]);
    } finally {
      try {
        await rival.query('ROLLBACK');
      } catch {
        // Already committed, or the connection is gone: nothing to undo.
      }
      await rival.end();
    }
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
    // `healthy → revoked`: a working link ended, and the row says so.
    expect(lastOf('plaid.item.revoked')).toMatchObject({
      resourceId: itemId,
      detail: { from: 'healthy' },
    });
  });

  it('records each ladder action against EXACTLY the set of priors it admits — twelve edges, as sets (M49 PR6)', () => {
    // The containment direction the per-edge drives cannot give: each of them
    // looks only at its own event. This says no action ever recorded a `from`
    // outside the three live priors, and that every one of the twelve was
    // reached. Compared as SETS, because a mis-attributed edge preserves a
    // count.
    const froms = (action: string): Set<unknown> =>
      new Set(
        audited()
          .filter((e) => e.action === action)
          .map((e) => e.detail['from']),
      );
    const live = new Set(['healthy', 'login_required', 'error']);
    expect({
      login_required: froms('plaid.item.login_required'),
      errored: froms('plaid.item.errored'),
      synced: froms('plaid.item.synced'),
      revoked: froms('plaid.item.revoked'),
    }).toEqual({ login_required: live, errored: live, synced: live, revoked: live });

    // Every recorded `from` is a member of the table's own vocabulary — the
    // assertion that catches a double answering a boolean, or a `null` that
    // the schema would have refused anyway but a string `'null'` it would not.
    const ddl = new Set(ddlItemStatuses());
    expect(ddl.size).toBe(4);
    const recorded = audited()
      .filter((e) => e.action.startsWith('plaid.item.') && 'from' in e.detail)
      .map((e) => e.detail['from']);
    expect(recorded.length).toBeGreaterThanOrEqual(12);
    expect(recorded.filter((f) => !ddl.has(f as string))).toEqual([]);
    // And `revoked` is never a prior — the tombstone argument, on real rows.
    expect(recorded).not.toContain('revoked');
  });

  it('THE STATEMENT answers null on a row that already moved, and the prior on one that had not (M49 PR6)', async () => {
    // The statement layer, against Postgres: `setStatus` and `markRevoked`
    // are compare-and-sets on liveness, and a revoked row is not live. The
    // service's `if (prior !== null)` guards are proven one layer up, by the
    // unit spec with the double forced to null; this proves what the double
    // stands in for.
    const repo = app.get(ItemsRepo);
    const db = app.get(Db);
    const onRevoked = await db.withTransaction(OWNER, async (tx) => ({
      set: await repo.setStatus(tx, itemId, 'healthy'),
      revoke: await repo.markRevoked(tx, itemId, new Date()),
    }));
    expect(onRevoked).toEqual({ set: null, revoke: null });
    expect(await statusOf(itemId)).toBe('revoked');

    const d = await linkAnother('public-stub-ladder-d');
    const onLive = await db.withTransaction(OWNER, (tx) => repo.setStatus(tx, d.id, 'error'));
    expect(onLive).toBe('healthy');
    expect(await statusOf(d.id)).toBe('error');
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
      'plaid.item.errored',
      'plaid.item.revoked',
      'plaid.webhook.rejected',
      'crypto.field.decrypted',
    ]) {
      expect(actions).toContain(required);
    }
  });

  it('no version capture in this schema keeps a blind index (M25 PR1)', async () => {
    // Asks the DATABASE what function it is running, not what the migration
    // says — a redaction written and never applied, or superseded by a later
    // CREATE OR REPLACE that lost it, is invisible to a text scan. The static
    // half is `packages/contracts/test/version-capture-redaction.spec.ts`.
    //
    // THE CORPUS IS ASSERTED FIRST, because an empty corpus and a clean one
    // produce the same empty gap list. `plaid_items` carries the blind index this
    // milestone is about.
    const corpus = await blindIndexCaptureCorpus(admin, schema);
    expect([...corpus.keys()]).toContain('plaid_items');
    expect(await blindIndexCaptureGaps(admin, schema)).toEqual([]);
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
