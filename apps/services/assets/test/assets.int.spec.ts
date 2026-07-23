/**
 * End-to-end integration test against a real Postgres, gated exactly like
 * packages/db: set PG_TEST_URL to run (CI service container; locally e.g.
 * postgres://estate:estate_dev@localhost:5435/financial). Runs the service's
 * real migrations into a scratch schema, boots the Nest app over it with an
 * in-memory audit producer, and drives the full ledger flow with supertest:
 * ciphertext at rest, append-only enforcement, step-up gating, share-sum
 * invariants (app + DB trigger), optimistic concurrency, idempotency,
 * temporal (as-of) queries, projection rebuild, and the audit PII firewall.
 */
import 'reflect-metadata';
import type { Server } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { Test } from '@nestjs/testing';
import type { INestApplication } from '@nestjs/common';
import { checkConventions, Migrator } from '@estate/db';
import {
  AssetLedgerAppendedEvent,
  AuditEventSchema,
  TOPICS,
  type MfaLevel,
} from '@estate/contracts';
import { SESSION_VERIFIER, type SessionContext, type SessionVerifier } from '@estate/auth-guard';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import type { AssetDto, CommandResult, NetWorthDto } from '../src/assets.service';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { AUDIT_PRODUCER, PG_POOL_CONFIG } from '../src/di-tokens';
import { RebuildService } from '../src/rebuild.service';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const OWNER = randomUUID();
const STRANGER = randomUUID();

/**
 * Stands in for real identity introspection: a bearer token of the form
 * `<level>:<userId>` verifies to that session (mirrors what CallerGuard would
 * get from `HttpSessionVerifier` → identity's `/v1/auth/session`). A malformed
 * token verifies to null (⇒ 401). The real cross-service path is proven in the
 * session-verification e2e; here we isolate the asset service.
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
const CONTACT_A = randomUUID();
const CONTACT_B = randomUUID();
const TITLE = 'Lake house on Shore Road';
const SECRET_NOTES = 'combination is 12-34-56';
const SECRET_LOCATION = 'safe behind the painting';
const VALUE = '850000.00';

interface RawViewRow {
  title: string;
  category: string;
  in_trust: boolean;
  est_value_ct: Buffer;
  cost_basis_ct: Buffer;
  location_ct: Buffer;
  notes_ct: Buffer;
  deleted_at: Date | null;
}

describeIfPg('asset ledger service end to end', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `assetsvc_test_${Date.now()}`;
  let admin: Client;
  let app: INestApplication;
  let server: Server;
  let producer: InMemoryAuditProducer;
  let assetId: string;

  const asOwner = (): Record<string, string> => bearer('mfa', OWNER);
  const asStranger = (): Record<string, string> => bearer('mfa', STRANGER);
  // A fresh step-up now comes from a stepped-up SESSION (not a boolean header):
  // same owner, mfa_level 'stepup', within the ≤5-min window.
  const withStepUp = (): Record<string, string> => bearer('stepup', OWNER);

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Unqualified trigger inserts (…_versions) must resolve on this raw client.
    await admin.query(`SET search_path TO ${schema}, public`);

    const migrClient = new Client({
      connectionString: pgUrl,
      options: `-c search_path=${schema}`,
    });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_financial_schema.sql');
    } finally {
      await migrClient.end();
    }

    process.env['DATABASE_URL'] = pgUrl;
    process.env['KMS_MASTER_KEY_HEX'] = randomBytes(32).toString('hex');
    delete process.env['KAFKA_BROKERS'];

    producer = new InMemoryAuditProducer();
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AUDIT_PRODUCER)
      .useValue(producer)
      .overrideProvider(PG_POOL_CONFIG)
      .useValue({ connectionString: pgUrl, options: `-c search_path=${schema}` })
      .overrideProvider(SESSION_VERIFIER)
      .useValue(fakeVerifier)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    server = app.getHttpServer() as Server;
  });

  afterAll(async () => {
    await app?.close();
    await admin?.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin?.end();
  });

  it('rejects a request with no bearer token, and one with a forged token (401)', async () => {
    await request(server).get('/v1/assets').expect(401, { error: 'unauthorized' });
    await request(server)
      .get('/v1/assets')
      .set('authorization', 'Bearer forged-token')
      .expect(401, { error: 'unauthorized' });
  });

  it('creates an asset and stores only ciphertext for sensitive fields', async () => {
    const res = await request(server)
      .post('/v1/assets')
      .set(asOwner())
      .send({
        category: 'real_estate',
        title: TITLE,
        estValue: VALUE,
        valuationAsOf: '2026-07-01',
        valuationSource: 'appraisal',
        costBasis: '400000.00',
        location: SECRET_LOCATION,
        notes: SECRET_NOTES,
        inTrust: true,
      })
      .expect(201);
    const ack = res.body as CommandResult;
    assetId = ack.assetId;
    expect(ack.version).toBe('1');
    expect(ack.replayed).toBe(false);

    const { rows: views } = await admin.query<RawViewRow>(
      `SELECT * FROM assets_view WHERE asset_id = $1`,
      [assetId],
    );
    expect(views).toHaveLength(1);
    const view = views[0]!;
    // Plaintext columns per docs/02 §3 DDL.
    expect(view.title).toBe(TITLE);
    expect(view.category).toBe('real_estate');
    expect(view.in_trust).toBe(true);
    // Sensitive columns are AEAD ciphertext — never the plaintext bytes.
    for (const col of ['est_value_ct', 'cost_basis_ct', 'location_ct', 'notes_ct'] as const) {
      expect(Buffer.isBuffer(view[col])).toBe(true);
    }
    expect(view.est_value_ct.includes(Buffer.from(VALUE))).toBe(false);
    expect(view.notes_ct.includes(Buffer.from('12-34-56'))).toBe(false);
    expect(view.location_ct.includes(Buffer.from('painting'))).toBe(false);

    const { rows: events } = await admin.query<{ event_type: string; payload_ct: Buffer }>(
      `SELECT * FROM asset_events WHERE asset_id = $1`,
      [assetId],
    );
    expect(events).toHaveLength(1);
    expect(events[0]!.event_type).toBe('AssetCreated');
    expect(events[0]!.payload_ct.includes(Buffer.from(TITLE))).toBe(false);
    expect(events[0]!.payload_ct.includes(Buffer.from(VALUE))).toBe(false);
  });

  it('reads back the decrypted view (owner only)', async () => {
    const res = await request(server).get(`/v1/assets/${assetId}`).set(asOwner()).expect(200);
    const dto = res.body as AssetDto;
    expect(dto.estValue).toBe(VALUE);
    expect(dto.notes).toBe(SECRET_NOTES);
    expect(dto.version).toBe('1');

    await request(server)
      .get(`/v1/assets/${assetId}`)
      .set(asStranger())
      .expect(403, { error: 'forbidden' });
  });

  it('appends valuations and enforces If-Match optimistic concurrency', async () => {
    await request(server)
      .post(`/v1/assets/${assetId}/valuations`)
      .set(asOwner())
      .send({ estValue: '900000.00', valuationAsOf: '2026-07-15', valuationSource: 'market' })
      .expect(201);

    await request(server)
      .patch(`/v1/assets/${assetId}`)
      .set({ ...asOwner(), 'if-match': '1' }) // stale token: latest is 2
      .send({ title: 'stale write' })
      .expect(409, { error: 'version_conflict' });

    const ok = await request(server)
      .patch(`/v1/assets/${assetId}`)
      .set({ ...asOwner(), 'if-match': '2' })
      .send({ inTrust: true })
      .expect(200);
    expect((ok.body as CommandResult).version).toBe('3');
  });

  it('is idempotent per client eventId', async () => {
    const eventId = randomUUID();
    const body = { eventId, ownershipPct: 50 };
    const first = await request(server)
      .post(`/v1/assets/${assetId}/ownership`)
      .set(asOwner())
      .send(body)
      .expect(200);
    const retry = await request(server)
      .post(`/v1/assets/${assetId}/ownership`)
      .set(asOwner())
      .send(body)
      .expect(200);
    expect((retry.body as CommandResult).replayed).toBe(true);
    expect((retry.body as CommandResult).version).toBe((first.body as CommandResult).version);
    const { rows } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM asset_events WHERE event_id = $1`,
      [eventId],
    );
    expect(rows[0]!.n).toBe(1);
  });

  it('gates beneficiary changes on the step-up assertion (docs/01 §5)', async () => {
    await request(server)
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(asOwner()) // no step-up header
      .send({ contactId: CONTACT_A, designation: 'primary', sharePct: 60 })
      .expect(403, { error: 'stepup_required' });

    await request(server)
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(withStepUp())
      .send({ contactId: CONTACT_A, designation: 'primary', sharePct: 60 })
      .expect(201);
  });

  it('enforces the share-sum invariant in the app AND at the database', async () => {
    await request(server)
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(withStepUp())
      .send({ contactId: CONTACT_B, designation: 'primary', sharePct: 50 })
      .expect(422, { error: 'share_sum_exceeded' });

    // Direct write bypassing the app: the constraint trigger is the last line.
    await expect(
      admin.query(
        `INSERT INTO asset_beneficiaries (asset_id, contact_id, designation, share_pct)
         VALUES ($1, $2, 'primary', 50.000)`,
        [assetId, CONTACT_B],
      ),
    ).rejects.toThrow(/exceeds 100/);

    await request(server)
      .post(`/v1/assets/${assetId}/beneficiaries`)
      .set(withStepUp())
      .send({ contactId: CONTACT_B, designation: 'primary', sharePct: 40 })
      .expect(201);

    const res = await request(server)
      .get(`/v1/assets/${assetId}/beneficiaries`)
      .set(asOwner())
      .expect(200);
    const totals = (res.body as { totals: unknown }).totals;
    expect(totals).toEqual([{ designation: 'primary', sharePct: 100, designationComplete: true }]);
  });

  it('captures versions with actor attribution when a designation is removed', async () => {
    await request(server)
      .delete(`/v1/assets/${assetId}/beneficiaries/${CONTACT_B}?designation=primary`)
      .set(withStepUp())
      .expect(200);
    const { rows } = await admin.query<{ operation: string; actor_id: string }>(
      `SELECT operation, row_data, actor_id FROM asset_beneficiaries_versions
        WHERE row_data->>'contact_id' = $1
        ORDER BY version_seq DESC LIMIT 1`,
      [CONTACT_B],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.operation).toBe('UPDATE'); // soft delete is an UPDATE
    // withTransaction sets the app.actor_id GUC — attribution flows to versions.
    expect(rows[0]!.actor_id).toBe(OWNER);
  });

  it('answers as-of temporal queries from the ledger', async () => {
    const today = new Date().toISOString().slice(0, 10);
    const beforeEverything = await request(server)
      .get('/v1/assets?asOf=2020-01-01')
      .set(asOwner())
      .expect(200);
    expect(beforeEverything.body).toEqual([]);

    const now = await request(server).get(`/v1/assets?asOf=${today}`).set(asOwner()).expect(200);
    const held = now.body as AssetDto[];
    expect(held).toHaveLength(1);
    expect(held[0]!.title).toBe(TITLE);
    expect(held[0]!.estValue).toBe('900000.00'); // latest valuation
    expect(held[0]!.ownershipPct).toBe(50);
  });

  it('serves net worth with ownership weighting', async () => {
    const res = await request(server).get('/v1/net-worth').set(asOwner()).expect(200);
    const nw = res.body as NetWorthDto;
    expect(nw.totalValue).toBe('450000.00'); // 50% × 900k
    expect(nw.inTrustValue).toBe('450000.00');
    expect(nw.inTrustPct).toBe(100);
  });

  it('serves full event history (decrypted payloads, seq versions)', async () => {
    const res = await request(server)
      .get(`/v1/assets/${assetId}/events`)
      .set(asOwner())
      .expect(200);
    const history = res.body as Array<{ eventType: string; payload: { title?: string } }>;
    expect(history.map((e) => e.eventType)).toEqual([
      'AssetCreated',
      'ValuationRecorded',
      'AssetDetailsUpdated',
      'OwnershipChanged',
      'BeneficiaryDesignated',
      'BeneficiaryDesignated',
      'BeneficiaryRemoved',
    ]);
    expect(history[0]!.payload.title).toBe(TITLE);
    await request(server).get(`/v1/assets/${assetId}/events`).set(asStranger()).expect(403);
  });

  it('append-only: a non-owner role cannot UPDATE or DELETE ledger rows', async () => {
    const role = `assets_app_${Date.now()}`;
    await admin.query(`CREATE ROLE ${role}`);
    try {
      await admin.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role}`);
      await admin.query(`GRANT SELECT, INSERT ON asset_events TO ${role}`);
      await admin.query(`SET ROLE ${role}`);
      await expect(
        admin.query(`UPDATE asset_events SET event_type = 'Tampered' WHERE asset_id = $1`, [
          assetId,
        ]),
      ).rejects.toThrow(/permission denied/);
      await expect(
        admin.query(`DELETE FROM asset_events WHERE asset_id = $1`, [assetId]),
      ).rejects.toThrow(/permission denied/);
    } finally {
      await admin.query(`RESET ROLE`);
      await admin.query(`DROP OWNED BY ${role}`);
      await admin.query(`DROP ROLE ${role}`);
      await admin.query(`SET search_path TO ${schema}, public`);
    }
  });

  it('rebuild detects projection tampering and repairs it from the ledger', async () => {
    await admin.query(
      `UPDATE assets_view SET title = 'TAMPERED', in_trust = false WHERE asset_id = $1`,
      [assetId],
    );
    const rebuild = app.get(RebuildService);

    const detect = await rebuild.rebuild({ repair: false });
    expect(detect.diffs.map((d) => d.field).sort()).toEqual(['in_trust', 'title']);

    const repaired = await rebuild.rebuild({ repair: true });
    expect(repaired.repaired).toBe(true);
    const clean = await rebuild.rebuild({ repair: false });
    expect(clean.diffs).toEqual([]);

    const res = await request(server).get(`/v1/assets/${assetId}`).set(asOwner()).expect(200);
    const dto = res.body as AssetDto;
    expect(dto.title).toBe(TITLE);
    expect(dto.inTrust).toBe(true);

    // Rebuild decryptions are system-actor, distinct-purpose audit events.
    const rebuildAudits = producer.messages
      .filter((m) => m.topic === TOPICS.auditEvents)
      .map((m) => AuditEventSchema.parse(JSON.parse(m.value)))
      .filter(
        (e) =>
          e.action === 'crypto.field.decrypted' && e.detail['purpose'] === 'projection_rebuild',
      );
    expect(rebuildAudits.length).toBeGreaterThan(0);
    expect(new Set(rebuildAudits.map((e) => e.actorType))).toEqual(new Set(['system']));
    expect(producer.messages.some((m) => m.value.includes('asset.projection.rebuilt'))).toBe(true);
  });

  it('retires the asset: list/read exclude it, commands 404, history survives', async () => {
    await request(server)
      .post(`/v1/assets/${assetId}/retire`)
      .set(asOwner())
      .send({ reason: 'sold' })
      .expect(200);
    await request(server).get(`/v1/assets/${assetId}`).set(asOwner()).expect(404);
    const list = await request(server).get('/v1/assets').set(asOwner()).expect(200);
    expect(list.body).toEqual([]);
    await request(server)
      .post(`/v1/assets/${assetId}/valuations`)
      .set(asOwner())
      .send({ estValue: '1.00', valuationAsOf: '2026-07-21', valuationSource: 'market' })
      .expect(404);
    const history = await request(server)
      .get(`/v1/assets/${assetId}/events`)
      .set(asOwner())
      .expect(200);
    const entries = history.body as Array<{ eventType: string }>;
    expect(entries[entries.length - 1]!.eventType).toBe('AssetRetired');
    // No hard delete anywhere: the row is soft-deleted, the ledger intact.
    const { rows } = await admin.query<{ deleted_at: Date | null }>(
      `SELECT deleted_at FROM assets_view WHERE asset_id = $1`,
      [assetId],
    );
    expect(rows[0]!.deleted_at).not.toBeNull();
  });

  it('concurrent first-writes cannot mint two active DEKs (unique index + adoption)', async () => {
    const newUser = randomUUID();
    const results = await Promise.all(
      [1, 2, 3, 4].map((i) =>
        request(server)
          .post('/v1/assets')
          .set(bearer('mfa', newUser))
          .send({ category: 'cash', title: `Account ${i}` }),
      ),
    );
    for (const res of results) {
      expect(res.status).toBe(201);
    }
    const { rows } = await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [newUser],
    );
    expect(rows[0]!.n).toBe(1);
  });

  it('every produced message passes the PII firewall (no values, titles, or notes)', () => {
    expect(producer.messages.length).toBeGreaterThan(0);
    for (const message of producer.messages) {
      for (const secret of [
        TITLE,
        SECRET_NOTES,
        SECRET_LOCATION,
        '12-34-56',
        VALUE,
        '900000',
        '400000',
      ]) {
        expect(message.value).not.toContain(secret);
      }
      if (message.topic === TOPICS.auditEvents) {
        AuditEventSchema.parse(JSON.parse(message.value)); // shape-valid, enum-only
      }
      if (message.topic === TOPICS.assetEvents) {
        AssetLedgerAppendedEvent.parse(JSON.parse(message.value));
      }
    }
    const actions = new Set(
      producer.messages
        .filter((m) => m.topic === TOPICS.auditEvents)
        .map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action),
    );
    for (const required of [
      'asset.created',
      'asset.valuation.recorded',
      'asset.ownership.changed',
      'asset.updated',
      'asset.beneficiary.designated',
      'asset.beneficiary.removed',
      'asset.retired',
      'asset.projection.rebuilt',
      'crypto.field.decrypted',
    ]) {
      expect(actions).toContain(required);
    }
  });

  it('satisfies the schema conventions (append-only ledger, versioned business tables)', async () => {
    const violations = await checkConventions(admin, {
      schema,
      businessTables: ['asset_beneficiaries'],
      appendOnlyTables: ['asset_events'],
    });
    expect(violations).toEqual([]);

    // assets_view is a rebuildable projection (docs/02 §8): soft-delete column
    // present, keyed by asset_id, and deliberately NO versions shadow table —
    // its history IS asset_events.
    const { rows: cols } = await admin.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = 'assets_view'`,
      [schema],
    );
    const names = cols.map((c) => c.column_name);
    expect(names).toContain('deleted_at');
    expect(names).toContain('dek_id');
    const { rows: shadow } = await admin.query(
      `SELECT 1 FROM information_schema.tables
        WHERE table_schema = $1 AND table_name = 'assets_view_versions'`,
      [schema],
    );
    expect(shadow).toEqual([]);
  });
});
