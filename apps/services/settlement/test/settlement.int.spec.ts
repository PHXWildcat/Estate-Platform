import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { checkConventions, Migrator } from '@estate/db';
import { Client } from 'pg';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { SettlementAuthz } from '../src/authz.service';
import { CasesRepo } from '../src/cases.repo';
import { ContactAttemptsRepo } from '../src/contact-attempts.repo';
import { CoreReadsRepo } from '../src/core-reads.repo';
import { Db } from '../src/db';
import { EventsService } from '../src/events.service';
import { OperatorsRepo } from '../src/operators.repo';
import { SettingsRepo } from '../src/settings.repo';
import { SettlementService } from '../src/settlement.service';
import { TasksRepo } from '../src/tasks.repo';
import { StubNotifier } from '../src/notifications';
import { FakeIdentityLock, testConfig, type ClockHolder } from './support';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/** Resolve a co-tenant service's migrations dir (file paths only — runtime
 * services never import each other; docs/04 boundary rule 4). */
function migrationsDirOf(pkg: string): string {
  return join(dirname(require.resolve(`${pkg}/package.json`)), 'migrations');
}

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

describeIfPg('settlement service against Postgres (core-cluster co-tenant)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `settlementsvc_test_${Date.now()}`;
  let admin: Client;
  let db: Db;

  const clock: ClockHolder = { value: new Date('2026-07-27T12:00:00Z') };
  const clockFn = (): Date => clock.value;

  let service: SettlementService;
  let identity: FakeIdentityLock;
  let notifier: StubNotifier;
  let producer: InMemoryAuditProducer;

  const DECEDENT = randomUUID();
  const REPORTER = randomUUID();
  const OPERATOR = randomUUID();
  const SESSION = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    // The real co-tenancy: profile's migrations and settlement's migrations
    // land in the SAME schema, sharing one schema_migrations table with
    // disjoint filenames (the Plaid-on-financial precedent, now on core).
    for (const dir of [
      migrationsDirOf('@estate/service-profile'),
      join(__dirname, '..', 'migrations'),
    ]) {
      const client = new Client({
        connectionString: pgUrl,
        options: `-c search_path=${schema}`,
      });
      await client.connect();
      try {
        await new Migrator(client, dir).migrate();
      } finally {
        await client.end();
      }
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    identity = new FakeIdentityLock();
    notifier = new StubNotifier();
    producer = new InMemoryAuditProducer();
    service = new SettlementService(
      db,
      new CasesRepo(),
      new ContactAttemptsRepo(),
      new OperatorsRepo(),
      new SettingsRepo(),
      new TasksRepo(),
      new CoreReadsRepo(db),
      new SettlementAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
      new EventsService(producer, clockFn),
      notifier,
      identity,
      testConfig(),
      clockFn,
    );

    // Seed the core-cluster reality settlement reads: the decedent's contact
    // repository names the reporter as a linked platform user with an
    // executor designation.
    const contactId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.contacts (id, owner_user_id, name_ct, linked_user_id, dek_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [contactId, DECEDENT, Buffer.from('ct'), REPORTER, randomUUID()],
    );
    await admin.query(
      `INSERT INTO ${schema}.role_assignments
         (owner_user_id, contact_id, role, scope_type, effective_condition)
       VALUES ($1, $2, 'executor', 'estate', 'on_death_verified')`,
      [DECEDENT, contactId],
    );
    await admin.query(`INSERT INTO ${schema}.settlement_operators (user_id) VALUES ($1)`, [
      OPERATOR,
    ]);
  }, 120_000);

  afterAll(async () => {
    if (db) {
      await db.onModuleDestroy();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  it('migrations are idempotent and the shared schema_migrations holds both owners', async () => {
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      const { applied } = await new Migrator(client, join(__dirname, '..', 'migrations')).migrate();
      expect(applied).toEqual([]);
    } finally {
      await client.end();
    }
    const rows = await admin.query<{ name: string }>(
      `SELECT name FROM ${schema}.schema_migrations ORDER BY name`,
    );
    expect(rows.rows.map((r) => r.name)).toEqual([
      '001_core_schema.sql',
      '001_settlement_schema.sql',
      '002_dek_unique_active.sql',
      '002_settlement_admin.sql',
    ]);
  });

  it('meets the docs/02 conventions (append-only tables; cases hand-checked below)', async () => {
    const violations = await checkConventions(admin, {
      schema,
      // settlement_tasks is the one PR2 table with a full soft-delete shape
      // (docs/02 §7 gives it deleted_at). Cases, stages and distributions
      // deliberately have none — they are evidence, access records, and
      // financial records respectively — so they are asserted by hand below.
      businessTables: ['settlement_tasks'],
      appendOnlyTables: [
        'settlement_cases_versions',
        'settlement_settings_versions',
        'settlement_contact_attempts',
        'settlement_access_stages_versions',
        'settlement_tasks_versions',
        'distributions_versions',
      ],
    });
    expect(violations).toEqual([]);
  });

  it('settlement_cases: versioned + updated_at triggers, and NO deleted_at by design', async () => {
    // Qualified by schema, not just table name: every suite runs in its own
    // scratch schema inside ONE database, so an unqualified catalog query
    // sees other suites' identically-named tables too (the M6 lesson).
    const triggers = await admin.query<{ tgname: string }>(
      `SELECT t.tgname FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = 'settlement_cases' AND NOT t.tgisinternal
        ORDER BY t.tgname`,
      [schema],
    );
    expect(triggers.rows.map((r) => r.tgname)).toEqual([
      'trg_settlement_cases_updated_at',
      'trg_settlement_cases_versions',
    ]);
    const deletedAt = await admin.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = 'settlement_cases' AND column_name = 'deleted_at'`,
      [schema],
    );
    expect(deletedAt.rows).toHaveLength(0);
  });

  it('the DDL CHECKs hold: reviewer ≠ reporter and no privileged status without review', async () => {
    // DML must run on the schema-scoped pool (`db`), not the admin client:
    // the version-capture trigger resolves settlement_cases_versions via
    // search_path, so admin (search_path=public) would 42P01 inside the
    // trigger before the CHECK under test ever fires.
    const caseId = randomUUID();
    await db.query(
      `INSERT INTO settlement_cases (id, decedent_user_id, reported_by, report_source)
       VALUES ($1, $2, $3, 'trusted_contact')`,
      [caseId, randomUUID(), REPORTER],
    );
    await expect(
      db.query(
        `UPDATE settlement_cases
            SET status = 'verifying', human_review_by = $2, human_review_at = now()
          WHERE id = $1`,
        [caseId, REPORTER],
      ),
    ).rejects.toMatchObject({ code: '23514' });
    await expect(
      db.query(
        `UPDATE settlement_cases
            SET status = 'waiting_period', waiting_period_ends = now()
          WHERE id = $1`,
        [caseId],
      ),
    ).rejects.toMatchObject({ code: '23514' });
    await db.query(`DELETE FROM settlement_cases WHERE id = $1`, [caseId]);
  });

  it('runs the full §5.1 flow: report → review → waiting period → sweep → verify', async () => {
    // Intake enforces the REAL linked-contact rows seeded above.
    await expect(
      service.report(randomUUID(), SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toMatchObject({ response: { error: 'not_found' } });

    const documentId = randomUUID();
    const dto = await service.report(REPORTER, SESSION, {
      decedentUserId: DECEDENT,
      source: 'death_certificate_upload',
      evidence: [{ type: 'document', documentId, version: 1 }],
    });
    const caseId = dto.caseId;
    expect(dto.status).toBe('reported');

    // One open case per decedent — enforced by the real partial unique index.
    await expect(
      service.report(REPORTER, SESSION, {
        decedentUserId: DECEDENT,
        source: 'trusted_contact',
        evidence: [],
      }),
    ).rejects.toMatchObject({ response: { error: 'case_exists' } });

    await service.startReview(OPERATOR, SESSION, caseId);
    const approved = await service.decideReview(OPERATOR, SESSION, caseId, {
      decision: 'approve',
    });
    expect(approved.status).toBe('waiting_period');
    expect(identity.setStateCalls).toContainEqual({
      userId: DECEDENT,
      state: 'deceased_pending',
      caseId,
    });

    // The sweep against the real unique index: idempotent per (case, seq).
    let sweep = await service.runContactSweep(clock.value);
    expect(sweep.attempts).toBe(1);
    sweep = await service.runContactSweep(clock.value);
    expect(sweep.attempts).toBe(0);
    clock.value = new Date(clock.value.getTime() + 25 * HOUR);
    sweep = await service.runContactSweep(clock.value);
    expect(sweep.attempts).toBe(2);

    // The evidence authority answers from the real jsonb containment query.
    await expect(service.evidenceReadAuthority(OPERATOR, documentId, 1)).resolves.toEqual({
      allowed: true,
      caseId,
      ownerUserId: REPORTER,
    });
    await expect(service.evidenceReadAuthority(REPORTER, documentId, 1)).resolves.toEqual({
      allowed: false,
      caseId: null,
      ownerUserId: null,
    });

    // Verification: refused during the wait, performed after it.
    await expect(service.confirmVerification(OPERATOR, SESSION, caseId)).rejects.toMatchObject({
      response: { error: 'waiting_period_active' },
    });
    clock.value = new Date(clock.value.getTime() + 5 * DAY);
    const verified = await service.confirmVerification(OPERATOR, SESSION, caseId);
    expect(verified.status).toBe('verified');
    expect(identity.setStateCalls).toContainEqual(
      expect.objectContaining({ userId: DECEDENT, state: 'settlement', caseId }),
    );

    // The version trail captured every transition with its GUC actor.
    const versions = await admin.query<{ actor_id: string | null; row_data: { status: string } }>(
      `SELECT actor_id, row_data FROM ${schema}.settlement_cases_versions
        WHERE row_id = $1 ORDER BY version_seq`,
      [caseId],
    );
    expect(versions.rows.map((r) => r.row_data.status)).toEqual([
      'reported',
      'verifying',
      'waiting_period',
    ]);
    expect(versions.rows.map((r) => r.actor_id)).toEqual([OPERATOR, OPERATOR, OPERATOR]);
  }, 60_000);

  it('the owner voids a fresh case for a second decedent; settings freeze while open', async () => {
    const decedent2 = randomUUID();
    const contactId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.contacts (id, owner_user_id, name_ct, linked_user_id, dek_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [contactId, decedent2, Buffer.from('ct'), REPORTER, randomUUID()],
    );
    const dto = await service.report(REPORTER, SESSION, {
      decedentUserId: decedent2,
      source: 'trusted_contact',
      evidence: [],
    });

    await expect(
      service.updateSettings(decedent2, SESSION, { waitingPeriodDays: 30 }),
    ).rejects.toMatchObject({ response: { error: 'case_open' } });

    const voided = await service.void(decedent2, SESSION, dto.caseId);
    expect(voided.status).toBe('rejected_fraud');
    expect(voided.resolution).toBe('owner_voided');
    expect(identity.setStateCalls).toContainEqual({
      userId: decedent2,
      state: 'active',
      caseId: dto.caseId,
    });

    // Terminal case frees the settings and the open-case slot.
    await expect(
      service.updateSettings(decedent2, SESSION, { waitingPeriodDays: 30 }),
    ).resolves.toEqual({ waitingPeriodDays: 30 });
    // The settings versions trail records the GUC actor on the next change.
    await service.updateSettings(decedent2, SESSION, { waitingPeriodDays: 21 });
    const versions = await admin.query<{ actor_id: string | null }>(
      `SELECT actor_id FROM ${schema}.settlement_settings_versions WHERE row_id = $1`,
      [decedent2],
    );
    expect(versions.rows).toEqual([{ actor_id: decedent2 }]);
  }, 60_000);

  it('reportable estates resolves from the real contacts/role_assignments rows', async () => {
    const estates = await service.reportableEstates(REPORTER);
    const mine = estates.find((e) => e.decedentUserId === DECEDENT);
    expect(mine?.roles).toEqual(['executor']);
  });
});
