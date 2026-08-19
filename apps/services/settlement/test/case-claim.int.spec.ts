/**
 * The claim marker and the two worklists against REAL POSTGRES.
 *
 * WHY THIS FILE EXISTS. `operator-worklists.spec.ts` fakes the repo, so it
 * proves the DECISIONS — who is refused, which event is emitted — and can
 * prove nothing about the statements. Mutation-tested before this file was
 * written: deleting `claimed_by = $2, claimed_at = $3` from
 * `markReviewStarted`'s UPDATE left all thirteen of those tests GREEN, because
 * a fake repo has no SQL to break. That is the M13 contact-link lesson exactly
 * ("a fix whose defect lived in SQL must be pinned by a test that runs SQL"),
 * and it is the reason the claim marker gets a second spec rather than a
 * comment saying it is covered.
 *
 * The two DDL constraints migration 003 adds are the other half: a CHECK is a
 * property of the database and no fake can carry one.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Client } from 'pg';
import { Migrator } from '@estate/db';
import { Db } from '../src/db';
import { ADMINISTRABLE_STATUSES, CasesRepo, QUEUE_STATUSES } from '../src/cases.repo';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('the case claim marker and the worklists, against Postgres', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `caseclaim_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  const cases = new CasesRepo();
  const NOW = new Date('2026-08-19T12:00:00.000Z');

  const DECEDENT = randomUUID();
  const REPORTER = randomUUID();
  const OPERATOR = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Pinned for the same reason the operator-CLI spec pins it: a schema
    // prefix scopes only the statements WE write, while a trigger body or a
    // default expression resolves through the CONNECTION's search_path.
    await admin.query(`SET search_path = ${schema}`);
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      await new Migrator(client, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await client.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
  }, 120_000);

  afterAll(async () => {
    if (db) await db.onModuleDestroy();
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  beforeEach(async () => {
    // TRUNCATE, not DELETE: DELETE fires the row trigger, whose body writes to
    // settlement_cases_versions — and a reset that writes is a reset that can
    // land somewhere else (the M20 PR4 lesson).
    await admin.query(`TRUNCATE ${schema}.settlement_cases CASCADE`);
  });

  async function reported(): Promise<string> {
    const row = await db.withTransaction(REPORTER, (tx) =>
      cases.insert(tx, {
        decedentUserId: DECEDENT,
        reportedBy: REPORTER,
        source: 'trusted_contact',
        evidence: [],
      }),
    );
    return row.id;
  }

  it('markReviewStarted WRITES the claimer, and the row reads it back', async () => {
    const caseId = await reported();
    const ok = await db.withTransaction(OPERATOR, (tx) =>
      cases.markReviewStarted(tx, caseId, OPERATOR, NOW),
    );
    expect(ok).toBe(true);

    const row = await cases.findById(db, caseId);
    expect(row?.status).toBe('verifying');
    expect(row?.claimed_by).toBe(OPERATOR);
    expect(row?.claimed_at?.toISOString()).toBe(NOW.toISOString());
  });

  it('the claim pair travels together — the DDL refuses a half-written claim', async () => {
    const caseId = await reported();
    await expect(
      admin.query(`UPDATE ${schema}.settlement_cases SET claimed_by = $2 WHERE id = $1`, [
        caseId,
        OPERATOR,
      ]),
    ).rejects.toThrow(/settlement_cases_claim_pair/);
  });

  it('the DDL refuses the REPORTER as claimer, whatever the service does', async () => {
    // The readable refusal lives in the service; this is the backstop, and a
    // backstop nobody triggers in a test is a backstop nobody has read.
    const caseId = await reported();
    await expect(
      admin.query(
        `UPDATE ${schema}.settlement_cases SET claimed_by = $2, claimed_at = now() WHERE id = $1`,
        [caseId, REPORTER],
      ),
    ).rejects.toThrow(/settlement_cases_claimer_not_reporter/);
  });

  it('the version trigger captures the claim with no trigger change', async () => {
    // Asserted rather than assumed: 001 captures a whole-row `to_jsonb(OLD)`,
    // so a new column rides along for free — the kind of "free" consequence
    // that turns out to be wrong often enough to be worth measuring.
    const caseId = await reported();
    await db.withTransaction(OPERATOR, (tx) => cases.markReviewStarted(tx, caseId, OPERATOR, NOW));
    const { rows } = await admin.query<{ row_data: Record<string, unknown> }>(
      `SELECT row_data FROM ${schema}.settlement_cases_versions WHERE row_id = $1 ORDER BY version_seq`,
      [caseId],
    );
    expect(rows.length).toBeGreaterThan(0);
    // The capture is the PRIOR image, so the claim columns exist and are null.
    expect(Object.keys(rows[0]?.row_data ?? {})).toEqual(
      expect.arrayContaining(['claimed_by', 'claimed_at']),
    );
  });

  it('a case is on exactly one worklist, and the SQL agrees with the constants', async () => {
    // Drives the REAL queries rather than the status arrays: whether Postgres
    // filters on the set the constant names is a question only Postgres
    // answers.
    const caseId = await reported();
    expect((await cases.listOpenForReview(db)).map((r) => r.id)).toEqual([caseId]);
    expect(await cases.listAdministrable(db)).toEqual([]);

    await admin.query(
      `UPDATE ${schema}.settlement_cases
          SET status = 'verified', human_review_by = $2, human_review_at = now(),
              verified_at = now()
        WHERE id = $1`,
      [caseId, OPERATOR],
    );

    expect(await cases.listOpenForReview(db)).toEqual([]);
    expect((await cases.listAdministrable(db)).map((r) => r.id)).toEqual([caseId]);
  });

  it('every status either query selects is one the DDL admits', async () => {
    // The constants are interpolated into SQL as literals. If one ever drifted
    // from the table's own CHECK the query would silently match nothing, which
    // is a worklist that is always empty rather than an error.
    //
    // CORRECTED IN THE PR3b REVIEW: the first version compared the constants
    // against a status list RETYPED IN THIS FILE, which is the "list retyped in
    // a spec" the design set out to avoid — and it was measurably toothless
    // (removing `distributing` from 001's CHECK left this test GREEN while
    // `operator-worklists.spec.ts`, which reads the migration, went red). It
    // asks the LIVE CATALOG now, which is stronger than either: not the
    // migration's text but the constraint the database is actually enforcing,
    // in the schema this suite migrated.
    const { rows } = await admin.query<{ src: string }>(
      `SELECT pg_get_constraintdef(c.oid) AS src
         FROM pg_constraint c
         JOIN pg_class t ON t.oid = c.conrelid
         JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = $1 AND t.relname = 'settlement_cases'
          AND c.conname = 'settlement_cases_status_check'`,
      [schema],
    );
    const src = rows[0]?.src;
    // Anti-vacuity: a renamed constraint would leave `admitted` empty, and an
    // empty superset contains nothing — which fails loudly rather than passing.
    expect(typeof src).toBe('string');
    const admitted = new Set([...(src as string).matchAll(/'([a-z_]+)'/g)].map((m) => m[1]));
    expect(admitted.size).toBeGreaterThan(1);
    const selected = [...QUEUE_STATUSES, ...ADMINISTRABLE_STATUSES];
    expect(selected.filter((status) => !admitted.has(status))).toEqual([]);
  });

  /**
   * THE INVARIANT 003 ASSERTED IN PROSE AND MIGRATION 004 ENFORCES.
   *
   * `cases.repo.ts` says a case "can never be `verifying` with no owner"; that
   * was a property of one UPDATE and not of the table, and the PR3b review
   * proved a bare status write produced exactly that row. Pinned here rather
   * than in a unit test for the reason the whole file exists: a fake repo has
   * no CHECK to violate.
   *
   * BOTH HALVES OF `NOT VALID`, because grandfathering is the design and an
   * untested grandfather clause is a clause nobody has read. A fresh schema has
   * no pre-004 rows, so the second case MAKES one the only way it can be made —
   * by disabling the constraint for one statement, which is itself the proof
   * that the constraint is what refuses in the first case.
   */
  it('refuses a NEW case that enters verifying with no claimer', async () => {
    const caseId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.settlement_cases (id, decedent_user_id, reported_by, report_source, status)
       VALUES ($1, $2, $3, 'trusted_contact', 'reported')`,
      [caseId, randomUUID(), REPORTER],
    );
    await expect(
      admin.query(`UPDATE ${schema}.settlement_cases SET status = 'verifying' WHERE id = $1`, [
        caseId,
      ]),
    ).rejects.toThrow(/settlement_cases_claimed_when_verifying/);
    const { rows } = await admin.query<{ status: string }>(
      `SELECT status FROM ${schema}.settlement_cases WHERE id = $1`,
      [caseId],
    );
    expect(rows[0]?.status).toBe('reported');
  });

  it('grandfathers a pre-004 unowned case, and still lets it be decided', async () => {
    const caseId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.settlement_cases (id, decedent_user_id, reported_by, report_source, status)
       VALUES ($1, $2, $3, 'trusted_contact', 'reported')`,
      [caseId, randomUUID(), REPORTER],
    );
    // The only way to mint the pre-004 shape once 004 has run.
    await admin.query(
      `ALTER TABLE ${schema}.settlement_cases DROP CONSTRAINT settlement_cases_claimed_when_verifying`,
    );
    await admin.query(`UPDATE ${schema}.settlement_cases SET status = 'verifying' WHERE id = $1`, [
      caseId,
    ]);
    await admin.query(
      `ALTER TABLE ${schema}.settlement_cases
         ADD CONSTRAINT settlement_cases_claimed_when_verifying
         CHECK (status <> 'verifying' OR claimed_by IS NOT NULL) NOT VALID`,
    );

    // It survives — NOT VALID does not scan what is already there…
    const { rows: kept } = await admin.query<{ n: string }>(
      `SELECT count(*) AS n FROM ${schema}.settlement_cases
        WHERE id = $1 AND status = 'verifying' AND claimed_by IS NULL`,
      [caseId],
    );
    expect(kept[0]?.n).toBe('1');

    // …and it is not stranded: deciding it leaves `verifying`, so the
    // constraint is satisfied and the UPDATE is allowed.
    await admin.query(
      `UPDATE ${schema}.settlement_cases
          SET status = 'rejected_fraud', resolution = 'operator_rejected', resolved_at = now()
        WHERE id = $1`,
      [caseId],
    );
    const { rows: after } = await admin.query<{ status: string }>(
      `SELECT status FROM ${schema}.settlement_cases WHERE id = $1`,
      [caseId],
    );
    expect(after[0]?.status).toBe('rejected_fraud');
  });
});
