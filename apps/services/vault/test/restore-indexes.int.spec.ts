/**
 * Migration 006's two indexes and the generated handle, against real Postgres
 * (M27 PR1b).
 *
 * An index is a property of a STATEMENT, so a unit suite that fakes the repo
 * cannot see whether these exist — and neither can a reader of the migration
 * file, because a file being present in the tree is not the same as its
 * statement having run. The `auth-events-index.int.spec.ts` precedent applies
 * verbatim, including its reason for asserting the migrator's record and the
 * object's existence SEPARATELY.
 *
 * WHAT IS DIFFERENT HERE, AND WHY IT NEEDS MORE THAN AN EXISTENCE CHECK. Both
 * of PR1b's readers are shaped around a specific index, and both fail SILENTLY
 * if the shape drifts: the answers stay correct and the plan degrades. So the
 * column order and the partial predicate are asserted from `indexdef` rather
 * than inferred, and the last block EXPLAINs the reader itself.
 *
 * THE PLAN IS MEASURED ON THE STATEMENT THE REPO ISSUES, CAPTURED FROM IT.
 * The first version of this file EXPLAINed a query written out by hand in the
 * test — the right shape, the right index, and a string that appears nowhere in
 * the product. It passed for the reason it was wrong: it was never about
 * `listRestorable` at all, so rewriting that method's body to the flat
 * `deleted_reason = ANY($2)` form left every assertion green while the plan
 * abandoned the index entirely. The reader is now called through a `Queryable`
 * that records rather than executes, so the text under EXPLAIN cannot be
 * anything other than the text Postgres will receive in production.
 *
 * (The same review found the old block asserting `not.toContain('Sort')`, which
 * is FALSE of the real query: it merges one ordered scan per reason and must
 * sort the union. That assertion could only hold because it was measuring the
 * hand-written single-reason query, and it is now inverted and explained.)
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { ItemsRepo, RESTORABLE_REASONS } from '../src/items.repo';
import type { Queryable } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/**
 * The statement `ItemsRepo.listRestorable` issues, taken from the repo rather
 * than restated. The fake `Queryable` records and returns nothing, which is
 * exactly what a reader over an empty result does — no branch here depends on
 * rows coming back.
 */
function capture(call: (q: Queryable) => unknown, name: string): Statement {
  let captured: Statement | undefined;
  const recorder: Queryable = {
    query: (text: string, values?: unknown[]) => {
      captured = { text, values: values ?? [] };
      return Promise.resolve([]);
    },
  };
  void call(recorder);
  if (!captured) throw new Error(`${name} issued no statement`);
  return captured;
}

interface Statement {
  text: string;
  values: unknown[];
}

const capturedListRestorable = (userId: string): Statement =>
  capture(
    (q) =>
      new ItemsRepo().listRestorable(q, {
        userId,
        // DERIVED, so a fourth restorable reason widens this fence instead of
        // leaving it measuring a stale set.
        restorable: RESTORABLE_REASONS,
        limit: 20,
      }),
    'listRestorable',
  );

const capturedListVersions = (userId: string, itemId: string): Statement =>
  capture(
    (q) => new ItemsRepo().listVersions(q, { userId, itemId, limit: 20, cursor: 1_000_000 }),
    'listVersions',
  );

const MIGRATION = '006_vault_item_restore.sql';
const VERSIONS_INDEX = 'ix_vault_items_versions_row_revision';
const RETIRED_INDEX = 'ix_vault_items_user_retired';

describeIfPg('the restore reader indexes (M27 PR1b)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `vaultrestidx_test_${Date.now()}`;
  let admin: Client;

  const owner = randomUUID();

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }
    await admin.query(`SET search_path TO ${schema}, public`);
  });

  afterAll(async () => {
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('the migrator recorded the migration as applied', async () => {
    const { rows } = await admin.query<{ name: string }>(
      `SELECT name FROM ${schema}.schema_migrations WHERE name = $1`,
      [MIGRATION],
    );
    expect(rows.map((r) => r.name)).toEqual([MIGRATION]);
  });

  it('both indexes exist, in this schema and not another suite’s', async () => {
    // Filtered on schemaname: this Postgres is shared and every int suite makes
    // its own scratch schema, so an unqualified pg_catalog query would happily
    // find another suite's identically-named object and pass over its own.
    const { rows } = await admin.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes
        WHERE schemaname = $1 AND indexname = ANY($2::text[])
        ORDER BY indexname`,
      [schema, [VERSIONS_INDEX, RETIRED_INDEX]],
    );
    expect(rows.map((r) => r.indexname)).toEqual([RETIRED_INDEX, VERSIONS_INDEX]);
  });

  it('the versions index covers (row_id, revision DESC), in that order', async () => {
    // The order is the whole value: the reader filters `row_id` for equality
    // and then wants the newest revisions, bounded by LIMIT. Reversed, the
    // LIMIT cannot stop early and every page costs the row's whole history.
    const { rows } = await admin.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE schemaname = $1 AND indexname = $2`,
      [schema, VERSIONS_INDEX],
    );
    expect(rows[0]?.indexdef).toMatch(/\(row_id, revision DESC\)/);
  });

  it('the retired index is PARTIAL on deleted_at IS NOT NULL, with reason as a key', async () => {
    const { rows } = await admin.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE schemaname = $1 AND indexname = $2`,
      [schema, RETIRED_INDEX],
    );
    const def = rows[0]?.indexdef ?? '';
    expect(def).toMatch(/\(user_id, deleted_reason, deleted_at DESC, id DESC\)/);
    expect(def).toMatch(/WHERE \(deleted_at IS NOT NULL\)/);
    // `deleted_reason` is a KEY COLUMN and must NOT be in the predicate: the
    // restorable set is derived in TypeScript, and encoding it here would be a
    // frozen SQL copy that silently stops covering the query when the set grows.
    expect(def).not.toMatch(/WHERE.*deleted_reason/);
  });

  it('the generated handle equals the image’s own revision, and is NULL before 005', async () => {
    // `revision` on the shadow table is GENERATED from `row_data`, so it cannot
    // disagree with the image it names. Both arms are exercised: an image that
    // carries the key, and one that does not (every capture predating 005).
    const withRevision = randomUUID();
    const withoutRevision = randomUUID();
    await admin.query(
      `INSERT INTO vault_items_versions (row_id, operation, row_data) VALUES
         ($1, 'UPDATE', jsonb_build_object('revision', 41, 'blob_version', 3)),
         ($2, 'UPDATE', jsonb_build_object('blob_version', 1))`,
      [withRevision, withoutRevision],
    );

    const { rows } = await admin.query<{ row_id: string; revision: number | null }>(
      `SELECT row_id, revision FROM vault_items_versions WHERE row_id = ANY($1::uuid[])`,
      [[withRevision, withoutRevision]],
    );
    const byRow = new Map(rows.map((r) => [r.row_id, r.revision]));
    expect(byRow.get(withRevision)).toBe(41);
    // NULL is not an oversight: an image with no handle cannot be NAMED, and an
    // image that cannot be named cannot be restored by mistake.
    expect(byRow.get(withoutRevision)).toBeNull();
  });

  describe('the retired index actually serves the reader that needs it', () => {
    let plan: string;

    beforeAll(async () => {
      // Enough rows that a sequential scan is not simply the cheaper plan — on
      // a nearly-empty table the planner correctly ignores an index, and an
      // EXPLAIN there would measure the row count rather than the schema.
      await admin.query(
        `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version, deleted_at, deleted_reason)
         SELECT gen_random_uuid(), $1, 'password', '\\x00'::bytea, 1,
                now() - (g || ' minutes')::interval,
                CASE WHEN g % 2 = 0 THEN 'user_delete' ELSE 'vault_reset' END
           FROM generate_series(1, 4000) g`,
        [owner],
      );
      await admin.query(`ANALYZE vault_items`);

      const sql = capturedListRestorable(owner);
      // ANTI-VACUITY. If the capture ever comes back empty — a renamed method,
      // a repo that stops issuing one statement — every assertion below would
      // be made about an empty string and the whole block would pass by
      // describing nothing.
      expect(sql.text).toContain('FROM vault_items');
      expect(sql.values).toHaveLength(5);

      const { rows } = await admin.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN (COSTS OFF) ${sql.text}`,
        sql.values,
      );
      plan = rows.map((r) => r['QUERY PLAN']).join('\n');
    }, 60000);

    it('plans an index scan on the retired index', () => {
      expect(plan).toContain(`Index Scan using ${RETIRED_INDEX}`);
    });

    it('never falls back to a sequential scan of the items table', () => {
      // This is what the `deleted_reason = ANY($2)` shape degrades to on this
      // fixture. It is a SILENT degradation: same rows, same order, right
      // answer, and a plan that reads every item the user ever retired.
      expect(plan).not.toContain('Seq Scan on vault_items');
    });

    it('pushes the LIMIT inside the per-reason scan, not just above the merge', () => {
      // THE SHAPE-INVARIANT ASSERTION, and the reason this block does not rest
      // on "no Seq Scan". Whether a flat `= ANY` query gets a sequential scan
      // or a bitmap one is a function of the DATA, so on a differently-shaped
      // table that mutation could keep an index and still be wrong. What it can
      // never have is a second `Limit`: only the LATERAL puts one per reason,
      // where it can stop the index early. Two nodes — the merge's and the
      // scan's — is the property, and it does not depend on the fixture.
      expect(plan.match(/Limit/g) ?? []).toHaveLength(2);
    });

    it('uses BOTH leading key columns of the index, so each scan stops early', () => {
      // `deleted_reason` is the index's second key column and is bound per
      // iteration from the unnest. Without it in the Index Cond the scan walks
      // every retired row for the user and filters, which is the cost the
      // column order exists to avoid.
      const cond = plan.split('\n').find((l) => l.includes('Index Cond')) ?? '';
      expect(cond).toContain('user_id');
      expect(cond).toContain('deleted_reason');
    });

    it('sorts the MERGED rows, and that Sort is correct rather than a defect', () => {
      // Stated because an earlier version of this file asserted the opposite.
      // Each per-reason scan comes out in index order, but the union of them
      // does not, so a top-level Sort is inherent to the shape. It is bounded
      // by (reasons x limit) rows — unlike the mutation's, which sorts every
      // matching row in the table.
      expect(plan).toContain('Sort');
    });
  });

  describe('the versions index actually serves the versions reader', () => {
    // THE OTHER READER, and it was missing. This file's header claimed BOTH of
    // PR1b's readers were covered while only one had a plan asserted about it —
    // a fence whose input is narrower than its claim, green for the same reason
    // it is wrong.
    let plan: string;

    beforeAll(async () => {
      const item = randomUUID();
      await admin.query(
        `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
         VALUES ($1, $2, 'password', '\\x00'::bytea, 1)`,
        [item, owner],
      );
      // A long history on the target row, and a much longer table around it:
      // the LATERAL's value is that it stops after LIMIT rows instead of
      // reading the row's whole past, and that is invisible on a short one.
      await admin.query(
        `INSERT INTO vault_items_versions (row_id, operation, row_data)
         SELECT $1, 'UPDATE', jsonb_build_object('revision', g, 'blob_version', g)
           FROM generate_series(1, 3000) g`,
        [item],
      );
      await admin.query(
        `INSERT INTO vault_items_versions (row_id, operation, row_data)
         SELECT gen_random_uuid(), 'UPDATE', jsonb_build_object('revision', g, 'blob_version', g)
           FROM generate_series(1, 20000) g`,
      );
      await admin.query(`ANALYZE vault_items_versions`);

      const sql = capturedListVersions(owner, item);
      expect(sql.text).toContain('vault_items_versions');
      expect(sql.values).toHaveLength(4);

      const { rows } = await admin.query<{ 'QUERY PLAN': string }>(
        `EXPLAIN (COSTS OFF) ${sql.text}`,
        sql.values,
      );
      plan = rows.map((r) => r['QUERY PLAN']).join('\n');
    }, 60000);

    it('plans an index scan on the versions index', () => {
      expect(plan).toContain(`Index Scan using ${VERSIONS_INDEX}`);
    });

    it('never scans the whole shadow table', () => {
      // Without the index this is a scan of every image of every user's every
      // item — the table nothing prunes.
      expect(plan).not.toContain('Seq Scan on vault_items_versions');
    });

    it('keeps the LIMIT inside the LATERAL, where it can stop the index early', () => {
      // The measured difference this shape exists for: with the cursor in a
      // plain JOIN condition the LIMIT applies after the join, so a page costs
      // the row's whole history instead of one index descent.
      expect(plan).toContain('Limit');
      expect(plan).not.toContain('Sort');
    });
  });
});
