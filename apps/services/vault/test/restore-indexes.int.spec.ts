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
 * than inferred, and the reader's own predicate is asserted to CONTAIN the
 * index's — because Postgres matches a partial index by its predicate and not
 * through migration 004's CHECK equivalence, so `deleted_reason IS NOT NULL`
 * would return the same rows off a sequential scan.
 */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

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

  it('the reader spells the index predicate verbatim, not 004’s equivalent', () => {
    // Postgres matches a partial index by its PREDICATE. `deleted_reason IS NOT
    // NULL` is equivalent under migration 004's CHECK, returns the same rows,
    // and gets a sequential scan — a silent de-optimisation with no wrong
    // answer to notice. So the reader's text is asserted to carry the index's.
    const repo = readFileSync(join(__dirname, '..', 'src', 'items.repo.ts'), 'utf8');
    const listRestorable = repo.slice(repo.indexOf('async listRestorable'));
    const body = listRestorable.slice(0, listRestorable.indexOf('\n  }'));
    expect(body).toContain('deleted_at IS NOT NULL');
    expect(body).not.toContain('deleted_reason IS NOT NULL');
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

  it('the retired index actually serves the restorable list', async () => {
    // Enough rows that a sequential scan is not simply the cheaper plan — on a
    // nearly-empty table the planner correctly ignores an index, and an EXPLAIN
    // there would measure the row count rather than the schema.
    await admin.query(
      `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version, deleted_at, deleted_reason)
       SELECT gen_random_uuid(), $1, 'password', '\\x00'::bytea, 1,
              now() - (g || ' minutes')::interval,
              CASE WHEN g % 2 = 0 THEN 'user_delete' ELSE 'vault_reset' END
         FROM generate_series(1, 4000) g`,
      [owner],
    );
    await admin.query(`ANALYZE vault_items`);

    const { rows } = await admin.query<{ 'QUERY PLAN': string }>(
      `EXPLAIN (COSTS OFF)
       SELECT id FROM vault_items
        WHERE user_id = $1 AND deleted_at IS NOT NULL AND deleted_reason = 'user_delete'
        ORDER BY deleted_at DESC, id DESC LIMIT 20`,
      [owner],
    );
    const plan = rows.map((r) => r['QUERY PLAN']).join('\n');
    expect(plan).toContain(RETIRED_INDEX);
    // And no sort: the index supplies the order the reader asks for.
    expect(plan).not.toContain('Sort');
  });
});
