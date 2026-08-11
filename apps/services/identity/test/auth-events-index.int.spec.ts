/**
 * The auth_events index, against real Postgres (M16).
 *
 * An index is a property of a STATEMENT, so the M13 rule applies at full
 * strength: a unit suite that fakes the repo cannot see whether this exists,
 * and neither can a reader of the migration file, because a file being present
 * in the tree is not the same as its statement having run.
 *
 * TWO FACTS, ASSERTED SEPARATELY AND ON PURPOSE — the 2026-08-06 lesson from
 * profile's `role-unique-migration.int.spec.ts`. That migration was first
 * appended to an already-applied file, and the pair of facts an edited-in-place
 * migration separates is exactly "the migrator recorded this name" and "the
 * object it creates is there". Asserting only the first passes over a file
 * whose contents changed after it was applied; asserting only the second passes
 * over an index some other migration happened to create. So both.
 *
 * The third assertion is the one with teeth: the index has to SERVE the query
 * it was added for. An index on the right table with the wrong column order
 * satisfies both facts above and still leaves `lastOccurredAt` — the docs/03
 * §5.1 owner-liveness read — on a sequential scan.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { AuthEventsRepo } from '../src/auth-events.repo';
import { Db } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const MIGRATION = '005_auth_events_index.sql';
const INDEX = 'ix_auth_events_user_kind_time';

describeIfPg('auth_events index (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identityaeidx_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let events: AuthEventsRepo;

  const user = randomUUID();

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

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    events = new AuthEventsRepo(db);

    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [user, Buffer.from('ct'), Buffer.from('bidx'), randomUUID()],
    );
  });

  afterAll(async () => {
    // `Db` is a Nest provider wrapping a pg Pool; it closes through the
    // lifecycle hook, not an `end()`. Calling the wrong one throws inside
    // afterAll, leaves the pool open, and jest hangs on the handle rather than
    // failing — which is how this was found.
    await db?.onModuleDestroy();
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

  it('the index exists on auth_events', async () => {
    // Filtered on nspname: this Postgres is shared and every int suite creates
    // its own scratch schema, so an unqualified pg_catalog query would happily
    // find another suite's identically-named object and pass over its own.
    const { rows } = await admin.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes
        WHERE schemaname = $1 AND tablename = 'auth_events' AND indexname = $2`,
      [schema, INDEX],
    );
    expect(rows.map((r) => r.indexname)).toEqual([INDEX]);
  });

  it('covers (user_id, kind, occurred_at) in that order', async () => {
    // The column ORDER is the whole value of the index — both readers filter
    // user_id and kind for equality and then want the newest row. A definition
    // check rather than an EXPLAIN, because on a nearly-empty table the planner
    // correctly prefers a sequential scan and an EXPLAIN assertion here would
    // measure the row count rather than the schema.
    const { rows } = await admin.query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes
        WHERE schemaname = $1 AND tablename = 'auth_events' AND indexname = $2`,
      [schema, INDEX],
    );
    expect(rows[0]?.indexdef).toMatch(/\(user_id, kind, occurred_at DESC\)/);
  });

  it('lastOccurredAt still answers correctly through it', async () => {
    // The index is an optimisation and must not change the answer. This is the
    // docs/03 §5.1 owner-liveness read: the NEWEST occurrence wins, and an
    // unrelated kind must not be mistaken for one.
    await events.insert({ userId: user, kind: 'stepup.granted' });
    await events.insert({ userId: user, kind: 'stepup.denied' });
    await events.insert({ userId: user, kind: 'stepup.granted' });

    const granted = await events.lastOccurredAt(user, 'stepup.granted');
    const denied = await events.lastOccurredAt(user, 'stepup.denied');
    expect(granted).toBeInstanceOf(Date);
    expect(denied).toBeInstanceOf(Date);
    expect((granted as Date).getTime()).toBeGreaterThanOrEqual((denied as Date).getTime());
    expect(await events.lastOccurredAt(user, 'stepup.never.happened')).toBeNull();
    expect(await events.lastOccurredAt(randomUUID(), 'stepup.granted')).toBeNull();
  });
});
