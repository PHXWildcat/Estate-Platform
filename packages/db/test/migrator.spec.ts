/**
 * Integration tests for the migrator + conventions against a real Postgres.
 * Gated on PG_TEST_URL (CI provides a service container; locally use
 * docker-compose.dev.yml and e.g. postgres://estate:estate_dev@localhost:5433/auth).
 */
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from 'pg';
import {
  softDeleteUniqueIndexSql,
  updatedAtFunctionSql,
  updatedAtTriggerSql,
  versionsTableSql,
} from '../src/conventions';
import { MigrationDriftError, Migrator, type SqlSession } from '../src/migrator';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/** Records the statements issued, so ordering can be asserted without a server. */
class RecordingSession implements SqlSession {
  readonly queries: string[] = [];

  query(text: string): Promise<{ rows: Array<Record<string, unknown>> }> {
    this.queries.push(text);
    return Promise.resolve({ rows: [] });
  }
}

describe('Migrator statement ordering', () => {
  it('takes the advisory lock BEFORE creating schema_migrations', async () => {
    // The regression pin for the co-tenant race. `CREATE TABLE IF NOT EXISTS`
    // is not race-safe: two sessions can pass the existence check together and
    // the loser raises duplicate_relation. Running it outside the lock meant
    // the two migration jobs that share a cluster — profile+settlement on core,
    // assets+plaid on financial — could collide on a fresh database. The
    // concurrency test below can only catch that intermittently; this cannot
    // miss it.
    const dir = await mkdtemp(join(tmpdir(), 'estate-mig-order-'));
    try {
      const session = new RecordingSession();
      await new Migrator(session, dir).migrate();
      const lockAt = session.queries.findIndex((q) => q.includes('pg_advisory_lock'));
      const createAt = session.queries.findIndex((q) =>
        q.includes('CREATE TABLE IF NOT EXISTS schema_migrations'),
      );
      expect(lockAt).toBeGreaterThanOrEqual(0);
      expect(createAt).toBeGreaterThan(lockAt);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('always releases the lock, even when the run fails', async () => {
    const session = new RecordingSession();
    await expect(new Migrator(session, '/no/such/dir').migrate()).rejects.toThrow();
    expect(session.queries.some((q) => q.includes('pg_advisory_unlock'))).toBe(true);
  });
});

const SETUP_SQL = `
${updatedAtFunctionSql()}

CREATE TABLE widgets (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title      TEXT NOT NULL,
  email_bidx BYTEA,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

${updatedAtTriggerSql('widgets')}
${versionsTableSql('widgets')}
${softDeleteUniqueIndexSql('widgets', ['email_bidx'])}
`;

describeIfPg('Migrator against Postgres', () => {
  let client: Client;
  let dir: string;
  let migrator: Migrator;
  const schema = `mig_test_${Date.now()}`;

  beforeAll(async () => {
    client = new Client({ connectionString: process.env['PG_TEST_URL'] });
    await client.connect();
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    dir = await mkdtemp(join(tmpdir(), 'estate-mig-'));
    await writeFile(join(dir, '001_setup.sql'), SETUP_SQL, 'utf8');
    migrator = new Migrator(client, dir);
  });

  afterAll(async () => {
    await client.query(`DROP SCHEMA ${schema} CASCADE`);
    await client.end();
    await rm(dir, { recursive: true, force: true });
  });

  it('applies pending migrations once, then no-ops', async () => {
    expect((await migrator.migrate()).applied).toEqual(['001_setup.sql']);
    expect((await migrator.migrate()).applied).toEqual([]);
  });

  it('maintains updated_at by trigger and captures prior rows in _versions', async () => {
    const actor = randomUUID();
    const inserted = await client.query(
      `INSERT INTO widgets (title) VALUES ('original') RETURNING id, updated_at`,
    );
    const row = inserted.rows[0] as { id: string; updated_at: Date };

    await client.query(`SELECT set_config('app.actor_id', $1, false)`, [actor]);
    await client.query(`SELECT set_config('app.change_reason', 'test_edit', false)`);
    await client.query(`UPDATE widgets SET title = 'renamed' WHERE id = $1`, [row.id]);

    const versions = await client.query(
      `SELECT operation, row_data, actor_id, reason FROM widgets_versions WHERE row_id = $1`,
      [row.id],
    );
    expect(versions.rows).toHaveLength(1);
    const version = versions.rows[0] as {
      operation: string;
      row_data: { title: string };
      actor_id: string;
      reason: string;
    };
    expect(version.operation).toBe('UPDATE');
    expect(version.row_data.title).toBe('original'); // full PRIOR row
    expect(version.actor_id).toBe(actor);
    expect(version.reason).toBe('test_edit');

    const current = await client.query(`SELECT title, updated_at FROM widgets WHERE id = $1`, [
      row.id,
    ]);
    const updated = current.rows[0] as { title: string; updated_at: Date };
    expect(updated.title).toBe('renamed');
    expect(updated.updated_at.getTime()).toBeGreaterThan(row.updated_at.getTime());
  });

  it('enforces uniqueness only among non-deleted rows (soft delete)', async () => {
    const bidx = Buffer.from('aa11', 'hex');
    await client.query(`INSERT INTO widgets (title, email_bidx) VALUES ('a', $1)`, [bidx]);
    await expect(
      client.query(`INSERT INTO widgets (title, email_bidx) VALUES ('b', $1)`, [bidx]),
    ).rejects.toThrow(/duplicate key/);
    await client.query(`UPDATE widgets SET deleted_at = now() WHERE email_bidx = $1`, [bidx]);
    await expect(
      client.query(`INSERT INTO widgets (title, email_bidx) VALUES ('c', $1)`, [bidx]),
    ).resolves.toBeDefined();
  });

  it('detects drift when an applied migration is edited', async () => {
    await writeFile(join(dir, '001_setup.sql'), `${SETUP_SQL}\n-- sneaky edit`, 'utf8');
    await expect(migrator.migrate()).rejects.toThrow(MigrationDriftError);
    await writeFile(join(dir, '001_setup.sql'), SETUP_SQL, 'utf8'); // restore
  });

  it('applies newly added migrations in order', async () => {
    await writeFile(
      join(dir, '002_add_note.sql'),
      `ALTER TABLE widgets ADD COLUMN note TEXT;`,
      'utf8',
    );
    expect((await migrator.migrate()).applied).toEqual(['002_add_note.sql']);
  });
});

describeIfPg('Migrator co-tenant concurrency', () => {
  // Two services sharing one cluster (profile+settlement on core,
  // assets+plaid on financial) run their migration jobs at the same moment
  // against a database where NOTHING exists yet — including schema_migrations.
  const schema = `mig_race_${Date.now()}`;
  let clients: Client[];
  let dirs: string[];

  beforeAll(async () => {
    clients = [];
    dirs = [];
    for (const owner of ['alpha', 'beta']) {
      const client = new Client({ connectionString: process.env['PG_TEST_URL'] });
      await client.connect();
      clients.push(client);
      const dir = await mkdtemp(join(tmpdir(), `estate-mig-${owner}-`));
      // Disjoint file names, as the real co-tenants have.
      await writeFile(
        join(dir, `001_${owner}.sql`),
        `CREATE TABLE ${owner}_thing (id UUID PRIMARY KEY DEFAULT gen_random_uuid());`,
        'utf8',
      );
      dirs.push(dir);
    }
    await clients[0]!.query(`CREATE SCHEMA ${schema}`);
    for (const client of clients) {
      await client.query(`SET search_path TO ${schema}`);
    }
  });

  afterAll(async () => {
    await clients[0]!.query(`DROP SCHEMA ${schema} CASCADE`);
    for (const client of clients) {
      await client.end();
    }
    for (const dir of dirs) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('two co-owners bootstrapping the same empty cluster both succeed', async () => {
    const results = await Promise.all(
      clients.map((client, i) => new Migrator(client, dirs[i]!).migrate()),
    );
    expect(results[0]!.applied).toEqual(['001_alpha.sql']);
    expect(results[1]!.applied).toEqual(['001_beta.sql']);
    // Both co-owners' rows live in the one shared bookkeeping table, and each
    // ignores the other's — the co-tenancy mechanic M7 relies on.
    const { rows } = await clients[0]!.query<{ name: string }>(
      'SELECT name FROM schema_migrations ORDER BY name',
    );
    expect(rows.map((r) => r.name)).toEqual(['001_alpha.sql', '001_beta.sql']);
  });
});
