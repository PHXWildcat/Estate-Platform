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
import { MigrationDriftError, Migrator } from '../src/migrator';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

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
