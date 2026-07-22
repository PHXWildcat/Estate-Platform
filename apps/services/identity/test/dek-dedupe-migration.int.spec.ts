/**
 * Integration tests for migration 002_dek_unique_active's pre-flight dedupe
 * (auth cluster). Gated exactly like the other int suites: set PG_TEST_URL to
 * run. Each case stages a fresh scratch schema at the 001 baseline, seeds a
 * pre-index DEK state the getOrCreateDek race could have left behind, then
 * runs the full migrator so 002 applies against real data.
 *
 * The safety property under test: a DEK is retired (destroyed_at set — i.e.
 * crypto-shredded) ONLY when verified unreferenced; any state the migration
 * cannot prove safe must abort it, retiring nothing.
 */
import { mkdtemp, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Migrator } from '@estate/db';
import { Client } from 'pg';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const MIGRATIONS = join(__dirname, '..', 'migrations');
const BLOCKED = /DEK dedupe blocked/;

describeIfPg('002_dek_unique_active pre-flight dedupe (auth cluster)', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  let baselineDir: string;

  beforeAll(async () => {
    // A staged migrations dir holding only 001, so each case can seed the
    // pre-002 world before the full dir (001 checksum unchanged) applies 002.
    baselineDir = await mkdtemp(join(tmpdir(), 'idsvc-dedupe-'));
    await copyFile(
      join(MIGRATIONS, '001_auth_schema.sql'),
      join(baselineDir, '001_auth_schema.sql'),
    );
  });

  /** Fresh scratch schema migrated to the 001 baseline only. */
  async function withBaselineSchema(
    fn: (client: Client, schema: string) => Promise<void>,
  ): Promise<void> {
    const schema = `idsvc_dedupe_${Date.now()}_${randomBytes(4).toString('hex')}`;
    const client = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await client.connect();
    try {
      await client.query(`CREATE SCHEMA ${schema}`);
      await new Migrator(client, baselineDir).migrate();
      await fn(client, schema);
    } finally {
      await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await client.end();
    }
  }

  async function seedDek(
    client: Client,
    dekId: string,
    userId: string,
    createdAt: string,
  ): Promise<void> {
    await client.query(
      `INSERT INTO deks (dek_id, user_id, kek_alias, wrapped_key, created_at)
       VALUES ($1, $2, 'local', $3, $4)`,
      [dekId, userId, randomBytes(32), createdAt],
    );
  }

  async function seedUser(client: Client, userId: string, dekId: string): Promise<void> {
    await client.query(
      `INSERT INTO users (id, email_ct, email_bidx, dek_id) VALUES ($1, $2, $3, $4)`,
      [userId, randomBytes(16), randomBytes(32), dekId],
    );
  }

  async function activeDeks(client: Client, userId: string): Promise<string[]> {
    const { rows } = await client.query(
      `SELECT dek_id FROM deks WHERE user_id = $1 AND destroyed_at IS NULL`,
      [userId],
    );
    return rows.map((r) => (r as { dek_id: string }).dek_id).sort();
  }

  it('retires the unreferenced newer DEK, keeps the one users.dek_id references, and installs the unique index', async () => {
    await withBaselineSchema(async (client, schema) => {
      const userId = randomUUID();
      const referenced = randomUUID();
      const orphan = randomUUID();
      await seedDek(client, referenced, userId, '2026-07-01T00:00:00Z');
      await seedDek(client, orphan, userId, '2026-07-02T00:00:00Z'); // newer, but unreferenced
      await seedUser(client, userId, referenced);

      await new Migrator(client, MIGRATIONS).migrate();

      expect(await activeDeks(client, userId)).toEqual([referenced]);
      // Retired, not deleted — no hard deletes anywhere.
      const { rows } = await client.query(
        `SELECT destroyed_at FROM deks WHERE dek_id = $1`,
        [orphan],
      );
      expect((rows[0] as { destroyed_at: Date | null }).destroyed_at).not.toBeNull();

      // The plain index is superseded by the unique partial index…
      const idx = await client.query(
        `SELECT indexname FROM pg_indexes WHERE schemaname = $1 AND tablename = 'deks'`,
        [schema],
      );
      const names = idx.rows.map((r) => (r as { indexname: string }).indexname);
      expect(names).toContain('ux_deks_user_active');
      expect(names).not.toContain('ix_deks_user_active');
      // …and the database now rejects a second active DEK outright.
      await expect(seedDek(client, randomUUID(), userId, '2026-07-03T00:00:00Z')).rejects.toMatchObject(
        { code: '23505' },
      );
    });
  });

  it('keeps the newest DEK when nothing references either (orphaned first-write race)', async () => {
    await withBaselineSchema(async (client) => {
      const userId = randomUUID();
      const older = randomUUID();
      const newest = randomUUID();
      await seedDek(client, older, userId, '2026-07-01T00:00:00Z');
      await seedDek(client, newest, userId, '2026-07-02T00:00:00Z');

      await new Migrator(client, MIGRATIONS).migrate();

      expect(await activeDeks(client, userId)).toEqual([newest]);
    });
  });

  it('MFA rows bind the newest active DEK implicitly — with users.dek_id on the older one, the migration aborts and retires nothing', async () => {
    await withBaselineSchema(async (client) => {
      const userId = randomUUID();
      const explicitRef = randomUUID();
      const implicitRef = randomUUID();
      await seedDek(client, explicitRef, userId, '2026-07-01T00:00:00Z');
      await seedDek(client, implicitRef, userId, '2026-07-02T00:00:00Z');
      await seedUser(client, userId, explicitRef);
      // mfa_methods.secret_ct carries no dek_id; encrypt/decrypt resolve the
      // NEWEST active DEK, so this row pins `implicitRef` invisibly to SQL.
      await client.query(
        `INSERT INTO mfa_methods (user_id, kind, secret_ct) VALUES ($1, 'totp', $2)`,
        [userId, randomBytes(32)],
      );

      await expect(new Migrator(client, MIGRATIONS).migrate()).rejects.toThrow(BLOCKED);

      // Rolled back: both DEKs still active, 002 not recorded.
      expect(await activeDeks(client, userId)).toHaveLength(2);
      const { rows } = await client.query(
        `SELECT name FROM schema_migrations WHERE name = '002_dek_unique_active.sql'`,
      );
      expect(rows).toHaveLength(0);
    });
  });

  it('a DEK referenced only by a users_versions row image still blocks the migration', async () => {
    await withBaselineSchema(async (client) => {
      const userId = randomUUID();
      const historical = randomUUID();
      const current = randomUUID();
      await seedDek(client, historical, userId, '2026-07-01T00:00:00Z');
      await seedDek(client, current, userId, '2026-07-02T00:00:00Z');
      await seedUser(client, userId, historical);
      // The version-capture trigger snapshots the old row (dek_id=historical)
      // into users_versions; the live row now references `current`.
      await client.query(`UPDATE users SET dek_id = $1 WHERE id = $2`, [current, userId]);

      await expect(new Migrator(client, MIGRATIONS).migrate()).rejects.toThrow(BLOCKED);
      expect(await activeDeks(client, userId)).toHaveLength(2);
    });
  });
});
