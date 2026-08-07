/**
 * Integration tests for migration 004_role_assignments_unique's pre-flight.
 * Gated like the other int suites: set PG_TEST_URL to run. Each case stages a
 * scratch schema at the pre-004 baseline, seeds the duplicate state that could
 * already exist, then runs the full migrator so 004 applies against real data.
 *
 * TWO PROPERTIES UNDER TEST, and the second is why this file exists rather than
 * a hand check:
 *
 *  1. The index REFUSES to be created over pre-existing duplicate live
 *     designations, naming them, and retires nothing — the
 *     `002_dek_unique_active` rule. Duplicates are identical as designations but
 *     not as rows: each has its own id and `permission_grants.role_assignment_id`
 *     references it, so retiring the "spare" would silently revoke every grant
 *     hanging off it. A migration must not pick which one dies.
 *  2. It IS a separate file. The index was first appended to 003, which the
 *     migrator had already recorded — and the migrator keys on FILENAME, so the
 *     edit would silently never have run. The local stack proved it: 003 applied,
 *     index absent. This suite would have caught that, because it applies the
 *     real directory and then asserts the index exists.
 */
import { mkdtemp, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { Migrator } from '@estate/db';
import { Client } from 'pg';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const MIGRATIONS = join(__dirname, '..', 'migrations');
const BLOCKED = /duplicate live role_assignments exist/;

describeIfPg('004_role_assignments_unique pre-flight', () => {
  jest.setTimeout(120_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  let baselineDir: string;

  beforeAll(async () => {
    // Everything up to but NOT including 004, so a case can seed the pre-index
    // world and then let the real directory apply 004 over it.
    baselineDir = await mkdtemp(join(tmpdir(), 'profsvc-roleuniq-'));
    for (const file of [
      '001_core_schema.sql',
      '002_dek_unique_active.sql',
      '003_contact_link_invitations.sql',
    ]) {
      await copyFile(join(MIGRATIONS, file), join(baselineDir, file));
    }
  });

  async function withBaselineSchema(
    fn: (client: Client, schema: string) => Promise<void>,
  ): Promise<void> {
    const schema = `profsvc_roleuniq_${Date.now()}_${randomBytes(4).toString('hex')}`;
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

  async function seedContact(client: Client, ownerId: string): Promise<string> {
    const id = randomUUID();
    await client.query(
      `INSERT INTO contacts (id, owner_user_id, name_ct, dek_id) VALUES ($1, $2, $3, $4)`,
      [id, ownerId, randomBytes(16), randomUUID()],
    );
    return id;
  }

  async function seedRole(
    client: Client,
    ownerId: string,
    contactId: string,
    opts: { role?: string; condition?: string; scopeId?: string | null; deleted?: boolean } = {},
  ): Promise<string> {
    const id = randomUUID();
    await client.query(
      `INSERT INTO role_assignments
         (id, owner_user_id, contact_id, role, scope_type, scope_id, effective_condition, deleted_at)
       VALUES ($1, $2, $3, $4, 'estate', $5, $6, $7)`,
      [
        id,
        ownerId,
        contactId,
        opts.role ?? 'executor',
        opts.scopeId ?? null,
        opts.condition ?? 'on_death_verified',
        opts.deleted === true ? new Date() : null,
      ],
    );
    return id;
  }

  async function applyRest(client: Client): Promise<string[]> {
    const { applied } = await new Migrator(client, MIGRATIONS).migrate();
    return applied;
  }

  async function hasIndex(client: Client, schema: string): Promise<boolean> {
    const { rows } = await client.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM pg_indexes
        WHERE schemaname = $1 AND indexname = 'ux_role_assignments_live'`,
      [schema],
    );
    return rows[0]?.n !== '0';
  }

  it('applies on a clean database, and the index is really there', async () => {
    await withBaselineSchema(async (client, schema) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      await seedRole(client, owner, contact);

      const applied = await applyRest(client);
      // The whole reason this is a separate file: an edit to an applied 003
      // would leave `applied` empty here and the index absent.
      expect(applied).toContain('004_role_assignments_unique.sql');
      expect(await hasIndex(client, schema)).toBe(true);
    });
  });

  it('REFUSES over pre-existing duplicates, naming them, retiring nothing', async () => {
    await withBaselineSchema(async (client, schema) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      const first = await seedRole(client, owner, contact);
      const second = await seedRole(client, owner, contact);

      await expect(applyRest(client)).rejects.toThrow(BLOCKED);

      // Nothing retired: the migration must not choose which designation dies,
      // because `permission_grants` reference the row id, not the designation.
      const { rows } = await client.query<{ id: string; deleted_at: Date | null }>(
        `SELECT id, deleted_at FROM role_assignments ORDER BY id`,
      );
      expect(rows).toHaveLength(2);
      for (const row of rows) {
        expect(row.deleted_at).toBeNull();
      }
      expect(rows.map((r) => r.id).sort()).toEqual([first, second].sort());
      expect(await hasIndex(client, schema)).toBe(false);
    });
  });

  it('treats a SOFT-DELETED duplicate as no duplicate at all', async () => {
    await withBaselineSchema(async (client, schema) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      await seedRole(client, owner, contact);
      await seedRole(client, owner, contact, { deleted: true });

      // The index is partial on deleted_at, so a revoked designation frees the
      // slot — which is what makes re-granting after a revoke work.
      expect(await applyRest(client)).toContain('004_role_assignments_unique.sql');
      expect(await hasIndex(client, schema)).toBe(true);
    });
  });

  it('does not confuse designations that differ only by condition or scope', async () => {
    await withBaselineSchema(async (client, schema) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      await seedRole(client, owner, contact, { condition: 'immediate' });
      await seedRole(client, owner, contact, { condition: 'on_death_verified' });
      await seedRole(client, owner, contact, { condition: 'immediate', scopeId: randomUUID() });

      expect(await applyRest(client)).toContain('004_role_assignments_unique.sql');
      expect(await hasIndex(client, schema)).toBe(true);
    });
  });

  it('the pre-flight groups NULL scopes together, so whole-estate dupes are caught', async () => {
    await withBaselineSchema(async (client) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      await seedRole(client, owner, contact, { scopeId: null });
      await seedRole(client, owner, contact, { scopeId: null });
      await expect(applyRest(client)).rejects.toThrow(BLOCKED);
    });
  });

  /**
   * THE COALESCE IS THE INDEX'S OWN BUSINESS, and it has to be tested THROUGH THE
   * INDEX. An earlier version of this case seeded two whole-estate duplicates and
   * asserted the migration refused — which passes with or without the COALESCE,
   * because the pre-flight's GROUP BY treats NULLs as equal while a UNIQUE INDEX
   * does not. The test was named for a property it never touched: caught by
   * mutating the COALESCE away and watching the suite stay green.
   *
   * So this one migrates a CLEAN database (pre-flight satisfied, index created)
   * and then asks Postgres to accept the duplicate. Without the COALESCE it does,
   * and unlimited duplicates of precisely the BROADEST designation slip through.
   */
  it('the COALESCE matters: the INDEX itself rejects a second whole-estate designation', async () => {
    await withBaselineSchema(async (client, schema) => {
      const owner = randomUUID();
      const contact = await seedContact(client, owner);
      await seedRole(client, owner, contact, { scopeId: null });

      expect(await applyRest(client)).toContain('004_role_assignments_unique.sql');
      expect(await hasIndex(client, schema)).toBe(true);

      // scope_id IS NULL on both rows: only COALESCE makes them collide.
      await expect(seedRole(client, owner, contact, { scopeId: null })).rejects.toThrow(
        /ux_role_assignments_live|duplicate key/,
      );

      // ...and a NAMED scope is still a different designation, so it inserts.
      await expect(
        seedRole(client, owner, contact, { scopeId: randomUUID() }),
      ).resolves.toBeDefined();
    });
  });
});
