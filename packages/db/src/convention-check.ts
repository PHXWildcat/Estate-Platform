import type { SqlSession } from './migrator';

/**
 * Automated verification that a migrated schema actually implements the
 * docs/02 conventions — the acceptance-criteria "schema-convention checker".
 * Run it in integration tests against every service's migrated schema so a
 * migration that forgets a shadow table or REVOKE fails CI, not review.
 */
export interface ConventionCheckOptions {
  /** Schema name the service's tables live in. */
  schema: string;
  /**
   * Mutable business tables: must have id/created_at/updated_at/deleted_at,
   * an updated_at trigger, a `<table>_versions` shadow table (INSERT-only)
   * and its capture trigger.
   */
  businessTables?: readonly string[];
  /** Append-only stores: PUBLIC must hold no UPDATE/DELETE grants. */
  appendOnlyTables?: readonly string[];
}

export async function checkConventions(
  db: SqlSession,
  options: ConventionCheckOptions,
): Promise<string[]> {
  const violations: string[] = [];
  const schema = options.schema;

  for (const table of options.businessTables ?? []) {
    const { rows: cols } = await db.query(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2`,
      [schema, table],
    );
    const byName = new Map(cols.map((c) => [c['column_name'] as string, c['data_type'] as string]));
    if (byName.get('id') !== 'uuid') {
      violations.push(`${table}: missing UUID primary column 'id'`);
    }
    for (const required of ['created_at', 'updated_at', 'deleted_at']) {
      if (!byName.has(required)) {
        violations.push(`${table}: missing convention column '${required}'`);
      }
    }

    const { rows: versionsTable } = await db.query(
      `SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2`,
      [schema, `${table}_versions`],
    );
    if (versionsTable.length === 0) {
      violations.push(`${table}: missing versions shadow table '${table}_versions'`);
    } else {
      violations.push(...(await publicWriteGrants(db, schema, `${table}_versions`)));
    }

    for (const [trigger, purpose] of [
      [`trg_${table}_updated_at`, 'updated_at maintenance'],
      [`trg_${table}_versions`, 'version capture'],
    ] as const) {
      const { rows } = await db.query(
        `SELECT 1 FROM information_schema.triggers
         WHERE trigger_schema = $1 AND event_object_table = $2 AND trigger_name = $3`,
        [schema, table, trigger],
      );
      if (rows.length === 0) {
        violations.push(`${table}: missing ${purpose} trigger '${trigger}'`);
      }
    }
  }

  for (const table of options.appendOnlyTables ?? []) {
    violations.push(...(await publicWriteGrants(db, schema, table)));
  }

  return violations;
}

async function publicWriteGrants(db: SqlSession, schema: string, table: string): Promise<string[]> {
  // has_table_privilege cannot evaluate the PUBLIC pseudo-role, so inspect
  // the grants catalog directly: any UPDATE/DELETE grant to PUBLIC on an
  // append-only/versions table violates the convention.
  const { rows } = await db.query(
    `SELECT privilege_type FROM information_schema.role_table_grants
     WHERE table_schema = $1 AND table_name = $2 AND grantee = 'PUBLIC'
       AND privilege_type IN ('UPDATE','DELETE')`,
    [schema, table],
  );
  return rows.map((r) => `${table}: PUBLIC holds ${r['privilege_type'] as string} grant`);
}
