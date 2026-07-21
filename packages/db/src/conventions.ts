/**
 * The docs/02 table conventions as SQL generators. Migrations call these
 * instead of hand-writing the boilerplate, so the conventions are impossible
 * to forget and trivial to audit:
 *
 *  - `updated_at` maintained by trigger
 *  - `<table>_versions` shadow table written by trigger on UPDATE/DELETE,
 *    INSERT-only (REVOKE UPDATE/DELETE)
 *  - append-only REVOKEs for event/audit tables
 *  - partial unique indexes that exclude soft-deleted rows
 *
 * Generators only interpolate validated identifiers — never data.
 */

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

function assertIdentifier(name: string): void {
  if (!IDENTIFIER.test(name)) {
    throw new Error(`invalid SQL identifier: ${JSON.stringify(name)}`);
  }
}

/** Shared trigger function; run once per database, before any updatedAtTriggerSql. */
export function updatedAtFunctionSql(): string {
  return `
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
`.trim();
}

export function updatedAtTriggerSql(table: string): string {
  assertIdentifier(table);
  return `
CREATE TRIGGER trg_${table}_updated_at
BEFORE UPDATE ON ${table}
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
`.trim();
}

/**
 * Versioning per docs/02: every mutable business table gets a shadow table
 * capturing the full prior row (as jsonb — ciphertext columns stay
 * ciphertext), the actor, and a reason, on every UPDATE or DELETE. The shadow
 * table is INSERT-only. Actor/reason flow through the per-request GUCs
 * `app.actor_id` / `app.change_reason`.
 *
 * Requires the base table to have a UUID primary key column `id`.
 */
export function versionsTableSql(table: string): string {
  assertIdentifier(table);
  return `
CREATE TABLE IF NOT EXISTS ${table}_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON ${table}_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION ${table}_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO ${table}_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.id,
    TG_OP,
    to_jsonb(OLD),
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_${table}_versions
BEFORE UPDATE OR DELETE ON ${table}
FOR EACH ROW EXECUTE FUNCTION ${table}_capture_version();
`.trim();
}

/** Append-only enforcement for event/audit tables (docs/02 §3/§6). */
export function appendOnlySql(table: string): string {
  assertIdentifier(table);
  return `REVOKE UPDATE, DELETE ON ${table} FROM PUBLIC;`;
}

/** Unique constraint that ignores soft-deleted rows (docs/02 conventions). */
export function softDeleteUniqueIndexSql(
  table: string,
  columns: readonly string[],
  indexName?: string,
): string {
  assertIdentifier(table);
  if (columns.length === 0) {
    throw new Error('at least one column required');
  }
  columns.forEach(assertIdentifier);
  const name = indexName ?? `ux_${table}_${columns.join('_')}`;
  assertIdentifier(name);
  return `
CREATE UNIQUE INDEX ${name} ON ${table} (${columns.join(', ')})
WHERE deleted_at IS NULL;
`.trim();
}
