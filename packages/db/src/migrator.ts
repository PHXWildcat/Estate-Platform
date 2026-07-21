import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

/**
 * A SINGLE database session (pg `Client` or a checked-out `PoolClient`).
 * Must not be a `Pool`: the advisory lock is session-scoped, so lock and
 * unlock have to run on the same connection.
 */
export interface SqlSession {
  query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

export class MigrationDriftError extends Error {
  constructor(readonly file: string) {
    super(
      `migration drift: ${file} changed after it was applied. ` +
        'Applied migrations are immutable — add a new migration instead.',
    );
    this.name = 'MigrationDriftError';
  }
}

// Arbitrary but stable app-wide advisory lock id for "migrations running".
const MIGRATION_LOCK_ID = 727_274;

/**
 * Minimal, deterministic SQL migration runner. Plain .sql files, applied in
 * lexicographic order, each in its own transaction, recorded with a content
 * checksum. Re-running is a no-op; editing an applied file is an error
 * (drift detection). Concurrent runners serialize on an advisory lock.
 *
 * Deliberately not a DSL: docs/02 DDL is the source of truth and should be
 * readable as SQL in review.
 */
export class Migrator {
  constructor(
    private readonly db: SqlSession,
    private readonly dir: string,
  ) {}

  async migrate(): Promise<{ applied: string[] }> {
    await this.db.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name       TEXT PRIMARY KEY,
        checksum   TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )`);
    await this.db.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
    try {
      const files = (await readdir(this.dir)).filter((f) => f.endsWith('.sql')).sort();
      const { rows } = await this.db.query('SELECT name, checksum FROM schema_migrations');
      const seen = new Map(rows.map((r) => [r['name'] as string, r['checksum'] as string]));

      const applied: string[] = [];
      for (const file of files) {
        const sql = await readFile(join(this.dir, file), 'utf8');
        const checksum = checksumOf(sql);
        const prior = seen.get(file);
        if (prior !== undefined) {
          if (prior !== checksum) {
            throw new MigrationDriftError(file);
          }
          continue;
        }
        await this.db.query('BEGIN');
        try {
          await this.db.query(sql);
          await this.db.query('INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)', [
            file,
            checksum,
          ]);
          await this.db.query('COMMIT');
        } catch (err) {
          await this.db.query('ROLLBACK');
          throw err;
        }
        applied.push(file);
      }
      return { applied };
    } finally {
      await this.db.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
    }
  }
}

/** Checksum over LF-normalized content so Windows/Unix checkouts agree. */
export function checksumOf(sql: string): string {
  return createHash('sha256').update(sql.replaceAll('\r\n', '\n'), 'utf8').digest('hex');
}
