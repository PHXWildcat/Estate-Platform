import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolConfig, type QueryResultRow } from 'pg';
import { PG_POOL_CONFIG } from './di-tokens';

/**
 * A query surface shared by the pooled Db and an open transaction, so
 * repositories can serve both without knowing which they run under (the assets
 * service's shape, adopted verbatim).
 */
export interface Queryable {
  query<T extends QueryResultRow>(text: string, values?: unknown[]): Promise<T[]>;
}

/**
 * Thin provider around a pg Pool. Every query goes through here so the rule
 * "parameterized queries only" has a single enforcement point, and so tests
 * can point the pool at a scratch schema via PoolConfig.options
 * (e.g. `-c search_path=...`).
 */
@Injectable()
export class Db implements Queryable, OnModuleDestroy {
  private readonly pool: Pool;

  constructor(@Inject(PG_POOL_CONFIG) poolConfig: PoolConfig) {
    this.pool = new Pool(poolConfig);
  }

  async query<T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> {
    const result = await this.pool.query<T>(text, values);
    return result.rows;
  }

  /**
   * Run `fn` inside a single transaction — the assets-service chokepoint, needed
   * here for the M13 PR3 link redemption.
   *
   * Redemption has to spend the invitation AND write the link or do NEITHER: an
   * invitation marked spent with no link written locks that contact out of ever
   * being linked, and a link written from an invitation still live is
   * replayable. A data-modifying CTE cannot express that — its UPDATE commits
   * even when the outer statement matches no rows — so the two statements need a
   * real transaction around them.
   *
   * `app.actor_id` is set transaction-locally so the `contacts` version-capture
   * trigger records WHO caused the captured row. On this path that is the
   * REDEEMER, not the owner, which is exactly what the trail should say.
   */
  async withTransaction<T>(actorId: string, fn: (tx: Queryable) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // set_config(..., true) is transaction-local: it resets at COMMIT/ROLLBACK.
      await client.query(`SELECT set_config('app.actor_id', $1, true)`, [actorId]);
      const tx: Queryable = {
        query: async <R extends QueryResultRow>(
          text: string,
          values: unknown[] = [],
        ): Promise<R[]> => {
          const result = await client.query<R>(text, values);
          return result.rows;
        },
      };
      const result = await fn(tx);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // The original error is the one that matters; a failed ROLLBACK on a
        // broken connection must not mask it.
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }
}

/** Postgres unique-violation detector (contacts soft-delete uniqueness, DEK uniqueness). */
export function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505'
  );
}
