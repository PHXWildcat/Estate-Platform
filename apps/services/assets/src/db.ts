import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolConfig, type QueryResultRow } from 'pg';
import { PG_POOL_CONFIG } from './di-tokens';

/**
 * A query surface shared by the pooled Db and an open transaction, so
 * repositories can serve both without knowing which they run under. Every
 * query goes through one of the two chokepoints below — the rule
 * "parameterized queries only" has exactly two enforcement points.
 */
export interface Queryable {
  query<T extends QueryResultRow>(text: string, values?: unknown[]): Promise<T[]>;
}

/**
 * Thin provider around a pg Pool, plus the transaction chokepoint the ledger
 * requires (append + projection must commit atomically). Tests can point the
 * pool at a scratch schema via PoolConfig.options (`-c search_path=...`).
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
   * Run `fn` inside a single transaction. The transaction-scoped GUC
   * `app.actor_id` is set so the version-capture triggers record who caused
   * each captured row (docs/02 conventions).
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

/** Postgres unique-violation detector (event-id idempotency, DEK uniqueness). */
export function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505'
  );
}

/** Postgres check-violation detector (share-sum constraint trigger). */
export function isCheckViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23514'
  );
}
