import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolConfig, type QueryResultRow } from 'pg';
import { PG_POOL_CONFIG } from './di-tokens';

/**
 * A query surface shared by the pooled Db and an open transaction, so
 * repositories can serve both without knowing which they run under (the assets
 * service's shape, adopted verbatim by profile and now here).
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
   * Run `fn` inside a single transaction — the assets/profile chokepoint,
   * arriving in identity LAST of the nine services and for two reasons at once
   * (M17 PR2).
   *
   * ATOMICITY. A password change has to write the new hash AND revoke the
   * user's other sessions or do NEITHER. A hash written without the revocation
   * leaves every credential minted under the OLD password live, which is the
   * whole thing a password change is for; a revocation without the hash signs
   * somebody out of their own account and changes nothing. Two statements on a
   * pool are two chances for the process to die in between.
   *
   * ATTRIBUTION, and this is why it could not be deferred. `users_versions`
   * captures a row image on every `users` UPDATE and stamps
   * `current_setting('app.actor_id')` as the actor. Identity was the ONE
   * service that never set it — measured against real Postgres, every captured
   * row came back `actor_id NULL, reason NULL` — so before this the single
   * durable record of a password change would have been an unattributed row
   * image. That matters more here than anywhere: PR2 also REDACTS the hash out
   * of that image, and the argument for redacting is that what survives capture
   * is who and when. Without attribution there is no who, and the capture would
   * be pure liability.
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

/** Postgres unique-violation detector (no-enumeration register path, DEK uniqueness). */
export function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505'
  );
}
