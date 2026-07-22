import { Inject, Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolConfig, type QueryResultRow } from 'pg';
import { PG_POOL_CONFIG } from './di-tokens';

/**
 * Thin provider around a pg Pool. Every query goes through here so the rule
 * "parameterized queries only" has a single enforcement point, and so tests
 * can point the pool at a scratch schema via PoolConfig.options
 * (e.g. `-c search_path=...`).
 */
@Injectable()
export class Db implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(@Inject(PG_POOL_CONFIG) poolConfig: PoolConfig) {
    this.pool = new Pool(poolConfig);
  }

  async query<T extends QueryResultRow>(text: string, values: unknown[] = []): Promise<T[]> {
    const result = await this.pool.query<T>(text, values);
    return result.rows;
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
