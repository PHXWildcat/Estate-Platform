import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export const DEFAULT_WAITING_PERIOD_DAYS = 5;

/**
 * The owner's waiting-period setting (docs/03 §5.1: default 5 days,
 * configurable UP). Absent row = the default; the floor lives in the DDL
 * CHECK, the zod schema, and the service's max() — three restatements of the
 * same invariant, none trusting the others.
 */
@Injectable()
export class SettingsRepo {
  async waitingPeriodDays(q: Queryable | Db, userId: string): Promise<number> {
    const rows = await q.query<{ waiting_period_days: number }>(
      `SELECT waiting_period_days FROM settlement_settings WHERE user_id = $1`,
      [userId],
    );
    return rows[0]?.waiting_period_days ?? DEFAULT_WAITING_PERIOD_DAYS;
  }

  async upsert(tx: Queryable, userId: string, waitingPeriodDays: number): Promise<void> {
    await tx.query(
      `INSERT INTO settlement_settings (user_id, waiting_period_days)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET waiting_period_days = EXCLUDED.waiting_period_days`,
      [userId, waitingPeriodDays],
    );
  }
}
