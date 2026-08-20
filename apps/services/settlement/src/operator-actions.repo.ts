import { Injectable } from '@nestjs/common';

import type { Db, Queryable } from './db';
import { OPERATOR_BREADTH_WINDOW_MS, type PermissiveOperatorAction } from './operator-breadth';

/**
 * The operator action ledger — one row per PERMISSIVE operator action.
 *
 * Written inside the caller's transaction, never on the pool: the row and the
 * action it describes commit together or not at all. A ledger that could
 * survive a rolled-back action would over-count, and one written after commit
 * could be lost while the action stood — either way the counter would stop
 * describing the thing it counts.
 *
 * There is no `delete` and no `update`. The bound is only meaningful over an
 * append-only record, and migration 006 grants no path to either.
 */
@Injectable()
export class OperatorActionsRepo {
  /** Append one action. Callers pass `tx`, never the pool. */
  async record(
    tx: Queryable,
    operatorId: string,
    caseId: string,
    action: PermissiveOperatorAction,
    at: Date,
  ): Promise<void> {
    await tx.query(
      `INSERT INTO settlement_operator_actions (operator_id, case_id, action, occurred_at)
       VALUES ($1, $2, $3, $4)`,
      [operatorId, caseId, action, at],
    );
  }

  /**
   * How many DISTINCT estates this operator has touched inside the window.
   *
   * Counting distinct `case_id` rather than rows is the whole point of the
   * bound: thirty actions on one estate is one, and one action on each of
   * thirty estates is thirty.
   */
  async distinctCasesSince(q: Queryable | Db, operatorId: string, now: Date): Promise<number> {
    const since = new Date(now.getTime() - OPERATOR_BREADTH_WINDOW_MS);
    const rows = await q.query<{ n: string }>(
      `SELECT COUNT(DISTINCT case_id)::text AS n
         FROM settlement_operator_actions
        WHERE operator_id = $1 AND occurred_at > $2`,
      [operatorId, since],
    );
    // COUNT returns BIGINT, which pg hands back as a string; parsing it here
    // rather than at the call site keeps the one place that knows that.
    return Number(rows[0]?.n ?? '0');
  }
}
