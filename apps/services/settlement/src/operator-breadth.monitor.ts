import { Injectable } from '@nestjs/common';

import type { Queryable } from './db';
import { OperatorActionsRepo } from './operator-actions.repo';
import { breadthExceeded, type PermissiveOperatorAction } from './operator-breadth';

/**
 * The one spelling of "record this permissive action and tell me the breadth".
 *
 * It exists as a service rather than as a private helper on each of the two
 * services that need it for the reason the operator gate does: two copies of
 * one behaviour is how the gate drifted about which database handle to ask on,
 * and the cost of finding that out was a milestone review.
 *
 * The split — `record` inside the transaction, the emit outside — is not
 * squeamishness. The ledger row must commit with the action it describes or the
 * counter stops describing anything, while an audit event must NOT be emitted
 * from inside a transaction that may still roll back, or the trail reports work
 * that never happened. So the count comes back from the transaction and the
 * caller emits after it commits.
 */
@Injectable()
export class OperatorBreadthMonitor {
  constructor(private readonly actions: OperatorActionsRepo) {}

  /**
   * Append the action and return how many DISTINCT estates this operator has
   * touched in the window, this one included. Call inside `tx`.
   */
  async record(
    tx: Queryable,
    operator: string,
    caseId: string,
    action: PermissiveOperatorAction,
    now: Date,
  ): Promise<number> {
    await this.actions.record(tx, operator, caseId, action, now);
    return this.actions.distinctCasesSince(tx, operator, now);
  }

  /** Whether that breadth crosses the ceiling. Pure; the caller emits. */
  exceeded(distinctCases: number): boolean {
    return breadthExceeded(distinctCases);
  }
}
