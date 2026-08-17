import { ForbiddenException, Injectable } from '@nestjs/common';
import { OperatorsRepo } from './operators.repo';
import type { Db, Queryable } from './db';

/**
 * THE ONE PLACE THE OPERATOR ALLOWLIST IS CONSULTED.
 *
 * Before M21 PR2 the settlement service read the allowlist at SEVEN call
 * sites, in four distinct shapes, and they did not agree with each other:
 *
 *   1. `settlement.service.assertOperator` — pool read, throws.
 *   2. `admin.service.assertOperator` — byte-identical, separately declared.
 *   3. `admin.service.assertCaseVisible` — a bare `isOperator` branch that
 *      returns the case instead of throwing.
 *   4. `setDistributionStatus` — an inline `isOperator || isExecutorOf`
 *      disjunction, and the ONLY one of the seven that read the allowlist on
 *      the TRANSACTION handle rather than the pool.
 *
 * plus three more direct reads feeding a value rather than a refusal
 * (`addEvidence`, `getCase`, `evidenceReadAuthority`) — six on the pool, one on
 * a transaction.
 *
 * (An earlier version of this comment said "FOUR independent paths" and
 * enumerated the four shapes as though that were the whole inventory. It was
 * not: `git grep 'operators.isOperator(' 56c8fbd` returns seven. The count is
 * corrected here rather than quietly, because a shipped comment stating a
 * measurement that is wrong is what stops the next person measuring.)
 *
 * Several spellings of one question is the M8 PR2 shape, and here the drift had
 * already produced a real disagreement about WHEN operator status is decided —
 * see `assertIn`.
 *
 * WHY A CLASS AND NOT A FUNCTION: unifying N copies of a guard is only safe if
 * the unified one is tested harder than the copies were, because the blast
 * radius is now every caller. `test/operator-gate.spec.ts` drives this directly
 * — which none of the four copies ever had — and `test/operator-gate-fence.spec.ts`
 * asserts it is the only reader of the allowlist.
 *
 * WHAT IT DELIBERATELY DOES NOT DO: decide anything about a CASE. Operator
 * status here is global and unscoped, which is a property of the interim
 * allowlist rather than of this class — see docs/03 §6aa.
 */
@Injectable()
export class OperatorGate {
  constructor(private readonly operators: OperatorsRepo) {}

  /**
   * Resolve operator status on a caller-supplied handle.
   *
   * There is NO DEFAULT, because which handle a caller passes is a decision
   * rather than a detail: a write passes its own `tx` so the allowlist answer
   * belongs to the same transaction as the row it authorizes, and only a read
   * with no transaction to be consistent with passes the pool.
   *
   * WHAT THIS BUYS, STATED EXACTLY, because the tempting claim is wrong.
   * Before M21 PR2, `startReview` and `confirmVerification` — the two §5.1
   * routes that begin and end a death case — resolved the allowlist on the POOL
   * and only then opened the transaction they were guarding, while
   * `setDistributionStatus` read it on `tx`. Reading on `tx` NARROWS the window
   * in which a concurrent revoke is invisible; it DOES NOT CLOSE IT. These
   * transactions are READ COMMITTED, so each statement takes a fresh snapshot
   * and a revoke committing after this read is still unseen at commit time.
   * Closing it would mean taking a share lock on the allowlist row so a revoke
   * had to wait — real contention on every operator action, to serialize
   * against an adversary who must be an operator being revoked in that exact
   * instant. Not taken; recorded in docs/03 §6aa instead.
   *
   * So the property this argument actually secures is CONSISTENCY, not
   * atomicity: one question, asked on one handle, with the service no longer
   * disagreeing with itself about when operator status is decided.
   */
  async is(q: Queryable | Db, userId: string): Promise<boolean> {
    return this.operators.isOperator(q, userId);
  }

  /**
   * Refuse a non-operator, and RETURN THE MEASURED ANSWER.
   *
   * The return value exists so Cedar is handed a value derived from the
   * allowlist read rather than a literal. Three call sites used to pass a
   * hardcoded `true` to `assertCan`, which was correct only because this check
   * had run a few lines above — delete that line and the route opened to
   * anyone, with the policy still evaluating happily against a constant that
   * asserted the very thing nobody had checked. Binding the result makes the
   * dependency structural: remove the check and the argument stops existing.
   */
  async assertIn(q: Queryable | Db, userId: string): Promise<true> {
    if (!(await this.is(q, userId))) {
      throw new ForbiddenException({ error: 'forbidden' });
    }
    return true;
  }
}
