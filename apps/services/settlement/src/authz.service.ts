import { ForbiddenException, NotFoundException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/**
 * Action vocabulary for settlement cases (settlement.cedar). 'review' covers
 * the review lifecycle (start/approve/reject); 'verify' is the separate
 * post-waiting-period confirmation; 'void' is the owner's kill switch;
 * 'evidence_add' covers reporter/operator evidence attach.
 */
export type SettlementAction = 'read' | 'void' | 'evidence_add' | 'review' | 'verify';

/**
 * A settlement case as a Cedar resource. Deliberately carries `decedent` and
 * `reporter` — NOT `owner`: owner.cedar permits an owner ANY action on an
 * owned resource, and the case subject must hold exactly read + void on their
 * own death case (settlement.cedar's narrow permits).
 */
export function caseResource(
  caseId: string,
  decedentUserId: string,
  reporterUserId: string,
): EntityInput {
  return {
    uid: { type: 'SettlementCase', id: caseId },
    attrs: {
      decedent: ref('User', decedentUserId),
      reporter: ref('User', reporterUserId),
    },
  };
}

/** Owner-scoped settings resource: owner.cedar's `owner` attribute applies. */
export function settingsResource(userId: string): EntityInput {
  return {
    uid: { type: 'SettlementSettings', id: userId },
    attrs: { owner: ref('User', userId) },
  };
}

/**
 * The principal, with operator-ness RESOLVED by the service (from the
 * settlement_operators allowlist) and passed as an attribute — the
 * profile.cedar resolve-first pattern; policies never look anything up.
 * The attribute is always present, false included, because `principal has
 * isSettlementOperator` guards the policy.
 */
export function principalEntity(userId: string, isOperator: boolean): EntityInput {
  return {
    uid: { type: 'User', id: userId },
    attrs: { isSettlementOperator: isOperator },
  };
}

/** Cedar PEP for settlement. Deny-by-default; a deny is a bare 403. */
@Injectable()
export class SettlementAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  can(
    principalUserId: string,
    isOperator: boolean,
    action: SettlementAction | 'manage',
    resource: EntityInput,
  ): boolean {
    const result = this.pdp.authorize({
      principal: { type: 'User', id: principalUserId },
      action: { type: 'Action', id: action },
      resource: resource.uid,
      entities: [resource, principalEntity(principalUserId, isOperator)],
    });
    return result.decision === 'allow';
  }

  assertCan(
    principalUserId: string,
    isOperator: boolean,
    action: SettlementAction | 'manage',
    resource: EntityInput,
  ): void {
    if (!this.can(principalUserId, isOperator, action, resource)) {
      // Never echo principal, resource, or reason.
      throw new ForbiddenException({ error: 'forbidden' });
    }
  }

  /**
   * Like `assertCan`, but a deny answers the SAME 404 a missing case does.
   *
   * ON A PATH SCOPED BY A CASE ID, "exists but is not yours" MUST BE
   * INDISTINGUISHABLE FROM "DOES NOT EXIST". Every case-scoped read here used
   * to answer 404 for an unknown id and 403 for a real one, which tells any
   * authenticated caller holding an id whether a death case exists for it —
   * measured live across `getCase`, and the four admin reads that go through
   * `assertCaseVisible` (timeline, stages, tasks, distributions). It is the
   * same defect M19 PR1 closed in assets one milestone earlier, in the service
   * whose ids name death cases.
   *
   * Use this wherever the resource was located BY the id under authorization.
   * Keep `assertCan` where the id is one the caller already holds by other
   * means and the refusal reveals nothing new — the operator write paths, where
   * a non-operator is refused BEFORE any lookup and so learns nothing either
   * way, and the owner's own `manage`/`void`.
   */
  assertCanOrNotFound(
    principalUserId: string,
    isOperator: boolean,
    action: SettlementAction | 'manage',
    resource: EntityInput,
  ): void {
    if (!this.can(principalUserId, isOperator, action, resource)) {
      throw new NotFoundException({ error: 'not_found' });
    }
  }
}
