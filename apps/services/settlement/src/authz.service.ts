import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
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
}
