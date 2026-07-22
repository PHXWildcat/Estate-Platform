import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/** Actions in the plaid service's vocabulary (Cedar `Action::"<id>"`). */
export type PlaidAction = 'read' | 'create' | 'sync' | 'revoke';

/**
 * Build the Cedar resource entity for a Plaid item (or the caller's account
 * collection). Owner-only by design: financial connections are never visible
 * to beneficiaries or role-holders — owner.cedar's `resource.owner ==
 * principal` is the single permit that can match, and deny-by-default covers
 * the rest.
 */
export function plaidItemResource(itemId: string, ownerUserId: string): EntityInput {
  return {
    uid: { type: 'PlaidItem', id: itemId },
    attrs: { owner: ref('User', ownerUserId) },
  };
}

/**
 * The plaid service's Policy Enforcement Point. Wraps the shared Cedar PDP
 * (deny-by-default) and turns a deny into a generic 403 `{ error:
 * 'forbidden' }`. No PII ever reaches the decision — only entity IDs.
 */
@Injectable()
export class PlaidAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  assertCan(principalUserId: string, action: PlaidAction, resource: EntityInput): void {
    const allowed =
      this.pdp.authorize({
        principal: { type: 'User', id: principalUserId },
        action: { type: 'Action', id: action },
        resource: resource.uid,
        entities: [resource],
      }).decision === 'allow';
    if (!allowed) {
      // Generic token only — never echo the principal, resource, or reason.
      throw new ForbiddenException({ error: 'forbidden' });
    }
  }
}
