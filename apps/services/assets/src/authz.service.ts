import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/** Actions in the asset service's vocabulary (Cedar `Action::"<id>"`). */
export type AssetAction = 'read' | 'create' | 'update' | 'delete' | 'manage';

/**
 * Build the Cedar resource entity for an asset.
 *
 * M3 scope: `owner` drives everything (owner.cedar permits the owner any
 * action). `namedBeneficiaries` — the attribute beneficiary.cedar reads — is
 * always present but ALWAYS EMPTY for now: mapping asset_beneficiaries rows
 * to platform users requires contacts.linked_user_id from the core cluster,
 * which this service can only learn from a contact-link projection over core
 * domain events (tracked follow-up). Deny-by-default makes the empty set
 * safe: beneficiary principals simply match no permit yet.
 */
export function assetResource(
  assetId: string,
  ownerUserId: string,
  namedBeneficiaries: readonly string[] = [],
): EntityInput {
  return {
    uid: { type: 'Asset', id: assetId },
    attrs: {
      owner: ref('User', ownerUserId),
      namedBeneficiaries: namedBeneficiaries.map((userId) => ref('User', userId)),
    },
  };
}

/**
 * The asset service's Policy Enforcement Point. Wraps the shared Cedar PDP
 * (deny-by-default) and turns a deny into a generic 403 `{ error:
 * 'forbidden' }`. No PII ever reaches the decision — only entity IDs.
 */
@Injectable()
export class AssetsAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  /**
   * Authorize `principalUserId` to perform `action` on `resource`. Throws a
   * generic ForbiddenException on deny — anything short of an explicit Cedar
   * allow is refused.
   */
  assertCan(
    principalUserId: string,
    action: AssetAction,
    resource: EntityInput,
    entities: readonly EntityInput[] = [resource],
  ): void {
    if (!this.can(principalUserId, action, resource, entities)) {
      // Generic token only — never echo the principal, resource, or reason.
      throw new ForbiddenException({ error: 'forbidden' });
    }
  }

  /** Non-throwing variant for list filtering (per-item visibility checks). */
  can(
    principalUserId: string,
    action: AssetAction,
    resource: EntityInput,
    entities: readonly EntityInput[] = [resource],
  ): boolean {
    return (
      this.pdp.authorize({
        principal: { type: 'User', id: principalUserId },
        action: { type: 'Action', id: action },
        resource: resource.uid,
        entities: entities.length > 0 ? entities : [resource],
      }).decision === 'allow'
    );
  }
}
