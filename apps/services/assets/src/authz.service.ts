import { ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
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
 * domain events. Deny-by-default makes the empty set safe: beneficiary
 * principals simply match no permit yet.
 *
 * OWNER: the owner-initiated sharing milestone (docs/03 §5.5 / §6s). This said
 * "(tracked follow-up)" from M3 until M21 PR0, and nothing tracked it — the
 * defect class that whole PR exists to close. Note what the empty set means
 * precisely: `beneficiary.cedar` ships in the shared bundle and is LOADED, and
 * the attribute it matches on arrives from the default parameter below, which
 * all seven `assetResource` call sites take by omission. So the policy is live
 * and structurally unmatchable — a stronger statement than "beneficiary
 * visibility is unwired", and the reason no beneficiary can read anything
 * today. Closing it is a projection, not a policy change.
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

  /**
   * Like `assertCan`, but a deny answers the SAME 404 (`not_found`) a missing
   * row does. On a path scoped by an asset id, "exists but is not yours" must
   * be indistinguishable from "does not exist" — a distinct 403 confirms that
   * a guessed id names a real asset, the enumeration oracle the M10 PEP and
   * the M13 profile predicate both close (docs/03 TB1). Use this wherever the
   * resource was located BY the id under authorization; keep `assertCan` for
   * denials that reveal nothing (e.g. create, whose resource does not exist).
   */
  assertCanOrNotFound(
    principalUserId: string,
    action: AssetAction,
    resource: EntityInput,
    entities: readonly EntityInput[] = [resource],
  ): void {
    if (!this.can(principalUserId, action, resource, entities)) {
      throw new NotFoundException({ error: 'not_found' });
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
