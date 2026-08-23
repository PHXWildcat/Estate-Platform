import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/**
 * THE ACTIONS THIS SERVICE ASKS CEDAR ABOUT.
 *
 * `read_history`, `undelete` and `restore` are M27 PR1b's, and they are three
 * distinct ids rather than one `restore` because the action id is what a later
 * policy can name. `owner.cedar` permits any action when `resource.owner ==
 * principal`, so today all five behave alike — but PR3 introduces a principal
 * who is NOT the owner, and the only actions a non-owner policy grants are the
 * ones it names. Collapsing these now would mean a future grant of "read a
 * version" could not be written without also granting "put one back".
 */
export type VaultAction =
  'read' | 'read_history' | 'create' | 'update' | 'undelete' | 'restore' | 'delete' | 'manage';

/** The vault itself (keyset, session lifecycle), owned by exactly one user. */
export function vaultResource(userId: string): EntityInput {
  return { uid: { type: 'Vault', id: userId }, attrs: { owner: ref('User', userId) } };
}

/**
 * A single item. Ownership is the only attribute: there are no beneficiary or
 * grantee reads in Zone A, because nothing else holds a key that could open it.
 * That changes when emergency access lands, and it changes here, not by
 * loosening a policy elsewhere.
 */
export function vaultItemResource(itemId: string, ownerUserId: string): EntityInput {
  return { uid: { type: 'VaultItem', id: itemId }, attrs: { owner: ref('User', ownerUserId) } };
}

/**
 * The vault's policy enforcement point. Deny by default: the bundled
 * owner.cedar policy permits only when `resource.owner == principal`, and this
 * service adds no policy of its own.
 */
@Injectable()
export class VaultAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  assertCan(
    principalUserId: string,
    action: VaultAction,
    resource: EntityInput,
    entities: readonly EntityInput[] = [resource],
  ): void {
    const result = this.pdp.authorize({
      principal: { type: 'User', id: principalUserId },
      action: { type: 'Action', id: action },
      resource: resource.uid,
      entities,
    });
    // Generic token only - never echo the principal, resource, or reason.
    if (result.decision !== 'allow') throw new ForbiddenException({ error: 'forbidden' });
  }
}
