import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

export type VaultAction = 'read' | 'create' | 'update' | 'delete' | 'manage';

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
