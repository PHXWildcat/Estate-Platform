import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type CedarValue, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
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
/**
 * THE ACTION VOCABULARY IS DATA, so the suite can enumerate it (M27 PR1b).
 *
 * It was a bare union, and PR1b widened it by three — `read_history`,
 * `undelete`, `restore` — none of which any test exercised in either direction,
 * because `authz.spec.ts` iterated a hand-written list of the five that existed
 * when it was written. A type cannot be enumerated at runtime, so the list
 * beside it could not have been derived; as a const array it can, and a ninth
 * action now arrives with its permit-the-owner and deny-a-stranger cases
 * already written.
 */
export const VAULT_ACTIONS = [
  'read',
  'read_history',
  'create',
  'update',
  'undelete',
  'restore',
  'delete',
  'manage',
  // M27 PR3b. The ninth, and the first that is NOT a thing the owner does:
  // a released emergency-access grantee reading the owner's items. It is a
  // separate id rather than `read` because `vault.cedar` grants exactly the
  // actions it names, and `read` is also what `beneficiary.cedar` grants on
  // any resource naming the principal.
  'read_by_grantee',
] as const;

export type VaultAction = (typeof VAULT_ACTIONS)[number];

/** The vault itself (keyset, session lifecycle), owned by exactly one user. */
export function vaultResource(userId: string): EntityInput {
  return { uid: { type: 'Vault', id: userId }, attrs: { owner: ref('User', userId) } };
}

/**
 * A single item. Ownership was the only attribute until M27 PR3b: there were no
 * beneficiary or grantee reads in Zone A, because nothing else held a key that
 * could open one. Emergency access changed that, and — as the earlier version
 * of this comment promised — it changed HERE, by naming the grantees on the
 * resource, not by loosening a policy elsewhere.
 *
 * `emergencyGrantees` is OMITTED when empty rather than passed as `[]`, and the
 * distinction is the control: `vault.cedar` is guarded by
 * `resource has emergencyGrantees`, so an owner-side call site that forgets to
 * pass grantees produces a resource that CANNOT match the grantee policy. The
 * failure direction of a mistake here is refusal.
 */
export function vaultItemResource(
  itemId: string,
  ownerUserId: string,
  emergencyGranteeUserIds: readonly string[] = [],
): EntityInput {
  const attrs: Record<string, CedarValue> = { owner: ref('User', ownerUserId) };
  if (emergencyGranteeUserIds.length > 0) {
    attrs.emergencyGrantees = emergencyGranteeUserIds.map((id) => ref('User', id));
  }
  return { uid: { type: 'VaultItem', id: itemId }, attrs };
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
