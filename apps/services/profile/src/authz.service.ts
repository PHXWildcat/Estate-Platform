import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/** Actions in the core cluster's vocabulary (Cedar `Action::"<id>"`). */
export type CoreAction = 'read' | 'create' | 'update' | 'delete' | 'manage';

/** Cedar resource types this service authorizes. */
export type CoreResourceType = 'Profile' | 'Contact' | 'FamilyMember' | 'RoleAssignment';

/**
 * Build the Cedar resource entity for an owned core resource. Two attributes
 * drive the decision:
 *  - `owner`: the owning User — owner.cedar permits the owner ANY action.
 *  - `grantees`: the set of Users holding an effective read grant for THIS
 *    resource — profile.cedar permits a read to any grantee. The set is
 *    resolved from permission_grants/role_assignments by the caller before the
 *    PDP is consulted, so authorization data is explicit, not implicit.
 *
 * `grantees` is always present (empty when nobody is granted) so the policy's
 * `resource has grantees` guard is stable; an empty set simply matches no one.
 */
export function coreResource(
  type: CoreResourceType,
  resourceId: string,
  ownerUserId: string,
  grantees: readonly string[] = [],
): EntityInput {
  return {
    uid: { type, id: resourceId },
    attrs: {
      owner: ref('User', ownerUserId),
      grantees: grantees.map((userId) => ref('User', userId)),
    },
  };
}

/**
 * The Profile & Contacts Policy Enforcement Point (PEP). The first real PEP in
 * the platform: it wraps the shared Cedar PDP (deny-by-default) and turns a
 * `deny` into a generic 403 `{ error: 'forbidden' }`. No PII ever reaches the
 * decision — only entity IDs and the resolved grant set — and no endpoint may
 * return core data without first passing `assertCan`.
 */
@Injectable()
export class ProfileAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  /**
   * Authorize `principalUserId` to perform `action` on `resource`. `resource`
   * MUST be one of the `entities` (with its owner/grantees attrs); any extra
   * entities the policies reference may be supplied too. Throws a generic
   * ForbiddenException on deny — deny by default, so anything short of an
   * explicit Cedar allow is refused.
   */
  assertCan(
    principalUserId: string,
    action: CoreAction,
    resource: EntityInput,
    entities: readonly EntityInput[] = [resource],
  ): void {
    const result = this.pdp.authorize({
      principal: { type: 'User', id: principalUserId },
      action: { type: 'Action', id: action },
      resource: resource.uid,
      entities: entities.length > 0 ? entities : [resource],
    });
    if (result.decision !== 'allow') {
      // Generic token only — never echo the principal, resource, or reason.
      throw new ForbiddenException({ error: 'forbidden' });
    }
  }

  /** Non-throwing variant for list filtering (per-item visibility checks). */
  can(
    principalUserId: string,
    action: CoreAction,
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
