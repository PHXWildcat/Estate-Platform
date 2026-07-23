import { ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/** Actions in the document service's vocabulary (Cedar `Action::"<id>"`). */
export type DocumentAction = 'read' | 'create' | 'update' | 'delete' | 'manage';

/**
 * Build the Cedar resource entity for a document.
 *
 * M4 scope: `owner` drives everything (owner.cedar permits the owner any
 * action). Role-holder read grants (executor/trustee/attorney per docs/01 §5)
 * arrive with the contact-link projection follow-up; deny-by-default makes
 * the owner-only attribute set safe until then.
 */
export function documentResource(documentId: string, ownerUserId: string): EntityInput {
  return {
    uid: { type: 'Document', id: documentId },
    attrs: {
      owner: ref('User', ownerUserId),
    },
  };
}

/**
 * The document service's Policy Enforcement Point. Wraps the shared Cedar PDP
 * (deny-by-default) and turns a deny into a generic 403 `{ error:
 * 'forbidden' }`. No PII ever reaches the decision — only entity IDs.
 */
@Injectable()
export class DocumentsAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  /**
   * Authorize `principalUserId` to perform `action` on `resource`. Throws a
   * generic ForbiddenException on deny — anything short of an explicit Cedar
   * allow is refused.
   */
  assertCan(
    principalUserId: string,
    action: DocumentAction,
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
    action: DocumentAction,
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
