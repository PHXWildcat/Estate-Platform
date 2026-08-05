import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { ref, type EntityInput, type PolicyDecisionPoint } from '@estate/authz';
import { POLICY_DECISION_POINT } from './di-tokens';

/**
 * Action vocabulary for assistant conversations (assistant.cedar). Exhaustive
 * by construction: the policy names exactly these three verbs, so a fourth
 * capability cannot be reached by inventing a string here — it needs a policy
 * edit, which is a reviewed change.
 */
export type AssistantAction = 'read' | 'converse' | 'delete';

/**
 * A conversation as a Cedar resource. The attribute is `subject`, NOT `owner`,
 * and that is load-bearing: owner.cedar permits a principal ANY action on a
 * resource carrying `owner` that equals them, so naming it `owner` here would
 * implicitly grant every verb in the product — including ones a later
 * milestone adds, such as export or share, which docs/01 §5 requires to be
 * step-up gated rather than inherited. settlement.cedar avoids `owner` for the
 * same mechanical reason.
 */
export function conversationResource(conversationId: string, ownerUserId: string): EntityInput {
  return {
    uid: { type: 'AssistantConversation', id: conversationId },
    attrs: { subject: ref('User', ownerUserId) },
  };
}

/**
 * Cedar PEP for the assistant.
 *
 * A denial raises 404, not 403. Every other estate service treats the
 * distinction as an information leak, and it matters more here than anywhere:
 * 403 on a conversation id confirms that the conversation EXISTS, which turns
 * an id-guessing loop into an oracle for "does this person use the assistant,
 * and how many conversations do they have". Not-found and not-yours are the
 * same answer.
 */
@Injectable()
export class AssistantAuthz {
  constructor(@Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint) {}

  can(principalUserId: string, action: AssistantAction, resource: EntityInput): boolean {
    const result = this.pdp.authorize({
      principal: { type: 'User', id: principalUserId },
      action: { type: 'Action', id: action },
      resource: resource.uid,
      entities: [resource],
    });
    return result.decision === 'allow';
  }

  /** Throws the uniform not-found. Never echoes principal, resource, or reason. */
  assertCan(principalUserId: string, action: AssistantAction, resource: EntityInput): void {
    if (!this.can(principalUserId, action, resource)) {
      throw new NotFoundException({ error: 'not_found' });
    }
  }
}
