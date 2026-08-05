import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * A deferred audit emission, held until the transaction that produced it has
 * COMMITTED.
 *
 * Kafka does not enrol in the Postgres transaction: `AuditProducer.send`
 * reaches the broker immediately and no ROLLBACK can recall it. An event
 * emitted inside a transaction that then rolls back is a permanent record, in
 * an append-only store, of a row that does not exist — and this service's
 * stream is the only account of what estate data reached a model provider, so
 * an auditor who cannot resolve a `resourceId` cannot tell "the platform lost
 * the row" from "the retrieval never happened".
 *
 * `remove()` already stated the rule (the M9 ordering rule, applied to
 * evidence); a turn is the same shape and must obey it too. Buffer, then flush
 * once the rows are durable.
 *
 * NOT everything belongs in a buffer. An event that is TRUE regardless of the
 * transaction's fate — a refusal that references no row created inside it —
 * must still fire on the failure path, or the control becomes silent exactly
 * when it acts. `assistant.egress.refused` is that case.
 */
export type PendingAudit = () => Promise<void>;

/**
 * Emit buffered events in the order they were recorded, after the commit.
 *
 * A failure here is the opposite trade from the one this exists to prevent:
 * the rows are durable and an event is missing, rather than an event asserting
 * rows that never landed. That is the same trade every audit-after-commit call
 * site in the product makes, and the error propagates rather than being
 * swallowed.
 */
export async function flushPendingAudit(pending: readonly PendingAudit[]): Promise<void> {
  for (const emit of pending) {
    await emit();
  }
}

/**
 * The single audit egress point for the AI estate assistant (docs/02 §6 PII
 * firewall: entity IDs and enum tokens only). In THIS service that firewall is
 * also a PROMPT-CONTENT firewall, and it is the stricter of the two: a turn
 * quotes whatever the tools retrieved, so a prompt, a completion, or a tool
 * result is estate data by construction. Nothing here may carry any of it.
 *
 * That property is enforced by SHAPE rather than by review — no method on this
 * class accepts free text, and none may ever be added. The parameters are UUIDs
 * and closed-vocabulary tokens (tool names, consent scopes, detector
 * categories, refusal reasons), every one of them a compile-time constant from
 * this service's own registries and never a value the model produced or a
 * document supplied (docs/03 §4 TB5: document text and OCR output are
 * untrusted data, never instructions — and never audit payloads either).
 * @estate/audit-emitter's schema gate is the backstop: SAFE_TOKEN_PATTERN
 * rejects whitespace and '@', so prose could not reach the append-only store
 * even if a call site tried.
 *
 * Refusals are recorded as loudly as successes — a tool denied for want of
 * consent, and an answer withheld because the privacy assertion tripped, are
 * controls firing, and the M9 rule is that a control which fires silently reads
 * as an outage. The complementary record, that a ciphertext was opened at all,
 * is FieldCrypto's own crypto.field.decrypted (already in the catalog, reused
 * here rather than redeclared).
 *
 * No domain topic: nothing consumes assistant events, and topics appear when a
 * consumer needs them (the M3 rule). A future consumer would in any case need
 * the docs/01 §4 Zone B Kafka payload crypto before it could be told anything
 * beyond the identifiers below.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  /** A user opened a new conversation. */
  async conversationStarted(userId: string, conversationId: string): Promise<void> {
    await this.conversation('assistant.conversation.started', userId, conversationId);
  }

  /**
   * A user soft-deleted a conversation. The transcript's ciphertext survives
   * under the no-hard-deletes rule; only crypto-shredding the user's assistant
   * DEK actually erases it, which is a separate (and separately audited) act.
   */
  async conversationDeleted(userId: string, conversationId: string): Promise<void> {
    await this.conversation('assistant.conversation.deleted', userId, conversationId);
  }

  /**
   * A user turn was accepted and sealed. The message id is the anchor: it ties
   * this event to the ciphertext row without the prompt itself ever leaving the
   * per-user DEK.
   */
  async messageSent(userId: string, conversationId: string, messageId: string): Promise<void> {
    await this.audit.emit({
      action: 'assistant.message.sent',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'assistant_message',
      resourceId: messageId,
      sessionId: null,
      detail: { conversationId },
    });
  }

  /**
   * The assistant's reply was produced and sealed. `toolCalls` is a COUNT and
   * `gateway` the provider adapter that answered (the LLM_MODE token, not a
   * model output) — together they make "which turns left the platform, and how
   * much estate data was retrieved for them" answerable from the audit stream
   * alone, which is what docs/03 §4 TB5 asks of a third-party model provider.
   */
  async turnCompleted(
    userId: string,
    conversationId: string,
    messageId: string,
    detail: { toolCalls: number; gateway: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'assistant.turn.completed',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'assistant_message',
      resourceId: messageId,
      sessionId: null,
      detail: { conversationId, toolCalls: detail.toolCalls, gateway: detail.gateway },
    });
  }

  /**
   * A retrieval tool ran. `scope` is the consent scope that admitted it, so
   * the pair (tool, scope) is the audit-visible half of "the assistant may
   * only read what the user separately consented to"; the tool call id anchors
   * the event to its append-only assistant_tool_calls row, whose result is
   * ciphertext. The retrieved values are never a parameter here.
   */
  async toolInvoked(
    userId: string,
    conversationId: string,
    detail: { tool: string; scope: string; toolCallId: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'assistant.tool.invoked',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'assistant_tool_call',
      resourceId: detail.toolCallId,
      sessionId: null,
      detail: { conversationId, tool: detail.tool, scope: detail.scope },
    });
  }

  /**
   * A retrieval was refused — missing consent, or a tool that failed. Anchored
   * on the conversation rather than on a tool-call row because a refusal is a
   * fact about the turn the user is having, and it must be emittable on paths
   * that never got as far as persisting a row. `reason` is a closed token
   * ('no_consent', 'error'), never a provider or downstream error message.
   */
  async toolRefused(
    userId: string,
    conversationId: string,
    detail: { tool: string; scope: string; reason: string },
  ): Promise<void> {
    await this.conversation('assistant.tool.refused', userId, conversationId, {
      tool: detail.tool,
      scope: detail.scope,
      reason: detail.reason,
    });
  }

  /**
   * A consent scope was granted by the step-up-verified owner. Keyed by the
   * user (a consent is a property of the person, and the grant row's id is not
   * what anyone reviews later), with the scope as the enum that matters.
   */
  async consentGranted(userId: string, detail: { scope: string }): Promise<void> {
    await this.consent('assistant.consent.granted', userId, detail.scope);
  }

  /** A consent scope was revoked. Recorded with the same weight as the grant. */
  async consentRevoked(userId: string, detail: { scope: string }): Promise<void> {
    await this.consent('assistant.consent.revoked', userId, detail.scope);
  }

  /**
   * The privacy assertion tripped on the way out and the answer was withheld
   * (docs/03 §4 TB5 risk #6 — the last line between retrieved estate data and
   * a third-party provider, or between one user's data and another's reply).
   * `detector` is the CATEGORY that fired — 'ssn', 'account_number' — never the
   * matched text, which is precisely the value this event exists to have kept
   * inside the platform. Logging it would make the control its own leak.
   */
  async egressRefused(
    userId: string,
    conversationId: string,
    detail: { detector: string },
  ): Promise<void> {
    await this.conversation('assistant.egress.refused', userId, conversationId, {
      detector: detail.detector,
    });
  }

  /** Conversation-anchored events: the user is always the actor and the subject. */
  private async conversation(
    action:
      | 'assistant.conversation.started'
      | 'assistant.conversation.deleted'
      | 'assistant.tool.refused'
      | 'assistant.egress.refused',
    userId: string,
    conversationId: string,
    detail: Record<string, string | number | boolean> = {},
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      // No delegated path exists into this service: it acts only on the
      // caller's own forwarded bearer, so the actor and the data subject are
      // always the same person and onBehalfOf stays null.
      resourceType: 'assistant_conversation',
      resourceId: conversationId,
      sessionId: null,
      detail,
    });
  }

  private async consent(
    action: 'assistant.consent.granted' | 'assistant.consent.revoked',
    userId: string,
    scope: string,
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'assistant_consent',
      resourceId: userId,
      sessionId: null,
      detail: { scope },
    });
  }
}
