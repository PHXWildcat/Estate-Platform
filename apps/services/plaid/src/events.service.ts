import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  PlaidItemLinkedEvent,
  PlaidItemStatusChangedEvent,
  PlaidItemSyncedEvent,
  TOPICS,
  type PlaidItemStatus,
} from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single egress point for this service's audit + domain events.
 *
 * Audit events (docs/02 §6: entity IDs and enums only — never plaintext
 * values, and NEVER tokens, institution names, balances, or masks) go to the
 * append-only audit cluster via AuditEmitter, which validates each payload
 * against @estate/contracts before the wire.
 *
 * Domain events go to TOPICS.plaidEvents keyed by itemId (per-item ordering),
 * carrying IDs/enums/counts ONLY — value-bearing payloads would require the
 * docs/01 §4 Zone B Kafka payload encryption, which is not built yet.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(
    @Inject(AUDIT_PRODUCER) private readonly producer: AuditProducer,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {
    this.audit = new AuditEmitter(producer, clock);
  }

  async itemLinked(actorId: string, itemId: string, institutionId: string): Promise<void> {
    await this.item('plaid.item.linked', actorId, itemId, { institutionId });
    await this.domain(actorId, PlaidItemLinkedEvent, 'plaid.item.linked', itemId, { itemId });
  }

  async itemSynced(actorId: string, itemId: string, accountsUpserted: number): Promise<void> {
    await this.item('plaid.item.synced', actorId, itemId, { accounts: accountsUpserted });
    await this.domain(actorId, PlaidItemSyncedEvent, 'plaid.item.synced', itemId, {
      itemId,
      accountsUpserted,
    });
  }

  async itemRevoked(actorId: string, itemId: string): Promise<void> {
    await this.item('plaid.item.revoked', actorId, itemId);
    await this.domain(actorId, PlaidItemStatusChangedEvent, 'plaid.item.status_changed', itemId, {
      itemId,
      status: 'revoked' satisfies PlaidItemStatus,
    });
  }

  /** Webhook-driven status flip; actor is the platform, not a user. */
  async itemLoginRequired(itemId: string): Promise<void> {
    await this.audit.emit({
      action: 'plaid.item.login_required',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'plaid_item',
      resourceId: itemId,
      sessionId: null,
      detail: {},
    });
    await this.domain(null, PlaidItemStatusChangedEvent, 'plaid.item.status_changed', itemId, {
      itemId,
      status: 'login_required' satisfies PlaidItemStatus,
    });
  }

  /** A webhook that failed signature verification. Reason token only. */
  async webhookRejected(reason: string): Promise<void> {
    await this.audit.emit({
      action: 'plaid.webhook.rejected',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'plaid_webhook',
      resourceId: null,
      sessionId: null,
      detail: { reason },
    });
  }

  /** TB5 anomalous-sync alert (counts only). */
  async syncAnomalous(itemId: string, detail: { syncsInWindow: number }): Promise<void> {
    await this.audit.emit({
      action: 'plaid.sync.anomalous',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'plaid_item',
      resourceId: itemId,
      sessionId: null,
      detail: { syncsInWindow: detail.syncsInWindow },
    });
  }

  private async item(
    action: 'plaid.item.linked' | 'plaid.item.synced' | 'plaid.item.revoked',
    actorId: string,
    itemId: string,
    detail: Record<string, string | number> = {},
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'plaid_item',
      resourceId: itemId,
      sessionId: null,
      detail,
    });
  }

  private async domain<T extends { parse: (v: unknown) => unknown }>(
    actorId: string | null,
    schema: T,
    type: string,
    itemId: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    const envelope = schema.parse({
      eventId: randomUUID(),
      type,
      version: 1,
      occurredAt: this.clock().toISOString(),
      actor: { id: actorId, type: actorId === null ? 'system' : 'user' },
      payload,
    });
    await this.producer.send({
      topic: TOPICS.plaidEvents,
      key: itemId,
      value: JSON.stringify(envelope),
    });
  }
}
