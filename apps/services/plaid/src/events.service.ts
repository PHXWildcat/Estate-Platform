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

  /**
   * A successful sync, AND the write of `healthy` it ships (M49 PR6).
   *
   * `from` is the status the `healthy` write found under its lock. It is the
   * only place the recovery of a dead item is recorded: `from: 'error'` or
   * `from: 'login_required'` is an item coming back, `from: 'healthy'` is the
   * no-op every routine sync performs — the two docs/03 §6kkk could not tell
   * apart, because this event fires on every sync. Not filed at all when the
   * write matched no live row: `syncItem` takes that write FIRST and stops
   * there, so nothing moved and there is nothing to record. An earlier draft
   * let this event fire with `from` omitted for that case, and the PR's review
   * found the arm executed by no test — it is gone rather than tested.
   */
  async itemSynced(
    actorId: string,
    itemId: string,
    accountsUpserted: number,
    from: PlaidItemStatus,
  ): Promise<void> {
    await this.item('plaid.item.synced', actorId, itemId, { accounts: accountsUpserted, from });
    await this.domain(actorId, PlaidItemSyncedEvent, 'plaid.item.synced', itemId, {
      itemId,
      accountsUpserted,
    });
  }

  async itemRevoked(actorId: string, itemId: string, from: PlaidItemStatus): Promise<void> {
    // THE EDGE: revoking a `healthy` item ends a working link; revoking one in
    // `error` or `login_required` retires a link that had already stopped
    // working, and only the prior status tells those apart.
    await this.item('plaid.item.revoked', actorId, itemId, { from });
    await this.domain(actorId, PlaidItemStatusChangedEvent, 'plaid.item.status_changed', itemId, {
      itemId,
      status: 'revoked' satisfies PlaidItemStatus,
    });
  }

  /**
   * Webhook-driven status flip; the actor is the platform, not a user, and
   * the OWNER is named in `onBehalfOf` — the repo's spelling for a platform
   * act on one person's resource (identity's `emailVerificationSent`,
   * notifications' emitters). Before M49 PR6 this row named no user in any
   * field, so it could reach the owner's trail only by a join on the item.
   */
  async itemLoginRequired(
    ownerUserId: string,
    itemId: string,
    from: PlaidItemStatus,
  ): Promise<void> {
    await this.audit.emit({
      action: 'plaid.item.login_required',
      actorId: null,
      actorType: 'system',
      onBehalfOf: ownerUserId,
      resourceType: 'plaid_item',
      resourceId: itemId,
      sessionId: null,
      // `from: 'login_required'` is a repeated webhook for an item already
      // waiting on its owner; `from: 'error'` is Plaid asking for a re-login on
      // an item the platform had written off. Both were `detail: {}` before.
      detail: { from },
    });
    await this.domain(null, PlaidItemStatusChangedEvent, 'plaid.item.status_changed', itemId, {
      itemId,
      status: 'login_required' satisfies PlaidItemStatus,
    });
  }

  /**
   * Plaid refused the sync with a client error (M49 PR6, docs/03 §6ppp): the
   * `invalid_access_token` arm writes `error`, and before this method nothing
   * recorded it — the one rung of the ladder with no event at all. The token
   * having died is the CAUSE this arm was built for, not the only one it
   * reports: `live-plaid-gateway.ts` maps HTTP 400 on the sync path to that one
   * token — and Plaid answers 400 for its whole error family — so a malformed
   * request files the same row as a dead token. The gap runs the other way too:
   * 401, 403 and 429 become `provider_error`, which this arm never sees, so an
   * item whose ACCESS was withdrawn at the client level writes no `error` and
   * files nothing. Two failures needing different remedies sharing one token,
   * and a third needing one and getting none: §6ppp's residual, one layer down.
   *
   * The actor is whoever asked for the sync: the owner on the route, or the
   * platform (`null`, `system`) when a webhook drove it — in which case the
   * owner is named in `onBehalfOf`, as `itemLoginRequired` does. That is the
   * honest attribution, and it is NOT the one `itemSynced` makes for the same
   * webhook-driven sync when it succeeds — §6ppp records that asymmetry rather
   * than copying the defect into a new member.
   */
  async itemErrored(
    actorUserId: string | null,
    ownerUserId: string,
    itemId: string,
    from: PlaidItemStatus,
  ): Promise<void> {
    await this.audit.emit({
      action: 'plaid.item.errored',
      actorId: actorUserId,
      actorType: actorUserId === null ? 'system' : 'user',
      onBehalfOf: actorUserId === null ? ownerUserId : null,
      resourceType: 'plaid_item',
      resourceId: itemId,
      sessionId: null,
      detail: { from },
    });
    await this.domain(
      actorUserId,
      PlaidItemStatusChangedEvent,
      'plaid.item.status_changed',
      itemId,
      { itemId, status: 'error' satisfies PlaidItemStatus },
    );
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

  /**
   * TB5 anomalous-sync alert (counts only). The platform acting on one
   * person's item, so the owner is named in `onBehalfOf` — the same spelling
   * `itemErrored` and `itemLoginRequired` gained in M49 PR6, applied here
   * because a rule applied to one member of a category is half-applied.
   * `webhookRejected` is NOT in this category: it records a webhook the
   * service refused to attribute to any item, so there is no owner to name.
   */
  async syncAnomalous(
    itemId: string,
    ownerUserId: string,
    detail: { syncsInWindow: number },
  ): Promise<void> {
    await this.audit.emit({
      action: 'plaid.sync.anomalous',
      actorId: null,
      actorType: 'system',
      onBehalfOf: ownerUserId,
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
