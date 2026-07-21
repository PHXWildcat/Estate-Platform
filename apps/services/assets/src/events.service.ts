import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  AssetLedgerAppendedEvent,
  TOPICS,
  type AssetCategory,
  type AssetEventType,
} from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single egress point for this service's audit + domain events.
 *
 * Audit events (docs/02 §6: entity IDs and enums only — never plaintext
 * values) go to the append-only audit cluster via AuditEmitter, which
 * validates each payload against @estate/contracts before the wire.
 *
 * Domain events — one `asset.ledger.appended` envelope per committed ledger
 * append — go to TOPICS.assetEvents, keyed by assetId (per-asset ordering).
 * They carry IDs/enums ONLY: no titles, no values. Sensitive payloads on the
 * bus would require the docs/01 §4 Zone B Kafka payload encryption
 * (packages/kafka), which is a tracked prerequisite for any future consumer
 * that needs more than identifiers.
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

  /** Publish the IDs-only domain event for a committed ledger append. */
  async ledgerAppended(input: {
    actorId: string;
    assetId: string;
    ledgerEventId: string;
    eventType: AssetEventType;
    category?: AssetCategory;
  }): Promise<void> {
    const envelope = AssetLedgerAppendedEvent.parse({
      eventId: randomUUID(),
      type: 'asset.ledger.appended',
      version: 1,
      occurredAt: this.clock().toISOString(),
      actor: { id: input.actorId, type: 'user' },
      payload: {
        assetId: input.assetId,
        ledgerEventId: input.ledgerEventId,
        eventType: input.eventType,
        ...(input.category !== undefined ? { category: input.category } : {}),
      },
    });
    await this.producer.send({
      topic: TOPICS.assetEvents,
      key: input.assetId,
      value: JSON.stringify(envelope),
    });
  }

  async assetCreated(actorId: string, assetId: string, category: AssetCategory): Promise<void> {
    await this.asset('asset.created', actorId, assetId, { category });
  }

  async assetUpdated(actorId: string, assetId: string): Promise<void> {
    await this.asset('asset.updated', actorId, assetId);
  }

  async valuationRecorded(actorId: string, assetId: string, source: string): Promise<void> {
    await this.asset('asset.valuation.recorded', actorId, assetId, { source });
  }

  async ownershipChanged(actorId: string, assetId: string): Promise<void> {
    await this.asset('asset.ownership.changed', actorId, assetId);
  }

  async beneficiaryDesignated(
    actorId: string,
    assetId: string,
    detail: { contactId: string; designation: string },
  ): Promise<void> {
    await this.asset('asset.beneficiary.designated', actorId, assetId, {
      contactId: detail.contactId,
      designation: detail.designation,
    });
  }

  async beneficiaryRemoved(
    actorId: string,
    assetId: string,
    detail: { contactId: string; designation: string },
  ): Promise<void> {
    await this.asset('asset.beneficiary.removed', actorId, assetId, {
      contactId: detail.contactId,
      designation: detail.designation,
    });
  }

  async assetRetired(actorId: string, assetId: string, reason?: string): Promise<void> {
    await this.asset('asset.retired', actorId, assetId, reason ? { reason } : {});
  }

  /** The rebuild run's summary record (counts only). actorType 'system'. */
  async projectionRebuilt(detail: {
    assets: number;
    events: number;
    diffs: number;
    repaired: boolean;
  }): Promise<void> {
    await this.audit.emit({
      action: 'asset.projection.rebuilt',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'asset_projection',
      resourceId: null,
      sessionId: null,
      detail: {
        assets: detail.assets,
        events: detail.events,
        diffs: detail.diffs,
        repaired: detail.repaired,
      },
    });
  }

  private async asset(
    action:
      | 'asset.created'
      | 'asset.updated'
      | 'asset.valuation.recorded'
      | 'asset.ownership.changed'
      | 'asset.beneficiary.designated'
      | 'asset.beneficiary.removed'
      | 'asset.retired',
    actorId: string,
    assetId: string,
    detail: Record<string, string> = {},
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'asset',
      resourceId: assetId,
      sessionId: null,
      detail,
    });
  }
}
