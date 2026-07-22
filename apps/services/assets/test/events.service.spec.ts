import { randomUUID } from 'node:crypto';
import { AssetLedgerAppendedEvent, AuditEventSchema, TOPICS } from '@estate/contracts';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { EventsService } from '../src/events.service';

const NOW = new Date('2026-07-21T12:00:00Z');

describe('EventsService', () => {
  let producer: InMemoryAuditProducer;
  let events: EventsService;
  const actor = randomUUID();
  const asset = randomUUID();

  beforeEach(() => {
    producer = new InMemoryAuditProducer();
    events = new EventsService(producer, () => NOW);
  });

  it('emits schema-valid audit events for every asset action', async () => {
    await events.assetCreated(actor, asset, 'real_estate');
    await events.assetUpdated(actor, asset);
    await events.valuationRecorded(actor, asset, 'appraisal');
    await events.ownershipChanged(actor, asset);
    await events.beneficiaryDesignated(actor, asset, {
      contactId: randomUUID(),
      designation: 'primary',
    });
    await events.beneficiaryRemoved(actor, asset, {
      contactId: randomUUID(),
      designation: 'primary',
    });
    await events.assetRetired(actor, asset, 'sold');
    await events.projectionRebuilt({ assets: 3, events: 12, diffs: 0, repaired: false });

    const audits = producer.messages.filter((m) => m.topic === TOPICS.auditEvents);
    expect(audits.map((m) => AuditEventSchema.parse(JSON.parse(m.value)).action)).toEqual([
      'asset.created',
      'asset.updated',
      'asset.valuation.recorded',
      'asset.ownership.changed',
      'asset.beneficiary.designated',
      'asset.beneficiary.removed',
      'asset.retired',
      'asset.projection.rebuilt',
    ]);
  });

  it('publishes IDs-only domain envelopes keyed by asset', async () => {
    const ledgerEventId = randomUUID();
    await events.ledgerAppended({
      actorId: actor,
      assetId: asset,
      ledgerEventId,
      eventType: 'AssetCreated',
      category: 'crypto',
    });
    const domain = producer.messages.filter((m) => m.topic === TOPICS.assetEvents);
    expect(domain).toHaveLength(1);
    expect(domain[0]!.key).toBe(asset);
    const envelope = AssetLedgerAppendedEvent.parse(JSON.parse(domain[0]!.value));
    expect(envelope.payload).toEqual({
      assetId: asset,
      ledgerEventId,
      eventType: 'AssetCreated',
      category: 'crypto',
    });
  });

  it('the audit PII firewall rejects free-text detail (shape enforcement)', async () => {
    await expect(
      events.audit.emit({
        action: 'asset.created',
        actorId: actor,
        actorType: 'user',
        onBehalfOf: null,
        resourceType: 'asset',
        resourceId: asset,
        sessionId: null,
        detail: { title: 'Grandmother’s emerald ring' },
      }),
    ).rejects.toThrow();
    expect(producer.messages).toHaveLength(0);
  });
});
