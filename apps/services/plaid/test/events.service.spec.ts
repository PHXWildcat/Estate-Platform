import { randomUUID } from 'node:crypto';
import { AuditEventSchema, PlaidItemStatusChangedEvent, TOPICS } from '@estate/contracts';
import { InMemoryAuditProducer } from '@estate/kafka';
import { EventsService } from '../src/events.service';

/**
 * THE EMITTER LAYER (M49 PR6). The service spec proves what `PlaidService`
 * PASSES to the emitter, through a recording double that never runs it; the
 * integration spec sees what a real emitter files on the ladder's twelve
 * edges, but only for the arms its journey reaches. Neither pins the
 * emitter's own shape arm by arm — the PR's review found an `itemSynced` arm
 * that took a null prior and was executed by no test at all (that arm is now
 * gone rather than tested). So this spec runs the real `EventsService` over
 * an in-memory producer and parses what comes out, one emitter at a time.
 */

const OWNER = randomUUID();
const ITEM = randomUUID();

function build(): { producer: InMemoryAuditProducer; events: EventsService } {
  const producer = new InMemoryAuditProducer();
  return { producer, events: new EventsService(producer, () => new Date('2026-09-09T00:00:00Z')) };
}

const audits = (producer: InMemoryAuditProducer): ReturnType<typeof AuditEventSchema.parse>[] =>
  producer.messages
    .filter((m) => m.topic === TOPICS.auditEvents)
    .map((m) => AuditEventSchema.parse(JSON.parse(m.value)));

describe('EventsService — the item ladder’s four emitters, as FILED', () => {
  it('every ladder emitter files `from`, and the one non-ladder item emitter does not', async () => {
    const { producer, events } = build();
    await events.itemLoginRequired(OWNER, ITEM, 'healthy');
    await events.itemErrored(OWNER, OWNER, ITEM, 'login_required');
    await events.itemSynced(OWNER, ITEM, 2, 'error');
    await events.itemRevoked(OWNER, ITEM, 'healthy');
    await events.itemLinked(OWNER, ITEM, 'ins_stub_109508');
    // Keyed by action and compared whole, so a `from` that landed on the
    // wrong emitter cannot preserve a count.
    expect(Object.fromEntries(audits(producer).map((e) => [e.action, e.detail]))).toEqual({
      'plaid.item.login_required': { from: 'healthy' },
      'plaid.item.errored': { from: 'login_required' },
      'plaid.item.synced': { accounts: 2, from: 'error' },
      'plaid.item.revoked': { from: 'healthy' },
      'plaid.item.linked': { institutionId: 'ins_stub_109508' },
    });
  });

  it('a platform actor names the OWNER in onBehalfOf; an owner actor names nobody', async () => {
    const { producer, events } = build();
    await events.itemErrored(null, OWNER, ITEM, 'healthy');
    await events.itemErrored(OWNER, OWNER, ITEM, 'healthy');
    await events.itemLoginRequired(OWNER, ITEM, 'error');
    expect(
      audits(producer).map((e) => ({
        action: e.action,
        actorId: e.actorId,
        actorType: e.actorType,
        onBehalfOf: e.onBehalfOf,
        // `resourceType` too: the projection decides what this spec can see,
        // and one dropped from it is a field no layer pins. `login_required`
        // had none anywhere until M49 PR6's review counted the projection's
        // keys against the emit's.
        resourceType: e.resourceType,
        resourceId: e.resourceId,
      })),
    ).toEqual([
      {
        action: 'plaid.item.errored',
        actorId: null,
        actorType: 'system',
        onBehalfOf: OWNER,
        resourceType: 'plaid_item',
        resourceId: ITEM,
      },
      {
        action: 'plaid.item.errored',
        actorId: OWNER,
        actorType: 'user',
        onBehalfOf: null,
        resourceType: 'plaid_item',
        resourceId: ITEM,
      },
      {
        action: 'plaid.item.login_required',
        actorId: null,
        actorType: 'system',
        onBehalfOf: OWNER,
        resourceType: 'plaid_item',
        resourceId: ITEM,
      },
    ]);
  });

  it('EVERY ladder emitter that has a domain envelope publishes one, keyed by the item', async () => {
    // The domain half, counted rather than sampled: a spec that pins one
    // envelope proves nothing about the other three, and deleting any of their
    // domain emits was a full survivor before M49 PR6's review counted them.
    // Derived from the emits themselves — action in, topic and key out.
    const { producer, events } = build();
    await events.itemLoginRequired(OWNER, ITEM, 'healthy');
    await events.itemErrored(null, OWNER, ITEM, 'login_required');
    await events.itemSynced(OWNER, ITEM, 2, 'error');
    await events.itemRevoked(OWNER, ITEM, 'healthy');
    const domain = producer.messages
      .filter((m) => m.topic === TOPICS.plaidEvents)
      .map((m) => {
        const envelope = JSON.parse(m.value) as { type: string; payload: { status?: string } };
        return { key: m.key, type: envelope.type, status: envelope.payload.status ?? null };
      });
    // FOUR EMITS, FOUR ENVELOPES, all keyed by the item — and `synced` carries
    // a type of its own rather than a status change, which is read here rather
    // than assumed: a first draft of this test parsed all four with the
    // status-changed schema and discovered the difference by throwing.
    expect(domain).toEqual([
      { key: ITEM, type: 'plaid.item.status_changed', status: 'login_required' },
      { key: ITEM, type: 'plaid.item.status_changed', status: 'error' },
      { key: ITEM, type: 'plaid.item.synced', status: null },
      { key: ITEM, type: 'plaid.item.status_changed', status: 'revoked' },
    ]);
  });

  it('the domain topic hears `error` as a status change, keyed by the item', async () => {
    const { producer, events } = build();
    await events.itemErrored(null, OWNER, ITEM, 'healthy');
    const domain = producer.messages.filter((m) => m.topic === TOPICS.plaidEvents);
    expect(domain).toHaveLength(1);
    expect(domain[0]!.key).toBe(ITEM);
    const envelope = PlaidItemStatusChangedEvent.parse(JSON.parse(domain[0]!.value));
    expect(envelope.payload).toEqual({ itemId: ITEM, status: 'error' });
    expect(envelope.actor).toEqual({ id: null, type: 'system' });
  });
});
