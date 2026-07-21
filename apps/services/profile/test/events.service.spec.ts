import { randomUUID } from 'node:crypto';
import { TOPICS } from '@estate/contracts';
import { InMemoryAuditProducer } from '../src/audit-producer';
import { EventsService } from '../src/events.service';

const ACTOR = randomUUID();
const RES = randomUUID();

function build() {
  const producer = new InMemoryAuditProducer();
  const events = new EventsService(producer, () => new Date());
  return { producer, events };
}

function actions(producer: InMemoryAuditProducer): string[] {
  return producer.messages
    .filter((m) => m.topic === TOPICS.auditEvents)
    .map((m) => (JSON.parse(m.value) as { action: string }).action);
}

describe('EventsService audit emission', () => {
  it('emits every profile/contacts action against the closed contracts catalog', async () => {
    const { producer, events } = build();
    await events.profileUpserted(ACTOR, RES);
    await events.familyMemberCreated(ACTOR, RES);
    await events.familyMemberUpdated(ACTOR, RES);
    await events.familyMemberDeleted(ACTOR, RES);
    await events.contactCreated(ACTOR, RES);
    await events.contactUpdated(ACTOR, RES);
    await events.contactDeleted(ACTOR, RES);
    await events.roleGranted(ACTOR, RES, { role: 'beneficiary', scopeType: 'asset' });
    await events.roleRevoked(ACTOR, RES);
    await events.permissionGranted(ACTOR, RES, { resource: 'contact', action: 'read' });

    // Each call validated cleanly against @estate/contracts (would throw if the
    // action token were missing from AUDIT_ACTIONS).
    expect(actions(producer)).toEqual([
      'profile.updated',
      'family_member.created',
      'family_member.updated',
      'family_member.deleted',
      'contact.created',
      'contact.updated',
      'contact.deleted',
      'role.granted',
      'role.revoked',
      'permission.granted',
    ]);
  });

  it('carries only IDs/enum tokens in detail (PII firewall) and partitions by actor', async () => {
    const { producer, events } = build();
    await events.roleGranted(ACTOR, RES, { role: 'trustee', scopeType: 'trust' });
    const msg = producer.messages[0] as { key: string; value: string };
    const parsed = JSON.parse(msg.value) as {
      actorId: string;
      resourceType: string;
      detail: Record<string, unknown>;
    };
    expect(msg.key).toBe(ACTOR); // partition key = actor
    expect(parsed.actorId).toBe(ACTOR);
    expect(parsed.resourceType).toBe('role_assignment');
    expect(parsed.detail).toEqual({ role: 'trustee', scopeType: 'trust' });
  });
});
