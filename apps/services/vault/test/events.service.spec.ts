import { AuditEventSchema, AUDIT_ACTIONS, TOPICS } from '@estate/contracts';
import { capturingEvents } from './support';

const USER = 'c3d4e5f6-a7b8-4c9d-8e0f-1a2b3c4d5e6f';
const SESSION = '11112222-3333-4444-8555-666677778888';
const ITEM = '99998888-7777-4666-8555-444433332222';
const VAULT_SESSION = 'aaaabbbb-cccc-4ddd-8eee-ffff00001111';

describe('EventsService', () => {
  it('emits every vault action to the audit topic', async () => {
    const captured = capturingEvents();
    const { events } = captured;

    await events.keysetCreated(USER, SESSION);
    await events.keysetUpdated(USER, SESSION, { revokedSessions: 2 });
    await events.opened(USER, SESSION, VAULT_SESSION);
    await events.openFailed(USER, SESSION, 'bad_proof');
    await events.itemsListed(USER, SESSION, 4, 'live');
    await events.itemCreated(USER, SESSION, ITEM, 'password');
    await events.itemAccessed(USER, SESSION, ITEM);
    await events.itemUpdated(USER, SESSION, ITEM, 3);
    await events.itemDeleted(USER, SESSION, ITEM);
    await events.reset(USER, SESSION, {
      itemsDestroyed: 7,
      // DISTINCT from every sibling count on purpose: these four numbers mean
      // four different things, and a fixture that gave them equal values could
      // not catch a producer that emitted one under another's key.
      itemsRelabelled: 5,
      revokedSessions: 1,
      escrowPoliciesRetired: 2,
    });
    await events.sessionRevoked(USER, SESSION, VAULT_SESSION, 'locked');

    expect(captured.actions()).toEqual([
      'vault.keyset.created',
      'vault.keyset.updated',
      'vault.opened',
      'vault.open.failed',
      'vault.items.listed',
      'vault.item.created',
      'vault.item.accessed',
      'vault.item.updated',
      'vault.item.deleted',
      'vault.reset',
      'vault.session.revoked',
    ]);
    for (const message of captured.producer.messages) {
      expect(message.topic).toBe(TOPICS.auditEvents);
      // Partitioned by actor: one principal's stream stays ordered, which is
      // the shape burst detection consumes.
      expect(message.key).toBe(USER);
    }

    // AND THE FOUR RESET COUNTS LAND UNDER THEIR OWN KEYS. The fixture above
    // gives them four DISTINCT values precisely so a producer that emitted one
    // under another's name would be visible — but nothing consumed that until
    // this assertion, so the distinctness was a comment describing a test that
    // did not exist. `itemsDestroyed` and `itemsRelabelled` are the pair most
    // worth pinning: they are adjacent, both counts of retired rows, and PR1b
    // introduced the second one.
    const reset = JSON.parse(
      captured.producer.messages.find(
        (m) => (JSON.parse(m.value) as { action: string }).action === 'vault.reset',
      )!.value,
    ) as { detail: Record<string, unknown> };
    expect(reset.detail).toEqual({
      itemsDestroyed: 7,
      itemsRelabelled: 5,
      revokedSessions: 1,
      escrowPoliciesRetired: 2,
    });
  });

  it('says WHICH list a bulk ciphertext read was (M27 PR1b)', async () => {
    // Both list routes hand back whole blobs and both record under
    // `vault.items.listed`, so `scope` is the only thing separating "showed me
    // my vault" from "showed me everything I had deleted". A required argument
    // rather than a default, so a third list route cannot inherit one silently.
    const captured = capturingEvents();
    await captured.events.itemsListed(USER, SESSION, 4, 'live');
    await captured.events.itemsListed(USER, SESSION, 2, 'restorable');

    const details = captured.producer.messages.map(
      (m) => (JSON.parse(m.value) as { detail: { count: number; scope: string } }).detail,
    );
    expect(details).toEqual([
      { count: 4, scope: 'live' },
      { count: 2, scope: 'restorable' },
    ]);
  });

  it('produces payloads that satisfy the shared audit contract', async () => {
    const captured = capturingEvents();
    await captured.events.itemCreated(USER, SESSION, ITEM, 'seed_phrase');
    const event = AuditEventSchema.parse(JSON.parse(captured.producer.messages[0]!.value));
    expect(event).toMatchObject({
      action: 'vault.item.created',
      actorId: USER,
      actorType: 'user',
      resourceType: 'vault_item',
      resourceId: ITEM,
      sessionId: SESSION,
      detail: { itemType: 'seed_phrase' },
    });
  });

  it('registers every action it emits in the shared enum', async () => {
    const captured = capturingEvents();
    await captured.events.opened(USER, SESSION, VAULT_SESSION);
    await captured.events.reset(USER, SESSION, {
      itemsDestroyed: 1,
      itemsRelabelled: 0,
      revokedSessions: 0,
      escrowPoliciesRetired: 0,
    });
    for (const action of captured.actions()) {
      expect(AUDIT_ACTIONS).toContain(action);
    }
  });

  it.each(['bad_proof', 'no_handshake', 'no_keyset'] as const)(
    'records a failed unlock with reason %s and nothing else',
    async (reason) => {
      const captured = capturingEvents();
      await captured.events.openFailed(USER, SESSION, reason);
      const event = AuditEventSchema.parse(JSON.parse(captured.producer.messages[0]!.value));
      expect(event.detail).toEqual({ reason });
    },
  );

  it('never carries anything but ids, enums and counts', async () => {
    const captured = capturingEvents();
    await captured.events.itemsListed(USER, SESSION, 12, 'restorable');
    await captured.events.itemUpdated(USER, SESSION, ITEM, 5);
    await captured.events.keysetUpdated(USER, SESSION, { revokedSessions: 3 });

    for (const message of captured.producer.messages) {
      const event = AuditEventSchema.parse(JSON.parse(message.value));
      for (const value of Object.values(event.detail)) {
        // The contract already enforces the token grammar; this asserts the
        // service never tries to smuggle free text through it.
        if (typeof value === 'string') {
          expect(value).toMatch(/^[A-Za-z0-9_.:-]{1,128}$/);
        } else {
          expect(['number', 'boolean']).toContain(typeof value);
        }
      }
    }
  });

  it('emits no domain events - there is no vault topic', async () => {
    const captured = capturingEvents();
    await captured.events.opened(USER, SESSION, VAULT_SESSION);
    const topics = new Set(captured.producer.messages.map((m) => m.topic));
    expect([...topics]).toEqual([TOPICS.auditEvents]);
  });
});
