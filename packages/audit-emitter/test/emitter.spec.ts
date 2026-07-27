import { randomUUID } from 'node:crypto';
import { AuditEventSchema, TOPICS } from '@estate/contracts';
import { AuditEmitter, AuditShapeError, type AuditEventInput } from '../src/emitter';

class FakeProducer {
  readonly sent: Array<{ topic: string; key: string; value: string }> = [];
  send(message: { topic: string; key: string; value: string }): Promise<void> {
    this.sent.push(message);
    return Promise.resolve();
  }
}

const ACTOR_ID = randomUUID();

function validInput(): AuditEventInput {
  return {
    action: 'auth.login.succeeded',
    actorId: ACTOR_ID,
    actorType: 'user',
    onBehalfOf: null,
    resourceType: 'session',
    resourceId: randomUUID(),
    sessionId: randomUUID(),
    detail: { mfa_level: 'mfa' },
  };
}

describe('AuditEmitter', () => {
  it('emits a schema-valid event to the audit topic, keyed by actor', async () => {
    const producer = new FakeProducer();
    const emitter = new AuditEmitter(producer);
    const event = await emitter.emit(validInput());

    expect(producer.sent).toHaveLength(1);
    const msg = producer.sent[0]!;
    expect(msg.topic).toBe(TOPICS.auditEvents);
    expect(msg.key).toBe(ACTOR_ID);
    expect(AuditEventSchema.parse(JSON.parse(msg.value))).toEqual(event);
  });

  it('defaults detail to {} and falls back to eventId as key when actor is null', async () => {
    const producer = new FakeProducer();
    const emitter = new AuditEmitter(producer);
    const { detail: _ignored, ...rest } = validInput();
    const event = await emitter.emit({ ...rest, actorId: null, actorType: 'system' });
    expect(event.detail).toEqual({});
    expect(producer.sent[0]!.key).toBe(event.eventId);
  });

  it('rejects free-text detail values and never calls the producer', async () => {
    const producer = new FakeProducer();
    const emitter = new AuditEmitter(producer);
    const input = validInput();
    input.detail = { note: 'John Smith viewed the will' };
    await expect(emitter.emit(input)).rejects.toThrow(AuditShapeError);
    expect(producer.sent).toHaveLength(0);
  });

  it('never includes the offending value in the thrown error', async () => {
    const emitter = new AuditEmitter(new FakeProducer());
    const input = validInput();
    input.detail = { email: 'alice@example.com' };
    try {
      await emitter.emit(input);
      throw new Error('expected rejection');
    } catch (err) {
      expect(err).toBeInstanceOf(AuditShapeError);
      expect((err as Error).message).not.toContain('alice@example.com');
      expect((err as AuditShapeError).paths).toContain('detail.email');
    }
  });

  it('rejects actions outside the closed catalog', async () => {
    const producer = new FakeProducer();
    const emitter = new AuditEmitter(producer);
    // A plausibly-shaped action that no service has registered. This used to be
    // 'vault.opened', which became real when M6 landed - the catalog grows one
    // reviewed entry at a time, so this fixture has to name something that is
    // still outside it.
    const input = { ...validInput(), action: 'vault.telepathy.performed' as never };
    await expect(emitter.emit(input)).rejects.toThrow(AuditShapeError);
    expect(producer.sent).toHaveLength(0);
  });
});
