import { InMemoryAuditProducer, KafkaAuditProducer, type ProducerLike } from '../src';

const OPTIONS = { clientId: 'service-test', brokers: ['broker:9092'] };
const MESSAGE = { topic: 'estate.audit.events.v1', key: 'user-1', value: '{"a":1}' };

/** A producer double whose connect outcome the test controls per attempt. */
function fakeProducer(connectOutcomes: Array<Error | null>): ProducerLike & {
  connectCalls: number;
  sent: unknown[];
  disconnectCalls: number;
} {
  const fake = {
    connectCalls: 0,
    sent: [] as unknown[],
    disconnectCalls: 0,
    connect(): Promise<void> {
      const outcome = connectOutcomes[fake.connectCalls] ?? null;
      fake.connectCalls += 1;
      return outcome ? Promise.reject(outcome) : Promise.resolve();
    },
    send(record: unknown): Promise<unknown> {
      fake.sent.push(record);
      return Promise.resolve(undefined);
    },
    disconnect(): Promise<void> {
      fake.disconnectCalls += 1;
      return Promise.resolve();
    },
  };
  return fake;
}

describe('KafkaAuditProducer', () => {
  it('connects once and reuses the connection across sends', async () => {
    const fake = fakeProducer([]);
    const producer = new KafkaAuditProducer(OPTIONS, fake);
    await producer.send(MESSAGE);
    await producer.send(MESSAGE);
    expect(fake.connectCalls).toBe(1);
    expect(fake.sent).toEqual([
      { topic: MESSAGE.topic, messages: [{ key: MESSAGE.key, value: MESSAGE.value }] },
      { topic: MESSAGE.topic, messages: [{ key: MESSAGE.key, value: MESSAGE.value }] },
    ]);
  });

  it('RETRIES after a failed connect instead of poisoning itself forever', async () => {
    // The bug this package exists to fix. `connecting ??= connect()` cached the
    // rejected PROMISE, so one unavailable-broker moment at startup made every
    // later send throw for the process's whole life — and since audit emission
    // is a hard dependency of every sensitive action, that is every sensitive
    // action, with no in-process signal that a restart was needed.
    const fake = fakeProducer([new Error('broker not ready')]);
    const producer = new KafkaAuditProducer(OPTIONS, fake);

    await expect(producer.send(MESSAGE)).rejects.toThrow('broker not ready');
    expect(fake.sent).toHaveLength(0);

    // Broker comes up; the very next send must succeed.
    await producer.send(MESSAGE);
    expect(fake.connectCalls).toBe(2);
    expect(fake.sent).toHaveLength(1);
  });

  it('keeps retrying across repeated failures, then recovers', async () => {
    const fake = fakeProducer([new Error('down'), new Error('still down')]);
    const producer = new KafkaAuditProducer(OPTIONS, fake);
    await expect(producer.send(MESSAGE)).rejects.toThrow('down');
    await expect(producer.send(MESSAGE)).rejects.toThrow('still down');
    await producer.send(MESSAGE);
    expect(fake.connectCalls).toBe(3);
    expect(fake.sent).toHaveLength(1);
  });

  it('shares ONE in-flight connect between concurrent sends', async () => {
    // The half of the memoisation that was correct and must survive the fix:
    // a burst of concurrent sends must not open a connection each.
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let connectCalls = 0;
    const fake: ProducerLike = {
      connect: (): Promise<void> => {
        connectCalls += 1;
        return gate;
      },
      send: (): Promise<unknown> => Promise.resolve(undefined),
      disconnect: (): Promise<void> => Promise.resolve(),
    };
    const producer = new KafkaAuditProducer(OPTIONS, fake);
    const sends = [producer.send(MESSAGE), producer.send(MESSAGE), producer.send(MESSAGE)];
    release();
    await Promise.all(sends);
    expect(connectCalls).toBe(1);
  });

  it('rejects every concurrent send when the shared connect fails, then recovers', async () => {
    const fake = fakeProducer([new Error('broker not ready')]);
    const producer = new KafkaAuditProducer(OPTIONS, fake);
    const results = await Promise.allSettled([producer.send(MESSAGE), producer.send(MESSAGE)]);
    expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected']);
    // One shared attempt for the burst — not one per caller.
    expect(fake.connectCalls).toBe(1);
    await producer.send(MESSAGE);
    expect(fake.connectCalls).toBe(2);
  });

  it('disconnects only when a connection was attempted', async () => {
    const never = fakeProducer([]);
    await new KafkaAuditProducer(OPTIONS, never).disconnect();
    expect(never.disconnectCalls).toBe(0);

    const used = fakeProducer([]);
    const producer = new KafkaAuditProducer(OPTIONS, used);
    await producer.send(MESSAGE);
    await producer.disconnect();
    expect(used.disconnectCalls).toBe(1);
  });

  it('does not disconnect a producer whose only connect failed', async () => {
    // The failed attempt cleared the cache, so there is nothing to close.
    const fake = fakeProducer([new Error('down')]);
    const producer = new KafkaAuditProducer(OPTIONS, fake);
    await expect(producer.send(MESSAGE)).rejects.toThrow('down');
    await producer.disconnect();
    expect(fake.disconnectCalls).toBe(0);
  });

  it('builds a real kafkajs producer when none is injected', () => {
    // Construction only — no broker is contacted until the first send.
    expect(() => new KafkaAuditProducer(OPTIONS)).not.toThrow();
  });
});

describe('InMemoryAuditProducer', () => {
  it('captures messages in order for assertions', async () => {
    const producer = new InMemoryAuditProducer();
    await producer.send(MESSAGE);
    await producer.send({ ...MESSAGE, key: 'user-2' });
    expect(producer.messages).toEqual([MESSAGE, { ...MESSAGE, key: 'user-2' }]);
  });
});
