import { TOPICS } from '@estate/contracts';
import type { Consumer, ConsumerEvents, EachMessagePayload } from 'kafkajs';
import { AuditConsumer } from '../src/consumer';
import type { AuditIngestor } from '../src/ingestor';

type CrashPayload = { error: unknown; groupId: string; restart: boolean };
type CrashListener = (event: { payload: CrashPayload }) => void;

/**
 * A stand-in for kafkajs's Consumer.
 *
 * `events.CRASH` carries the real string kafkajs emits, so a rename in the
 * library surfaces here rather than silently unsubscribing the fatal path.
 */
function fakeConsumer(): {
  consumer: Consumer;
  crash(payload: CrashPayload): void;
  subscribed: string[];
  deliver(raw: string): Promise<void>;
} {
  const crashListeners: CrashListener[] = [];
  const subscribed: string[] = [];
  let each: ((payload: EachMessagePayload) => Promise<void>) | null = null;

  const consumer = {
    events: { CRASH: 'consumer.crash' } as unknown as ConsumerEvents,
    on: (event: string, listener: CrashListener): (() => void) => {
      if (event === 'consumer.crash') {
        crashListeners.push(listener);
      }
      return () => undefined;
    },
    connect: (): Promise<void> => Promise.resolve(),
    subscribe: ({ topic }: { topic: string }): Promise<void> => {
      subscribed.push(topic);
      return Promise.resolve();
    },
    run: (config: {
      eachMessage: (payload: EachMessagePayload) => Promise<void>;
    }): Promise<void> => {
      each = config.eachMessage;
      return Promise.resolve();
    },
    disconnect: (): Promise<void> => Promise.resolve(),
  } as unknown as Consumer;

  return {
    consumer,
    subscribed,
    crash: (payload) => {
      for (const listener of crashListeners) {
        listener({ payload });
      }
    },
    deliver: async (raw) => {
      if (!each) {
        throw new Error('run() was never called');
      }
      await each({
        topic: TOPICS.auditEvents,
        partition: 0,
        message: { value: Buffer.from(raw, 'utf8'), offset: '7' },
      } as unknown as EachMessagePayload);
    },
  };
}

function fakeIngestor(status: 'appended' | 'duplicate' | 'rejected' = 'appended'): AuditIngestor {
  return {
    ingest: (): Promise<{ status: string; reason?: string }> =>
      Promise.resolve(status === 'rejected' ? { status, reason: 'schema' } : { status }),
  } as unknown as AuditIngestor;
}

describe('audit consumer crash handling', () => {
  let written: string[];

  beforeEach(() => {
    written = [];
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown): boolean => {
      written.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('A NON-RESTARTABLE CRASH IS FATAL — the process must not stay up ingesting nothing', async () => {
    // The defect PR2 left open: `consumer.run()` resolves once the fetch loop is
    // running, so a later failure arrives as an event. kafkajs restarts itself
    // only for RETRIABLE errors; otherwise it disconnects, emits CRASH and
    // returns — leaving a live process holding its Postgres socket, answering a
    // TCP probe, and never ingesting again. Silence, in the service whose
    // silence is the paging signal.
    const kafka = fakeConsumer();
    const fatal: unknown[] = [];
    await new AuditConsumer(kafka.consumer, fakeIngestor()).start((err) => fatal.push(err));

    const cause = new Error('SASL authentication failed');
    kafka.crash({ error: cause, groupId: 'audit-service', restart: false });

    expect(fatal).toEqual([cause]);
  });

  it('a RESTARTABLE crash is logged and left to kafkajs', async () => {
    // A broker blip: the events are still on the topic and kafkajs reconnects,
    // so killing the container would buy nothing and lose the group's position.
    const kafka = fakeConsumer();
    const fatal: unknown[] = [];
    await new AuditConsumer(kafka.consumer, fakeIngestor()).start((err) => fatal.push(err));

    kafka.crash({
      error: new Error('KafkaJSNumberOfRetriesExceeded'),
      groupId: 'audit-service',
      restart: true,
    });

    expect(fatal).toEqual([]);
    expect(written.join('')).toContain('audit_consumer_crash');
  });

  it('logs the crash by name and shape only — never a payload', async () => {
    const kafka = fakeConsumer();
    await new AuditConsumer(kafka.consumer, fakeIngestor()).start();
    kafka.crash({
      error: { ssn: '123-45-6789' },
      groupId: 'audit-service',
      restart: false,
    });
    const line = written.join('');
    expect(line).toContain('audit_consumer_crash');
    expect(line).toContain('unknown');
    expect(line).not.toContain('123-45-6789');
  });

  it('subscribes to the audit topic and keeps consuming', async () => {
    const kafka = fakeConsumer();
    const consumer = new AuditConsumer(kafka.consumer, fakeIngestor('rejected'));
    await consumer.start();
    expect(kafka.subscribed).toEqual([TOPICS.auditEvents]);
    await kafka.deliver('{"not":"an event"}');
    // A rejected message is counted, not thrown: one malformed event must never
    // stop the ingest loop.
    expect(consumer.rejectedCount).toBe(1);
  });
});
