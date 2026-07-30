import { Kafka } from 'kafkajs';
import type { AuditProducer } from '@estate/audit-emitter';

/**
 * The slice of kafkajs's `Producer` this wrapper drives. Narrow on purpose so
 * tests inject a double without a broker (the LivePlaidGateway `fetchImpl`
 * precedent); the real `Producer` satisfies it structurally.
 */
export interface ProducerLike {
  connect(): Promise<void>;
  send(record: { topic: string; messages: { key: string; value: string }[] }): Promise<unknown>;
  disconnect(): Promise<void>;
}

export interface KafkaProducerOptions {
  /**
   * Diagnostic label on the broker side (quotas, connection logs). NOT an
   * authorization principal — under docs/01 §3's MSK mTLS + per-service ACLs
   * the principal comes from the client certificate, not from this string.
   */
  clientId: string;
  brokers: string[];
}

/**
 * Kafka-backed producer for audit + domain events (MSK in production).
 *
 * ONE implementation. Until M8 this file existed seven times — once per
 * event-producing service, byte-identical but for the `clientId` literal — so
 * the connect bug below existed seven times too, and fixing it meant finding
 * all seven.
 *
 * CONNECT IS RETRIED, NOT MEMOISED-ON-FAILURE. The previous
 * `this.connecting ??= this.producer.connect()` cached the PROMISE, so a
 * single failed connect was re-thrown by every later `send()` for the rest of
 * the process's life. A service that started fractionally before its broker
 * came up would listen happily and then fail EVERY audited action — which,
 * since audit emission is a hard dependency of every sensitive action, means
 * every sensitive action — with no recovery short of a restart, and no
 * in-process signal that a restart was needed. That is a fail-closed outcome
 * rather than a dangerous one, but it is indistinguishable from a total
 * outage and it is entirely avoidable. Now the in-flight promise is still
 * shared (concurrent sends make one connection), and only a REJECTION clears
 * the cache so the next send tries again.
 */
export class KafkaAuditProducer implements AuditProducer {
  private readonly producer: ProducerLike;
  private connecting: Promise<void> | null = null;

  constructor(options: KafkaProducerOptions, producer?: ProducerLike) {
    this.producer =
      producer ?? new Kafka({ clientId: options.clientId, brokers: options.brokers }).producer();
  }

  private connect(): Promise<void> {
    this.connecting ??= this.producer.connect().catch((err: unknown) => {
      // Clear before rethrowing: a poisoned cache is the bug being fixed.
      this.connecting = null;
      throw err;
    });
    return this.connecting;
  }

  async send(message: { topic: string; key: string; value: string }): Promise<void> {
    await this.connect();
    await this.producer.send({
      topic: message.topic,
      messages: [{ key: message.key, value: message.value }],
    });
  }

  async disconnect(): Promise<void> {
    if (this.connecting) {
      await this.producer.disconnect();
    }
  }
}

/**
 * In-memory producer. Two sanctioned uses ONLY:
 *  - tests (assert on captured messages);
 *  - local dev without Kafka (NODE_ENV !== 'production').
 * Production wiring refuses to construct it — see each service's config.ts
 * and app.module.ts, which throw rather than fall back to it.
 */
export class InMemoryAuditProducer implements AuditProducer {
  readonly messages: Array<{ topic: string; key: string; value: string }> = [];

  send(message: { topic: string; key: string; value: string }): Promise<void> {
    this.messages.push(message);
    return Promise.resolve();
  }
}
