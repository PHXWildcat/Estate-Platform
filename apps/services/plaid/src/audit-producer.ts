import { Kafka, type Producer } from 'kafkajs';
import type { AuditProducer } from '@estate/audit-emitter';

/** Kafka-backed producer for audit + domain events (MSK in production). */
export class KafkaAuditProducer implements AuditProducer {
  private readonly producer: Producer;
  private connecting: Promise<void> | null = null;

  constructor(brokers: string[]) {
    this.producer = new Kafka({ clientId: 'service-plaid', brokers }).producer();
  }

  private connect(): Promise<void> {
    this.connecting ??= this.producer.connect();
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
 * Production wiring refuses to construct it — see config.ts / app.module.ts.
 */
export class InMemoryAuditProducer implements AuditProducer {
  readonly messages: Array<{ topic: string; key: string; value: string }> = [];

  send(message: { topic: string; key: string; value: string }): Promise<void> {
    this.messages.push(message);
    return Promise.resolve();
  }
}
