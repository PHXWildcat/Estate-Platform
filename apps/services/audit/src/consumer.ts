import { TOPICS } from '@estate/contracts';
import type { Consumer, EachMessagePayload } from 'kafkajs';
import type { AuditIngestor } from './ingestor';
import { log } from './logger';

/**
 * Kafka consumer loop for `estate.audit.events.v1`.
 *
 * Rejected messages (invalid JSON / schema violations) are counted and their
 * COORDINATES (topic/partition/offset + reason enum) logged — never any part
 * of the payload, which may contain exactly the PII the schema rejected. A
 * DLQ for operator triage of rejected offsets is a designed follow-up (see
 * README); until then the log line is the recovery pointer.
 */
export class AuditConsumer {
  private rejected = 0;

  constructor(
    private readonly consumer: Consumer,
    private readonly ingestor: AuditIngestor,
  ) {}

  /** Rejected-message count since process start (test/ops introspection). */
  get rejectedCount(): number {
    return this.rejected;
  }

  async start(): Promise<void> {
    await this.consumer.connect();
    await this.consumer.subscribe({ topic: TOPICS.auditEvents, fromBeginning: true });
    await this.consumer.run({
      eachMessage: (payload: EachMessagePayload) => this.handle(payload),
    });
  }

  async stop(): Promise<void> {
    await this.consumer.disconnect();
  }

  private async handle({ topic, partition, message }: EachMessagePayload): Promise<void> {
    const raw = message.value === null ? '' : message.value.toString('utf8');
    const result = await this.ingestor.ingest(raw);
    switch (result.status) {
      case 'appended':
        break;
      case 'duplicate':
        log({
          level: 'info',
          msg: 'audit_event_duplicate',
          topic,
          partition,
          offset: message.offset,
        });
        break;
      case 'rejected':
        this.rejected += 1;
        log({
          level: 'warn',
          msg: 'audit_event_rejected',
          reason: result.reason,
          topic,
          partition,
          offset: message.offset,
          rejectedTotal: this.rejected,
        });
        break;
    }
  }
}
