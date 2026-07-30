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

  /**
   * Begin consuming.
   *
   * @param onFatal called when the consumer dies for good — `main.ts` wires it
   * to the same fatal path a failed startup takes. Defaulted so tests and the
   * verify CLI can start a consumer without owning process control.
   */
  async start(onFatal: (err: unknown) => void = () => undefined): Promise<void> {
    // A CRASH THAT DOES NOT RESTART MUST KILL THE PROCESS.
    //
    // `consumer.run()` resolves once the fetch loop is RUNNING, so every
    // failure after that point arrives as an event rather than a rejected
    // promise. kafkajs restarts itself only when the error is RETRIABLE
    // (kafkajs 2.2.4 consumer/index.js: `shouldRestart = isErrorRetriable &&
    // restartOnFailure(e)`); for anything else it disconnects, emits CRASH and
    // returns — leaving this process alive, holding its Postgres socket,
    // answering a TCP probe, and ingesting nothing. That is precisely the "up
    // with a dead audit trail" state fatal.ts exists to prevent: PR2 closed it
    // for startup and left it open for steady state, which is the longer half
    // of the process's life.
    this.consumer.on(this.consumer.events.CRASH, ({ payload }) => {
      const error: unknown = payload.error;
      log({
        level: 'error',
        msg: 'audit_consumer_crash',
        // Restartable crashes are kafkajs reconnecting; they are noteworthy,
        // not fatal.
        restarting: payload.restart,
        groupId: payload.groupId,
        // Infrastructure detail only. Ingest failures never carry an event
        // payload into an error message — `ingest` returns a status instead.
        error: error instanceof Error ? `${error.name}: ${error.message}` : 'unknown',
      });
      if (!payload.restart) {
        onFatal(error);
      }
    });

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
