import { randomUUID } from 'node:crypto';
import { AuditEventSchema, TOPICS, type AuditEvent } from '@estate/contracts';

/** Transport boundary — Kafka in production, an in-memory double in tests. */
export interface AuditProducer {
  send(message: { topic: string; key: string; value: string }): Promise<void>;
}

/**
 * Thrown when an event fails the shape/PII guard. Carries only the offending
 * FIELD PATHS — never the offending values, which may be the PII we are
 * refusing to log.
 */
export class AuditShapeError extends Error {
  constructor(readonly paths: string[]) {
    super(`audit event rejected by shape/PII guard at: ${paths.join(', ')}`);
    this.name = 'AuditShapeError';
  }
}

export type AuditEventInput = Omit<AuditEvent, 'eventId' | 'occurredAt' | 'detail'> & {
  detail?: AuditEvent['detail'];
};

/**
 * The only sanctioned path for producing audit events. Validation against
 * `AuditEventSchema` happens before send, so free text, names, and emails
 * cannot reach the append-only store even through developer error
 * (docs/02 §6: entity IDs and enums only).
 */
export class AuditEmitter {
  constructor(
    private readonly producer: AuditProducer,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async emit(input: AuditEventInput): Promise<AuditEvent> {
    const candidate = {
      ...input,
      detail: input.detail ?? {},
      eventId: randomUUID(),
      occurredAt: this.now().toISOString(),
    };
    const parsed = AuditEventSchema.safeParse(candidate);
    if (!parsed.success) {
      throw new AuditShapeError(parsed.error.issues.map((i) => i.path.join('.') || '(root)'));
    }
    await this.producer.send({
      topic: TOPICS.auditEvents,
      // Partition by actor so one principal's stream stays ordered — the shape
      // insider-anomaly detection consumes (docs/03 §5.3).
      key: parsed.data.actorId ?? parsed.data.eventId,
      value: JSON.stringify(parsed.data),
    });
    return parsed.data;
  }
}
