import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  DocumentStatusChangedEvent,
  DocumentVersionCreatedEvent,
  TOPICS,
  type DocType,
  type DocumentSource,
  type ExecutionStatus,
} from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single egress point for this service's audit + domain events.
 *
 * Audit events (docs/02 §6: entity IDs and enums only — never plaintext
 * values, so never titles, variable values, or content) go to the append-only
 * audit cluster via AuditEmitter, which validates each payload against
 * @estate/contracts before the wire.
 *
 * Domain events go to TOPICS.documentEvents, keyed by documentId (per-document
 * ordering). IDs/enums ONLY — a value-bearing consumer would first need the
 * docs/01 §4 Zone B Kafka payload crypto (tracked prerequisite).
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(
    @Inject(AUDIT_PRODUCER) private readonly producer: AuditProducer,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {
    this.audit = new AuditEmitter(producer, clock);
  }

  async versionCreated(input: {
    actorId: string;
    documentId: string;
    version: number;
    docType: DocType;
    source: DocumentSource;
  }): Promise<void> {
    const envelope = DocumentVersionCreatedEvent.parse({
      eventId: randomUUID(),
      type: 'document.version.created',
      version: 1,
      occurredAt: this.clock().toISOString(),
      actor: { id: input.actorId, type: 'user' },
      payload: {
        documentId: input.documentId,
        version: input.version,
        docType: input.docType,
        source: input.source,
      },
    });
    await this.producer.send({
      topic: TOPICS.documentEvents,
      key: input.documentId,
      value: JSON.stringify(envelope),
    });
  }

  async statusChanged(input: {
    actorId: string;
    documentId: string;
    from: ExecutionStatus;
    to: ExecutionStatus;
  }): Promise<void> {
    const envelope = DocumentStatusChangedEvent.parse({
      eventId: randomUUID(),
      type: 'document.status.changed',
      version: 1,
      occurredAt: this.clock().toISOString(),
      actor: { id: input.actorId, type: 'user' },
      payload: { documentId: input.documentId, from: input.from, to: input.to },
    });
    await this.producer.send({
      topic: TOPICS.documentEvents,
      key: input.documentId,
      value: JSON.stringify(envelope),
    });
  }

  async documentGenerated(
    actorId: string,
    documentId: string,
    detail: { docType: DocType; state: string; templateId: string; templateVersion: number },
  ): Promise<void> {
    await this.document('document.generated', actorId, documentId, {
      docType: detail.docType,
      state: detail.state,
      templateId: detail.templateId,
      templateVersion: detail.templateVersion,
    });
  }

  async documentVersionCreated(
    actorId: string,
    documentId: string,
    detail: { version: number },
  ): Promise<void> {
    await this.document('document.version.created', actorId, documentId, {
      version: detail.version,
    });
  }

  async contentViewed(
    actorId: string,
    documentId: string,
    detail: { version: number },
  ): Promise<void> {
    await this.document('document.content.viewed', actorId, documentId, {
      version: detail.version,
    });
  }

  async documentStatusChanged(
    actorId: string,
    documentId: string,
    detail: { from: ExecutionStatus; to: ExecutionStatus },
  ): Promise<void> {
    await this.document('document.status.changed', actorId, documentId, {
      from: detail.from,
      to: detail.to,
    });
  }

  async documentDeleted(actorId: string, documentId: string): Promise<void> {
    await this.document('document.deleted', actorId, documentId);
  }

  /** Template publications/activations run as the CLI operator (actor null). */
  async templatePublished(
    templateId: string,
    detail: { docType: DocType; state: string; version: number },
  ): Promise<void> {
    await this.audit.emit({
      action: 'document.template.published',
      actorId: null,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'document_template',
      resourceId: templateId,
      sessionId: null,
      detail: { docType: detail.docType, state: detail.state, version: detail.version },
    });
  }

  async templateActivated(
    templateId: string,
    detail: { docType: DocType; state: string; version: number },
  ): Promise<void> {
    await this.audit.emit({
      action: 'document.template.activated',
      actorId: null,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'document_template',
      resourceId: templateId,
      sessionId: null,
      detail: { docType: detail.docType, state: detail.state, version: detail.version },
    });
  }

  private async document(
    action:
      | 'document.generated'
      | 'document.version.created'
      | 'document.content.viewed'
      | 'document.status.changed'
      | 'document.deleted',
    actorId: string,
    documentId: string,
    detail: Record<string, string | number | boolean> = {},
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'document',
      resourceId: documentId,
      sessionId: null,
      detail,
    });
  }
}
