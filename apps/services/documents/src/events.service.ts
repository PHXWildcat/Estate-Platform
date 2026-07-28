import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  DocumentStatusChangedEvent,
  DocumentVersionCreatedEvent,
  TOPICS,
  type DocType,
  type DocumentKind,
  type DocumentSource,
  type ExecutionStatus,
  type UploadFormat,
} from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';
import { sanitizeSignature } from './malware-scanner';

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
    docType: DocumentKind;
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

  /**
   * M7: a settlement operator read a document version registered as case
   * evidence. Unlike every other document event the actor is NOT the owner,
   * so onBehalfOf carries the document owner (the reporter who uploaded the
   * evidence) and the detail ties the read to its settlement case.
   */
  async evidenceAccessed(
    actorId: string,
    documentId: string,
    ownerUserId: string,
    detail: { version: number; caseId: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'document.evidence.accessed',
      actorId,
      actorType: 'user',
      onBehalfOf: ownerUserId,
      resourceType: 'document',
      resourceId: documentId,
      sessionId: null,
      detail: { version: detail.version, caseId: detail.caseId },
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

  async documentUploaded(
    actorId: string,
    documentId: string,
    detail: { kind: DocumentKind; format: UploadFormat },
  ): Promise<void> {
    await this.document('document.uploaded', actorId, documentId, {
      kind: detail.kind,
      format: detail.format,
    });
  }

  async ocrIndexed(
    actorId: string,
    documentId: string,
    detail: { version: number; tokens: number },
  ): Promise<void> {
    await this.document('document.ocr.indexed', actorId, documentId, {
      version: detail.version,
      tokens: detail.tokens,
    });
  }

  /**
   * A rejected upload never becomes a document — resourceId stays null and
   * the detail carries enums plus (for infections) the sanitized signature
   * token. The scanner signature is THIRD-PARTY data; re-clamp it through
   * sanitizeSignature HERE, at the audit egress, so the PII firewall never
   * depends on every present and future scanner adapter having sanitized
   * (defense in depth — the AuditEmitter schema gate is the final backstop).
   */
  async scanRejected(
    actorId: string,
    detail: {
      kind: DocumentKind;
      format: UploadFormat;
      reason: 'infected' | 'scanner_error';
      signature?: string;
    },
  ): Promise<void> {
    await this.audit.emit({
      action: 'document.scan.rejected',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'document_upload',
      resourceId: null,
      sessionId: null,
      detail: {
        kind: detail.kind,
        format: detail.format,
        reason: detail.reason,
        ...(detail.signature !== undefined
          ? { signature: sanitizeSignature(detail.signature) }
          : {}),
      },
    });
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
      | 'document.deleted'
      | 'document.uploaded'
      | 'document.ocr.indexed',
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
