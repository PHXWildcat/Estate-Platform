import { randomUUID } from 'node:crypto';
import {
  AuditEventSchema,
  DocumentStatusChangedEvent,
  DocumentVersionCreatedEvent,
  TOPICS,
} from '@estate/contracts';
import { capturingEvents } from './support';

const ACTOR = randomUUID();
const DOC = randomUUID();
const TEMPLATE = randomUUID();

describe('EventsService', () => {
  it('publishes contract-valid domain envelopes keyed by documentId', async () => {
    const { events, producer } = capturingEvents();
    await events.versionCreated({
      actorId: ACTOR,
      documentId: DOC,
      version: 2,
      docType: 'will',
      source: 'generated',
    });
    await events.statusChanged({
      actorId: ACTOR,
      documentId: DOC,
      from: 'signed',
      to: 'witnessed',
    });
    expect(producer.messages).toHaveLength(2);
    expect(producer.messages.every((m) => m.topic === TOPICS.documentEvents)).toBe(true);
    expect(producer.messages.every((m) => m.key === DOC)).toBe(true);
    const created = DocumentVersionCreatedEvent.parse(JSON.parse(producer.messages[0]!.value));
    expect(created.payload).toEqual({
      documentId: DOC,
      version: 2,
      docType: 'will',
      source: 'generated',
    });
    const status = DocumentStatusChangedEvent.parse(JSON.parse(producer.messages[1]!.value));
    expect(status.payload.from).toBe('signed');
  });

  it('emits contract-valid audit events (IDs and enums only)', async () => {
    const { events, producer } = capturingEvents();
    await events.documentGenerated(ACTOR, DOC, {
      docType: 'will',
      state: 'CA',
      templateId: TEMPLATE,
      templateVersion: 1,
    });
    await events.templatePublished(TEMPLATE, { docType: 'will', state: 'CA', version: 1 });
    await events.documentDeleted(ACTOR, DOC);
    for (const message of producer.messages) {
      const event = AuditEventSchema.parse(JSON.parse(message.value));
      expect(message.topic).toBe(TOPICS.auditEvents);
      expect(event.resourceId).toBeTruthy();
    }
  });

  it('the PII firewall rejects free-text detail values at the emitter', async () => {
    const { events } = capturingEvents();
    await expect(
      events.audit.emit({
        action: 'document.generated',
        actorId: ACTOR,
        actorType: 'user',
        onBehalfOf: null,
        resourceType: 'document',
        resourceId: DOC,
        sessionId: null,
        detail: { title: 'Will of Alexandra Example' },
      }),
    ).rejects.toThrow();
  });
});
