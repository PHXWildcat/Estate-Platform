import { randomUUID } from 'node:crypto';
import type { AuditEvent } from '@estate/contracts';

/** A valid audit event in the real wire shape (AuditEventSchema). */
export function makeEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    eventId: randomUUID(),
    occurredAt: '2026-07-20T12:00:00.000Z',
    action: 'auth.login.succeeded',
    actorId: randomUUID(),
    actorType: 'user',
    onBehalfOf: null,
    resourceType: 'session',
    resourceId: randomUUID(),
    sessionId: randomUUID(),
    detail: {},
    ...overrides,
  };
}
