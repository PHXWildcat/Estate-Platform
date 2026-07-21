import { randomUUID } from 'node:crypto';
import { AuditEventSchema } from '../src/audit';
import { AuthEventSchema, LoginSucceededEvent } from '../src/auth-events';

function validAuditEvent() {
  return {
    eventId: randomUUID(),
    occurredAt: new Date().toISOString(),
    action: 'crypto.field.decrypted' as const,
    actorId: randomUUID(),
    actorType: 'service' as const,
    onBehalfOf: null,
    resourceType: 'profile.field',
    resourceId: randomUUID(),
    sessionId: null,
    detail: { field: 'email', purpose: 'login_lookup', dek_id: randomUUID() },
  };
}

describe('audit event schema (PII firewall)', () => {
  it('accepts IDs, enum tokens, numbers, and booleans in detail', () => {
    const evt = validAuditEvent();
    evt.detail = {
      ...evt.detail,
      count: 3,
      elevated: false,
      status: 'stepup',
    } as typeof evt.detail;
    expect(AuditEventSchema.safeParse(evt).success).toBe(true);
  });

  it.each([
    ['free text with spaces', 'John Smith'],
    ['an email address', 'alice@example.com'],
    ['a long blob', 'x'.repeat(200)],
    ['empty string', ''],
  ])('rejects %s as a detail value', (_label, value) => {
    const evt = validAuditEvent();
    evt.detail = { ...evt.detail, leaked: value } as unknown as typeof evt.detail;
    expect(AuditEventSchema.safeParse(evt).success).toBe(false);
  });

  it('rejects unknown actions (catalog is closed)', () => {
    const evt = { ...validAuditEvent(), action: 'made.up.action' };
    expect(AuditEventSchema.safeParse(evt).success).toBe(false);
  });

  it('rejects non-token resource types', () => {
    const evt = { ...validAuditEvent(), resourceType: 'user profile row' };
    expect(AuditEventSchema.safeParse(evt).success).toBe(false);
  });
});

describe('auth event schemas', () => {
  it('accepts a valid login event and discriminates by type', () => {
    const evt = {
      eventId: randomUUID(),
      type: 'auth.login.succeeded' as const,
      version: 1 as const,
      occurredAt: new Date().toISOString(),
      actor: { id: randomUUID(), type: 'user' as const },
      payload: { userId: randomUUID(), sessionId: randomUUID(), mfaLevel: 'mfa' as const },
    };
    expect(LoginSucceededEvent.safeParse(evt).success).toBe(true);
    const parsed = AuthEventSchema.parse(evt);
    expect(parsed.type).toBe('auth.login.succeeded');
  });

  it('rejects payloads with extra PII-bearing shapes only when invalid types are used', () => {
    const evt = {
      eventId: randomUUID(),
      type: 'auth.login.succeeded',
      version: 1,
      occurredAt: new Date().toISOString(),
      actor: { id: randomUUID(), type: 'user' },
      payload: { userId: 'not-a-uuid', sessionId: randomUUID(), mfaLevel: 'mfa' },
    };
    expect(AuthEventSchema.safeParse(evt).success).toBe(false);
  });
});
