import type { AuditEvent } from '@estate/contracts';
import { canonicalize } from '../src/canonical';
import { makeEvent } from './helpers';

describe('canonicalize', () => {
  it('is independent of object key insertion order', () => {
    const base = makeEvent();
    // Same entries, deliberately different insertion order (top level and
    // inside detail).
    const a: AuditEvent = {
      eventId: base.eventId,
      occurredAt: base.occurredAt,
      action: base.action,
      actorId: base.actorId,
      actorType: base.actorType,
      onBehalfOf: null,
      resourceType: base.resourceType,
      resourceId: base.resourceId,
      sessionId: base.sessionId,
      detail: { alpha: 'a1', beta: 2, gamma: true },
    };
    const b: AuditEvent = {
      detail: { gamma: true, alpha: 'a1', beta: 2 },
      sessionId: base.sessionId,
      resourceId: base.resourceId,
      resourceType: base.resourceType,
      onBehalfOf: null,
      actorType: base.actorType,
      actorId: base.actorId,
      action: base.action,
      occurredAt: base.occurredAt,
      eventId: base.eventId,
    };
    expect(canonicalize(a).equals(canonicalize(b))).toBe(true);
  });

  it('sorts keys recursively in nested objects', () => {
    const event = makeEvent({ detail: { zeta: 1, alpha: 2, mid: 3 } });
    const text = canonicalize(event).toString('utf8');
    expect(text).toContain('"detail":{"alpha":2,"mid":3,"zeta":1}');
    // Top-level keys sorted too: "action" before "actorId" before "detail".
    expect(text.indexOf('"action"')).toBeLessThan(text.indexOf('"actorId"'));
    expect(text.indexOf('"actorType"')).toBeLessThan(text.indexOf('"detail"'));
  });

  it('encodes unicode as raw UTF-8 bytes, deterministically', () => {
    // canonicalize does not enforce the PII token pattern (the schema does);
    // it must still be byte-deterministic for any string content.
    const event = makeEvent({ detail: { token: 'café-日本' } });
    const a = canonicalize(event);
    const b = canonicalize({ ...event, detail: { ...event.detail } });
    expect(a.equals(b)).toBe(true);
    // 'é' = 0xC3 0xA9 in UTF-8 — raw bytes, not \u escapes.
    expect(a.includes(Buffer.from([0xc3, 0xa9]))).toBe(true);
    expect(a.toString('utf8')).not.toContain('\\u');
  });

  it('emits no whitespace between tokens', () => {
    const text = canonicalize(makeEvent({ detail: { a: 1, b: 'x' } })).toString('utf8');
    expect(text).not.toMatch(/\s/);
  });

  it('encodes nulls explicitly', () => {
    const text = canonicalize(makeEvent({ actorId: null, sessionId: null })).toString('utf8');
    expect(text).toContain('"actorId":null');
    expect(text).toContain('"sessionId":null');
  });

  it('rejects non-finite numbers instead of silently coercing', () => {
    const event = makeEvent({ detail: { bad: Number.POSITIVE_INFINITY } });
    expect(() => canonicalize(event)).toThrow('non-finite');
  });
});
