/**
 * THE ADDRESS-CHANGE AUDIT EMITTERS (M17 PR4), and what each may carry.
 *
 * The property under test is the PII firewall, not the plumbing: every detail
 * value is an enum token or a stringified count, never an address, never a
 * code, and the refusal event carries NO reason (the M14 PR1 rule — a trail
 * that named which refusal fired would be a progress meter for whoever is
 * guessing at a pending change). The throttle event carries no actor at all,
 * because the destination never resolved to anybody.
 */
import { EventsService } from '../src/events.service';
import type { AuditProducer } from '@estate/audit-emitter';

interface Emitted {
  action: string;
  actorId: string | null;
  detail: Record<string, string>;
}

function makeEvents(): { events: EventsService; emitted: Emitted[] } {
  const emitted: Emitted[] = [];
  // The REAL AuditEmitter runs (its schema validation included — a detail
  // value that broke the token grammar would throw here); only the transport
  // is a double, recording what would have crossed the broker.
  const producer: AuditProducer = {
    send: (message: { value: string }): Promise<void> => {
      const event = JSON.parse(message.value) as Emitted & { detail?: Record<string, string> };
      emitted.push({ action: event.action, actorId: event.actorId, detail: event.detail ?? {} });
      return Promise.resolve();
    },
  };
  return { events: new EventsService(producer, () => new Date('2026-08-13T12:00:00Z')), emitted };
}

const USER = 'b6c9a1de-0000-4000-8000-000000000042';

describe('the email-change audit events', () => {
  it('request/complete carry outcome tokens and counts — never an address, never a code', async () => {
    const { events, emitted } = makeEvents();
    await events.emailChangeRequested(USER, true);
    await events.emailChangeRequested(USER, false);
    await events.emailChangeCompleted(USER, {
      revokedSessions: 3,
      oldNotified: true,
      recipientReplaced: false,
    });

    expect(emitted.map((e) => [e.action, e.detail])).toEqual([
      ['auth.email.change_requested', { delivered: 'delivered' }],
      ['auth.email.change_requested', { delivered: 'failed' }],
      [
        'auth.email.change_completed',
        { revokedSessions: '3', oldNotified: 'delivered', recipientReplaced: 'failed' },
      ],
    ]);
    // The firewall itself, asserted rather than implied: every value in every
    // detail is drawn from a closed token set or is a stringified integer.
    for (const e of emitted) {
      for (const value of Object.values(e.detail)) {
        expect(value).toMatch(/^(delivered|failed|replaced|\d+)$/);
      }
    }
  });

  it('the refusal carries an actor and NO reason; the throttle carries neither', async () => {
    const { events, emitted } = makeEvents();
    await events.emailChangeFailed(USER);
    await events.emailChangeDenied(USER);
    await events.emailChangeCancelled(USER);
    await events.emailChangeThrottled();

    expect(emitted.map((e) => [e.action, e.actorId, e.detail])).toEqual([
      ['auth.email.change_failed', USER, {}],
      ['auth.email.change_denied', USER, {}],
      ['auth.email.change_cancelled', USER, {}],
      // No actor: the destination never resolved to anybody, and naming one
      // would make the trail say something about a person who may not exist.
      ['auth.email.change_throttled', null, {}],
    ]);
  });
});
