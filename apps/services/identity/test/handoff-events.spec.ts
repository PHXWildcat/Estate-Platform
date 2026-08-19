/**
 * THE HANDOFF AUDIT EMITTERS, and what each may carry (M15, widened M21 PR3a).
 *
 * The property under test is the UNIFORM REFUSAL, preserved in the audit
 * stream as well as on the wire. `auth.handoff.failed` covers unknown,
 * expired, already-spent and raced, and it must carry NO actor and NO reason —
 * a trail that named which one fired would re-create through the stream
 * exactly the oracle the uniform wire answer removes (the M14 PR1 rule).
 *
 * WHY IT IS HERE RATHER THAN IN `handoff.service.spec.ts`: the service calls a
 * zero-argument method, so no fake of it can tell a compliant emitter from a
 * chatty one. The emptiness is a property of THIS file, and the layer that owns
 * a property is the layer that must prove it. Before this spec it was asserted
 * only by the live-stack e2e, so a build with no stack could not see it.
 *
 * The REAL `AuditEmitter` runs — schema validation included — and only the
 * transport is doubled.
 */
import { EventsService } from '../src/events.service';
import type { AuditProducer } from '@estate/audit-emitter';
import { HANDOFF_AUDIENCES } from '../src/handoff.service';

interface Emitted {
  action: string;
  actorId: string | null;
  sessionId: string | null;
  /**
   * `AuditDetailValueSchema` admits a token STRING, a finite number or a
   * boolean — so this is typed to what the wire really carries rather than to
   * the string-only shape most emitters in this service happen to use. A
   * fixture that invents a narrower vocabulary tests the fixture.
   */
  detail: Record<string, string | number | boolean>;
}

function makeEvents(): { events: EventsService; emitted: Emitted[] } {
  const emitted: Emitted[] = [];
  const producer: AuditProducer = {
    send: (message: { value: string }): Promise<void> => {
      const event = JSON.parse(message.value) as Emitted & {
        detail?: Record<string, string | number | boolean>;
      };
      emitted.push({
        action: event.action,
        actorId: event.actorId,
        sessionId: event.sessionId,
        detail: event.detail ?? {},
      });
      return Promise.resolve();
    },
  };
  return { events: new EventsService(producer, () => new Date('2026-08-18T12:00:00Z')), emitted };
}

const USER = 'b6c9a1de-0000-4000-8000-000000000042';
const SESSION = 'b6c9a1de-0000-4000-8000-000000000043';

describe('the handoff audit events', () => {
  it('a REFUSAL carries no actor, no session and no reason at all', async () => {
    const { events, emitted } = makeEvents();
    await events.handoffFailed();

    expect(emitted).toHaveLength(1);
    expect(emitted[0]?.action).toBe('auth.handoff.failed');
    expect(emitted[0]?.actorId).toBeNull();
    expect(emitted[0]?.sessionId).toBeNull();
    // EXACT EQUALITY, not "does not contain a reason". A detail carrying any
    // key at all is a distinguisher, whatever it is called.
    expect(emitted[0]?.detail).toEqual({});
  });

  it.each(HANDOFF_AUDIENCES)(
    'a mint of the %s audience records the audience and the retirement, and nothing else',
    async (audience) => {
      // Derived from the vocabulary rather than listed: a third audience
      // arrives with this assertion already covering it. The audience IS the
      // fact an owner reviewing their own trail needs — it is the difference
      // between "I opened my vault" and "I opened the operator console".
      const { events, emitted } = makeEvents();
      await events.handoffMinted(USER, SESSION, { audience, retired: 1 });

      expect(emitted[0]?.action).toBe('auth.handoff.minted');
      expect(emitted[0]?.actorId).toBe(USER);
      // `retired` is a NUMBER on the wire, not a stringified count: the detail
      // schema admits string tokens, finite numbers and booleans, and this
      // emitter uses the second. Asserted as measured rather than as the
      // stringified shape most of this service's emitters happen to use.
      expect(emitted[0]?.detail).toEqual({ audience, retired: 1 });
    },
  );

  it.each(HANDOFF_AUDIENCES)(
    'a redemption of the %s audience is attributed, and names no code',
    async (audience) => {
      const { events, emitted } = makeEvents();
      await events.handoffRedeemed(USER, SESSION, { audience });

      expect(emitted[0]?.action).toBe('auth.handoff.redeemed');
      expect(emitted[0]?.actorId).toBe(USER);
      expect(emitted[0]?.detail).toEqual({ audience });
    },
  );

  it('no handoff event carries anything but enum tokens and counts', async () => {
    // The PII firewall restated for this family: the code, its digest and the
    // origin it was minted for are all absent by construction, and this is the
    // assertion that would notice one arriving.
    const { events, emitted } = makeEvents();
    await events.handoffMinted(USER, SESSION, { audience: 'operator', retired: 0 });
    await events.handoffRedeemed(USER, SESSION, { audience: 'operator' });
    await events.handoffFailed();

    for (const e of emitted) {
      for (const [key, value] of Object.entries(e.detail)) {
        // Every value is a closed-vocabulary token or a count. A code, a
        // digest or an origin would all fail this, and so would free text.
        expect(`${e.action}.${key}=${typeof value}:${String(value)}`).toMatch(
          /^[a-z0-9_.]+=(?:string:[a-z_]+|number:\d+|boolean:(?:true|false))$/,
        );
      }
    }
  });
});
