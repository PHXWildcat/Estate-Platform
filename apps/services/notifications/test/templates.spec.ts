import {
  ESTATE_NOTIFICATION_KINDS,
  NOTIFICATION_KINDS,
  SYSTEM_NOTIFICATION_KINDS,
} from '@estate/notifications-client';
import { render, renderAddressVerification, SUBJECT } from '../src/templates';

/**
 * The two body sources, so every property below is asserted over BOTH and a
 * template that escapes the doctrine by living on the other function cannot.
 * Derived from the wire constants rather than listed, and the first test pins
 * that the two sets together are exactly NOTIFICATION_KINDS — otherwise a
 * third category could appear with no coverage at all.
 */
const CODE = 'EV1-K7MN-0000-0000-0000-0000-0000-0000-0000';
const ALL_BODIES: ReadonlyArray<{ label: string; body: (deadline: Date | null) => string }> = [
  ...ESTATE_NOTIFICATION_KINDS.map((kind) => ({
    label: kind,
    body: (deadline: Date | null): string => render(kind, deadline).body,
  })),
  {
    label: 'identity.address_verification',
    body: (): string => renderAddressVerification(CODE).body,
  },
];

const DEADLINE = new Date('2026-08-09T17:30:00.000Z');

describe('the template registry (docs/03 §5.4 — content-free pointers)', () => {
  it('covers every wire kind across both body sources', () => {
    // The estate kinds and the system kinds together ARE the wire enum: a
    // third category would otherwise be invisible to every assertion here.
    expect([...ESTATE_NOTIFICATION_KINDS, ...SYSTEM_NOTIFICATION_KINDS].sort()).toEqual(
      [...NOTIFICATION_KINDS].sort(),
    );
    expect(ALL_BODIES).toHaveLength(NOTIFICATION_KINDS.length);
    for (const { body } of ALL_BODIES) {
      expect(body(null).length).toBeGreaterThan(20);
    }
  });

  it('keeps every code-bearing kind OUT of the estate send vocabulary', () => {
    // The two sets must be DISJOINT. `render` is typed over the estate kinds
    // alone so the compiler is the real fence, but the property worth pinning
    // at runtime is the one that makes the fence meaningful: nothing a
    // send-credential holder can name reaches a template that needs a code, so
    // no holder of that broadly-held secret can mail "enter this code:
    // undefined". Derived from the constants, so a kind moved between them
    // fails here rather than silently widening the send route.
    const estate = new Set<string>(ESTATE_NOTIFICATION_KINDS);
    for (const kind of SYSTEM_NOTIFICATION_KINDS) {
      expect(estate.has(kind)).toBe(false);
    }
  });

  it('states the code, and says what to do with it without linking anywhere', () => {
    const body = renderAddressVerification(CODE);
    expect(body.subject).toBe(SUBJECT);
    expect(body.body).toContain(CODE);
    // The one variable that is not a date (docs/03 §6c). It must be the WHOLE
    // code: a truncated one is worse than none, because the user would type it.
    expect(body.body).toContain('in the app');
  });

  it('uses ONE subject for every kind — a subject-line observer cannot tell them apart', () => {
    // Retitled by the M9 security review: this asserts subject uniformity and
    // nothing else. The old name claimed "a mailbox observer learns nothing
    // about which control fired", which the BODIES falsify — they name their
    // control deliberately, so that a notification is actionable. A test name
    // asserting a property the test does not check is how a false claim
    // survives review (the M8 vacuous anti-drop check, same class).
    for (const kind of ESTATE_NOTIFICATION_KINDS) {
      expect(render(kind, DEADLINE).subject).toBe(SUBJECT);
    }
    expect(renderAddressVerification(CODE).subject).toBe(SUBJECT);
  });

  it('contains no links, anywhere, ever — "we will never link you" is enforced, not drilled', () => {
    for (const { body } of ALL_BODIES) {
      const text = body(DEADLINE);
      expect(text).not.toMatch(/https?:\/\//i);
      expect(text).not.toMatch(/www\./i);
    }
  });

  it('carries the deadline as a date only — no clock precision to fingerprint a request', () => {
    const body = render('emergency.requested', DEADLINE).body;
    expect(body).toContain('2026-08-09');
    expect(body).not.toContain('17:30');
  });

  it('renders without a deadline when none applies', () => {
    const body = render('settlement.owner_contact', null).body;
    expect(body).not.toContain('until');
    expect(body).toContain('verify your identity');
  });

  it('has no unresolved placeholders — a template bug must not mail template syntax', () => {
    for (const { body } of ALL_BODIES) {
      expect(body(DEADLINE)).not.toMatch(/[{}<>$]/);
    }
  });
});
