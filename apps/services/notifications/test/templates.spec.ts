import { NOTIFICATION_KINDS } from '@estate/notifications-client';
import { render, SUBJECT } from '../src/templates';

const DEADLINE = new Date('2026-08-09T17:30:00.000Z');

describe('the template registry (docs/03 §5.4 — content-free pointers)', () => {
  it('covers every wire kind', () => {
    for (const kind of NOTIFICATION_KINDS) {
      const rendered = render(kind, null);
      expect(rendered.body.length).toBeGreaterThan(20);
    }
  });

  it('uses ONE subject for every kind — a subject-line observer cannot tell them apart', () => {
    // Retitled by the M9 security review: this asserts subject uniformity and
    // nothing else. The old name claimed "a mailbox observer learns nothing
    // about which control fired", which the BODIES falsify — they name their
    // control deliberately, so that a notification is actionable. A test name
    // asserting a property the test does not check is how a false claim
    // survives review (the M8 vacuous anti-drop check, same class).
    for (const kind of NOTIFICATION_KINDS) {
      expect(render(kind, DEADLINE).subject).toBe(SUBJECT);
    }
  });

  it('contains no links, anywhere, ever — "we will never link you" is enforced, not drilled', () => {
    for (const kind of NOTIFICATION_KINDS) {
      const body = render(kind, DEADLINE).body;
      expect(body).not.toMatch(/https?:\/\//i);
      expect(body).not.toMatch(/www\./i);
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
    for (const kind of NOTIFICATION_KINDS) {
      const body = render(kind, DEADLINE).body;
      expect(body).not.toMatch(/[{}<>$]/);
    }
  });
});
