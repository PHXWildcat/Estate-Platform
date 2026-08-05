import type { NotificationKind } from '@estate/notifications-client';

/**
 * The template registry: the ONLY source of carrier-visible words in the
 * platform, enforced by the closed kind enum on the wire (docs/03 §5.4 and
 * risk #10 — emails are content-free pointers).
 *
 * Three rules, each load-bearing:
 *  - NO user data. Not a name, not an asset, not a document title. The only
 *    variable is the deadline date the M6/M7 ports already carry.
 *  - NO links. Role-holder onboarding drills "we will never link you to a
 *    payment page"; the strongest form of that promise is never linking at
 *    all. Every body says "open your Estate app" and stops.
 *  - ONE subject for everything. A mailbox observer (or a shoulder-surfer at
 *    a lock screen) learns that Estate wants attention, never WHICH control is
 *    running — the delivery-channel identifier-leakage posture the M6 review
 *    asked this milestone to carry.
 */

export const SUBJECT = 'Estate — action needed';

/** Format a deadline for a sentence; UTC date only, no clock precision. */
function day(deadline: Date): string {
  return deadline.toISOString().slice(0, 10);
}

const UNTIL = (deadline: Date | null): string =>
  deadline === null ? '' : ` You have until ${day(deadline)} to respond.`;

const BODIES: Record<NotificationKind, (deadline: Date | null) => string> = {
  'emergency.requested': (d) =>
    `Someone you designated has asked for emergency access to your Estate vault. If you did not expect this, open your Estate app and deny the request — one tap stops it.${UNTIL(d)}`,
  'emergency.blocked': () =>
    'An emergency-access request on your Estate vault was blocked. Nothing was released. Open your Estate app to review.',
  'emergency.reminder': (d) =>
    `An emergency-access request on your Estate vault is still waiting. If you did not expect this, open your Estate app and deny it.${UNTIL(d)}`,
  'emergency.released': () =>
    'Emergency access to your Estate vault was released to a designated contact. Open your Estate app to review the full record.',
  'emergency.revoked': () =>
    'An emergency-access arrangement on your Estate vault was revoked. Open your Estate app to review.',
  'vault.reset': () =>
    'Your Estate vault was reset. Everything previously stored in it is now unrecoverable. If you did not do this, open your Estate app and review your security settings immediately.',
  'vault.grantees_changed': () =>
    'The emergency contacts for your Estate vault changed, and previous arrangements were retired. If you did not make this change, open your Estate app and review it.',
  'settlement.case_opened': (d) =>
    `A report was filed on your Estate account. If you are reading this, open your Estate app and verify your identity — that stops the process immediately.${UNTIL(d)}`,
  'settlement.owner_contact': (d) =>
    `Your Estate account is in a review period. Open your Estate app and verify your identity to stop it.${UNTIL(d)}`,
};

export interface RenderedNotification {
  readonly subject: string;
  readonly body: string;
}

export function render(kind: NotificationKind, deadline: Date | null): RenderedNotification {
  return { subject: SUBJECT, body: BODIES[kind](deadline) };
}
