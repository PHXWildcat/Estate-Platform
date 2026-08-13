import type { AccountSecurityKind, EstateNotificationKind } from '@estate/notifications-client';

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
 *  - ONE subject for everything. A mailbox observer scanning SUBJECT LINES
 *    learns that Estate wants attention and nothing more.
 *
 * SCOPED HONESTLY (M9 security review). That third rule covers the subject,
 * not the message. Every body below names its control in the first clause,
 * so a lock-screen body preview and the carrier itself do learn the EVENT
 * CLASS — "an emergency-access clock is running on this account", "a death
 * report was filed". That is a deliberate trade, not an oversight: a
 * context-free pointer is useless to a frightened owner who has seconds to
 * decide whether to deny, and the notification only functions as a control
 * if it says what to deny. What stays absent is everything that identifies a
 * PERSON or an ESTATE. An earlier version of this comment claimed an
 * observer never learns which control fired, which was true only of the
 * subject; docs/03 §6c now records the event-class leak as an accepted
 * residual instead of asserting the doctrine covers it.
 */

export const SUBJECT = 'Estate — action needed';

/** Format a deadline for a sentence; UTC date only, no clock precision. */
function day(deadline: Date): string {
  return deadline.toISOString().slice(0, 10);
}

const UNTIL = (deadline: Date | null): string =>
  deadline === null ? '' : ` You have until ${day(deadline)} to respond.`;

const BODIES: Record<EstateNotificationKind, (deadline: Date | null) => string> = {
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
  // M13. Names its control in the first clause like every body here, and no
  // more: not who claimed it, not which contact, not which estate.
  'contact.link_claimed': () =>
    'Someone used an invitation code to link themselves to a contact in your Estate account. If you did not send that code to them, open your Estate app and remove the link.',
};

export interface RenderedNotification {
  readonly subject: string;
  readonly body: string;
}

export function render(kind: EstateNotificationKind, deadline: Date | null): RenderedNotification {
  return { subject: SUBJECT, body: BODIES[kind](deadline) };
}

/**
 * The address-verification body (M14) — a SEPARATE function, not an entry in
 * BODIES, because it is the one message that carries a variable which is not a
 * date and `render`'s signature must stay unable to accept one.
 *
 * THE CODE IS THE APPROVED DEVIATION (docs/03 §6c). Everything else about the
 * doctrine survives verbatim and deliberately:
 *  - the code is PLATFORM-AUTHORED — identity mints it from `randomBytes` and
 *    it is never derived from anything a user or a caller wrote, so this is
 *    not a text field by another name;
 *  - it carries no estate fact, no name, no address, no identifier of any kind
 *    that outlives its few days;
 *  - NO LINK, same as every other body. The reader is told to type it into the
 *    app they already have, which is what keeps "we will never link you"
 *    literally true rather than nearly true;
 *  - the SAME subject as everything else, so a mailbox observer scanning
 *    subject lines still learns only that Estate wants attention.
 *
 * The event class does reach the carrier, as it does for every kind — here it
 * is the least sensitive one in the registry: that somebody is confirming an
 * address. It is also the only body in this file whose recipient may not be
 * the account holder, which is exactly the situation it exists to detect: a
 * stranger who receives this was typed into somebody's registration by mistake
 * or by design, and the message tells them to ignore it rather than act.
 */
export function renderAddressVerification(code: string): RenderedNotification {
  return {
    subject: SUBJECT,
    body:
      `Confirm this email address for your Estate account by entering this code in the app: ${code}. ` +
      'It expires shortly and can be used once. ' +
      // Deliberately NOT "you will not hear from us again": that would be a
      // promise this platform does not keep. An unverified address is re-asked
      // at a later login once the code lapses (bounded by the re-issue floor),
      // and until somebody proves ownership the address stays on file. What IS
      // true is that the code is worthless to whoever received it by mistake,
      // because redeeming it requires being signed in to the account.
      'If you did not create an Estate account, you can ignore this message — the code cannot be used without signing in to that account.',
  };
}

/**
 * The ACCOUNT-SECURITY bodies (M17).
 *
 * A SEPARATE Record from `BODIES`, not an addition to it, for the reason
 * `renderAddressVerification` is a separate function: `render`'s signature is
 * typed over `EstateNotificationKind`, and the estate send route's schema is
 * built from that same list, so keeping these out of it is what stops a
 * credential held by vault, settlement and profile from firing them. Total over
 * `AccountSecurityKind`, so a second security kind is a COMPILE error here
 * rather than a message nobody wrote.
 *
 * NO VARIABLES AT ALL, which is stricter than the estate bodies (they take a
 * deadline date). "Your password was changed at 14:02" would be friendlier and
 * would put a caller-chosen value in front of a reader; telling them to sign in
 * and check is both safer and the action they should take either way.
 *
 * The wording assumes the recipient may be the ATTACKER'S VICTIM rather than
 * the actor — that is the entire point of sending it — so it leads with what
 * to do if this was not them, and it does not link (the registry's no-links
 * rule, machine-checked over every body).
 */
const SECURITY_BODIES: Record<AccountSecurityKind, string> = {
  'identity.password_changed':
    'The password for your Estate account was just changed. ' +
    'If that was you, there is nothing to do. ' +
    'If it was not, open your Estate app and sign in to review your active devices and sessions — ' +
    'and if you cannot sign in, contact support.',
};

export function renderAccountSecurity(kind: AccountSecurityKind): RenderedNotification {
  return { subject: SUBJECT, body: SECURITY_BODIES[kind] };
}
