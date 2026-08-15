/**
 * The faithful notifications double (M20 PR0).
 *
 * WHY THIS EXISTS: the defect this PR fixes — three identity call sites
 * recording an undelivered mail as `delivered` in the append-only trail — was
 * invisible to every test in this directory, because every spec hand-rolled
 * its own double and NOT ONE of the twelve producing an outcome ever answered
 * on the arm where the discriminant and the answer disagree.
 *
 * MEASURED, because the first draft of this comment claimed something stronger
 * and false ("every one returned `{ accepted: true }`"): of 38 specs here, 13
 * name `accepted` and 12 produce an outcome. Four answered a bare
 * `{ accepted: true }`, which is not a valid `SendOutcome` at all — the
 * union's accepted arm carries `delivered`, `channel` and `recipientVerified`
 * too. But THREE produced fully valid four-field outcomes and were just as
 * uncheckable, which is the better point: validity of the literal was never
 * the mechanism. Every one of them was `delivered: true`. The gap the tests
 * could not see was not a malformed shape, it was an UNEXERCISED ARM.
 *
 * A DOUBLE MORE GENEROUS THAN THE PLATFORM IS WHERE THE BUG LIVES — the M16
 * PR2b lesson (`chrome-double.ts` supplied `getManifest` unconditionally, so
 * jsdom could not see that an offscreen document has no such method, and the
 * extension shipped unable to unlock a vault). Here the generosity was that
 * every simulated send SUCCEEDED, so a production read of `outcome.accepted`
 * scored true in every test that ever ran.
 *
 * So the outcomes are CONSTANTS TYPED AS `SendOutcome`, and the annotation on
 * each constant is the real check — it is the ONE place no cast intervenes. The
 * doubles themselves reach a constructor through `as never` or
 * `as unknown as NotificationsPort`, and a cast on the outer object leaves the
 * inner method's return type inferred and never compared to the port, so the
 * compiler alone could not have caught this and cannot be relied on to.
 *
 * `packages/notifications-client/test/delivery-outcome.spec.ts` is what keeps
 * it true: it forbids a hand-rolled `accepted:` literal anywhere in this
 * directory, so the next spec reaches for these rather than inventing a fourth
 * vocabulary, and it asserts these four constants carry the annotation.
 */
import type { SendOutcome } from '@estate/notifications-client';

/** The mail went. */
export const DELIVERED: SendOutcome = {
  accepted: true,
  delivered: true,
  channel: 'email',
  recipientVerified: true,
};

/**
 * The service ANSWERED and could not deliver — `no_recipient` (M9's recipient
 * feed is fire-and-forget, so a registration during a notifications outage
 * leaves no row) or `carrier_failure` (SES refused; a crypto-shredded DEK lands
 * here too). This is the outcome the three defective reads scored as a
 * delivery, and no spec in this directory could produce it before now.
 */
export const UNDELIVERED: SendOutcome = {
  accepted: true,
  delivered: false,
  channel: 'email',
  recipientVerified: false,
};

/** Delivered, to an address the user never proved (M14). */
export const DELIVERED_UNVERIFIED: SendOutcome = {
  accepted: true,
  delivered: true,
  channel: 'email',
  recipientVerified: false,
};

/** The request never reached a healthy service: unwired credential, network, non-2xx. */
export const UNREACHABLE: SendOutcome = { accepted: false };
