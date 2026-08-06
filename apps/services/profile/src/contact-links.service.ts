import { createHash, randomBytes } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { coreResource, ProfileAuthz } from './authz.service';
import { ContactsRepo } from './contacts.repo';
import { ContactLinksRepo, InvitationRaceError, MAX_REDEEM_ATTEMPTS } from './contact-links.repo';
import { CLOCK, CONFIG, LINK_NOTIFIER, type Clock } from './di-tokens';
import type { ProfileConfig } from './config';
import { EventsService } from './events.service';
import type { LinkNotificationPort } from './notifications';

/** How long a code the owner was told once stays usable. */
export const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** What the owner is shown, exactly once. */
export interface MintedInvitation {
  code: string;
  expiresAt: string;
}

/**
 * THE CONTACT LINK CEREMONY (M13 PR3).
 *
 * `contacts.linked_user_id` is an authorization edge — being a linked contact is
 * what makes someone able to open a death case (docs/03 §6b) and what makes an
 * executor resolvable (M7) — and until now it had no write path anywhere. This
 * is that path, and every choice in it inherits that control's weight.
 *
 * OWNER-INITIATED, OUT OF BAND, ONE-SHOT. The owner mints a code under step-up;
 * the server stores only its sha256; the owner is shown it ONCE and delivers it
 * however they already talk to this person (the M6 grantee-fingerprint
 * precedent). The contact redeems it while authenticated on THEIR OWN existing
 * account. Consequences, each deliberate:
 *
 *  - NOTHING HERE HANDLES AN ADDRESS, so M9's shipped doctrine (no content, no
 *    links, recipients addressed by user id alone) is untouched. An emailed
 *    invite would have contradicted a decision made one milestone ago.
 *  - THE CODE IS THE ONLY SELECTOR on redemption. There is no lookup by email or
 *    by user id, so redemption cannot be turned into an oracle for whether an
 *    account exists — which is the property docs/03 §6b credits for intake
 *    being unable to enumerate.
 *  - THE REDEEMER MUST ALREADY HAVE AN ACCOUNT. This is not an
 *    invite-to-register flow and cannot be used to create one.
 *
 * WHAT THE OWNER'S CHANNEL BUYS, AND WHAT IT COSTS. The trust anchor is the
 * owner's own out-of-band channel, exactly as in M6: an owner who sends the code
 * to the wrong person links the wrong person. That is detectable rather than
 * prevented — the claim is audited on both sides, notified to the owner, and
 * visible in their contact list — and unlinking is one click.
 *
 * EVERY REDEMPTION FAILURE IS THE SAME REFUSAL. Expired, spent, revoked,
 * unknown, self-directed, already-linked: all `invalid_code`. Distinguishing
 * them would tell whoever is holding a guess that their guess named something
 * real. The cost is a less helpful message for a legitimate user, paid down by
 * letting the owner re-issue freely.
 */
@Injectable()
export class ContactLinksService {
  constructor(
    private readonly links: ContactLinksRepo,
    private readonly contacts: ContactsRepo,
    private readonly authz: ProfileAuthz,
    private readonly events: EventsService,
    @Inject(LINK_NOTIFIER) private readonly notifier: LinkNotificationPort,
    @Inject(CONFIG) private readonly config: ProfileConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /**
   * Mint a single-use code for one of the owner's contacts. STEP-UP GATED at the
   * controller: this hands out a capability that ends in a §5.1-relevant
   * authorization edge, which puts it in the same class as naming a fiduciary.
   */
  async invite(callerUserId: string, contactId: string): Promise<MintedInvitation> {
    this.authz.assertCan(callerUserId, 'manage', coreResource('Contact', contactId, callerUserId));
    const contact = await this.contacts.findById(contactId);
    if (!contact || contact.owner_user_id !== callerUserId) {
      throw new NotFoundException({ error: 'not_found' });
    }
    if (contact.linked_user_id !== null) {
      // Nothing to invite: re-linking a linked contact would silently move an
      // authorization edge from one person to another.
      throw new ConflictException({ error: 'already_linked' });
    }

    // 160 bits, base32-ish so it can be read aloud down a phone line without
    // case or homoglyph ambiguity — the channel this ceremony assumes.
    const code = readableCode();
    const retired = await this.links.revokeLive(callerUserId, contactId);
    if (retired !== null) {
      // Re-issuing is normal (the owner was told once and may have lost it), but
      // the retirement is still recorded — a code that stopped working is a fact
      // an investigation may need.
      await this.events.contactLinkInvitationRevoked(callerUserId, contactId);
    }
    const expiresAt = new Date(this.clock().getTime() + INVITATION_TTL_MS);
    await this.links.insert({
      ownerUserId: callerUserId,
      contactId,
      codeSha256: sha256(code),
      expiresAt,
    });
    await this.events.contactLinkInvited(callerUserId, contactId);
    return { code, expiresAt: expiresAt.toISOString() };
  }

  /** Withdraw an unredeemed code. NOT step-up gated — see the controller. */
  async revokeInvitation(callerUserId: string, contactId: string): Promise<void> {
    this.authz.assertCan(callerUserId, 'manage', coreResource('Contact', contactId, callerUserId));
    const retired = await this.links.revokeLive(callerUserId, contactId);
    if (retired === null) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.contactLinkInvitationRevoked(callerUserId, contactId);
  }

  /**
   * Redeem a code, as the person being linked.
   *
   * THE AUTHORITY HERE IS THE CAPABILITY, NOT A POLICY, and that is the one
   * place in this service where no Cedar decision is taken. It is not an
   * omission: the redeemer has no relationship to the estate until this
   * succeeds, so there is nothing for a policy to decide about them — every
   * attribute a policy could match on is exactly what the code is standing in
   * for. Recorded as a deliberate deviation in docs/03 §6g rather than papered
   * over with a decision that would always be `deny` until it was `allow`.
   *
   * The route returns NOTHING about the estate — not the owner's id, not the
   * contact's name — because a stolen code must not become a read.
   */
  async redeem(callerUserId: string, code: string): Promise<void> {
    // Notifications are a PRECONDITION in production, on the M6/M7/M9 rule: a
    // link claimed silently is how somebody who obtained a code acquires a
    // §5.1 reporter capability without the owner ever hearing about it. The
    // notification IS the control here, so it gates the act.
    if (this.config.nodeEnv === 'production' && !this.notifier.deliversToRealChannels) {
      await this.events.contactLinkNotificationsRefused(callerUserId);
      throw new ServiceUnavailableException({ error: 'notifications_unavailable' });
    }

    const invitation = await this.links.findByCode(sha256(code));
    const now = this.clock();
    if (
      invitation === null ||
      invitation.redeemed_at !== null ||
      invitation.revoked_at !== null ||
      invitation.expires_at <= now ||
      invitation.attempts >= MAX_REDEEM_ATTEMPTS ||
      // Linking yourself to your own contact would make you eligible to report
      // your own death (settlement's `isLinkedContact`) — a self-referential
      // path with no second party in it.
      invitation.owner_user_id === callerUserId
    ) {
      if (invitation !== null) {
        // Only a REAL invitation has an attempt counter to move. An unknown code
        // leaves no trace by construction, which is also why the counter is a
        // bound on attacking a live code rather than a general rate limit.
        await this.links.countAttempt(invitation.id);
      }
      throw new BadRequestException({ error: 'invalid_code' });
    }

    let linked: boolean;
    try {
      linked = await this.links.redeem({
        invitationId: invitation.id,
        contactId: invitation.contact_id,
        redeemedBy: callerUserId,
        now,
      });
    } catch (err) {
      if (err instanceof InvitationRaceError) {
        // Rolled back: the invitation is still live, and the refusal is the same
        // one an unknown code gets.
        throw new BadRequestException({ error: 'invalid_code' });
      }
      throw err;
    }
    if (!linked) {
      throw new BadRequestException({ error: 'invalid_code' });
    }

    // THE NOTIFY RUNS FIRST, AND ITS OUTCOME IS RECORDED — both halves are the
    // M13 security review's confirmed finding, fixed here.
    //
    // First, because the audit emit below PROPAGATES broker failures (the M8
    // rule: a dead audit trail must be loud), and the original ordering let
    // exactly that loudness skip the owner notification: a broker blip after
    // the commit exited this method with the link standing, the owner untold,
    // and — the code being spent — no retry that would ever tell them. The
    // notification is the control that makes the ceremony's out-of-band trust
    // anchor auditable BY THE OWNER (docs/03 §6g), so an audit hiccup must not
    // be able to cancel it. The invitation row itself (redeemed_by/redeemed_at)
    // is the durable record of the claim; the audit event mirrors it.
    //
    // Second, the outcome: a notification failure still never rolls back the
    // link (the M6 design), but it is no longer silent — `ownerNotified` rides
    // the claim event as an enum, the M6/M9 precedent of vault recording
    // delivered_at NULL per send. A 'failed' here is the operator's signal to
    // re-drive the notification; without it, a mis-delivered code becoming an
    // invisible authorization edge — the outcome §6g's production precondition
    // exists to prevent — left no record anywhere when the send failed at the
    // network rather than at the carrier.
    let ownerNotified: 'delivered' | 'failed' = 'failed';
    try {
      await this.notifier.notify({ ownerUserId: invitation.owner_user_id });
      ownerNotified = 'delivered';
    } catch {
      // Recorded on the claim event below; the link stands either way.
    }
    // AUDITED ON BOTH SIDES: the owner's trail records that their contact was
    // claimed, the actor recorded is the redeemer, and the delivery outcome
    // rides along — so "who linked themselves to whose estate, and was the
    // owner told" is answerable from either end.
    await this.events.contactLinkClaimed(callerUserId, invitation.contact_id, ownerNotified);
  }

  /**
   * Remove a link. NOT step-up gated: this is the purely protective direction —
   * it takes an authorization edge AWAY — and the M6 rule is that a protective
   * action must never be harder than the permissive one that created it.
   *
   * It does cost something real: unlinking the owner's only linked contact
   * removes the one person who could report their death or rescue a §5.1 case.
   * That is the owner's decision to make, and making them find an authenticator
   * first would mean an owner who wants somebody out of their estate cannot act
   * from the session in front of them.
   */
  async unlink(callerUserId: string, contactId: string): Promise<void> {
    this.authz.assertCan(callerUserId, 'manage', coreResource('Contact', contactId, callerUserId));
    const removed = await this.links.unlink(callerUserId, contactId);
    if (!removed) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.events.contactLinkRemoved(callerUserId, contactId);
  }
}

function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * A 160-bit code in Crockford-style base32 (no I, L, O or U), grouped for
 * reading aloud: `ESL1-K7MN-…`. The alphabet matters because the delivery
 * channel this ceremony assumes is a person reading it to another person.
 *
 * THE WIDTH IS THE SECURITY PARAMETER, so it is derived, not asserted: 20 bytes
 * expanded at 5 bits per character is 32 characters exactly, and the spec pins
 * both the count and the derivation. The first implementation mapped one
 * character per BYTE — throwing away 3 bits each for a real width of 100 —
 * which is the M6 grantee-fingerprint defect (50 bits where the spec said 80)
 * reproduced move for move, and it was caught the same way: by looking at a
 * real code the running system minted.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const CODE_RANDOM_BYTES = 20;

function readableCode(): string {
  const bytes = randomBytes(CODE_RANDOM_BYTES);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >> bits) & 31];
    }
  }
  // 160 % 5 === 0, so nothing is left over; assert rather than assume.
  if (bits !== 0 || out.length !== (CODE_RANDOM_BYTES * 8) / 5) {
    throw new Error('link code derivation is broken');
  }
  return `ESL1-${(out.match(/.{1,4}/g) ?? []).join('-')}`;
}
