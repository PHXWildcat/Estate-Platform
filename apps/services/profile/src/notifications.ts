import type {
  EstateNotificationKind,
  NotificationsPort as NotificationsClientPort,
} from '@estate/notifications-client';

/**
 * The owner-notification port for the contact link ceremony (M13 PR3).
 *
 * ONE KIND, ONE DIRECTION. The owner is told when somebody CLAIMS a link to
 * their estate, and that is the whole surface. It is not decoration: a claim is
 * the moment a person acquires the ability to open a death case against this
 * owner (docs/03 §6b) and to exercise any grant attached to that contact, so a
 * claim nobody hears about is how a code that went to the wrong person becomes
 * an invisible authorization edge. The notification is what makes the ceremony's
 * trust anchor — the owner's own out-of-band channel — auditable by the owner
 * rather than only by us.
 *
 * The REDEEMER is deliberately not notified. They performed the act; telling
 * them adds nothing, and an unsolicited message to a user who typed a wrong code
 * would leak that the code belonged to someone.
 *
 * Content-free like every other notification (docs/03 §5.4 and risk #10): no
 * contact name, no estate identifier, no link. The notifications service owns
 * the wording and the address; this service never sees either.
 */

export interface LinkClaimedNotification {
  /** The estate owner — never the redeemer. */
  readonly ownerUserId: string;
}

/** What a send actually did (M14); the vault/settlement shape. */
export interface NotifyOutcome {
  readonly delivered: boolean;
  /** Whether the owner had PROVED the address it went to. */
  readonly recipientVerified: boolean;
}

export interface LinkNotificationPort {
  /** Identifies the adapter in the audit detail. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. Redemption REFUSES in
   * production behind an adapter that does not — the vault's
   * `deliversToRealChannels` rule, for the same reason: a control whose only
   * output is a message nobody receives is not a control.
   *
   * It is a property of the ADAPTER. `recipientVerified` below is the question
   * about the RECIPIENT that M14 exists to make askable.
   */
  readonly deliversToRealChannels: boolean;
  /**
   * Whether the delivery store holds an address this owner PROVED (M14). Fail
   * closed: unanswerable is `false`.
   *
   * Read by MINTING, not by redemption. Minting hands out a capability that
   * ends in a §5.1 authorization edge and the actor is the owner themselves, so
   * refusing costs them an action they can unblock by verifying. Redemption is
   * driven by the CONTACT, so refusing there would let an owner's own typo
   * permanently deny somebody they deliberately invited.
   */
  recipientVerified(ownerUserId: string): Promise<boolean>;
  notify(notification: LinkClaimedNotification): Promise<NotifyOutcome>;
}

/**
 * Dev/test adapter. Records what would have been sent so tests can assert on it.
 * NEVER a production channel — the service checks `deliversToRealChannels`.
 */
export class StubLinkNotifier implements LinkNotificationPort {
  readonly channel = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: LinkClaimedNotification[] = [];

  /** False, never true — a stub must not vouch for anything (M8's rule). */
  recipientVerified(): Promise<boolean> {
    return Promise.resolve(false);
  }

  notify(notification: LinkClaimedNotification): Promise<NotifyOutcome> {
    this.sent.push(notification);
    return Promise.resolve({ delivered: true, recipientVerified: false });
  }
}

// ESTATE kinds only (M14). Typing this as the narrower union means a sending
// service structurally cannot name the address-verification kind, which is the
// mirror of `SendSchema` refusing it on the wire.
const WIRE_KIND: EstateNotificationKind = 'contact.link_claimed';

/**
 * The real adapter: delegates to the notifications service, which owns address
 * resolution and the closed template registry — this service still never sees an
 * address. M14 stopped it throwing on non-delivery: the caller already recorded
 * that outcome (`ownerNotified: 'failed'`, the vault delivered_at-NULL
 * precedent), and an exception cannot carry the second fact a send now returns.
 * It never rolls the link back either way: a notification failure must not undo
 * the state change it describes (the M6 design), it must be VISIBLE instead.
 */
export class HttpLinkNotifier implements LinkNotificationPort {
  readonly channel = 'email';
  readonly deliversToRealChannels = true;

  constructor(private readonly client: NotificationsClientPort) {}

  async recipientVerified(ownerUserId: string): Promise<boolean> {
    const status = await this.client.recipientStatus(ownerUserId);
    return status?.verified === true;
  }

  async notify(notification: LinkClaimedNotification): Promise<NotifyOutcome> {
    const outcome = await this.client.send({
      userId: notification.ownerUserId,
      kind: WIRE_KIND,
      channel: 'email',
    });
    if (!outcome.accepted) {
      return { delivered: false, recipientVerified: false };
    }
    return { delivered: outcome.delivered, recipientVerified: outcome.recipientVerified };
  }
}
