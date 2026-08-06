import type {
  NotificationKind,
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

export interface LinkNotificationPort {
  /** Identifies the adapter in the audit detail. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. Redemption REFUSES in
   * production behind an adapter that does not — the vault's
   * `deliversToRealChannels` rule, for the same reason: a control whose only
   * output is a message nobody receives is not a control.
   */
  readonly deliversToRealChannels: boolean;
  notify(notification: LinkClaimedNotification): Promise<void>;
}

/**
 * Dev/test adapter. Records what would have been sent so tests can assert on it.
 * NEVER a production channel — the service checks `deliversToRealChannels`.
 */
export class StubLinkNotifier implements LinkNotificationPort {
  readonly channel = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: LinkClaimedNotification[] = [];

  notify(notification: LinkClaimedNotification): Promise<void> {
    this.sent.push(notification);
    return Promise.resolve();
  }
}

const WIRE_KIND: NotificationKind = 'contact.link_claimed';

/**
 * The real adapter: delegates to the notifications service, which owns address
 * resolution and the closed template registry — this service still never sees an
 * address. Throws on non-delivery so the caller records the failure; it never
 * rolls the link back, because a notification failure must not undo the state
 * change it describes (the M6 design).
 */
export class HttpLinkNotifier implements LinkNotificationPort {
  readonly channel = 'email';
  readonly deliversToRealChannels = true;

  constructor(private readonly client: NotificationsClientPort) {}

  async notify(notification: LinkClaimedNotification): Promise<void> {
    const outcome = await this.client.send({
      userId: notification.ownerUserId,
      kind: WIRE_KIND,
      channel: 'email',
    });
    if (!outcome.accepted || !outcome.delivered) {
      throw new Error('link-claimed notification was not delivered');
    }
  }
}
