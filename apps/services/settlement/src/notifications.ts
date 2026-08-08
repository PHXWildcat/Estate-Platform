import type {
  EstateNotificationKind,
  NotificationsPort as NotificationsClientPort,
} from '@estate/notifications-client';

/**
 * The owner-notification port for settlement (docs/03 §5.1 control 3).
 *
 * The waiting period only protects an owner who finds out a death report is
 * pending against their account, so notification is not a nicety attached to
 * this flow - it IS the flow's safety property. The service treats a missing
 * channel as a reason to refuse intake rather than a reason to proceed
 * quietly (the M6 emergency-access precedent).
 *
 * Notifications are content-free by design (docs/03 §5.4: all settlement
 * communication happens in-app; email/SMS carry only pointers). Nothing about
 * the reporter, the evidence, or the estate travels through this port.
 */

export type SettlementNotificationKind = 'case_opened' | 'owner_contact';

export interface SettlementNotification {
  readonly kind: SettlementNotificationKind;
  /** The recipient: the case subject being asked to prove they are alive. */
  readonly ownerUserId: string;
  readonly caseId: string;
  /** When the waiting period ends, so the owner knows how long they have. */
  readonly waitingPeriodEnds?: Date;
}

/**
 * What a send actually did (M14). See vault's identical type: `notify` stopped
 * throwing because an exception cannot carry the second fact a send returns.
 */
export interface NotifyOutcome {
  readonly delivered: boolean;
  /** Whether the owner had PROVED the address it went to. */
  readonly recipientVerified: boolean;
}

export interface NotificationPort {
  /** Identifies the adapter in the contact-attempt record. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. Intake and review-approve
   * refuse in production behind an adapter that does not - an unreachable
   * owner turns the waiting period into a formality.
   */
  readonly deliversToRealChannels: boolean;
  notify(notification: SettlementNotification): Promise<NotifyOutcome>;
}

/**
 * SETTLEMENT DELIBERATELY HAS NO `recipientVerified` READ, and that absence is
 * the M14 classification made structural.
 *
 * Intake, provider-signal intake and review-approve are PROCEED-AND-RECORD:
 * the actor is a reporter or an operator and the recipient is the DECEDENT, so
 * refusing on the owner's unverified address would deny a legitimate reporter
 * the §5.1 chain entirely — and it would deny it hardest for exactly the
 * dormant, never-verified owner a fraudulent report targets. So this service
 * never asks the question, holds no `NOTIFICATIONS_STATUS_INTERNAL_TOKEN`, and
 * learns the answer only as a by-product of a send it was making anyway. The
 * credential graph records the same fact from the other side.
 */

/**
 * Dev/test adapter. Records what would have been sent so tests can assert on
 * it. NEVER a production channel - the service checks
 * `deliversToRealChannels` before opening a case.
 */
export class StubNotifier implements NotificationPort {
  readonly channel = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: SettlementNotification[] = [];

  notify(notification: SettlementNotification): Promise<NotifyOutcome> {
    this.sent.push(notification);
    // `recipientVerified: false` — a stub must never be the permissive answer
    // to a security question (the M8 fail-open-in-style rule).
    return Promise.resolve({ delivered: true, recipientVerified: false });
  }
}

/** Wire kinds for the notifications service (closed set; content travels nowhere). */
// ESTATE kinds only (M14).
const WIRE_KIND: Record<SettlementNotificationKind, EstateNotificationKind> = {
  case_opened: 'settlement.case_opened',
  owner_contact: 'settlement.owner_contact',
};

/**
 * The real adapter (M9): delegates to the notifications service, which owns
 * address resolution and the closed template registry — this service still
 * never sees an address, preserving its no-email-lookup anti-enumeration
 * boundary. Throws on non-delivery so notifyOwner's swallow keeps meaning
 * "attempted, not confirmed" exactly as it did for the stub. Delivery is
 * email-only this milestone; the contact trail's channel cycle remains the
 * record of intent.
 */
export class HttpNotifier implements NotificationPort {
  readonly channel = 'email';
  readonly deliversToRealChannels = true;

  constructor(private readonly client: NotificationsClientPort) {}

  async notify(notification: SettlementNotification): Promise<NotifyOutcome> {
    const outcome = await this.client.send({
      userId: notification.ownerUserId,
      kind: WIRE_KIND[notification.kind],
      channel: 'email',
      ...(notification.waitingPeriodEnds !== undefined
        ? { deadline: notification.waitingPeriodEnds }
        : {}),
    });
    if (!outcome.accepted) {
      return { delivered: false, recipientVerified: false };
    }
    return { delivered: outcome.delivered, recipientVerified: outcome.recipientVerified };
  }
}
