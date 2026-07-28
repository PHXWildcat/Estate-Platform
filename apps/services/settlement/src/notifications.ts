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

export interface NotificationPort {
  /** Identifies the adapter in the contact-attempt record. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. Intake and review-approve
   * refuse in production behind an adapter that does not - an unreachable
   * owner turns the waiting period into a formality.
   */
  readonly deliversToRealChannels: boolean;
  notify(notification: SettlementNotification): Promise<void>;
}

/**
 * Dev/test adapter. Records what would have been sent so tests can assert on
 * it. NEVER a production channel - the service checks
 * `deliversToRealChannels` before opening a case.
 */
export class StubNotifier implements NotificationPort {
  readonly channel = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: SettlementNotification[] = [];

  notify(notification: SettlementNotification): Promise<void> {
    this.sent.push(notification);
    return Promise.resolve();
  }
}
