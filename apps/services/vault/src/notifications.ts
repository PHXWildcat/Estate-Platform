/**
 * The owner-notification port for emergency access.
 *
 * docs/03 §5.2's control is "multi-channel owner notification with one-tap
 * deny". The waiting period only protects an owner who finds out a request is
 * pending, so notification is not a nicety attached to this flow - it IS the
 * flow's safety property, and the service treats a missing channel as a reason
 * to refuse rather than a reason to proceed quietly.
 *
 * Notifications are content-free by design (docs/01 §2.10): the owner is told
 * that someone requested emergency access and given a way to deny it. Nothing
 * about the vault, the items, or the grantee's identity travels over email or
 * SMS.
 */

export type EmergencyNotificationKind =
  'requested' | 'blocked' | 'reminder' | 'released' | 'revoked';

export interface EmergencyNotification {
  readonly kind: EmergencyNotificationKind;
  readonly ownerUserId: string;
  readonly policyId: string;
  /** When the waiting period ends, so the owner knows how long they have. */
  readonly releasesAt?: Date;
}

export interface NotificationPort {
  /** Identifies the adapter in the notification record. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. The emergency-access routes
   * refuse to arm an escrow in production behind an adapter that does not -
   * an unreachable owner turns the waiting period into a formality.
   */
  readonly deliversToRealChannels: boolean;
  notify(notification: EmergencyNotification): Promise<void>;
}

/**
 * Dev/test adapter. Records what would have been sent so tests can assert on
 * it. NEVER a production channel - the service checks
 * `deliversToRealChannels` before arming an escrow.
 */
export class StubNotifier implements NotificationPort {
  readonly channel = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: EmergencyNotification[] = [];

  notify(notification: EmergencyNotification): Promise<void> {
    this.sent.push(notification);
    return Promise.resolve();
  }
}
