import type {
  EstateNotificationKind,
  NotificationsPort as NotificationsClientPort,
} from '@estate/notifications-client';

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
  | 'requested'
  | 'blocked'
  | 'reminder'
  | 'released'
  | 'revoked'
  // M9, closing the M6 review's two recorded follow-ups: the owner is told
  // when the vault is RESET (the one bearer-token-destructive route) and when
  // a reconfiguration retires the previous grantees.
  | 'reset'
  | 'grantees_changed';

export interface EmergencyNotification {
  readonly kind: EmergencyNotificationKind;
  readonly ownerUserId: string;
  /** Null for vault-level kinds ('reset') that outlive every policy. */
  readonly policyId: string | null;
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

/** Wire kinds for the notifications service (closed set; content travels nowhere). */
// ESTATE kinds only (M14): a sending service cannot name the
// address-verification kind, mirroring `SendSchema`'s refusal on the wire.
const WIRE_KIND: Record<EmergencyNotificationKind, EstateNotificationKind> = {
  requested: 'emergency.requested',
  blocked: 'emergency.blocked',
  reminder: 'emergency.reminder',
  released: 'emergency.released',
  revoked: 'emergency.revoked',
  reset: 'vault.reset',
  grantees_changed: 'vault.grantees_changed',
};

/**
 * The real adapter (M9): delegates to the notifications service, which owns
 * address resolution and the closed template registry — this service still
 * never sees an address. Throws on non-delivery so the caller's bookkeeping
 * records a null delivered_at, exactly as it did for the stub's failures.
 */
export class HttpNotifier implements NotificationPort {
  readonly channel = 'email';
  readonly deliversToRealChannels = true;

  constructor(private readonly client: NotificationsClientPort) {}

  async notify(notification: EmergencyNotification): Promise<void> {
    const outcome = await this.client.send({
      userId: notification.ownerUserId,
      kind: WIRE_KIND[notification.kind],
      channel: 'email',
      ...(notification.releasesAt !== undefined ? { deadline: notification.releasesAt } : {}),
    });
    if (!outcome.accepted || !outcome.delivered) {
      throw new Error('notification_not_delivered');
    }
  }
}
