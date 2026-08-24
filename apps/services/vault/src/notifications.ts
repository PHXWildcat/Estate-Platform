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
  | 'grantees_changed'
  // M27 PR3b: a released grantee opened the owner's items. The vault-local
  // name drops the `vault.` prefix the wire kind carries, like every member
  // here — this union is the SERVICE's vocabulary and `WIRE_KIND` is the only
  // place the two spellings meet.
  | 'read_by_grantee';

export interface EmergencyNotification {
  readonly kind: EmergencyNotificationKind;
  readonly ownerUserId: string;
  /** Null for vault-level kinds ('reset') that outlive every policy. */
  readonly policyId: string | null;
  /** When the waiting period ends, so the owner knows how long they have. */
  readonly releasesAt?: Date;
}

/**
 * What a send actually did (M14). `notify` no longer throws for a failed
 * delivery: the caller has always recorded that outcome (a null delivered_at),
 * and an exception was a poor carrier for a second fact.
 */
export interface NotifyOutcome {
  /** The carrier accepted the message. */
  readonly delivered: boolean;
  /**
   * Whether the owner had PROVED the address it went to. `false` also covers
   * "could not tell", which is the safe reading: the record says we could not
   * confirm reach, never that we could.
   */
  readonly recipientVerified: boolean;
}

export interface NotificationPort {
  /** Identifies the adapter in the notification record. */
  readonly channel: string;
  /**
   * Whether this adapter actually reaches a human. The emergency-access routes
   * refuse to arm an escrow in production behind an adapter that does not -
   * an unreachable owner turns the waiting period into a formality.
   *
   * IT IS A PROPERTY OF THE ADAPTER, NOT OF THE RECIPIENT, and M14 exists
   * because three shipped controls rested on it as if it were both: it is a
   * hardcoded literal chosen at DI time from this service's own NOTIFY_MODE,
   * so it asks whether SES is wired and never whether the stored address
   * belongs to the owner. `recipientVerified` below is the other half.
   */
  readonly deliversToRealChannels: boolean;
  /**
   * Whether the delivery store holds an address this owner PROVED they receive
   * mail at (M14).
   *
   * FAIL CLOSED: an unanswerable query — no credential, network failure,
   * non-2xx, contract drift — is `false`, never a permissive default. This is
   * the first network round trip the emergency-access gates have ever made, so
   * the decision about what an outage means is written here rather than
   * inherited from a thrown exception: an outage means the escrow does not arm,
   * which delays a legitimate owner by minutes and costs an attacker the whole
   * §5.2 waiting period.
   */
  recipientVerified(ownerUserId: string): Promise<boolean>;
  notify(notification: EmergencyNotification): Promise<NotifyOutcome>;
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

  /**
   * FALSE, not true. A stub that vouched for an address would be the
   * "fail-open in style" shape M8 PR1 named: the dev default must never be the
   * permissive answer to a security question. The arming gates are
   * production-scoped, so dev is unaffected in practice — this is about what
   * the stub SAYS, not what it lets through.
   */
  recipientVerified(): Promise<boolean> {
    return Promise.resolve(false);
  }

  notify(notification: EmergencyNotification): Promise<NotifyOutcome> {
    this.sent.push(notification);
    return Promise.resolve({ delivered: true, recipientVerified: false });
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
  read_by_grantee: 'vault.read_by_grantee',
};

/**
 * The real adapter (M9): delegates to the notifications service, which owns
 * address resolution and the closed template registry — this service still
 * never sees an address.
 *
 * M14 stopped it throwing on non-delivery. The caller already recorded that
 * outcome (a null delivered_at) by catching, and an exception cannot carry the
 * SECOND fact a send now returns — whether the address was proved. Narrowing
 * both to one value is the @estate/notifications-client discipline applied one
 * layer up: every failure becomes an outcome, never a control-flow surprise.
 */
export class HttpNotifier implements NotificationPort {
  readonly channel = 'email';
  readonly deliversToRealChannels = true;

  constructor(private readonly client: NotificationsClientPort) {}

  async recipientVerified(ownerUserId: string): Promise<boolean> {
    // `null` is UNANSWERABLE and collapses to false HERE, at the boundary that
    // knows what the question was for. The client keeps the two apart so this
    // decision has to be made explicitly rather than inherited.
    const status = await this.client.recipientStatus(ownerUserId);
    return status?.verified === true;
  }

  async notify(notification: EmergencyNotification): Promise<NotifyOutcome> {
    const outcome = await this.client.send({
      userId: notification.ownerUserId,
      kind: WIRE_KIND[notification.kind],
      channel: 'email',
      ...(notification.releasesAt !== undefined ? { deadline: notification.releasesAt } : {}),
    });
    if (!outcome.accepted) {
      return { delivered: false, recipientVerified: false };
    }
    return { delivered: outcome.delivered, recipientVerified: outcome.recipientVerified };
  }
}
