import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single audit egress point (docs/02 §6 PII firewall: entity IDs and enum
 * tokens only — in THIS service that emphatically excludes addresses, subject
 * lines, and bodies). The send event doubles as the logged-decryption record's
 * companion: FieldCrypto's sink emits crypto.field.decrypted for the address
 * read, and this event records what the plaintext was used FOR.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  /** A notification left (or failed to leave) the platform. */
  async notificationSent(
    userId: string,
    sendId: string,
    detail: {
      kind: string;
      requestedChannel: string;
      channel: string;
      outcome: 'sent' | 'no_recipient' | 'carrier_failure';
      transport: string;
    },
  ): Promise<void> {
    await this.audit.emit({
      action: 'notification.sent',
      actorId: null,
      actorType: 'service',
      onBehalfOf: userId,
      resourceType: 'notification',
      resourceId: sendId,
      sessionId: null,
      detail,
    });
  }

  /**
   * The user proved they receive mail at the stored address (M14).
   *
   * DISTINCT FROM `recipientUpdated` on purpose. That event fires on every
   * login and cannot attribute a change (docs/03 §6c records it as evidence
   * for recovery, never a detection control); this one fires once per address,
   * marks the moment three arming gates start trusting it, and is therefore
   * the event an investigation actually wants. Ids only, as ever: which
   * address was proved is exactly what this stream must not carry.
   */
  async recipientVerified(userId: string): Promise<void> {
    await this.audit.emit({
      action: 'notification.recipient.verified',
      actorId: null,
      actorType: 'service',
      onBehalfOf: userId,
      resourceType: 'notification_recipient',
      resourceId: userId,
      sessionId: null,
      detail: {},
    });
  }

  /** Identity registered or refreshed a user's delivery address. */
  async recipientUpdated(userId: string): Promise<void> {
    await this.audit.emit({
      action: 'notification.recipient.updated',
      actorId: null,
      actorType: 'service',
      onBehalfOf: userId,
      resourceType: 'notification_recipient',
      resourceId: userId,
      sessionId: null,
      // Deliberately empty: WHICH address it became is exactly what this
      // stream must never carry.
      detail: {},
    });
  }
}
