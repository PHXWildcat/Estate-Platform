import { Inject, Injectable } from '@nestjs/common';
import type { NotificationKind } from '@estate/notifications-client';
import type { FieldCrypto } from '@estate/crypto';
import { render, renderAddressVerification, type RenderedNotification } from './templates';
import { RecipientsRepo } from './recipients.repo';
import { SendsRepo, type SendOutcomeToken } from './sends.repo';
import { EventsService } from './events.service';
import { CLOCK, EMAIL_SENDER, FIELD_CRYPTO, SYSTEM_ACTOR_ID, type Clock } from './di-tokens';
import type { EmailSender } from './email';
import type { SendInput, RecipientInput, VerificationInput } from './schemas';
import { Db } from './db';

/** AAD field id binding recipient ciphertext to its column (docs/02 convention). */
const EMAIL_FIELD = 'notification_recipient.email';

/**
 * Send = resolve recipient → render the closed template → hand to the carrier
 * → record the truth. Every branch RECORDS: a send that failed is a fact the
 * callers' bookkeeping (vault's delivered_at, settlement's contact trail) and
 * the owner's after-the-fact review both depend on. Nothing here throws for a
 * missing recipient or a carrier refusal — those are outcomes.
 */
@Injectable()
export class NotificationsService {
  constructor(
    private readonly db: Db,
    private readonly recipients: RecipientsRepo,
    private readonly sends: SendsRepo,
    private readonly events: EventsService,
    @Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto,
    @Inject(EMAIL_SENDER) private readonly email: EmailSender,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  /** The capability bit callers' 503 gates ultimately rest on. */
  get deliversToRealChannels(): boolean {
    return this.email.deliversToRealChannels;
  }

  async send(input: SendInput): Promise<{ delivered: boolean; channel: string }> {
    const deadline = input.deadline !== undefined ? new Date(input.deadline) : null;
    return this.deliver({
      userId: input.userId,
      kind: input.kind,
      requestedChannel: input.channel,
      render: () => render(input.kind, deadline),
    });
  }

  /**
   * Mail one address-verification code (M14).
   *
   * Its own method rather than a branch inside `send`, mirroring its own route
   * and its own credential: the estate send path must stay unable to express a
   * code, and this path must stay unable to fire an estate kind. What they DO
   * share is `deliver` below — the recipient resolution, the audited decrypt,
   * the carrier hand-off and the append-only record are one implementation, so
   * a verification send cannot quietly skip the logging every other send gets.
   *
   * `requestedChannel` is 'email' and not a caller's choice: nothing about
   * confirming an address is served by asking for a channel the platform does
   * not have.
   */
  async sendAddressVerification(
    input: VerificationInput,
  ): Promise<{ delivered: boolean; channel: string }> {
    return this.deliver({
      userId: input.userId,
      kind: 'identity.address_verification',
      requestedChannel: 'email',
      render: () => renderAddressVerification(input.code),
    });
  }

  /**
   * The one delivery path: resolve recipient → render the closed template →
   * hand to the carrier → record the truth. Every branch RECORDS.
   *
   * `render` is a THUNK evaluated only once an address exists, so a template
   * that throws cannot be distinguished from a carrier failure by a caller and
   * — more importantly — the code in a verification body is never constructed
   * for a user the store cannot reach anyway.
   */
  private async deliver(job: {
    userId: string;
    kind: NotificationKind;
    requestedChannel: string;
    render: () => RenderedNotification;
  }): Promise<{ delivered: boolean; channel: string }> {
    const recipient = await this.recipients.find(job.userId);

    let outcome: SendOutcomeToken;
    let providerMessageId: string | null = null;
    if (recipient === null) {
      outcome = 'no_recipient';
    } else {
      try {
        // The decrypt is audited by FieldCrypto's sink (crypto.field.decrypted,
        // purpose notification_send) — the Zone B logged-decryption rule.
        const address = (
          await this.crypto.decryptField({
            userId: job.userId,
            dekId: recipient.dek_id,
            field: EMAIL_FIELD,
            ciphertext: recipient.email_ct,
            actorId: SYSTEM_ACTOR_ID,
            actorType: 'service',
            purpose: 'notification_send',
          })
        ).toString('utf8');
        const rendered = job.render();
        const sent = await this.email.send({
          to: address,
          subject: rendered.subject,
          body: rendered.body,
        });
        outcome = 'sent';
        providerMessageId = sent.providerMessageId;
      } catch {
        // Carrier or crypto failure: recorded, never echoed (the error could
        // carry the address). A shredded DEK lands here too: unreachable
        // address ⇒ no delivery, which is what erasure means.
        outcome = 'carrier_failure';
      }
    }

    const sendId = await this.sends.record({
      userId: job.userId,
      kind: job.kind,
      requestedChannel: job.requestedChannel,
      channel: 'email',
      outcome,
      providerMessageId,
    });
    await this.events.notificationSent(job.userId, sendId, {
      kind: job.kind,
      requestedChannel: job.requestedChannel,
      channel: 'email',
      outcome,
      transport: this.email.transport,
    });
    return { delivered: outcome === 'sent', channel: 'email' };
  }

  async upsertRecipient(input: RecipientInput): Promise<{ ok: true }> {
    const { ciphertext, dekId } = await this.crypto.encryptField(
      input.userId,
      EMAIL_FIELD,
      input.email,
    );
    await this.db.withTransaction(SYSTEM_ACTOR_ID, (tx) =>
      this.recipients.upsert(tx, { userId: input.userId, emailCt: ciphertext, dekId }),
    );
    await this.events.recipientUpdated(input.userId);
    return { ok: true };
  }

  /**
   * Record that the user proved ownership of the stored address (M14).
   *
   * `ok: false` when there is no live row to vouch for — a recipient that was
   * never fed, soft-deleted, or crypto-shredded. Identity turns that into a
   * refusal the user sees rather than a silent success, because "we marked
   * your address verified" about an address the store cannot reach is the
   * precise false assurance this milestone exists to remove.
   *
   * The write is audited under its own action, distinct from
   * `notification.recipient.updated`: an address CHANGING and an address being
   * VOUCHED FOR are different facts, and only one of them arms a gate.
   */
  async markRecipientVerified(userId: string): Promise<{ ok: boolean }> {
    const marked = await this.db.withTransaction(SYSTEM_ACTOR_ID, (tx) =>
      this.recipients.markVerified(tx, userId, this.clock()),
    );
    if (marked) {
      await this.events.recipientVerified(userId);
    }
    return { ok: marked };
  }

  /**
   * Answer whether the delivery store can PROVABLY reach this user (M14).
   *
   * A missing row and an unverified row both answer `false`: to a caller's
   * gate they mean the same thing, and returning a third state would invite a
   * gate to treat "never fed" as something other than "cannot reach". The send
   * log keeps them apart where the distinction is actionable (`no_recipient`).
   *
   * Never throws for an absent user, and returns no timestamp and no address —
   * one boolean about one named user is the whole grant.
   */
  async recipientStatus(userId: string): Promise<{ verified: boolean }> {
    const row = await this.recipients.findStatus(userId);
    return { verified: row?.verifiedAt != null };
  }
}
