import { Inject, Injectable } from '@nestjs/common';
import type { FieldCrypto } from '@estate/crypto';
import { render } from './templates';
import { RecipientsRepo } from './recipients.repo';
import { SendsRepo, type SendOutcomeToken } from './sends.repo';
import { EventsService } from './events.service';
import { EMAIL_SENDER, FIELD_CRYPTO, SYSTEM_ACTOR_ID } from './di-tokens';
import type { EmailSender } from './email';
import type { SendInput, RecipientInput } from './schemas';
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
  ) {}

  /** The capability bit callers' 503 gates ultimately rest on. */
  get deliversToRealChannels(): boolean {
    return this.email.deliversToRealChannels;
  }

  async send(input: SendInput): Promise<{ delivered: boolean; channel: string }> {
    const deadline = input.deadline !== undefined ? new Date(input.deadline) : null;
    const recipient = await this.recipients.find(input.userId);

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
            userId: input.userId,
            dekId: recipient.dek_id,
            field: EMAIL_FIELD,
            ciphertext: recipient.email_ct,
            actorId: SYSTEM_ACTOR_ID,
            actorType: 'service',
            purpose: 'notification_send',
          })
        ).toString('utf8');
        const rendered = render(input.kind, deadline);
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
      userId: input.userId,
      kind: input.kind,
      requestedChannel: input.channel,
      channel: 'email',
      outcome,
      providerMessageId,
    });
    await this.events.notificationSent(input.userId, sendId, {
      kind: input.kind,
      requestedChannel: input.channel,
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
}
