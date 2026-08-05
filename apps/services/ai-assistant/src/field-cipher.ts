import { Inject, Injectable } from '@nestjs/common';
import { FieldCrypto, type ActorType } from '@estate/crypto';
import { FIELD_CRYPTO } from './di-tokens';

/**
 * AAD field string for an encrypted message body (`assistant_messages.content_ct`).
 *
 * Bound to the MESSAGE id rather than being a flat `<table>.<column>` constant
 * because this service holds ONE DEK PER USER, covering every conversation that
 * user ever had (see dek.repository.ts). Under a single key, a flat field label
 * would authenticate every turn identically, so a database-tamper adversary
 * (docs/03 TB4) could splice one turn's ciphertext into another turn, reorder a
 * transcript, or move a turn from one conversation into another — and the AEAD
 * would verify happily, because nothing in the AAD contradicted the new
 * position. Binding the row id makes the ciphertext decrypt ONLY as "the body
 * of THIS message"; the message's conversation and seq are then trustworthy
 * plaintext columns, since moving the row means the body no longer opens.
 *
 * That matters more here than in the ledger: an attacker who can forge what the
 * user appears to have said, or what the assistant appears to have answered, is
 * attacking the record of advice about an estate (docs/01 §2.8).
 *
 * Changing this format is a RE-ENCRYPTION, and unlike assets there is no
 * rebuild to run — `assistant_messages` is append-only and its own source of
 * truth, so nothing can re-derive a turn's plaintext. A format change therefore
 * needs an explicit read-old/write-new migration, or it silently orphans every
 * existing transcript.
 */
export function messageField(messageId: string): string {
  return `assistant_message.${messageId}.content`;
}

/**
 * AAD field string for a tool call's encrypted result
 * (`assistant_tool_calls.result_ct`).
 *
 * Bound to the TOOL CALL id for the same reason as messageField — one per-user
 * DEK spans every conversation, so only the row binding stops a TB4 adversary
 * pairing the result of one retrieval with a different call's tool_name, scope
 * or outcome. The scope that admitted a read and the bytes that read returned
 * have to stay welded together: `assistant_tool_calls` is the audit-visible
 * half of "tool scopes are read-only and consent-gated" (docs/03 §4 TB5), and a
 * splice would let a result fetched under one consent scope appear to have been
 * fetched under another.
 *
 * Changing this format is a re-encryption with no rebuild path (append-only
 * table, no other copy of the plaintext) — see messageField.
 */
export function toolResultField(toolCallId: string): string {
  return `assistant_tool_call.${toolCallId}.result`;
}

/**
 * Thin injectable wrapper over @estate/crypto's FieldCrypto, scoped to this
 * service's per-USER key subject. Every value stored is AEAD ciphertext under
 * the owner's DEK, wrapped by 'ai-assistant/kek'; every decryption flows
 * through FieldCrypto, which emits `crypto.field.decrypted` before releasing
 * plaintext (fail-closed).
 *
 * Everything this service persists is Zone B content of the highest
 * sensitivity — the user's own words about their estate, plus whatever the
 * retrieval tools quoted back into the turn — so there is no "low-sensitivity
 * label" column here of the `documents.title` kind: conversation titles are
 * derived and displayed, never harvested from the body.
 *
 * `purpose` strings this service uses on decrypt, so an auditor reading
 * `crypto.field.decrypted` can tell the two apart without any plaintext:
 *   * `assistant_history_read`    — the service rebuilding a conversation's
 *     prior turns in order to compose the next one. Machine-driven, one burst
 *     per turn, and the plaintext leaves for the model provider.
 *   * `assistant_transcript_read` — a user reading their own history back.
 *     Human-driven, and the plaintext goes only to the person who wrote it.
 * A rise in the first without the second is a service reading more than it is
 * being asked to; the reverse is ordinary use. Collapsing them into one purpose
 * would make that distinction unrecoverable after the fact.
 *
 * actorType follows the assets convention: user-facing reads decrypt as 'user'
 * (the default), and work with no session behind it — a retention sweep over
 * expired conversations — passes 'system' so its audit trail is distinguishable
 * from real user access.
 */
@Injectable()
export class FieldCipher {
  constructor(@Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto) {}

  /** Ensure the owner has an active DEK and return its id. */
  getOrCreateDek(ownerUserId: string): Promise<string> {
    return this.crypto.getOrCreateDek(ownerUserId);
  }

  /**
   * Encrypt an optional field; null value ⇒ null ciphertext (column stays
   * NULL). The dekId is returned either way, so a row whose payload is absent
   * — a denied tool call has an outcome but no result — still records the key
   * it would have been written under, and the crypto-shred sweep can find it.
   */
  async encrypt(
    ownerUserId: string,
    field: string,
    value: string | null | undefined,
  ): Promise<{ ciphertext: Buffer | null; dekId: string }> {
    if (value === null || value === undefined) {
      return { ciphertext: null, dekId: await this.crypto.getOrCreateDek(ownerUserId) };
    }
    return this.crypto.encryptField(ownerUserId, field, value);
  }

  /** Decrypt an optional field to a UTF-8 string (audited). */
  async decrypt(input: {
    ownerUserId: string;
    dekId: string;
    field: string;
    ciphertext: Buffer | null;
    actorId: string;
    actorType?: ActorType;
    purpose: string;
  }): Promise<string | null> {
    if (input.ciphertext === null) {
      return null;
    }
    const buf = await this.crypto.decryptField({
      userId: input.ownerUserId,
      dekId: input.dekId,
      field: input.field,
      ciphertext: input.ciphertext,
      actorId: input.actorId,
      actorType: input.actorType ?? 'user',
      purpose: input.purpose,
    });
    return buf.toString('utf8');
  }
}
