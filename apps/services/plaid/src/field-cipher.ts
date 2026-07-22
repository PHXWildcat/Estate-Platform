import { Inject, Injectable } from '@nestjs/common';
import { FieldCrypto, type ActorType } from '@estate/crypto';
import { FIELD_CRYPTO } from './di-tokens';

/**
 * Thin injectable wrapper over @estate/crypto's FieldCrypto, scoped to this
 * service's actor conventions. Every value stored is AEAD ciphertext under
 * the owner's per-user plaid DEK ('plaid/kek' domain); every decryption flows
 * through FieldCrypto, which emits `crypto.field.decrypted` before releasing
 * plaintext (fail-closed). Access-token decrypts happen only in sync/revoke
 * paths, as actorType 'service' with purpose 'plaid_sync' / 'plaid_revoke' —
 * the decrypt-rate baseline for TB4's bulk-decryption detection.
 */
@Injectable()
export class FieldCipher {
  constructor(@Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto) {}

  /** Ensure the owner has an active plaid DEK and return its id. */
  getOrCreateDek(ownerUserId: string): Promise<string> {
    return this.crypto.getOrCreateDek(ownerUserId);
  }

  /** Encrypt an optional field; null value ⇒ null ciphertext (column stays NULL). */
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
