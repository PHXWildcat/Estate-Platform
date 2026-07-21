import { Inject, Injectable } from '@nestjs/common';
import { FieldCrypto } from '@estate/crypto';
import { FIELD_CRYPTO } from './di-tokens';

/**
 * Thin injectable wrapper over @estate/crypto's FieldCrypto, scoped to this
 * service's actor conventions. Every value stored is AEAD ciphertext under the
 * owner's per-user DEK; every decryption flows through FieldCrypto, which
 * emits `crypto.field.decrypted` before releasing plaintext (fail-closed).
 *
 * All fields of a given owner share that owner's active DEK, so the `dekId`
 * returned by any encrypt call is the row's `dek_id`.
 */
@Injectable()
export class FieldCipher {
  constructor(@Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto) {}

  /** Ensure the owner has an active DEK and return its id (for empty rows). */
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
      actorType: 'user',
      purpose: input.purpose,
    });
    return buf.toString('utf8');
  }
}
