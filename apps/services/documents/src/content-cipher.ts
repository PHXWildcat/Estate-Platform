import { Inject, Injectable } from '@nestjs/common';
import { FieldCrypto, type ActorType } from '@estate/crypto';
import { FIELD_CRYPTO } from './di-tokens';

/**
 * AAD field string for a document version's encrypted content. Combined with
 * FieldCrypto's subject binding (the DOCUMENT id — per-object DEKs, see
 * dek.repository.ts), the full AAD authenticates the ciphertext as "version N
 * of THIS document, owned by THIS user, hashing to THIS sha256". A DB/store
 * tamper adversary (docs/03 TB4) cannot splice a blob between documents,
 * owners, or versions, nor pair it with a forged content hash — the M3
 * review's F1 lesson applied from day one.
 *
 * All inputs are reconstructible from the document_versions row + documents
 * row, so decrypt needs no stored AAD.
 */
export function contentField(ownerUserId: string, version: number, sha256Hex: string): string {
  return `doc.${ownerUserId}.v${version}.${sha256Hex}`;
}

/**
 * Thin injectable wrapper over @estate/crypto's FieldCrypto, scoped to this
 * service's per-DOCUMENT key subject. Every stored blob is AEAD ciphertext
 * under the document's DEK; every decryption flows through FieldCrypto,
 * which emits `crypto.field.decrypted` before releasing plaintext
 * (fail-closed).
 */
@Injectable()
export class ContentCipher {
  constructor(@Inject(FIELD_CRYPTO) private readonly crypto: FieldCrypto) {}

  /** Ensure the document has an active DEK and return its id. */
  getOrCreateDek(documentId: string): Promise<string> {
    return this.crypto.getOrCreateDek(documentId);
  }

  /** Encrypt version content under the document's DEK. */
  async encrypt(input: {
    documentId: string;
    ownerUserId: string;
    version: number;
    sha256Hex: string;
    content: Buffer;
  }): Promise<{ ciphertext: Buffer; dekId: string }> {
    return this.crypto.encryptField(
      input.documentId,
      contentField(input.ownerUserId, input.version, input.sha256Hex),
      input.content,
    );
  }

  /** Decrypt version content (audited via FieldCrypto's sink). */
  async decrypt(input: {
    documentId: string;
    ownerUserId: string;
    version: number;
    sha256Hex: string;
    dekId: string;
    ciphertext: Buffer;
    actorId: string;
    actorType?: ActorType;
    purpose: string;
  }): Promise<Buffer> {
    return this.crypto.decryptField({
      userId: input.documentId,
      dekId: input.dekId,
      field: contentField(input.ownerUserId, input.version, input.sha256Hex),
      ciphertext: input.ciphertext,
      actorId: input.actorId,
      actorType: input.actorType ?? 'user',
      purpose: input.purpose,
    });
  }
}
