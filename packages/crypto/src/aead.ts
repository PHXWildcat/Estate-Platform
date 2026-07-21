import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { DecryptionFailedError } from './errors';

/**
 * Low-level AEAD sealing: AES-256-GCM with a versioned wire format.
 *
 * Wire format (docs/01 §4 "AEAD ciphertext with key-version tags"):
 *
 *   [ version: 1 byte ][ iv: 12 bytes ][ auth tag: 16 bytes ][ ciphertext ]
 *
 * The version byte lets us rotate algorithms without a data migration. AAD
 * binds a ciphertext to its context (user + field) so an attacker with DB
 * write access cannot splice a ciphertext into a different column or row and
 * trick the application into decrypting it in the wrong context.
 */

export const AEAD_VERSION = 0x01;
export const KEY_LENGTH = 32;

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const HEADER_LENGTH = 1 + IV_LENGTH + TAG_LENGTH;

export function seal(key: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  if (key.length !== KEY_LENGTH) {
    throw new RangeError(`key must be ${KEY_LENGTH} bytes`);
  }
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([AEAD_VERSION]), iv, cipher.getAuthTag(), ct]);
}

export function open(key: Buffer, sealed: Buffer, aad: Buffer): Buffer {
  if (key.length !== KEY_LENGTH) {
    throw new RangeError(`key must be ${KEY_LENGTH} bytes`);
  }
  if (sealed.length < HEADER_LENGTH || sealed[0] !== AEAD_VERSION) {
    throw new DecryptionFailedError();
  }
  const iv = sealed.subarray(1, 1 + IV_LENGTH);
  const tag = sealed.subarray(1 + IV_LENGTH, HEADER_LENGTH);
  const ct = sealed.subarray(HEADER_LENGTH);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    // Deliberately swallow the underlying error: OpenSSL error strings can
    // differ by failure mode and we must not create a decryption oracle.
    throw new DecryptionFailedError();
  }
}
