import { randomBytes } from 'node:crypto';
import { KEY_LENGTH, open, seal } from './aead';

/**
 * Key-provider boundary. Production implements this against AWS KMS
 * (CloudHSM-backed keys, IAM-scoped grants — the insider-threat chokepoint
 * per docs/03 §5.3). Services depend only on this interface so the KMS
 * adapter can live in its own package with its own IAM posture.
 */
export interface KmsKeyProvider {
  /** Generate a fresh 256-bit data key, returned both raw and wrapped by the KEK. */
  generateDataKey(kekAlias: string): Promise<{ plaintextKey: Buffer; wrappedKey: Buffer }>;
  /** Unwrap a previously wrapped data key. */
  unwrapDataKey(kekAlias: string, wrappedKey: Buffer): Promise<Buffer>;
}

/**
 * DEV/TEST ONLY key provider: wraps DEKs under an in-memory master key using
 * the same AEAD as field encryption, with the KEK alias as AAD (so a key
 * wrapped under one alias cannot be unwrapped under another).
 *
 * Never deploy this: it has no HSM root, no rotation, no audit, no IAM.
 * Production wiring must inject the AWS KMS provider instead.
 */
export class LocalKmsProvider implements KmsKeyProvider {
  private readonly masterKey: Buffer;

  constructor(masterKey: Buffer) {
    if (masterKey.length !== KEY_LENGTH) {
      throw new RangeError(`master key must be ${KEY_LENGTH} bytes`);
    }
    this.masterKey = masterKey;
  }

  static generate(): LocalKmsProvider {
    return new LocalKmsProvider(randomBytes(KEY_LENGTH));
  }

  static fromHex(hex: string): LocalKmsProvider {
    return new LocalKmsProvider(Buffer.from(hex, 'hex'));
  }

  generateDataKey(kekAlias: string): Promise<{ plaintextKey: Buffer; wrappedKey: Buffer }> {
    const plaintextKey = randomBytes(KEY_LENGTH);
    const wrappedKey = seal(this.masterKey, plaintextKey, aliasAad(kekAlias));
    return Promise.resolve({ plaintextKey, wrappedKey });
  }

  unwrapDataKey(kekAlias: string, wrappedKey: Buffer): Promise<Buffer> {
    return Promise.resolve(open(this.masterKey, wrappedKey, aliasAad(kekAlias)));
  }
}

function aliasAad(kekAlias: string): Buffer {
  return Buffer.from(`estate.kek.v1|${kekAlias}`, 'utf8');
}
