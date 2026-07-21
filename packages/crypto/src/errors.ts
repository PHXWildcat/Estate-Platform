/**
 * Crypto error hierarchy.
 *
 * SECURITY INVARIANT: error messages are fixed strings. They must never
 * interpolate plaintext, ciphertext, keys, or user-supplied values — errors
 * end up in logs, and logs must never carry secret material.
 */

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Any authentication/format failure while opening a sealed payload. */
export class DecryptionFailedError extends CryptoError {
  constructor() {
    super('decryption failed');
  }
}

/** The referenced DEK does not exist. */
export class DekNotFoundError extends CryptoError {
  constructor() {
    super('data key not found');
  }
}

/**
 * The referenced DEK was crypto-shredded (legal erasure). The ciphertext is
 * permanently irrecoverable by design — callers must treat this as "value
 * erased", not as a transient failure.
 */
export class DekDestroyedError extends CryptoError {
  constructor() {
    super('data key destroyed (crypto-shredded)');
  }
}

/**
 * The decryption-audit sink failed. We fail CLOSED: plaintext is never
 * released unless the audit event was accepted (docs/01: every decryption is
 * a logged event).
 */
export class AuditEmitFailedError extends CryptoError {
  constructor() {
    super('decryption audit emit failed; plaintext withheld');
  }
}
