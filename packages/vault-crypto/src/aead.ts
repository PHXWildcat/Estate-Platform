/**
 * AES-256-GCM envelopes for Zone A material.
 *
 * docs/01 §4 permits XChaCha20-Poly1305 or AES-256-GCM for the vault. AES-GCM
 * is chosen because WebCrypto implements it natively in browsers and in
 * Node >= 20, which keeps this package at zero dependencies; XChaCha would
 * require pulling a crypto library onto the highest-audit-surface code in the
 * product (docs/03 TB6, risk #4).
 *
 * Wire format: [1B version][12B nonce][ciphertext || 16B tag].
 * This is deliberately NOT the same layout as the server-side `@estate/crypto`
 * AEAD — the two zones share no key material and no format, and nothing may
 * ever hand a blob from one to the other.
 *
 * EVERY call takes an AAD string. There is no default and no optional
 * parameter: a Zone A ciphertext that is not bound to its context can be moved
 * between users, items, or roles by a server that never has to decrypt it.
 */

import { source, utf8 } from './bytes.js';

export const ENVELOPE_VERSION = 0x01;
export const NONCE_LENGTH = 12;
export const KEY_LENGTH = 32;
/** version byte + nonce + GCM tag; a shorter buffer cannot be a valid envelope. */
const MIN_ENVELOPE_LENGTH = 1 + NONCE_LENGTH + 16;

export class VaultCryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultCryptoError';
  }
}

/** Thrown for every decryption failure — wrong key, wrong AAD, or tampering. */
export class VaultDecryptionError extends VaultCryptoError {
  constructor() {
    // Never echo which check failed: distinguishing "wrong key" from "wrong
    // AAD" would hand an attacker an oracle for free.
    super('vault decryption failed');
    this.name = 'VaultDecryptionError';
  }
}

export type AesUsage = 'encrypt' | 'decrypt' | 'wrapKey' | 'unwrapKey';

const DEFAULT_USAGES: readonly AesUsage[] = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];

/**
 * Import raw key bytes as an AES-GCM key.
 *
 * `extractable` defaults to false: docs/03 TB6 asks for non-extractable keys
 * wherever the platform allows, so that a script running in the vault origin
 * can use a key but cannot read it out. Callers that genuinely need the raw
 * bytes back (only the keyset-rotation path does) must opt in explicitly.
 */
export async function importAesKey(
  raw: Uint8Array,
  usages: readonly AesUsage[] = DEFAULT_USAGES,
  extractable = false,
): Promise<CryptoKey> {
  if (raw.length !== KEY_LENGTH) throw new VaultCryptoError('AES key must be 32 bytes');
  return crypto.subtle.importKey('raw', source(raw), { name: 'AES-GCM' }, extractable, [...usages]);
}

export async function generateAesKey(
  usages: readonly AesUsage[] = DEFAULT_USAGES,
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, extractable, [...usages]);
}

function envelope(nonce: Uint8Array, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + nonce.length + body.length);
  out[0] = ENVELOPE_VERSION;
  out.set(nonce, 1);
  out.set(body, 1 + nonce.length);
  return out;
}

function parseEnvelope(sealed: Uint8Array): { nonce: Uint8Array; body: Uint8Array } {
  if (sealed.length < MIN_ENVELOPE_LENGTH) throw new VaultDecryptionError();
  if (sealed[0] !== ENVELOPE_VERSION) throw new VaultDecryptionError();
  return {
    nonce: sealed.subarray(1, 1 + NONCE_LENGTH),
    body: sealed.subarray(1 + NONCE_LENGTH),
  };
}

export async function seal(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const body = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: source(nonce), additionalData: source(utf8(aad)) },
    key,
    source(plaintext),
  );
  return envelope(nonce, new Uint8Array(body));
}

export async function open(key: CryptoKey, sealed: Uint8Array, aad: string): Promise<Uint8Array> {
  const { nonce, body } = parseEnvelope(sealed);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: source(nonce), additionalData: source(utf8(aad)) },
      key,
      source(body),
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new VaultDecryptionError();
  }
}

/**
 * Unwrap a 32-byte AES key directly into a non-extractable `CryptoKey`, so the
 * unwrapped key material never exists as JS-readable bytes. This is the normal
 * path for the master key and for per-item keys.
 */
export async function unwrapAesKey(
  wrappingKey: CryptoKey,
  sealed: Uint8Array,
  aad: string,
  usages: readonly AesUsage[] = DEFAULT_USAGES,
): Promise<CryptoKey> {
  const { nonce, body } = parseEnvelope(sealed);
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      source(body),
      wrappingKey,
      { name: 'AES-GCM', iv: source(nonce), additionalData: source(utf8(aad)) },
      { name: 'AES-GCM', length: 256 },
      false,
      [...usages],
    );
  } catch {
    throw new VaultDecryptionError();
  }
}
