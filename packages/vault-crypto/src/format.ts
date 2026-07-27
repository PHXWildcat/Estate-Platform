/**
 * Secret Key encoding.
 *
 * The Secret Key is 128 bits of device-generated entropy that never leaves the
 * user's devices, so the user has to be able to write it down, read it back,
 * and type it on another device. That makes the encoding a usability surface
 * with security consequences: a mistyped key must fail loudly at parse time
 * rather than silently deriving a wrong (but well-formed) unlock key.
 *
 * Format: `ES1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`
 *   - Crockford base32 (no I, L, O, U — the characters people confuse)
 *   - 16 entropy bytes + 1 checksum byte (first byte of SHA-256 of the entropy)
 *   - case-insensitive, and 1/l/i and 0/o are folded on input
 */

import { fromBase64, sha256, toBase64 } from './bytes';
import { VaultCryptoError } from './aead';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PREFIX = 'ES1';
const GROUP_SIZE = 7;
export const SECRET_KEY_BYTES = 16;
const ENCODED_CHARS = 28; // ceil((16 + 1) * 8 / 5)

export class SecretKeyFormatError extends VaultCryptoError {
  constructor(detail: string) {
    super(`invalid secret key: ${detail}`);
    this.name = 'SecretKeyFormatError';
  }
}

function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let accumulator = 0;
  let out = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(accumulator >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += ALPHABET[(accumulator << (5 - bits)) & 0x1f];
  return out;
}

function decodeBase32(text: string): Uint8Array {
  let bits = 0;
  let accumulator = 0;
  const out: number[] = [];
  for (const char of text) {
    const value = ALPHABET.indexOf(char);
    if (value < 0) throw new SecretKeyFormatError('character');
    accumulator = (accumulator << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((accumulator >> bits) & 0xff);
    }
  }
  // Whatever is left is padding and must be zero, so a corrupted final
  // character cannot decode to the same key.
  if ((accumulator & ((1 << bits) - 1)) !== 0) throw new SecretKeyFormatError('padding');
  return Uint8Array.from(out);
}

function normalize(text: string): string {
  return text.toUpperCase().replace(/[\s-]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
}

export async function generateSecretKey(): Promise<string> {
  const entropy = crypto.getRandomValues(new Uint8Array(SECRET_KEY_BYTES));
  return formatSecretKey(entropy);
}

export async function formatSecretKey(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== SECRET_KEY_BYTES) throw new SecretKeyFormatError('length');
  // sha256 always returns 32 bytes, so index 0 exists.
  const digest = await sha256(entropy);
  const payload = new Uint8Array(SECRET_KEY_BYTES + 1);
  payload.set(entropy);
  payload[SECRET_KEY_BYTES] = digest[0]!;

  const encoded = encodeBase32(payload);
  const groups: string[] = [];
  for (let i = 0; i < encoded.length; i += GROUP_SIZE) {
    groups.push(encoded.slice(i, i + GROUP_SIZE));
  }
  return `${PREFIX}-${groups.join('-')}`;
}

export async function parseSecretKey(text: string): Promise<Uint8Array> {
  const normalized = normalize(text);
  if (!normalized.startsWith(PREFIX)) throw new SecretKeyFormatError('prefix');

  const body = normalized.slice(PREFIX.length);
  if (body.length !== ENCODED_CHARS) throw new SecretKeyFormatError('length');

  const decoded = decodeBase32(body);
  const entropy = decoded.subarray(0, SECRET_KEY_BYTES);
  const digest = await sha256(entropy);
  if (decoded[SECRET_KEY_BYTES] !== digest[0]!) throw new SecretKeyFormatError('checksum');
  return Uint8Array.from(entropy);
}

/**
 * Storage helpers for callers that keep the Secret Key in a device keychain
 * rather than re-prompting for it. Deliberately NOT part of any request shape:
 * nothing in this package ever sends the Secret Key anywhere.
 */
export const secretKeyToBase64 = toBase64;
export const secretKeyFromBase64 = fromBase64;
