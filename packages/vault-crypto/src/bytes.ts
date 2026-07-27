/**
 * Byte helpers. Deliberately built on platform globals only (`TextEncoder`,
 * `btoa`/`atob`) so this package keeps a zero-dependency, browser-isomorphic
 * surface — see the package README for why that is a security requirement and
 * not a preference.
 */

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Adapter for WebCrypto's typings.
 *
 * TypeScript 5.7 made typed arrays generic over their backing buffer, so the
 * DOM's `BufferSource` only accepts `ArrayBuffer`-backed views. Every array this
 * package produces is ArrayBuffer-backed, and a `SharedArrayBuffer`-backed view
 * would be rejected by WebCrypto at runtime regardless. Asserting here keeps the
 * public API plain `Uint8Array` instead of leaking a generic parameter into
 * every caller's signatures. Type-level only — no runtime effect, no copy (a
 * copy would defeat `wipe`).
 */
export function source(bytes: Uint8Array): BufferSource {
  return bytes as BufferSource;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/**
 * Strict base64 decode: everything decoded here arrives from the network or the
 * database, so a malformed value must be a loud error rather than silently
 * decoding to truncated key material.
 */
export function fromBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0 || !BASE64_PATTERN.test(text)) {
    throw new TypeError('invalid base64');
  }
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError('xor operands must be the same length');
  const out = new Uint8Array(a.length);
  // Both indexes are in range: the lengths were just compared.
  for (let i = 0; i < a.length; i += 1) out[i] = a[i]! ^ b[i]!;
  return out;
}

/**
 * Best-effort zeroization. JS gives no guarantee (the GC may have copied the
 * buffer already), which is exactly why long-lived keys are held as
 * non-extractable `CryptoKey`s instead — this only covers the raw byte
 * material that has to exist transiently.
 */
export function wipe(...buffers: readonly Uint8Array[]): void {
  for (const buffer of buffers) buffer.fill(0);
}

export async function sha256(...parts: readonly Uint8Array[]): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', source(concatBytes(...parts)));
  return new Uint8Array(digest);
}
