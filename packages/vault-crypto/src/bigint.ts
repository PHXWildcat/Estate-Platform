/**
 * Minimal big-integer helpers backing the SRP-6a implementation.
 *
 * Timing: JS `bigint` arithmetic is not constant-time. Every JavaScript SRP
 * implementation shares this property; the residual is recorded in docs/04 and
 * bounded by network jitter. What this module CAN guarantee is that no code
 * path branches early on a secret comparison — hence `constantTimeEqual`.
 */

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** Big-endian, left-padded to exactly `length` bytes (SRP's PAD()). */
export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new RangeError('value must be non-negative');
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new RangeError('value does not fit in the requested length');
  return out;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new RangeError('modulus must be positive');
  if (exponent < 0n) throw new RangeError('exponent must be non-negative');
  let result = 1n;
  let current = base % modulus;
  if (current < 0n) current += modulus;
  let remaining = exponent;
  while (remaining > 0n) {
    if (remaining & 1n) result = (result * current) % modulus;
    current = (current * current) % modulus;
    remaining >>= 1n;
  }
  return result;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  // Both indexes are in range: the lengths were just compared. Asserting rather
  // than defaulting keeps this a single straight-line comparison.
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
