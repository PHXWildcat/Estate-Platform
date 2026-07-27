/**
 * Shamir secret sharing over GF(2^8), for splitting the contacts' half of the
 * recovery key across emergency-access grantees (docs/03 §5.2's "optional M-of-N
 * requirement so no single contact can unlock alone").
 *
 * Byte-wise over GF(256) rather than a big prime field: each byte of the secret
 * gets its own polynomial, so shares are exactly as long as the secret plus one
 * index byte, and the arithmetic is table lookups instead of bignum math. The
 * field is the AES field (reduction polynomial 0x11b), which is the same choice
 * every deployed implementation of this makes.
 *
 * Information-theoretic, not computational: with fewer than `threshold` shares,
 * every possible secret remains equally likely. That property is why the
 * platform share can be XOR-split away from the contacts' half - see recovery.ts.
 */

import { randomBytes } from './bytes';
import { VaultCryptoError } from './aead';

export const MAX_SHARES = 255;

export class ShamirError extends VaultCryptoError {
  constructor(detail: string) {
    super(`shamir failure: ${detail}`);
    this.name = 'ShamirError';
  }
}

/** log/exp tables for GF(2^8) with generator 3, built once at module load. */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let value = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = value;
    LOG[value] = i;
    // Multiply by the generator 3 = x + 1: (value << 1) ^ value, reduced.
    let next = value ^ ((value << 1) & 0xff);
    if (value & 0x80) next ^= 0x1b;
    value = next;
  }
  // Duplicate the table so exponent sums never need a modulo.
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255]!;
})();

/**
 * GF(2^8) multiply and divide. Exported because they are the primitive
 * everything else here rests on, and the field laws are worth asserting
 * directly rather than only through a round trip that could pass with two
 * cancelling bugs.
 */
export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

export function gfDiv(a: number, b: number): number {
  if (b === 0) throw new ShamirError('division by zero');
  if (a === 0) return 0;
  return EXP[LOG[a]! + 255 - LOG[b]!]!;
}

const mul = gfMul;
const div = gfDiv;

export interface Share {
  /** The evaluation point, 1..255. Never 0 - that is the secret itself. */
  readonly x: number;
  readonly y: Uint8Array;
}

/** Wire form: one index byte followed by the share body. */
export function encodeShare(share: Share): Uint8Array {
  const out = new Uint8Array(share.y.length + 1);
  out[0] = share.x;
  out.set(share.y, 1);
  return out;
}

export function decodeShare(bytes: Uint8Array): Share {
  if (bytes.length < 2) throw new ShamirError('share too short');
  const x = bytes[0]!;
  if (x === 0) throw new ShamirError('invalid share index');
  return { x, y: bytes.subarray(1) };
}

/**
 * Split `secret` into `shares` pieces, any `threshold` of which reconstruct it.
 *
 * threshold = 1 is allowed and is the product default: every grantee holds a
 * full copy of the contacts' half. It still cannot open the vault alone,
 * because the platform half is what enforces the waiting period.
 */
export function split(secret: Uint8Array, options: { shares: number; threshold: number }): Share[] {
  const { shares, threshold } = options;
  if (secret.length === 0) throw new ShamirError('empty secret');
  if (!Number.isInteger(shares) || shares < 1 || shares > MAX_SHARES) {
    throw new ShamirError('share count out of range');
  }
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > shares) {
    throw new ShamirError('threshold out of range');
  }

  const out: Share[] = [];
  for (let i = 0; i < shares; i += 1) out.push({ x: i + 1, y: new Uint8Array(secret.length) });

  for (let byteIndex = 0; byteIndex < secret.length; byteIndex += 1) {
    // Polynomial with the secret byte as the constant term.
    const coefficients = new Uint8Array(threshold);
    coefficients[0] = secret[byteIndex]!;
    if (threshold > 1) coefficients.set(randomBytes(threshold - 1), 1);

    for (const share of out) {
      // Horner evaluation at x.
      let acc = 0;
      for (let power = threshold - 1; power >= 0; power -= 1) {
        acc = mul(acc, share.x) ^ coefficients[power]!;
      }
      share.y[byteIndex] = acc;
    }
    coefficients.fill(0);
  }
  return out;
}

/**
 * Reconstruct the secret by Lagrange interpolation at x = 0.
 *
 * Supplying more than the threshold is fine; supplying fewer produces a
 * well-formed but wrong answer, which is the nature of the scheme - the caller
 * finds out because the reconstructed key fails to unwrap anything. That is a
 * deliberate property, not a missing check: a "wrong number of shares" error
 * would leak how many are needed.
 */
export function combine(shares: readonly Share[]): Uint8Array {
  if (shares.length === 0) throw new ShamirError('no shares');
  const length = shares[0]!.y.length;
  if (length === 0) throw new ShamirError('empty share');

  const seen = new Set<number>();
  for (const share of shares) {
    if (share.x === 0) throw new ShamirError('invalid share index');
    if (share.y.length !== length) throw new ShamirError('share length mismatch');
    if (seen.has(share.x)) throw new ShamirError('duplicate share index');
    seen.add(share.x);
  }

  const secret = new Uint8Array(length);
  for (let byteIndex = 0; byteIndex < length; byteIndex += 1) {
    let acc = 0;
    for (const share of shares) {
      // Lagrange basis polynomial for this share, evaluated at 0.
      let basis = 1;
      for (const other of shares) {
        if (other.x === share.x) continue;
        basis = mul(basis, div(other.x, share.x ^ other.x));
      }
      acc ^= mul(share.y[byteIndex]!, basis);
    }
    secret[byteIndex] = acc;
  }
  return secret;
}
