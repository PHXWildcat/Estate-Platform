import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Opaque token primitives. Tokens are 32 random bytes, base64url on the wire;
 * only their SHA-256 digest is stored (a DB leak yields nothing replayable).
 * SHA-256 (not Argon2) is correct here: the preimage has 256 bits of entropy,
 * so brute force is the attack that doesn't exist.
 */

export const TOKEN_BYTES = 32;

export function generateOpaqueToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/** Constant-time hash comparison (defense in depth; lookups are by hash anyway). */
export function tokenHashEquals(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
