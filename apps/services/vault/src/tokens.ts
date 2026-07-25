import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Vault session tokens, handled exactly like identity's access tokens
 * (apps/services/identity/src/tokens.ts): opaque, high-entropy, and stored as
 * a SHA-256 digest only.
 *
 * SHA-256 rather than a password hash is deliberate: the preimage is 32 random
 * bytes, so brute force is the attack that does not exist, and a slow hash on
 * every vault request would buy nothing.
 */
export const TOKEN_BYTES = 32;

export function generateOpaqueToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token).digest();
}

export function tokenHashEquals(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
