import { createHash, randomBytes } from 'node:crypto';

/**
 * READ-ALOUD SINGLE-USE CODES, extracted (M16).
 *
 * This repo has minted human-typed codes three times now — M13's contact link
 * (`ESL1-`), M14's address verification (`EV1-`), and M16's extension pairing
 * (`EP1-`) — and until this file the derivation existed twice, byte-identical
 * apart from a prefix, in `contact-links.service.ts` and
 * `email-verification.service.ts`. A THIRD copy is the shape the M8 PR2 entry
 * describes exactly: seven byte-identical audit producers that all carried the
 * same bug because there was one behaviour and several places to fix it.
 *
 * WHAT IS AND IS NOT UNIFIED, stated rather than left to be discovered.
 * Identity's two ceremonies share this module. PROFILE'S DOES NOT: it is a
 * different service, so sharing would need a package, and unifying a shipped
 * M13 ceremony is a change to M13 rather than a part of M16. Two copies remain,
 * which is worse than one and better than three; closing it properly means a
 * small shared package and touching profile's tests, and that is its own PR.
 */

export function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/**
 * Reduce a code to the one form that gets hashed — M13's fold, unchanged.
 *
 * The alphabet excludes I, L, O and U so a code survives being read off a
 * screen and typed, or read aloud. Redemption must fold the same way the mint
 * did, or the very confusions the alphabet exists to survive (lowercase, a
 * typed "O" for zero, dropped grouping dashes) fail with the uniform refusal
 * and the user's only remedy is a fresh code — the usability defect the M13
 * review found hiding behind a security property.
 *
 * IT CANNOT COLLIDE, and the argument is M13's: the fold is INJECTIVE ON MINTED
 * CODES. A prefix is constant within a ceremony, so it folds identically for
 * every code of that ceremony and distinguishes nothing; the body is drawn from
 * an alphabet excluding I, L, O and U, so within the body the fold is the
 * identity. Two different minted codes therefore differ in their bodies both
 * before and after folding. Case-folding costs no entropy: the generator only
 * ever emits uppercase.
 */
export function canonicalCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
}

/** Crockford-style base32: no I, L, O or U. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const CODE_RANDOM_BYTES = 20;

/** Characters a `CODE_RANDOM_BYTES` body occupies at 5 bits each. */
export const CODE_BODY_LENGTH = (CODE_RANDOM_BYTES * 8) / 5;

/**
 * What a minted code with this prefix folds to — MEASURED, not counted by hand,
 * and pinned by each ceremony's spec against a real mint. Redemption checks
 * this rather than trusting a request schema's length bound, which measures the
 * RAW submission and is therefore satisfied by separators alone (the M13 round-3
 * finding, where `min(8)` was met by dashes that folded to nothing).
 */
export function canonicalLengthFor(prefix: string): number {
  return canonicalCode(prefix).length + CODE_BODY_LENGTH;
}

/**
 * A 160-bit code in Crockford-style base32, grouped for reading: `EP1-K7MN-…`.
 *
 * THE WIDTH IS THE SECURITY PARAMETER, so it is derived and asserted, never
 * assumed: 20 bytes at 5 bits per character is 32 characters exactly. M6's
 * grantee fingerprint carried 50 bits where its spec said 80, and M13's first
 * link code mapped one character per BYTE for a real width of 100 — both found
 * by looking at what a running system actually minted, which is why the
 * derivation fails loudly here instead of silently shipping a short code.
 */
export function readableCode(prefix: string): string {
  const bytes = randomBytes(CODE_RANDOM_BYTES);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >> bits) & 31];
    }
  }
  // 160 % 5 === 0, so nothing is left over; assert rather than assume.
  if (bits !== 0 || out.length !== CODE_BODY_LENGTH) {
    throw new Error('readable code derivation is broken');
  }
  return `${prefix}${(out.match(/.{1,4}/g) ?? []).join('-')}`;
}
