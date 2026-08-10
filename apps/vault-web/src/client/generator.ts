/**
 * The password generator (docs/00 §7).
 *
 * Forty lines and no dependency, which is why it ships in M15 while autofill,
 * attachments and family sharing do not: creating a password item without a
 * generator reliably produces a weak password, so the omission would not be
 * neutral.
 *
 * `crypto.getRandomValues` and REJECTION SAMPLING. The obvious `% alphabet.length`
 * is biased whenever 256 is not a multiple of the alphabet size — for the 74-character
 * set below that makes the first 34 characters about 1.35× likelier than the rest,
 * which is a real (if modest) loss of entropy in the one place this app exists to
 * produce it. Discarding out-of-range bytes costs a handful of extra draws.
 */

/**
 * Deliberately excludes nothing for "readability": a generated password is
 * copied, not retyped, so the ambiguous-character folding M13's link code and
 * M14's verification code need would only shrink the space for no benefit.
 * Symbols are included because sites that reject them are rarer than sites that
 * require them.
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.!@#$%^&*';

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;
export const DEFAULT_LENGTH = 24;

export class GeneratorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GeneratorError';
  }
}

export function generatePassword(length: number = DEFAULT_LENGTH): string {
  if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
    // Throws rather than clamping: silently generating a shorter password than
    // asked for is the kind of helpfulness that costs entropy without telling
    // anyone (the M10 `moneyToCents` lesson — validate, do not guess).
    throw new GeneratorError(`length must be between ${MIN_LENGTH} and ${MAX_LENGTH}`);
  }

  // The largest multiple of the alphabet size that fits in a byte. Anything at
  // or above it is discarded rather than folded.
  const limit = Math.floor(256 / ALPHABET.length) * ALPHABET.length;
  const out: string[] = [];
  const buffer = new Uint8Array(length);

  while (out.length < length) {
    crypto.getRandomValues(buffer);
    for (const byte of buffer) {
      if (byte >= limit) {
        continue; // biased draw, discarded
      }
      out.push(ALPHABET[byte % ALPHABET.length] as string);
      if (out.length === length) {
        break;
      }
    }
  }
  buffer.fill(0);
  return out.join('');
}

/** Bits of entropy in a generated password of this length, for the UI to state. */
export function entropyBits(length: number): number {
  return Math.floor(length * Math.log2(ALPHABET.length));
}
