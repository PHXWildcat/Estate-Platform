import { randomBytes } from 'node:crypto';
import { KEY_LENGTH } from '../src/aead';
import { blindIndex, emailBlindIndex, normalizeEmail } from '../src/blind-index';

const key = randomBytes(KEY_LENGTH);

describe('blind indexes', () => {
  it('is deterministic for the same key/purpose/value', () => {
    expect(blindIndex(key, 'email.v1', 'a@example.com')).toEqual(
      blindIndex(key, 'email.v1', 'a@example.com'),
    );
  });

  it('differs across values, keys, and purposes (domain separation)', () => {
    const base = blindIndex(key, 'email.v1', 'a@example.com');
    expect(blindIndex(key, 'email.v1', 'b@example.com')).not.toEqual(base);
    expect(blindIndex(randomBytes(KEY_LENGTH), 'email.v1', 'a@example.com')).not.toEqual(base);
    expect(blindIndex(key, 'contact-email.v1', 'a@example.com')).not.toEqual(base);
  });

  it('normalizes email case, whitespace, and unicode compatibility forms', () => {
    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com');
    // full-width characters fold to ASCII under NFKC
    expect(normalizeEmail('ａｌｉｃｅ@example.com')).toBe('alice@example.com');
  });

  it('indexes visually identical emails identically', () => {
    expect(emailBlindIndex(key, ' ALICE@example.com')).toEqual(
      emailBlindIndex(key, 'alice@Example.Com  '),
    );
  });

  it('enforces key length and purpose presence', () => {
    expect(() => blindIndex(randomBytes(16), 'email.v1', 'x')).toThrow(RangeError);
    expect(() => blindIndex(key, '', 'x')).toThrow(RangeError);
  });
});
