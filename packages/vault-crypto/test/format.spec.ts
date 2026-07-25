import {
  formatSecretKey,
  generateSecretKey,
  parseSecretKey,
  SECRET_KEY_BYTES,
  SecretKeyFormatError,
} from '../src/format';
import { randomBytes } from '../src/bytes';

const PREFIX_LENGTH = 'ES1-'.length;

describe('secret key format', () => {
  it('round-trips generated keys', async () => {
    const text = await generateSecretKey();
    expect(text).toMatch(
      /^ES1-[0-9A-HJKMNP-TV-Z]{7}-[0-9A-HJKMNP-TV-Z]{7}-[0-9A-HJKMNP-TV-Z]{7}-[0-9A-HJKMNP-TV-Z]{7}$/,
    );
    expect(await parseSecretKey(text)).toHaveLength(SECRET_KEY_BYTES);
  });

  it('preserves the entropy exactly', async () => {
    const entropy = randomBytes(SECRET_KEY_BYTES);
    expect(Buffer.from(await parseSecretKey(await formatSecretKey(entropy)))).toEqual(
      Buffer.from(entropy),
    );
  });

  it('generates a different key every time', async () => {
    expect(await generateSecretKey()).not.toBe(await generateSecretKey());
  });

  it('accepts the forms a person actually types', async () => {
    const entropy = randomBytes(SECRET_KEY_BYTES);
    const canonical = await formatSecretKey(entropy);
    const variants = [
      canonical.toLowerCase(),
      canonical.replace(/-/g, ''),
      `  ${canonical}  `,
      canonical.replace(/-/g, ' '),
    ];
    for (const variant of variants) {
      expect(Buffer.from(await parseSecretKey(variant))).toEqual(Buffer.from(entropy));
    }
  });

  it('folds the characters people confuse', async () => {
    const entropy = new Uint8Array(SECRET_KEY_BYTES);
    const canonical = await formatSecretKey(entropy);
    // The all-zero key encodes as all '0's, so typing 'O' must still work.
    const typedWithLetterO = canonical.replace(/0/g, 'O');
    expect(Buffer.from(await parseSecretKey(typedWithLetterO))).toEqual(Buffer.from(entropy));
  });

  it('rejects single mistyped characters', async () => {
    // Fixed entropy so the result is deterministic: the checksum catches about
    // 255 of every 256 single-character errors, and a random vector would make
    // the rare collision a flaky failure instead of a known one.
    const entropy = Uint8Array.from({ length: SECRET_KEY_BYTES }, (_, i) => i * 17 + 3);
    const canonical = await formatSecretKey(entropy);

    const accepted: string[] = [];
    for (let index = PREFIX_LENGTH; index < canonical.length; index += 1) {
      if (canonical[index] === '-') continue;
      for (const replacement of '23456789ABCDEFGHJKMNPQRSTVWXYZ') {
        if (canonical[index] === replacement) continue;
        const mutated = `${canonical.slice(0, index)}${replacement}${canonical.slice(index + 1)}`;
        try {
          await parseSecretKey(mutated);
          accepted.push(mutated);
        } catch {
          // expected
        }
      }
    }
    expect(accepted).toEqual([]);
  });

  it.each([
    ['a missing prefix', 'AB1-1234567-1234567-1234567-1234567'],
    ['a truncated body', 'ES1-1234567-1234567-1234567'],
    ['an overlong body', 'ES1-1234567-1234567-1234567-1234567-1234567'],
    ['an out-of-alphabet character', 'ES1-123456$-1234567-1234567-1234567'],
    ['an empty string', ''],
  ])('rejects %s', async (_label, text) => {
    await expect(parseSecretKey(text)).rejects.toThrow(SecretKeyFormatError);
  });

  it('rejects entropy of the wrong size', async () => {
    await expect(formatSecretKey(randomBytes(8))).rejects.toThrow(SecretKeyFormatError);
  });
});
