import { bigIntToBytes, bytesToBigInt, constantTimeEqual, modPow } from '../src/bigint';
import {
  concatBytes,
  fromBase64,
  randomBytes,
  sha256,
  toBase64,
  utf8,
  wipe,
  xorBytes,
} from '../src/bytes';

describe('byte helpers', () => {
  it('round-trips base64', () => {
    const bytes = randomBytes(48);
    expect(Buffer.from(fromBase64(toBase64(bytes)))).toEqual(Buffer.from(bytes));
  });

  it('matches node base64', () => {
    const bytes = randomBytes(31);
    expect(toBase64(bytes)).toBe(Buffer.from(bytes).toString('base64'));
  });

  it.each([
    ['a bad character', 'not base64!'],
    ['a bad length', 'abcde'],
  ])('rejects %s rather than decoding garbage', (_label, text) => {
    expect(() => fromBase64(text)).toThrow(TypeError);
  });

  it('concatenates in order', () => {
    expect(Buffer.from(concatBytes(utf8('ab'), utf8('cd'), utf8('e')))).toEqual(
      Buffer.from(utf8('abcde')),
    );
    expect(concatBytes()).toHaveLength(0);
  });

  it('xors equal-length buffers and refuses unequal ones', () => {
    expect(
      Buffer.from(xorBytes(Uint8Array.from([0xf0, 0x0f]), Uint8Array.from([0xff, 0xff]))),
    ).toEqual(Buffer.from(Uint8Array.from([0x0f, 0xf0])));
    expect(() => xorBytes(new Uint8Array(2), new Uint8Array(3))).toThrow(RangeError);
  });

  it('wipes buffers', () => {
    const secret = randomBytes(16);
    wipe(secret);
    expect(Buffer.from(secret)).toEqual(Buffer.alloc(16));
  });

  it('hashes like node:crypto', async () => {
    const { createHash } = await import('node:crypto');
    const a = utf8('estate');
    const b = utf8('vault');
    expect(Buffer.from(await sha256(a, b))).toEqual(
      createHash('sha256')
        .update(Buffer.concat([a, b]))
        .digest(),
    );
  });

  it('returns different random bytes each call', () => {
    expect(Buffer.from(randomBytes(32))).not.toEqual(Buffer.from(randomBytes(32)));
  });
});

describe('bigint helpers', () => {
  it('round-trips big-endian conversions', () => {
    const bytes = randomBytes(64);
    expect(Buffer.from(bigIntToBytes(bytesToBigInt(bytes), 64))).toEqual(Buffer.from(bytes));
  });

  it('left-pads to the requested width', () => {
    expect(Buffer.from(bigIntToBytes(1n, 4))).toEqual(Buffer.from([0, 0, 0, 1]));
  });

  it.each([
    ['a value that does not fit', (): Uint8Array => bigIntToBytes(256n, 1)],
    ['a negative value', (): Uint8Array => bigIntToBytes(-1n, 4)],
  ])('rejects %s', (_label, act) => {
    expect(act).toThrow(RangeError);
  });

  it('computes modular exponentiation', () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
    expect(modPow(5n, 0n, 7n)).toBe(1n);
    expect(modPow(-3n, 3n, 7n)).toBe(modPow(4n, 3n, 7n));
  });

  it.each([
    ['a non-positive modulus', (): bigint => modPow(2n, 2n, 0n)],
    ['a negative exponent', (): bigint => modPow(2n, -1n, 7n)],
  ])('rejects %s', (_label, act) => {
    expect(act).toThrow(RangeError);
  });

  it('compares in constant time', () => {
    const a = randomBytes(32);
    expect(constantTimeEqual(a, Uint8Array.from(a))).toBe(true);
    expect(constantTimeEqual(a, randomBytes(32))).toBe(false);
    expect(constantTimeEqual(a, randomBytes(31))).toBe(false);
  });
});
