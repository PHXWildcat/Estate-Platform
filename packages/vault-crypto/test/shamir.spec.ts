import { randomBytes } from '../src/bytes';
import {
  combine,
  decodeShare,
  encodeShare,
  gfDiv,
  gfMul,
  MAX_SHARES,
  ShamirError,
  split,
} from '../src/shamir';

describe('GF(2^8) field arithmetic', () => {
  it('has 0 as an absorbing element and 1 as the identity', () => {
    for (let a = 0; a < 256; a += 1) {
      expect(gfMul(a, 0)).toBe(0);
      expect(gfMul(0, a)).toBe(0);
      expect(gfMul(a, 1)).toBe(a);
      expect(gfMul(1, a)).toBe(a);
    }
  });

  it('is commutative and closed over the whole field', () => {
    // Assert once over the whole table rather than 65k times: a per-pair
    // expect() makes this test take half a minute for no extra information.
    const violations: string[] = [];
    for (let a = 0; a < 256; a += 1) {
      for (let b = 0; b < 256; b += 1) {
        const product = gfMul(a, b);
        if (product !== gfMul(b, a)) violations.push(`commutativity at ${a},${b}`);
        if (product < 0 || product > 255) violations.push(`closure at ${a},${b}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it('is associative and distributes over XOR', () => {
    for (let i = 0; i < 256; i += 1) {
      const a = (i * 7 + 1) & 0xff;
      const b = (i * 31 + 5) & 0xff;
      const c = (i * 97 + 13) & 0xff;
      expect(gfMul(gfMul(a, b), c)).toBe(gfMul(a, gfMul(b, c)));
      expect(gfMul(a, b ^ c)).toBe(gfMul(a, b) ^ gfMul(a, c));
    }
  });

  it('divides as the exact inverse of multiplication', () => {
    const violations: string[] = [];
    for (let a = 0; a < 256; a += 1) {
      for (let b = 1; b < 256; b += 1) {
        if (gfDiv(gfMul(a, b), b) !== a) violations.push(`${a}/${b}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it('refuses division by zero', () => {
    expect(() => gfDiv(5, 0)).toThrow(ShamirError);
  });

  it('divides zero by anything to zero', () => {
    for (let b = 1; b < 256; b += 1) expect(gfDiv(0, b)).toBe(0);
  });
});

const SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) % 256);

function subset<T>(items: readonly T[], count: number): T[] {
  return items.slice(0, count);
}

describe('shamir over GF(256)', () => {
  it('reconstructs from exactly the threshold', () => {
    const shares = split(SECRET, { shares: 5, threshold: 3 });
    expect(Buffer.from(combine(subset(shares, 3)))).toEqual(Buffer.from(SECRET));
  });

  it('reconstructs from more than the threshold', () => {
    const shares = split(SECRET, { shares: 5, threshold: 3 });
    expect(Buffer.from(combine(shares))).toEqual(Buffer.from(SECRET));
  });

  it('reconstructs from any combination, not just the first ones', () => {
    const shares = split(SECRET, { shares: 5, threshold: 2 });
    const combinations: Array<[number, number]> = [
      [0, 1],
      [0, 4],
      [2, 3],
      [1, 4],
      [3, 4],
    ];
    for (const [a, b] of combinations) {
      expect(Buffer.from(combine([shares[a]!, shares[b]!]))).toEqual(Buffer.from(SECRET));
    }
  });

  it('yields nothing from fewer than the threshold', () => {
    const shares = split(SECRET, { shares: 5, threshold: 3 });
    // Under the threshold the scheme is information-theoretically secure: the
    // interpolation still produces bytes, they are just unrelated to the secret.
    expect(Buffer.from(combine(subset(shares, 2)))).not.toEqual(Buffer.from(SECRET));
  });

  it('supports threshold 1, the product default', () => {
    const shares = split(SECRET, { shares: 3, threshold: 1 });
    for (const share of shares) {
      expect(Buffer.from(combine([share]))).toEqual(Buffer.from(SECRET));
    }
  });

  it('supports n-of-n', () => {
    const shares = split(SECRET, { shares: 4, threshold: 4 });
    expect(Buffer.from(combine(shares))).toEqual(Buffer.from(SECRET));
    expect(Buffer.from(combine(subset(shares, 3)))).not.toEqual(Buffer.from(SECRET));
  });

  it('produces different shares on every split', () => {
    const first = split(SECRET, { shares: 3, threshold: 2 });
    const second = split(SECRET, { shares: 3, threshold: 2 });
    expect(Buffer.from(first[0]!.y)).not.toEqual(Buffer.from(second[0]!.y));
  });

  it('handles every byte value, including zero', () => {
    const secret = Uint8Array.from({ length: 256 }, (_, i) => i % 256);
    const shares = split(secret, { shares: 4, threshold: 2 });
    expect(Buffer.from(combine(subset(shares, 2)))).toEqual(Buffer.from(secret));
  });

  it('round-trips random secrets', () => {
    for (let i = 0; i < 20; i += 1) {
      const secret = randomBytes(32);
      const shares = split(secret, { shares: 5, threshold: 3 });
      expect(Buffer.from(combine(subset(shares, 3)))).toEqual(Buffer.from(secret));
    }
  });

  it('numbers shares from 1, never 0', () => {
    const shares = split(SECRET, { shares: 3, threshold: 2 });
    expect(shares.map((s) => s.x)).toEqual([1, 2, 3]);
  });

  it('supports the maximum share count', () => {
    const shares = split(Uint8Array.from([42]), { shares: MAX_SHARES, threshold: 2 });
    expect(shares).toHaveLength(MAX_SHARES);
    expect(Buffer.from(combine(subset(shares, 2)))).toEqual(Buffer.from([42]));
  });

  it.each([
    ['an empty secret', (): unknown => split(new Uint8Array(0), { shares: 3, threshold: 2 })],
    ['zero shares', (): unknown => split(SECRET, { shares: 0, threshold: 1 })],
    ['too many shares', (): unknown => split(SECRET, { shares: 256, threshold: 2 })],
    [
      'a threshold above the share count',
      (): unknown => split(SECRET, { shares: 2, threshold: 3 }),
    ],
    ['a zero threshold', (): unknown => split(SECRET, { shares: 3, threshold: 0 })],
    ['a fractional threshold', (): unknown => split(SECRET, { shares: 3, threshold: 1.5 })],
  ])('rejects %s', (_label, act) => {
    expect(act).toThrow(ShamirError);
  });

  it.each([
    ['no shares', (): unknown => combine([])],
    [
      'a duplicate index',
      (): unknown => {
        const shares = split(SECRET, { shares: 3, threshold: 2 });
        return combine([shares[0]!, shares[0]!]);
      },
    ],
    [
      'mismatched lengths',
      (): unknown =>
        combine([
          { x: 1, y: new Uint8Array(4) },
          { x: 2, y: new Uint8Array(8) },
        ]),
    ],
    ['a zero index', (): unknown => combine([{ x: 0, y: new Uint8Array(4) }])],
    ['an empty share', (): unknown => combine([{ x: 1, y: new Uint8Array(0) }])],
  ])('refuses to combine %s', (_label, act) => {
    expect(act).toThrow(ShamirError);
  });
});

describe('share encoding', () => {
  it('round-trips', () => {
    const shares = split(SECRET, { shares: 3, threshold: 2 });
    const encoded = encodeShare(shares[1]!);
    expect(encoded).toHaveLength(SECRET.length + 1);
    const decoded = decodeShare(encoded);
    expect(decoded.x).toBe(shares[1]!.x);
    expect(Buffer.from(decoded.y)).toEqual(Buffer.from(shares[1]!.y));
  });

  it('still reconstructs after an encode/decode round trip', () => {
    const shares = split(SECRET, { shares: 4, threshold: 2 }).map((s) =>
      decodeShare(encodeShare(s)),
    );
    expect(Buffer.from(combine(subset(shares, 2)))).toEqual(Buffer.from(SECRET));
  });

  it.each([
    ['a truncated buffer', new Uint8Array(1)],
    ['a zero index', Uint8Array.from([0, 1, 2, 3])],
  ])('rejects %s', (_label, bytes) => {
    expect(() => decodeShare(bytes)).toThrow(ShamirError);
  });
});
