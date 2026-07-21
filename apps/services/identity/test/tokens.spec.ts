import { generateOpaqueToken, hashToken, tokenHashEquals } from '../src/tokens';

describe('opaque tokens', () => {
  it('generates 32-byte base64url tokens with no padding or URL-hostile chars', () => {
    const token = generateOpaqueToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
  });

  it('generates unique tokens', () => {
    const seen = new Set(Array.from({ length: 100 }, () => generateOpaqueToken()));
    expect(seen.size).toBe(100);
  });

  it('hashes deterministically to 32 bytes (sha256)', () => {
    const token = generateOpaqueToken();
    const h1 = hashToken(token);
    const h2 = hashToken(token);
    expect(h1).toHaveLength(32);
    expect(h1.equals(h2)).toBe(true);
  });

  it('different tokens hash differently', () => {
    expect(hashToken(generateOpaqueToken()).equals(hashToken(generateOpaqueToken()))).toBe(false);
  });

  it('never stores or compares the raw token (hash is not the token bytes)', () => {
    const token = generateOpaqueToken();
    expect(hashToken(token).equals(Buffer.from(token, 'base64url'))).toBe(false);
  });

  it('tokenHashEquals compares in constant time semantics (equal/unequal/length-mismatch)', () => {
    const a = hashToken('a');
    expect(tokenHashEquals(a, hashToken('a'))).toBe(true);
    expect(tokenHashEquals(a, hashToken('b'))).toBe(false);
    expect(tokenHashEquals(a, a.subarray(0, 16))).toBe(false);
  });
});
