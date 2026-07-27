import { createHash } from 'node:crypto';
import { generateOpaqueToken, hashToken, TOKEN_BYTES, tokenHashEquals } from '../src/tokens';

describe('vault session tokens', () => {
  it('generates high-entropy opaque tokens', () => {
    const token = generateOpaqueToken();
    expect(Buffer.from(token, 'base64url')).toHaveLength(TOKEN_BYTES);
    expect(token).not.toBe(generateOpaqueToken());
  });

  it('stores only a digest', () => {
    const token = generateOpaqueToken();
    const hash = hashToken(token);
    expect(hash).toEqual(createHash('sha256').update(token).digest());
    expect(hash.toString('base64url')).not.toContain(token);
  });

  it('compares digests without leaking length or content', () => {
    const token = generateOpaqueToken();
    expect(tokenHashEquals(hashToken(token), hashToken(token))).toBe(true);
    expect(tokenHashEquals(hashToken(token), hashToken(generateOpaqueToken()))).toBe(false);
    expect(tokenHashEquals(hashToken(token), Buffer.alloc(16))).toBe(false);
  });
});
