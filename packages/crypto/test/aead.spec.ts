import { randomBytes } from 'node:crypto';
import { AEAD_VERSION, KEY_LENGTH, open, seal } from '../src/aead';
import { DecryptionFailedError } from '../src/errors';

const key = randomBytes(KEY_LENGTH);
const aad = Buffer.from('estate.field.v1|user-1|email');

describe('aead seal/open', () => {
  it('round-trips plaintext', () => {
    const pt = Buffer.from('alice@example.com', 'utf8');
    const sealed = seal(key, pt, aad);
    expect(open(key, sealed, aad)).toEqual(pt);
  });

  it('round-trips empty and binary plaintext', () => {
    for (const pt of [Buffer.alloc(0), randomBytes(1024)]) {
      expect(open(key, seal(key, pt, aad), aad)).toEqual(pt);
    }
  });

  it('emits the versioned wire format with a fresh IV per call', () => {
    const pt = Buffer.from('same plaintext');
    const a = seal(key, pt, aad);
    const b = seal(key, pt, aad);
    expect(a[0]).toBe(AEAD_VERSION);
    expect(a.equals(b)).toBe(false); // random IV ⇒ no deterministic ciphertext
  });

  it('rejects tampered ciphertext', () => {
    const sealed = seal(key, Buffer.from('secret'), aad);
    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1]! ^= 0x01;
    expect(() => open(key, tampered, aad)).toThrow(DecryptionFailedError);
  });

  it('rejects a tampered auth tag', () => {
    const sealed = seal(key, Buffer.from('secret'), aad);
    const tampered = Buffer.from(sealed);
    tampered[5]! ^= 0x01; // inside IV/tag header region
    expect(() => open(key, tampered, aad)).toThrow(DecryptionFailedError);
  });

  it('rejects the wrong AAD (context binding)', () => {
    const sealed = seal(key, Buffer.from('secret'), aad);
    const otherContext = Buffer.from('estate.field.v1|user-1|ssn');
    expect(() => open(key, sealed, otherContext)).toThrow(DecryptionFailedError);
  });

  it('rejects the wrong key', () => {
    const sealed = seal(key, Buffer.from('secret'), aad);
    expect(() => open(randomBytes(KEY_LENGTH), sealed, aad)).toThrow(DecryptionFailedError);
  });

  it('rejects truncated, garbage, and unknown-version input', () => {
    expect(() => open(key, Buffer.alloc(0), aad)).toThrow(DecryptionFailedError);
    expect(() => open(key, randomBytes(10), aad)).toThrow(DecryptionFailedError);
    const sealed = seal(key, Buffer.from('secret'), aad);
    const wrongVersion = Buffer.from(sealed);
    wrongVersion[0] = 0x7f;
    expect(() => open(key, wrongVersion, aad)).toThrow(DecryptionFailedError);
  });

  it('never leaks plaintext or ciphertext in error messages', () => {
    const sealed = seal(key, Buffer.from('super-secret-value'), aad);
    const tampered = Buffer.from(sealed);
    tampered[tampered.length - 1]! ^= 0x01;
    try {
      open(key, tampered, aad);
      throw new Error('expected failure');
    } catch (err) {
      expect((err as Error).message).toBe('decryption failed');
    }
  });

  it('enforces key length', () => {
    expect(() => seal(randomBytes(16), Buffer.from('x'), aad)).toThrow(RangeError);
    expect(() => open(randomBytes(16), Buffer.from('x'), aad)).toThrow(RangeError);
  });
});
