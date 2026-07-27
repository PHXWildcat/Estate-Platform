/**
 * The 2SKD derivation is checked against `node:crypto` - an independent
 * (OpenSSL) implementation of PBKDF2, HKDF and AES-GCM - rather than against
 * hand-copied test vectors. A mistyped vector can agree with a bug; two
 * independent implementations agreeing cannot.
 */
import { createDecipheriv, createHmac, hkdfSync, pbkdf2Sync } from 'node:crypto';

import { seal } from '../src/aead';
import { toBase64, utf8, xorBytes } from '../src/bytes';
import {
  assertSupportedKdfParams,
  defaultKdfParams,
  deriveKeysetAuthKey,
  deriveVaultKeys,
  hmacSha256,
  MAX_ITERATIONS,
  MIN_ITERATIONS,
  VaultParameterError,
} from '../src/kdf';
import { masterKeyAad } from '../src/keyset';

const USER_ID = '3f1a0b7e-4c1d-4a55-9f2e-2c8d5f0a1b33';
const PASSWORD = 'correct horse battery staple';
const SECRET_KEY = Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 1);
const AUK_SALT = Uint8Array.from({ length: 16 }, (_, i) => 200 - i);
const SRP_SALT = Uint8Array.from({ length: 16 }, (_, i) => i + 40);
// The floor rather than the default: every derivation here costs real time and
// the construction under test is identical either way.
const ITERATIONS = MIN_ITERATIONS;

function nodeHkdf(ikm: Uint8Array, salt: Uint8Array, info: string): Uint8Array {
  return new Uint8Array(hkdfSync('sha256', ikm, salt, utf8(info), 32));
}

/** An independent transcription of the construction documented in kdf.ts. */
function referenceDerivation(): { auk: Uint8Array; srpX: Uint8Array } {
  const saltPrime = nodeHkdf(utf8(USER_ID), AUK_SALT, 'estate.vault.2skd.salt.v1');
  const passwordKey = new Uint8Array(
    pbkdf2Sync(PASSWORD.normalize('NFKD'), saltPrime, ITERATIONS, 32, 'sha256'),
  );
  const secretKeyPart = nodeHkdf(SECRET_KEY, utf8(USER_ID), 'estate.vault.2skd.sk.v1');
  const base = xorBytes(passwordKey, secretKeyPart);
  return {
    auk: nodeHkdf(base, AUK_SALT, 'estate.vault.auk.v1'),
    srpX: nodeHkdf(base, SRP_SALT, 'estate.vault.srp-x.v1'),
  };
}

describe('deriveVaultKeys (2SKD)', () => {
  const params = defaultKdfParams(toBase64(AUK_SALT), ITERATIONS);

  it('derives the SRP private key exactly as an independent implementation does', async () => {
    const keys = await deriveVaultKeys({
      userId: USER_ID,
      password: PASSWORD,
      secretKey: SECRET_KEY,
      kdfParams: params,
      srpSalt: SRP_SALT,
    });
    expect(Buffer.from(keys.srpX)).toEqual(Buffer.from(referenceDerivation().srpX));
  });

  it('derives an unlock key an independent implementation can decrypt with', async () => {
    const keys = await deriveVaultKeys({
      userId: USER_ID,
      password: PASSWORD,
      secretKey: SECRET_KEY,
      kdfParams: params,
      srpSalt: SRP_SALT,
    });
    const plaintext = Uint8Array.from([1, 2, 3, 4, 5]);
    const aad = masterKeyAad(USER_ID);
    const sealed = await seal(keys.auk, plaintext, aad);

    // Take our envelope apart by hand and let OpenSSL do the decryption.
    const nonce = sealed.subarray(1, 13);
    const body = sealed.subarray(13);
    const tag = body.subarray(body.length - 16);
    const ciphertext = body.subarray(0, body.length - 16);

    const decipher = createDecipheriv('aes-256-gcm', referenceDerivation().auk, nonce);
    decipher.setAAD(Buffer.from(utf8(aad)));
    decipher.setAuthTag(tag);
    const opened = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    expect(opened).toEqual(Buffer.from(plaintext));
  });

  it('changes the derived key when any single input changes', async () => {
    const derive = (overrides: {
      userId?: string;
      password?: string;
      secretKey?: Uint8Array;
      srpSalt?: Uint8Array;
    }): Promise<Uint8Array> =>
      deriveVaultKeys({
        userId: overrides.userId ?? USER_ID,
        password: overrides.password ?? PASSWORD,
        secretKey: overrides.secretKey ?? SECRET_KEY,
        kdfParams: params,
        srpSalt: overrides.srpSalt ?? SRP_SALT,
      }).then((keys) => keys.srpX);

    const baseline = Buffer.from(await derive({}));
    const variants = await Promise.all([
      derive({ userId: '00000000-0000-4000-8000-000000000000' }),
      derive({ password: 'correct horse battery stapl3' }),
      derive({ secretKey: new Uint8Array(16) }),
      derive({ srpSalt: new Uint8Array(16) }),
    ]);
    for (const variant of variants) {
      expect(Buffer.from(variant)).not.toEqual(baseline);
    }
  });

  it('normalizes the password so the same characters derive the same key', async () => {
    // Precomposed U+00E9 vs "e" + combining acute U+0301: identical to the
    // user, different bytes. Someone who enrolls on one platform has to be able
    // to unlock on another.
    const derive = (password: string): Promise<Uint8Array> =>
      deriveVaultKeys({
        userId: USER_ID,
        password,
        secretKey: SECRET_KEY,
        kdfParams: params,
        srpSalt: SRP_SALT,
      }).then((keys) => keys.srpX);

    // Written as escapes because the difference is invisible in a source file.
    const precomposed = 'caf\u00e9';
    const decomposedText = 'cafe\u0301';
    expect(precomposed).not.toEqual(decomposedText);

    const composed = await derive(precomposed);
    const decomposed = await derive(decomposedText);
    expect(composed).not.toBe(decomposed);
    expect(Buffer.from(composed)).toEqual(Buffer.from(decomposed));
  });
});

describe('assertSupportedKdfParams', () => {
  const valid = defaultKdfParams(toBase64(AUK_SALT));

  it('accepts the one supported profile', () => {
    expect(assertSupportedKdfParams({ ...valid })).toEqual(valid);
  });

  it.each([
    ['a lowered iteration count', { iterations: MIN_ITERATIONS - 1 }],
    ['an absurd iteration count', { iterations: MAX_ITERATIONS + 1 }],
    ['a fractional iteration count', { iterations: 700_000.5 }],
    ['a non-numeric iteration count', { iterations: '650000' }],
    ['a substituted SRP group', { srpGroup: 'rfc5054-1024' }],
    ['a substituted cipher', { cipher: 'aes-128-gcm' }],
    ['a substituted KDF', { alg: 'pbkdf2-sha1' }],
    ['an unknown version', { v: 2 }],
    ['a short salt', { aukSalt: toBase64(new Uint8Array(8)) }],
    ['a non-base64 salt', { aukSalt: 'not base64!' }],
    ['a non-string salt', { aukSalt: 12345 }],
    ['a missing salt', { aukSalt: undefined }],
  ])('rejects %s from the server', (_label, override) => {
    expect(() => assertSupportedKdfParams({ ...valid, ...override })).toThrow(VaultParameterError);
  });

  it.each([[null], [undefined], ['string'], [42], [[]]])('rejects %p', (value) => {
    expect(() => assertSupportedKdfParams(value)).toThrow(VaultParameterError);
  });
});

describe('deriveKeysetAuthKey', () => {
  it('is bound to both the session key and the vault session id', async () => {
    const sessionKey = Uint8Array.from({ length: 32 }, (_, i) => i);
    const a = await deriveKeysetAuthKey(sessionKey, 'session-a');
    const b = await deriveKeysetAuthKey(sessionKey, 'session-b');
    const c = await deriveKeysetAuthKey(new Uint8Array(32), 'session-a');

    expect(a).toHaveLength(32);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
    expect(Buffer.from(a)).not.toEqual(Buffer.from(c));
    expect(Buffer.from(await deriveKeysetAuthKey(sessionKey, 'session-a'))).toEqual(Buffer.from(a));
  });
});

describe('hmacSha256', () => {
  it('matches node:crypto', async () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i * 3);
    const message = utf8('estate vault');
    const expected = createHmac('sha256', key).update(message).digest();
    expect(Buffer.from(await hmacSha256(key, message))).toEqual(expected);
  });
});
