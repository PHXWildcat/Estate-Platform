import {
  ENVELOPE_VERSION,
  generateAesKey,
  importAesKey,
  NONCE_LENGTH,
  open,
  seal,
  unwrapAesKey,
  VaultCryptoError,
  VaultDecryptionError,
} from '../src/aead';
import { randomBytes, utf8 } from '../src/bytes';

const AAD = 'estate.vault.test.v1|user|item';

describe('seal / open', () => {
  it('round-trips under the same key and AAD', async () => {
    const key = await generateAesKey();
    const plaintext = utf8('seed phrase: correct horse battery staple');
    const sealed = await seal(key, plaintext, AAD);
    expect(Buffer.from(await open(key, sealed, AAD))).toEqual(Buffer.from(plaintext));
  });

  it('produces a versioned envelope with a fresh nonce each time', async () => {
    const key = await generateAesKey();
    const first = await seal(key, utf8('x'), AAD);
    const second = await seal(key, utf8('x'), AAD);

    expect(first[0]).toBe(ENVELOPE_VERSION);
    expect(Buffer.from(first.subarray(1, 1 + NONCE_LENGTH))).not.toEqual(
      Buffer.from(second.subarray(1, 1 + NONCE_LENGTH)),
    );
    expect(Buffer.from(first)).not.toEqual(Buffer.from(second));
  });

  it('fails closed on a different AAD', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, utf8('x'), AAD);
    await expect(open(key, sealed, `${AAD}!`)).rejects.toThrow(VaultDecryptionError);
  });

  it('fails closed on a different key', async () => {
    const sealed = await seal(await generateAesKey(), utf8('x'), AAD);
    await expect(open(await generateAesKey(), sealed, AAD)).rejects.toThrow(VaultDecryptionError);
  });

  it('fails closed on tampered ciphertext', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, utf8('x'), AAD);
    sealed.set([sealed[sealed.length - 1]! ^ 0x01], sealed.length - 1);
    await expect(open(key, sealed, AAD)).rejects.toThrow(VaultDecryptionError);
  });

  it('fails closed on a tampered nonce', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, utf8('x'), AAD);
    sealed.set([sealed[1]! ^ 0x01], 1);
    await expect(open(key, sealed, AAD)).rejects.toThrow(VaultDecryptionError);
  });

  it.each([
    ['an unknown envelope version', (sealed: Uint8Array) => (sealed[0] = 0x02)],
    ['a truncated envelope', null],
  ])('rejects %s', async (_label, mutate) => {
    const key = await generateAesKey();
    const sealed = await seal(key, utf8('x'), AAD);
    if (mutate) {
      mutate(sealed);
      await expect(open(key, sealed, AAD)).rejects.toThrow(VaultDecryptionError);
    } else {
      await expect(open(key, sealed.subarray(0, 10), AAD)).rejects.toThrow(VaultDecryptionError);
    }
  });

  it('never reveals which check failed', async () => {
    const key = await generateAesKey();
    const sealed = await seal(key, utf8('x'), AAD);
    const wrongKey = open(await generateAesKey(), sealed, AAD).catch((err: Error) => err.message);
    const wrongAad = open(key, sealed, 'other').catch((err: Error) => err.message);
    expect(await wrongKey).toBe(await wrongAad);
  });
});

describe('importAesKey', () => {
  it('rejects a key of the wrong length', async () => {
    await expect(importAesKey(randomBytes(16))).rejects.toThrow(VaultCryptoError);
  });

  it('produces a non-extractable key by default', async () => {
    const key = await importAesKey(randomBytes(32));
    expect(key.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  });

  it('can opt in to an extractable key for the rotation path', async () => {
    const raw = randomBytes(32);
    const key = await importAesKey(raw, ['encrypt', 'decrypt'], true);
    expect(Buffer.from(new Uint8Array(await crypto.subtle.exportKey('raw', key)))).toEqual(
      Buffer.from(raw),
    );
  });
});

describe('unwrapAesKey', () => {
  it('unwraps into a usable, non-extractable key', async () => {
    const wrappingKey = await generateAesKey();
    const inner = randomBytes(32);
    const wrapped = await seal(wrappingKey, inner, AAD);

    const unwrapped = await unwrapAesKey(wrappingKey, wrapped, AAD, ['encrypt', 'decrypt']);
    expect(unwrapped.extractable).toBe(false);

    // Usable: it decrypts what the same raw key encrypted.
    const reference = await importAesKey(inner, ['encrypt', 'decrypt'], false);
    const sealed = await seal(reference, utf8('hello'), AAD);
    expect(Buffer.from(await open(unwrapped, sealed, AAD))).toEqual(Buffer.from(utf8('hello')));
  });

  it('fails closed on the wrong AAD', async () => {
    const wrappingKey = await generateAesKey();
    const wrapped = await seal(wrappingKey, randomBytes(32), AAD);
    await expect(unwrapAesKey(wrappingKey, wrapped, 'other')).rejects.toThrow(VaultDecryptionError);
  });

  it('rejects a malformed envelope', async () => {
    const wrappingKey = await generateAesKey();
    await expect(unwrapAesKey(wrappingKey, new Uint8Array(4), AAD)).rejects.toThrow(
      VaultDecryptionError,
    );
  });
});
