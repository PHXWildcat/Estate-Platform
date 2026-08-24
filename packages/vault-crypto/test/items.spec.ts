import { generateAesKey, VaultCryptoError, VaultDecryptionError } from '../src/aead';
import { utf8 } from '../src/bytes';
import { decryptItem, encryptItem, itemContentAad, itemKeyAad, VaultItemRef } from '../src/items';

const REF: VaultItemRef = {
  userId: 'e2b0c8a1-9d3f-4c77-8a12-5b6d7e8f9a0b',
  itemId: '11111111-2222-4333-8444-555555555555',
  blobVersion: 1,
};
const SECRET = utf8('bank login: hunter2');

describe('vault item envelopes', () => {
  it('round-trips under the master key', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, SECRET);
    expect(Buffer.from(await decryptItem(masterKey, REF, blob))).toEqual(Buffer.from(SECRET));
  });

  /*
   * A READ-ONLY MASTER KEY MUST NOT YIELD A WRITING ITEM KEY (M27 PR3b review).
   *
   * M27 PR3b hands a grantee the owner's master key as
   * `['decrypt', 'unwrapKey']` and rests on the claim that the browser will not
   * let such a key seal anything into the owner's vault. `unwrapKey` is
   * genuinely required to open an item, so the claim only holds if the key that
   * comes BACK out of the unwrap cannot encrypt either — and it could, because
   * `decryptItem` asked for `['encrypt', 'decrypt']` while only ever
   * decrypting. This is the test that makes the claim checkable instead of
   * asserted, driven through the real `decryptItem` rather than by inspecting
   * the source.
   */
  it('a read-only master key cannot produce an item key that seals', async () => {
    const ownerKey = await generateAesKey(['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], true);
    const blob = await encryptItem(ownerKey, REF, SECRET);

    // Exactly what `VaultSession.collectGrant` imports for a grantee: the
    // owner's own key bytes, re-imported read-only and non-extractable.
    const grantedKey = await crypto.subtle.importKey(
      'raw',
      await crypto.subtle.exportKey('raw', ownerKey),
      'AES-GCM',
      false,
      ['decrypt', 'unwrapKey'],
    );

    // WHAT DECRYPTITEM ASKS FOR, observed rather than re-derived. Wrapping
    // `unwrapKey` is the only way to see the usages without reimplementing the
    // envelope format here, and a reimplementation is a second copy that can
    // agree with itself while both are wrong.
    const realUnwrap = crypto.subtle.unwrapKey.bind(crypto.subtle);
    const seen: KeyUsage[][] = [];
    crypto.subtle.unwrapKey = async (
      format: 'raw',
      wrapped: BufferSource,
      unwrapping: CryptoKey,
      unwrapAlgo: AlgorithmIdentifier,
      unwrappedAlgo: AlgorithmIdentifier,
      ext: boolean,
      usages: KeyUsage[],
    ) => {
      seen.push([...usages]);
      return realUnwrap(format, wrapped, unwrapping, unwrapAlgo, unwrappedAlgo, ext, usages);
    };

    try {
      // THE PAIR THAT MATTERS. Narrowing the usage must not cost the grantee
      // the capability they actually need, so the read still has to work…
      expect(Buffer.from(await decryptItem(grantedKey, REF, blob))).toEqual(Buffer.from(SECRET));
    } finally {
      crypto.subtle.unwrapKey = realUnwrap;
    }

    // ANTI-VACUITY: the wrapper really was called, or the absence below is free.
    expect(seen).toHaveLength(1);
    // …and the item key it produced cannot seal anything back into the vault,
    // which is what makes "the browser enforces it" true rather than asserted.
    expect(seen[0]).toEqual(['decrypt']);
    expect(seen[0]).not.toContain('encrypt');
  });

  it('never contains the plaintext', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, SECRET);
    expect(Buffer.from(blob).includes(Buffer.from(SECRET))).toBe(false);
  });

  it('uses a distinct item key per item, so blobs never repeat', async () => {
    const masterKey = await generateAesKey();
    const first = await encryptItem(masterKey, REF, SECRET);
    const second = await encryptItem(masterKey, REF, SECRET);
    expect(Buffer.from(first)).not.toEqual(Buffer.from(second));
  });

  it('rejects a blob belonging to another item', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, SECRET);
    const otherItem = { ...REF, itemId: '99999999-2222-4333-8444-555555555555' };
    await expect(decryptItem(masterKey, otherItem, blob)).rejects.toThrow(VaultDecryptionError);
  });

  it('rejects a blob belonging to another user', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, SECRET);
    const otherUser = { ...REF, userId: '00000000-0000-4000-8000-000000000000' };
    await expect(decryptItem(masterKey, otherUser, blob)).rejects.toThrow(VaultDecryptionError);
  });

  it('rejects a blob replayed at a different version (anti-rollback)', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, { ...REF, blobVersion: 2 }, SECRET);
    await expect(decryptItem(masterKey, { ...REF, blobVersion: 1 }, blob)).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it('rejects a blob under a different master key', async () => {
    const blob = await encryptItem(await generateAesKey(), REF, SECRET);
    await expect(decryptItem(await generateAesKey(), REF, blob)).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it.each([
    ['a truncated blob', (blob: Uint8Array) => blob.subarray(0, 2)],
    ['an unknown blob version', (blob: Uint8Array) => Uint8Array.from([0x02, ...blob.subarray(1)])],
    [
      'a wrapped-key length past the end',
      (blob: Uint8Array) => Uint8Array.from([blob[0] ?? 1, 0xff, 0xff, ...blob.subarray(3)]),
    ],
  ])('rejects %s', async (_label, mutate) => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, SECRET);
    await expect(decryptItem(masterKey, REF, mutate(blob))).rejects.toThrow(VaultDecryptionError);
  });

  it.each([[0], [-1], [1.5]])('rejects blob version %p', async (blobVersion) => {
    const masterKey = await generateAesKey();
    await expect(encryptItem(masterKey, { ...REF, blobVersion }, SECRET)).rejects.toThrow(
      VaultCryptoError,
    );
  });

  it('handles an empty item body', async () => {
    const masterKey = await generateAesKey();
    const blob = await encryptItem(masterKey, REF, new Uint8Array(0));
    expect(await decryptItem(masterKey, REF, blob)).toHaveLength(0);
  });
});

describe('AAD construction', () => {
  it('separates the content and key-wrap domains', () => {
    expect(itemKeyAad(REF.userId, REF.itemId)).toBe(
      `estate.vault.wrap.itemkey.v1|${REF.userId}|${REF.itemId}`,
    );
    expect(itemContentAad(REF)).toBe(
      `estate.vault.item.v1|${REF.userId}|${REF.itemId}|${REF.blobVersion}`,
    );
    expect(itemKeyAad(REF.userId, REF.itemId)).not.toBe(itemContentAad(REF));
  });

  it('leaves the item key AAD free of the version, so rekeying needs no re-encryption', () => {
    expect(itemKeyAad(REF.userId, REF.itemId)).toBe(itemKeyAad(REF.userId, REF.itemId));
    expect(itemContentAad({ ...REF, blobVersion: 2 })).not.toBe(itemContentAad(REF));
  });
});
