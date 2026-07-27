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
