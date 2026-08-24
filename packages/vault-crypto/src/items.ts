/**
 * Vault item envelopes: what the server stores in `vault_items.blob_ct`.
 *
 * Every item gets its own random content key, wrapped by the master key inside
 * the same blob. The extra 61 bytes per item buy two things the vault needs
 * later: emergency-access scope limits (docs/03 §5.2 — granting a contact a
 * subset of the vault means handing over some item keys, not the master key)
 * and master-key rotation that rewraps keys instead of re-encrypting content.
 *
 * Blob layout: [1B version][2B wrapped-key length BE][wrapped item key][sealed content]
 *
 * Both ciphertexts are bound to context by AAD, and the two AADs are
 * domain-separated: a wrapped item key and any other 32-byte secret wrapped
 * under the same master key can never be substituted for one another by a
 * server that never sees either in the clear.
 */

import {
  generateAesKey,
  open,
  seal,
  unwrapAesKey,
  VaultCryptoError,
  VaultDecryptionError,
} from './aead.js';

export const ITEM_BLOB_VERSION = 0x01;
const HEADER_LENGTH = 3;

export interface VaultItemRef {
  readonly userId: string;
  readonly itemId: string;
  /** `vault_items.blob_version`: 1 on create, N+1 on an update of version N. */
  readonly blobVersion: number;
}

export function itemKeyAad(userId: string, itemId: string): string {
  return `estate.vault.wrap.itemkey.v1|${userId}|${itemId}`;
}

export function itemContentAad(ref: VaultItemRef): string {
  return `estate.vault.item.v1|${ref.userId}|${ref.itemId}|${ref.blobVersion}`;
}

function assertRef(ref: VaultItemRef): void {
  if (!Number.isInteger(ref.blobVersion) || ref.blobVersion < 1) {
    throw new VaultCryptoError('blob version must be a positive integer');
  }
}

export async function encryptItem(
  masterKey: CryptoKey,
  ref: VaultItemRef,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  assertRef(ref);
  // Extractable so the raw bytes can be wrapped; the key exists only for the
  // duration of this call and is never returned to the caller.
  const itemKey = await generateAesKey(['encrypt', 'decrypt'], true);
  const rawItemKey = new Uint8Array(await crypto.subtle.exportKey('raw', itemKey));
  try {
    const wrapped = await seal(masterKey, rawItemKey, itemKeyAad(ref.userId, ref.itemId));
    const content = await seal(itemKey, plaintext, itemContentAad(ref));
    if (wrapped.length > 0xffff) throw new VaultCryptoError('wrapped key too large');

    const blob = new Uint8Array(HEADER_LENGTH + wrapped.length + content.length);
    blob[0] = ITEM_BLOB_VERSION;
    blob[1] = (wrapped.length >> 8) & 0xff;
    blob[2] = wrapped.length & 0xff;
    blob.set(wrapped, HEADER_LENGTH);
    blob.set(content, HEADER_LENGTH + wrapped.length);
    return blob;
  } finally {
    rawItemKey.fill(0);
  }
}

export async function decryptItem(
  masterKey: CryptoKey,
  ref: VaultItemRef,
  blob: Uint8Array,
): Promise<Uint8Array> {
  assertRef(ref);
  if (blob.length < HEADER_LENGTH || blob[0] !== ITEM_BLOB_VERSION)
    throw new VaultDecryptionError();

  // Indexes 1 and 2 exist: the header length was just checked.
  const wrappedLength = (blob[1]! << 8) | blob[2]!;
  const contentStart = HEADER_LENGTH + wrappedLength;
  if (contentStart > blob.length) throw new VaultDecryptionError();

  /*
   * `['decrypt']`, NOT `['encrypt', 'decrypt']` (M27 PR3b review).
   *
   * This function only ever calls `open`, so the `encrypt` usage was never
   * used — but granting it had a consequence one zone up. M27 PR3b hands a
   * grantee the owner's master key with `['decrypt', 'unwrapKey']` and claims
   * that "a key the platform refuses to encrypt with cannot be talked into
   * sealing a blob into somebody else's Zone A — the browser enforces that".
   * The browser did NOT enforce it: `unwrapKey` is genuinely required to open
   * an item, and this call handed back a per-item key that COULD seal. So the
   * granted key did yield keys that produce valid owner ciphertext, and the
   * only thing standing in the way was that no route accepts such a blob from
   * a grantee.
   *
   * Narrowing here makes the platform guarantee real rather than incidental.
   * Nothing needs the wider set: `encryptItem` GENERATES a fresh item key and
   * never unwraps one, so this is the only unwrap of an item key in the tree.
   */
  const itemKey = await unwrapAesKey(
    masterKey,
    blob.subarray(HEADER_LENGTH, contentStart),
    itemKeyAad(ref.userId, ref.itemId),
    ['decrypt'],
  );
  return open(itemKey, blob.subarray(contentStart), itemContentAad(ref));
}
