/**
 * The vault keyset: enrollment, unlock, and password change.
 *
 * This module is the client half of the `vault_keysets` row (docs/02 §5). The
 * server stores the SRP verifier, the salts, the KDF parameters, and the master
 * key wrapped by a key it never sees — and can do nothing with any of it.
 */

import { importAesKey, open, seal, unwrapAesKey, VaultCryptoError } from './aead';
import { fromBase64, randomBytes, toBase64, utf8, wipe } from './bytes';
import { constantTimeEqual } from './bigint';
import {
  assertSupportedKdfParams,
  DEFAULT_ITERATIONS,
  defaultKdfParams,
  deriveKeysetAuthKey,
  deriveVaultKeys,
  hmacSha256,
  KdfParams,
  SALT_LENGTH,
} from './kdf';
import { generateSecretKey, parseSecretKey } from './format';
import {
  ClientEphemeral,
  ClientSession,
  computeClientSession,
  computeVerifier,
  createClientEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  srpPrivateKey,
  verifyServerProof,
} from './srp';

export const MASTER_KEY_BYTES = 32;

export function masterKeyAad(userId: string): string {
  return `estate.vault.wrap.master.v1|${userId}`;
}

/** Exactly the fields the server persists in `vault_keysets`. */
export interface VaultKeysetPayload {
  readonly srpSalt: string;
  readonly srpVerifier: string;
  readonly wrappedMasterKey: string;
  readonly kdfParams: KdfParams;
}

export interface VaultEnrollment {
  /**
   * Shown to the user exactly once and never transmitted. Losing it means the
   * vault cannot be unlocked from a new device — that is the design, not a bug.
   */
  readonly secretKey: string;
  readonly payload: VaultKeysetPayload;
}

/**
 * Canonical bytes for the keyset-replacement MAC.
 *
 * The field order is written out rather than derived from `Object.keys`, so the
 * encoding cannot change because someone reordered an interface. Client and
 * server both call this, which is the whole reason it lives in the shared
 * client package.
 */
export function canonicalKeysetPayload(payload: VaultKeysetPayload): Uint8Array {
  const { kdfParams } = payload;
  return utf8(
    JSON.stringify([
      'estate.vault.keyset.v1',
      payload.srpSalt,
      payload.srpVerifier,
      payload.wrappedMasterKey,
      kdfParams.v,
      kdfParams.alg,
      kdfParams.iterations,
      kdfParams.aukSalt,
      kdfParams.srpGroup,
      kdfParams.cipher,
    ]),
  );
}

export async function keysetProof(
  keysetAuthKey: Uint8Array,
  payload: VaultKeysetPayload,
): Promise<string> {
  return toBase64(await hmacSha256(keysetAuthKey, canonicalKeysetPayload(payload)));
}

export async function verifyKeysetProof(
  keysetAuthKey: Uint8Array,
  payload: VaultKeysetPayload,
  proof: string,
): Promise<boolean> {
  let presented: Uint8Array;
  try {
    presented = fromBase64(proof);
  } catch {
    return false;
  }
  const expected = await hmacSha256(keysetAuthKey, canonicalKeysetPayload(payload));
  return constantTimeEqual(expected, presented);
}

async function buildKeyset(input: {
  readonly userId: string;
  readonly password: string;
  readonly secretKey: Uint8Array;
  readonly masterKey: Uint8Array;
  readonly iterations: number;
}): Promise<VaultKeysetPayload> {
  const aukSalt = randomBytes(SALT_LENGTH);
  const srpSalt = randomBytes(SALT_LENGTH);
  const kdfParams = defaultKdfParams(toBase64(aukSalt), input.iterations);

  const keys = await deriveVaultKeys({
    userId: input.userId,
    password: input.password,
    secretKey: input.secretKey,
    kdfParams,
    srpSalt,
  });
  const verifier = computeVerifier(srpPrivateKey(keys.srpX));
  wipe(keys.srpX);

  const wrapped = await seal(keys.auk, input.masterKey, masterKeyAad(input.userId));
  return {
    srpSalt: toBase64(srpSalt),
    srpVerifier: encodeGroupElement(verifier),
    wrappedMasterKey: toBase64(wrapped),
    kdfParams,
  };
}

export async function createVaultEnrollment(input: {
  readonly userId: string;
  readonly password: string;
  readonly iterations?: number;
}): Promise<{ enrollment: VaultEnrollment; masterKey: CryptoKey }> {
  const secretKeyText = await generateSecretKey();
  const secretKey = await parseSecretKey(secretKeyText);
  const masterKeyBytes = randomBytes(MASTER_KEY_BYTES);
  try {
    const payload = await buildKeyset({
      userId: input.userId,
      password: input.password,
      secretKey,
      masterKey: masterKeyBytes,
      iterations: input.iterations ?? DEFAULT_ITERATIONS,
    });
    const masterKey = await importAesKey(masterKeyBytes, [
      'encrypt',
      'decrypt',
      'wrapKey',
      'unwrapKey',
    ]);
    return { enrollment: { secretKey: secretKeyText, payload }, masterKey };
  } finally {
    wipe(masterKeyBytes, secretKey);
  }
}

export interface UnlockPreparation {
  readonly userId: string;
  readonly auk: CryptoKey;
  readonly x: bigint;
  readonly ephemeral: ClientEphemeral;
  readonly srpSalt: Uint8Array;
  /** base64 of the padded client public value, for the wire. */
  readonly publicA: string;
}

/**
 * Derive keys and the SRP client ephemeral from the material the server
 * returned at `POST /v1/vault/srp/start`.
 *
 * `kdfParams` is untyped on the way in on purpose: it arrived from the server,
 * so it goes through `assertSupportedKdfParams` before anything is derived.
 */
export async function prepareUnlock(input: {
  readonly userId: string;
  readonly password: string;
  readonly secretKey: string;
  readonly kdfParams: unknown;
  readonly srpSalt: string;
}): Promise<UnlockPreparation> {
  const kdfParams = assertSupportedKdfParams(input.kdfParams);
  const srpSalt = fromBase64(input.srpSalt);
  if (srpSalt.length !== SALT_LENGTH) throw new VaultCryptoError('invalid srp salt');

  const secretKey = await parseSecretKey(input.secretKey);
  try {
    const keys = await deriveVaultKeys({
      userId: input.userId,
      password: input.password,
      secretKey,
      kdfParams,
      srpSalt,
    });
    const x = srpPrivateKey(keys.srpX);
    wipe(keys.srpX);

    const ephemeral = createClientEphemeral();
    return {
      userId: input.userId,
      auk: keys.auk,
      x,
      ephemeral,
      srpSalt,
      publicA: encodeGroupElement(ephemeral.A),
    };
  } finally {
    wipe(secretKey);
  }
}

/** Compute the client proof M1 for the server's challenge B. */
export async function proveUnlock(
  preparation: UnlockPreparation,
  serverB: string,
): Promise<{ m1: string; session: ClientSession }> {
  const session = await computeClientSession({
    userId: preparation.userId,
    salt: preparation.srpSalt,
    x: preparation.x,
    ephemeral: preparation.ephemeral,
    B: decodeGroupElement(serverB, 'server public value'),
  });
  return { m1: toBase64(session.M1), session };
}

export interface UnlockedVault {
  /** Non-extractable: usable for item crypto, not readable by page script. */
  readonly masterKey: CryptoKey;
  /** Authenticates a later keyset replacement on this vault session. */
  readonly keysetAuthKey: Uint8Array;
}

/**
 * Verify the server's proof, then unwrap the master key.
 *
 * The order matters: M2 is checked first, so a server that could not prove it
 * holds the verifier never gets its `wrappedMasterKey` fed into our unwrap path.
 */
export async function finishUnlock(input: {
  readonly preparation: UnlockPreparation;
  readonly session: ClientSession;
  readonly serverM2: string;
  readonly wrappedMasterKey: string;
  readonly vaultSessionId: string;
}): Promise<UnlockedVault> {
  verifyServerProof(input.session, fromBase64(input.serverM2));
  const masterKey = await unwrapAesKey(
    input.preparation.auk,
    fromBase64(input.wrappedMasterKey),
    masterKeyAad(input.preparation.userId),
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  );
  const keysetAuthKey = await deriveKeysetAuthKey(input.session.sessionKey, input.vaultSessionId);
  return { masterKey, keysetAuthKey };
}

/**
 * Recover the raw master key bytes. Only the password-change path needs this:
 * the new keyset has to wrap the SAME master key under a new unlock key, and
 * `CryptoKey`s that are non-extractable (the default everywhere else) cannot be
 * re-wrapped. Callers must wipe the result.
 */
export async function exportMasterKeyBytes(input: {
  readonly userId: string;
  readonly auk: CryptoKey;
  readonly wrappedMasterKey: string;
}): Promise<Uint8Array> {
  return open(input.auk, fromBase64(input.wrappedMasterKey), masterKeyAad(input.userId));
}

/**
 * Build a replacement keyset for a password change, plus the proof that the
 * caller knew the current password.
 *
 * The Secret Key is unchanged by a password change — only the password half of
 * the derivation moves.
 */
export async function buildKeysetChange(input: {
  readonly userId: string;
  readonly newPassword: string;
  readonly secretKey: string;
  readonly masterKey: Uint8Array;
  readonly keysetAuthKey: Uint8Array;
  readonly iterations?: number;
}): Promise<{ payload: VaultKeysetPayload; proof: string }> {
  const secretKey = await parseSecretKey(input.secretKey);
  try {
    const payload = await buildKeyset({
      userId: input.userId,
      password: input.newPassword,
      secretKey,
      masterKey: input.masterKey,
      iterations: input.iterations ?? DEFAULT_ITERATIONS,
    });
    return { payload, proof: await keysetProof(input.keysetAuthKey, payload) };
  } finally {
    wipe(secretKey);
  }
}
