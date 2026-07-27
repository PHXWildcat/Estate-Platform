/**
 * End-to-end flows: enrollment, unlock over a real SRP handshake, and password
 * change. The "server" here is the same `srp.ts` server half the vault service
 * uses, holding only what `vault_keysets` holds.
 */
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  verifyClientSession,
} from '../src/srp';
import { fromBase64, randomBytes, toBase64, utf8 } from '../src/bytes';
import { decryptItem, encryptItem } from '../src/items';
import {
  DEFAULT_ITERATIONS,
  deriveKeysetAuthKey,
  MIN_ITERATIONS,
  VaultParameterError,
} from '../src/kdf';
import { VaultCryptoError, VaultDecryptionError } from '../src/aead';
import {
  buildKeysetChange,
  canonicalKeysetPayload,
  createVaultEnrollment,
  exportMasterKeyBytes,
  finishUnlock,
  keysetProof,
  prepareUnlock,
  proveUnlock,
  VaultKeysetPayload,
  verifyKeysetProof,
} from '../src/keyset';

const USER_ID = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const PASSWORD = 'a long enough vault password';
const VAULT_SESSION_ID = '5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
const ITERATIONS = MIN_ITERATIONS;

// These derive real keys at the real iteration count, so they are slow by
// design. The ceiling is generous because the whole monorepo suite runs in
// parallel on modest hardware, and a timeout here would report as a crypto
// failure when it is really contention.
jest.setTimeout(120_000);

/** Everything the server knows, and nothing else. */
interface StoredKeyset {
  readonly payload: VaultKeysetPayload;
}

/** The full unlock exchange: client, wire, and the service's server half. */
async function openVault(
  stored: StoredKeyset,
  credentials: { password: string; secretKey: string },
): Promise<{
  masterKey: CryptoKey;
  keysetAuthKey: Uint8Array;
  serverSessionKey: Uint8Array;
} | null> {
  const verifier = decodeGroupElement(stored.payload.srpVerifier, 'verifier');
  const serverEphemeral = await createServerEphemeral(verifier);

  const preparation = await prepareUnlock({
    userId: USER_ID,
    password: credentials.password,
    secretKey: credentials.secretKey,
    kdfParams: stored.payload.kdfParams,
    srpSalt: stored.payload.srpSalt,
  });
  // The server sends B on the wire in the padded encoding.
  const { m1, session } = await proveUnlock(preparation, encodeGroupElement(serverEphemeral.B));

  const verified = await verifyClientSession({
    userId: USER_ID,
    salt: fromBase64(stored.payload.srpSalt),
    verifier,
    ephemeral: serverEphemeral,
    A: decodeGroupElement(preparation.publicA, 'client public value'),
    M1: fromBase64(m1),
  });
  if (!verified) return null;

  const unlocked = await finishUnlock({
    preparation,
    session,
    serverM2: toBase64(verified.M2),
    wrappedMasterKey: stored.payload.wrappedMasterKey,
    vaultSessionId: VAULT_SESSION_ID,
  });
  return { ...unlocked, serverSessionKey: verified.sessionKey };
}

describe('vault enrollment', () => {
  it('produces a keyset the server can store and nothing it can use', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });

    expect(enrollment.secretKey).toMatch(/^ES1-[0-9A-HJKMNP-TV-Z-]+$/);
    expect(fromBase64(enrollment.payload.srpSalt)).toHaveLength(16);
    expect(fromBase64(enrollment.payload.srpVerifier)).toHaveLength(512);
    expect(enrollment.payload.kdfParams.iterations).toBe(ITERATIONS);

    // Nothing the server stores contains the password or the Secret Key.
    const stored = JSON.stringify(enrollment.payload);
    expect(stored).not.toContain(PASSWORD);
    expect(stored).not.toContain(enrollment.secretKey);
  });

  it('defaults to the shipped iteration count when the caller does not choose one', async () => {
    const { enrollment } = await createVaultEnrollment({ userId: USER_ID, password: PASSWORD });
    expect(enrollment.payload.kdfParams.iterations).toBe(DEFAULT_ITERATIONS);
    expect(DEFAULT_ITERATIONS).toBeGreaterThanOrEqual(MIN_ITERATIONS);
  });

  it('gives every enrollment fresh salts and a fresh master key', async () => {
    const first = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const second = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    expect(first.enrollment.payload.srpSalt).not.toBe(second.enrollment.payload.srpSalt);
    expect(first.enrollment.payload.kdfParams.aukSalt).not.toBe(
      second.enrollment.payload.kdfParams.aukSalt,
    );
    expect(first.enrollment.payload.srpVerifier).not.toBe(second.enrollment.payload.srpVerifier);
  });
});

describe('vault unlock', () => {
  it('opens the vault and recovers the same master key', async () => {
    const { enrollment, masterKey } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });

    const ref = { userId: USER_ID, itemId: VAULT_SESSION_ID, blobVersion: 1 };
    const blob = await encryptItem(masterKey, ref, utf8('seed phrase'));

    const opened = await openVault(
      { payload: enrollment.payload },
      { password: PASSWORD, secretKey: enrollment.secretKey },
    );
    expect(opened).not.toBeNull();
    expect(Buffer.from(await decryptItem(opened!.masterKey, ref, blob))).toEqual(
      Buffer.from(utf8('seed phrase')),
    );
  });

  it('agrees with the server on the keyset-auth key', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const opened = await openVault(
      { payload: enrollment.payload },
      { password: PASSWORD, secretKey: enrollment.secretKey },
    );
    const serverSide = await deriveKeysetAuthKey(opened!.serverSessionKey, VAULT_SESSION_ID);
    expect(Buffer.from(opened!.keysetAuthKey)).toEqual(Buffer.from(serverSide));
  });

  it('fails with the wrong password', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const opened = await openVault(
      { payload: enrollment.payload },
      { password: 'not the vault password', secretKey: enrollment.secretKey },
    );
    expect(opened).toBeNull();
  });

  it('fails with the wrong Secret Key, even with the right password', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const other = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const opened = await openVault(
      { payload: enrollment.payload },
      { password: PASSWORD, secretKey: other.enrollment.secretKey },
    );
    expect(opened).toBeNull();
  });

  it('rejects an SRP salt of the wrong size', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    await expect(
      prepareUnlock({
        userId: USER_ID,
        password: PASSWORD,
        secretKey: enrollment.secretKey,
        kdfParams: enrollment.payload.kdfParams,
        srpSalt: toBase64(new Uint8Array(8)),
      }),
    ).rejects.toThrow(VaultCryptoError);
  });

  it('refuses server-supplied parameters outside the pinned profile', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    await expect(
      prepareUnlock({
        userId: USER_ID,
        password: PASSWORD,
        secretKey: enrollment.secretKey,
        kdfParams: { ...enrollment.payload.kdfParams, iterations: 1000 },
        srpSalt: enrollment.payload.srpSalt,
      }),
    ).rejects.toThrow(VaultParameterError);
  });

  it('rejects a master key wrapped for a different user', async () => {
    const mine = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const theirs = await createVaultEnrollment({
      userId: '00000000-0000-4000-8000-000000000000',
      password: PASSWORD,
      iterations: ITERATIONS,
    });

    const preparation = await prepareUnlock({
      userId: USER_ID,
      password: PASSWORD,
      secretKey: mine.enrollment.secretKey,
      kdfParams: mine.enrollment.payload.kdfParams,
      srpSalt: mine.enrollment.payload.srpSalt,
    });
    await expect(
      exportMasterKeyBytes({
        userId: USER_ID,
        auk: preparation.auk,
        wrappedMasterKey: theirs.enrollment.payload.wrappedMasterKey,
      }),
    ).rejects.toThrow(VaultDecryptionError);
  });
});

describe('password change', () => {
  it('keeps the same master key, so existing items still open', async () => {
    const { enrollment, masterKey } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const ref = { userId: USER_ID, itemId: VAULT_SESSION_ID, blobVersion: 1 };
    const blob = await encryptItem(masterKey, ref, utf8('recovery codes'));

    const opened = await openVault(
      { payload: enrollment.payload },
      { password: PASSWORD, secretKey: enrollment.secretKey },
    );
    const preparation = await prepareUnlock({
      userId: USER_ID,
      password: PASSWORD,
      secretKey: enrollment.secretKey,
      kdfParams: enrollment.payload.kdfParams,
      srpSalt: enrollment.payload.srpSalt,
    });
    const masterKeyBytes = await exportMasterKeyBytes({
      userId: USER_ID,
      auk: preparation.auk,
      wrappedMasterKey: enrollment.payload.wrappedMasterKey,
    });

    const change = await buildKeysetChange({
      userId: USER_ID,
      newPassword: 'an entirely different password',
      secretKey: enrollment.secretKey,
      masterKey: masterKeyBytes,
      keysetAuthKey: opened!.keysetAuthKey,
      iterations: ITERATIONS,
    });

    // The server verifies the proof before replacing anything.
    await expect(
      verifyKeysetProof(opened!.keysetAuthKey, change.payload, change.proof),
    ).resolves.toBe(true);

    const reopened = await openVault(
      { payload: change.payload },
      { password: 'an entirely different password', secretKey: enrollment.secretKey },
    );
    expect(reopened).not.toBeNull();
    expect(Buffer.from(await decryptItem(reopened!.masterKey, ref, blob))).toEqual(
      Buffer.from(utf8('recovery codes')),
    );
  });

  it('leaves the old password unable to open the new keyset', async () => {
    const { enrollment } = await createVaultEnrollment({
      userId: USER_ID,
      password: PASSWORD,
      iterations: ITERATIONS,
    });
    const opened = await openVault(
      { payload: enrollment.payload },
      { password: PASSWORD, secretKey: enrollment.secretKey },
    );
    const preparation = await prepareUnlock({
      userId: USER_ID,
      password: PASSWORD,
      secretKey: enrollment.secretKey,
      kdfParams: enrollment.payload.kdfParams,
      srpSalt: enrollment.payload.srpSalt,
    });
    const masterKeyBytes = await exportMasterKeyBytes({
      userId: USER_ID,
      auk: preparation.auk,
      wrappedMasterKey: enrollment.payload.wrappedMasterKey,
    });
    const change = await buildKeysetChange({
      userId: USER_ID,
      newPassword: 'an entirely different password',
      secretKey: enrollment.secretKey,
      masterKey: masterKeyBytes,
      keysetAuthKey: opened!.keysetAuthKey,
      iterations: ITERATIONS,
    });

    const withOldPassword = await openVault(
      { payload: change.payload },
      { password: PASSWORD, secretKey: enrollment.secretKey },
    );
    expect(withOldPassword).toBeNull();
  });
});

describe('keyset proof', () => {
  const payload: VaultKeysetPayload = {
    srpSalt: toBase64(new Uint8Array(16)),
    srpVerifier: toBase64(new Uint8Array(512)),
    wrappedMasterKey: toBase64(new Uint8Array(61)),
    kdfParams: {
      v: 1,
      alg: 'pbkdf2-sha256',
      iterations: MIN_ITERATIONS,
      aukSalt: toBase64(new Uint8Array(16)),
      srpGroup: 'rfc5054-4096',
      cipher: 'aes-256-gcm',
    },
  };

  it('accepts a proof over the exact payload', async () => {
    const key = randomBytes(32);
    const proof = await keysetProof(key, payload);
    await expect(verifyKeysetProof(key, payload, proof)).resolves.toBe(true);
  });

  it('rejects a proof made under a different session key', async () => {
    const proof = await keysetProof(randomBytes(32), payload);
    await expect(verifyKeysetProof(randomBytes(32), payload, proof)).resolves.toBe(false);
  });

  it.each([
    ['the wrapped master key', { wrappedMasterKey: toBase64(new Uint8Array(62)) }],
    ['the verifier', { srpVerifier: toBase64(new Uint8Array(511)) }],
    ['the salt', { srpSalt: toBase64(Uint8Array.from({ length: 16 }, () => 1)) }],
  ])('rejects a payload whose %s was swapped in flight', async (_label, override) => {
    const key = randomBytes(32);
    const proof = await keysetProof(key, payload);
    await expect(verifyKeysetProof(key, { ...payload, ...override }, proof)).resolves.toBe(false);
  });

  it('rejects a payload whose KDF parameters were swapped in flight', async () => {
    const key = randomBytes(32);
    const proof = await keysetProof(key, payload);
    const tampered = {
      ...payload,
      kdfParams: { ...payload.kdfParams, iterations: MIN_ITERATIONS + 1 },
    };
    await expect(verifyKeysetProof(key, tampered, proof)).resolves.toBe(false);
  });

  it('rejects a malformed proof without throwing', async () => {
    await expect(verifyKeysetProof(randomBytes(32), payload, 'not base64!')).resolves.toBe(false);
  });

  it('canonicalizes independently of key order', () => {
    const reordered: VaultKeysetPayload = {
      wrappedMasterKey: payload.wrappedMasterKey,
      kdfParams: payload.kdfParams,
      srpVerifier: payload.srpVerifier,
      srpSalt: payload.srpSalt,
    };
    expect(Buffer.from(canonicalKeysetPayload(reordered))).toEqual(
      Buffer.from(canonicalKeysetPayload(payload)),
    );
  });
});
