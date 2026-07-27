import { VaultCryptoError, VaultDecryptionError } from '../src/aead';
import { fromBase64, randomBytes, toBase64 } from '../src/bytes';
import {
  generateRecoveryKeyPair,
  openWithPrivateKey,
  publicKeyFingerprint,
  sealToPublicKey,
  type RecoveryKeyPair,
} from '../src/ecies';
import { createEscrow, recoverMasterKey, type HeldShare } from '../src/recovery';

const OWNER = 'f0e1d2c3-b4a5-4968-8778-695a4b3c2d1e';
const GRANTEES = [
  '11111111-2222-4333-8444-555555555555',
  '66666666-7777-4888-8999-aaaaaaaaaaaa',
  'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
];

// P-256 keygen and ECDH are slow enough that a contended machine can drift
// past a tighter ceiling; see keyset.spec.ts for the same reasoning.
jest.setTimeout(120_000);

async function keypairs(count: number): Promise<RecoveryKeyPair[]> {
  const pairs: RecoveryKeyPair[] = [];
  for (let i = 0; i < count; i += 1) pairs.push(await generateRecoveryKeyPair());
  return pairs;
}

function heldShare(
  escrowShare: { granteeUserId: string; sealedShare: string },
  pair: RecoveryKeyPair,
): HeldShare {
  return {
    granteeUserId: escrowShare.granteeUserId,
    sealedShare: escrowShare.sealedShare,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
  };
}

describe('ECIES sealing to a grantee key', () => {
  it('round-trips', async () => {
    const [pair] = await keypairs(1);
    const sealed = await sealToPublicKey(pair!.publicKey, Uint8Array.from([1, 2, 3]), 'aad');
    const opened = await openWithPrivateKey(pair!.privateKey, sealed, 'aad');
    expect(Buffer.from(opened)).toEqual(Buffer.from([1, 2, 3]));
  });

  it('produces a different ciphertext every time', async () => {
    const [pair] = await keypairs(1);
    const first = await sealToPublicKey(pair!.publicKey, Uint8Array.from([7]), 'aad');
    const second = await sealToPublicKey(pair!.publicKey, Uint8Array.from([7]), 'aad');
    expect(Buffer.from(first)).not.toEqual(Buffer.from(second));
  });

  it('fails closed for the wrong recipient', async () => {
    const [mine, theirs] = await keypairs(2);
    const sealed = await sealToPublicKey(mine!.publicKey, Uint8Array.from([1]), 'aad');
    await expect(openWithPrivateKey(theirs!.privateKey, sealed, 'aad')).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it('fails closed on a different AAD', async () => {
    const [pair] = await keypairs(1);
    const sealed = await sealToPublicKey(pair!.publicKey, Uint8Array.from([1]), 'aad');
    await expect(openWithPrivateKey(pair!.privateKey, sealed, 'other')).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it.each([
    ['a truncated envelope', (s: Uint8Array): Uint8Array => s.subarray(0, 2)],
    ['an unknown version', (s: Uint8Array): Uint8Array => Uint8Array.from([9, ...s.subarray(1)])],
  ])('rejects %s', async (_label, mutate) => {
    const [pair] = await keypairs(1);
    const sealed = await sealToPublicKey(pair!.publicKey, Uint8Array.from([1]), 'aad');
    await expect(openWithPrivateKey(pair!.privateKey, mutate(sealed), 'aad')).rejects.toThrow(
      VaultDecryptionError,
    );
  });

  it('rejects a malformed recipient key', async () => {
    await expect(sealToPublicKey(new Uint8Array(65), Uint8Array.from([1]), 'aad')).rejects.toThrow(
      /invalid recipient public key/,
    );
  });
});

describe('public key fingerprint', () => {
  it('is short, stable and readable', async () => {
    const [pair] = await keypairs(1);
    const fingerprint = await publicKeyFingerprint(pair!.publicKey);
    expect(fingerprint).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
    expect(await publicKeyFingerprint(pair!.publicKey)).toBe(fingerprint);
  });

  it('differs between keys', async () => {
    const [a, b] = await keypairs(2);
    expect(await publicKeyFingerprint(a!.publicKey)).not.toBe(
      await publicKeyFingerprint(b!.publicKey),
    );
  });
});

describe('emergency access escrow', () => {
  const masterKey = randomBytes(32);

  it('reconstructs the master key from the platform half plus a share', async () => {
    const pairs = await keypairs(1);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: [{ granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey }],
      threshold: 1,
    });

    const recovered = await recoverMasterKey({
      ownerUserId: OWNER,
      platformPart: escrow.platformPart,
      wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
      shares: [heldShare(escrow.shares[0]!, pairs[0]!)],
    });
    expect(Buffer.from(recovered)).toEqual(Buffer.from(masterKey));
  });

  it('needs the threshold number of grantees when M-of-N is configured', async () => {
    const pairs = await keypairs(3);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: GRANTEES.map((granteeUserId, i) => ({
        granteeUserId,
        publicKey: pairs[i]!.publicKey,
      })),
      threshold: 2,
    });

    const two = await recoverMasterKey({
      ownerUserId: OWNER,
      platformPart: escrow.platformPart,
      wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
      shares: [heldShare(escrow.shares[0]!, pairs[0]!), heldShare(escrow.shares[2]!, pairs[2]!)],
    });
    expect(Buffer.from(two)).toEqual(Buffer.from(masterKey));

    // One share short: the reconstructed key is wrong, so the unwrap fails.
    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: [heldShare(escrow.shares[0]!, pairs[0]!)],
      }),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it('is useless to colluding grantees without the platform half', async () => {
    // The control that makes the waiting period real: every grantee shares
    // their piece and they still cannot open the vault.
    const pairs = await keypairs(3);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: GRANTEES.map((granteeUserId, i) => ({
        granteeUserId,
        publicKey: pairs[i]!.publicKey,
      })),
      threshold: 1,
    });

    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: toBase64(randomBytes(32)), // anything but the real half
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: escrow.shares.map((share, i) => heldShare(share, pairs[i]!)),
      }),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it('is useless to the platform without any grantee share', async () => {
    // The mirror property: a full database dump holds platform_part and the
    // recovery-wrapped master key, and neither opens anything.
    const pairs = await keypairs(1);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: [{ granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey }],
      threshold: 1,
    });

    const platformOnly = fromBase64(escrow.platformPart);
    expect(platformOnly).toHaveLength(32);
    // Without a share there is no contacts half to XOR against; the best the
    // server can do is guess, and the wrapped key stays sealed.
    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: [
          {
            granteeUserId: GRANTEES[0]!,
            sealedShare: escrow.shares[0]!.sealedShare,
            publicKey: (await generateRecoveryKeyPair()).publicKey,
            privateKey: (await generateRecoveryKeyPair()).privateKey,
          },
        ],
      }),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it('binds each share to its owner, grantee and key', async () => {
    const pairs = await keypairs(1);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: [{ granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey }],
      threshold: 1,
    });

    // Same share, wrong owner in the AAD.
    await expect(
      recoverMasterKey({
        ownerUserId: '00000000-0000-4000-8000-000000000000',
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: [heldShare(escrow.shares[0]!, pairs[0]!)],
      }),
    ).rejects.toThrow(VaultDecryptionError);

    // Same share, wrong grantee in the AAD.
    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: escrow.platformPart,
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: [{ ...heldShare(escrow.shares[0]!, pairs[0]!), granteeUserId: GRANTEES[1]! }],
      }),
    ).rejects.toThrow(VaultDecryptionError);
  });

  it('records the key each share was sealed to', async () => {
    const pairs = await keypairs(1);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: [{ granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey }],
      threshold: 1,
    });
    expect(fromBase64(escrow.shares[0]!.publicKeySha256)).toHaveLength(32);
    expect(escrow.shares[0]!.granteeUserId).toBe(GRANTEES[0]);
  });

  it.each([
    ['no grantees', { grantees: [], threshold: 1 }],
    ['a threshold above the grantee count', { grantees: 1, threshold: 2 }],
    ['a zero threshold', { grantees: 1, threshold: 0 }],
  ])('refuses to build an escrow with %s', async (_label, spec) => {
    const count = Array.isArray(spec.grantees) ? 0 : spec.grantees;
    const pairs = await keypairs(Math.max(count, 1));
    const grantees = Array.from({ length: count }, (_, i) => ({
      granteeUserId: GRANTEES[i]!,
      publicKey: pairs[i]!.publicKey,
    }));
    await expect(
      createEscrow({ ownerUserId: OWNER, masterKey, grantees, threshold: spec.threshold }),
    ).rejects.toThrow(VaultCryptoError);
  });

  it('refuses duplicate grantees', async () => {
    const pairs = await keypairs(2);
    await expect(
      createEscrow({
        ownerUserId: OWNER,
        masterKey,
        grantees: [
          { granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey },
          { granteeUserId: GRANTEES[0]!, publicKey: pairs[1]!.publicKey },
        ],
        threshold: 1,
      }),
    ).rejects.toThrow(VaultCryptoError);
  });

  it('refuses a platform half of the wrong size', async () => {
    const pairs = await keypairs(1);
    const escrow = await createEscrow({
      ownerUserId: OWNER,
      masterKey,
      grantees: [{ granteeUserId: GRANTEES[0]!, publicKey: pairs[0]!.publicKey }],
      threshold: 1,
    });
    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: toBase64(randomBytes(16)),
        wrappedMasterKeyRecovery: escrow.wrappedMasterKeyRecovery,
        shares: [heldShare(escrow.shares[0]!, pairs[0]!)],
      }),
    ).rejects.toThrow(VaultCryptoError);
  });

  it('refuses to recover with no shares', async () => {
    await expect(
      recoverMasterKey({
        ownerUserId: OWNER,
        platformPart: toBase64(randomBytes(32)),
        wrappedMasterKeyRecovery: toBase64(randomBytes(61)),
        shares: [],
      }),
    ).rejects.toThrow(VaultCryptoError);
  });
});
