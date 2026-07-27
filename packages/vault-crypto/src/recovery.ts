/**
 * Emergency-access escrow (docs/01 §2.5, docs/03 §5.2).
 *
 * The shape of the problem: designated contacts must be able to open the vault
 * after the owner cannot, but never quietly and never on their own timetable.
 * docs/03 §5.2's attack is a contact invoking access while the owner is alive
 * and simply unaware, so the waiting period is the control that matters - and a
 * waiting period is only real if the contacts genuinely cannot proceed without
 * the platform.
 *
 * So the recovery key is split twice, at two different levels:
 *
 *   RK  =  platform_part  XOR  contacts_part
 *                               |
 *                               +-- Shamir M-of-N across the grantees
 *
 * The XOR split is a one-time pad: either half alone is information-theoretically
 * useless, so every colluding contact in the world cannot reconstruct RK without
 * the platform releasing its half - which it does only after the waiting period
 * elapses without an owner denial. The Shamir layer then decides how many
 * contacts must cooperate among themselves.
 *
 * What this does NOT defend against, stated plainly: the platform half is held
 * by the server, so a server that chooses to release it early defeats the
 * waiting period. That is inherent to the docs/01 design - a delay enforced by
 * a party is only as good as that party - and the compensating controls are the
 * audit trail and owner notification. What the split DOES guarantee is that a
 * database dump alone is not enough (the contacts' shares are sealed to keys the
 * server never holds) and a rogue contact alone is not enough either.
 */

import { importAesKey, open, seal, VaultCryptoError } from './aead';
import { fromBase64, randomBytes, toBase64, wipe, xorBytes } from './bytes';
import { openWithPrivateKey, publicKeyDigest, sealToPublicKey } from './ecies';
import { combine, decodeShare, encodeShare, split } from './shamir';

export const RECOVERY_KEY_BYTES = 32;

export function recoveryWrapAad(ownerUserId: string): string {
  return `estate.vault.wrap.recovery.v1|${ownerUserId}`;
}

/**
 * The sealed share is bound to the grantee's key fingerprint, so a share sealed
 * to a substituted key cannot be silently passed off as one sealed to the real
 * grantee.
 */
export function shareAad(
  ownerUserId: string,
  granteeUserId: string,
  publicKeySha256Base64: string,
): string {
  return `estate.vault.share.v1|${ownerUserId}|${granteeUserId}|${publicKeySha256Base64}`;
}

export interface EscrowGrantee {
  readonly granteeUserId: string;
  /** Raw P-256 public key, fingerprint-verified by the owner out of band. */
  readonly publicKey: Uint8Array;
}

export interface SealedShare {
  readonly granteeUserId: string;
  readonly sealedShare: string;
  readonly publicKeySha256: string;
}

export interface EscrowMaterial {
  /** Server-held half of the recovery key; released only after the wait. */
  readonly platformPart: string;
  /** The master key wrapped by the recovery key. */
  readonly wrappedMasterKeyRecovery: string;
  readonly threshold: number;
  readonly shares: readonly SealedShare[];
}

export async function createEscrow(input: {
  readonly ownerUserId: string;
  readonly masterKey: Uint8Array;
  readonly grantees: readonly EscrowGrantee[];
  readonly threshold: number;
}): Promise<EscrowMaterial> {
  const { ownerUserId, masterKey, grantees, threshold } = input;
  if (grantees.length === 0) throw new VaultCryptoError('escrow needs at least one grantee');
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > grantees.length) {
    throw new VaultCryptoError('threshold must be between 1 and the number of grantees');
  }
  const granteeIds = new Set(grantees.map((g) => g.granteeUserId));
  if (granteeIds.size !== grantees.length) throw new VaultCryptoError('duplicate grantee');

  const recoveryKey = randomBytes(RECOVERY_KEY_BYTES);
  const contactsPart = randomBytes(RECOVERY_KEY_BYTES);
  const platformPart = xorBytes(recoveryKey, contactsPart);

  try {
    const recoveryAesKey = await importAesKey(recoveryKey, ['encrypt', 'decrypt']);
    const wrapped = await seal(recoveryAesKey, masterKey, recoveryWrapAad(ownerUserId));

    const pieces = split(contactsPart, { shares: grantees.length, threshold });
    const shares: SealedShare[] = [];
    for (let i = 0; i < grantees.length; i += 1) {
      const grantee = grantees[i]!;
      const digest = toBase64(await publicKeyDigest(grantee.publicKey));
      const sealed = await sealToPublicKey(
        grantee.publicKey,
        encodeShare(pieces[i]!),
        shareAad(ownerUserId, grantee.granteeUserId, digest),
      );
      shares.push({
        granteeUserId: grantee.granteeUserId,
        sealedShare: toBase64(sealed),
        publicKeySha256: digest,
      });
    }
    for (const piece of pieces) wipe(piece.y);

    return {
      platformPart: toBase64(platformPart),
      wrappedMasterKeyRecovery: toBase64(wrapped),
      threshold,
      shares,
    };
  } finally {
    wipe(recoveryKey, contactsPart);
  }
}

export interface HeldShare {
  readonly granteeUserId: string;
  readonly sealedShare: string;
  /** The grantee's own keypair; the private half is wrapped under their MK. */
  readonly publicKey: Uint8Array;
  readonly privateKey: Uint8Array;
}

/**
 * Reconstruct the owner's master key from the released platform half plus
 * enough grantee shares. Runs entirely on the grantee's device.
 */
export async function recoverMasterKey(input: {
  readonly ownerUserId: string;
  readonly platformPart: string;
  readonly wrappedMasterKeyRecovery: string;
  readonly shares: readonly HeldShare[];
}): Promise<Uint8Array> {
  if (input.shares.length === 0) throw new VaultCryptoError('no shares supplied');

  const pieces = [];
  for (const held of input.shares) {
    const digest = toBase64(await publicKeyDigest(held.publicKey));
    const opened = await openWithPrivateKey(
      held.privateKey,
      fromBase64(held.sealedShare),
      shareAad(input.ownerUserId, held.granteeUserId, digest),
    );
    pieces.push(decodeShare(opened));
  }

  const contactsPart = combine(pieces);
  const platformPart = fromBase64(input.platformPart);
  if (platformPart.length !== contactsPart.length) {
    throw new VaultCryptoError('recovery halves do not match');
  }
  const recoveryKey = xorBytes(platformPart, contactsPart);

  try {
    const recoveryAesKey = await importAesKey(recoveryKey, ['encrypt', 'decrypt']);
    return await open(
      recoveryAesKey,
      fromBase64(input.wrappedMasterKeyRecovery),
      recoveryWrapAad(input.ownerUserId),
    );
  } finally {
    wipe(recoveryKey, contactsPart);
  }
}
