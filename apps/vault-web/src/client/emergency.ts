import {
  createEscrow,
  fromBase64,
  generateRecoveryKeyPair,
  open,
  publicKeyFingerprint,
  recoverMasterKey,
  seal,
  toBase64,
  wipe,
  type EscrowGrantee,
} from '/lib/vault-crypto/index.js';
import { request, type ApiResult } from './api.js';

/**
 * EMERGENCY ACCESS on the device (docs/03 §5.2, M6 PR2's design).
 *
 * The shape of the problem: designated contacts must be able to open the vault
 * when the owner cannot, but never quietly and never on their own timetable.
 * The recovery key is split twice —
 *
 *     RK = platform_part XOR contacts_part
 *                              |
 *                              +-- Shamir M-of-N across the grantees
 *
 * — so every colluding contact in the world still cannot reconstruct RK without
 * the platform releasing its half after the waiting period. All of that
 * splitting happens HERE, on the owner's device: the server receives a
 * platform half, a wrapped master key, and shares already sealed to keys it
 * does not hold.
 *
 * THE FINGERPRINT CEREMONY IS THE PART A UI CAN GET WRONG. A malicious server
 * could serve its OWN public key in place of a grantee's and — already holding
 * `platform_part` and the recovery-wrapped master key — read the entire escrow.
 * Nothing server-side can detect that, because `grantee_public_key_sha256` is
 * derived client-side from whatever key the client was handed and binds just as
 * happily to a substituted one. The ONLY defence is the owner confirming a
 * short fingerprint with the grantee over a channel this platform does not
 * control, which is why `sealShares` refuses to run until every candidate has
 * been confirmed and why the fingerprint is shown, never auto-accepted.
 *
 * The M6 security review widened that fingerprint from 50 bits to 80 for a
 * client that did not exist yet. This is that client.
 */

/** AAD for the owner's own recovery private key, wrapped under their master key. */
function recoveryPrivateKeyAad(userId: string): string {
  return `estate.vault.wrap.recoverykey.v1|${userId}`;
}

export interface GranteeCandidate {
  readonly contactId: string;
  readonly userId: string;
  readonly name: string;
}

/** A candidate plus the fingerprint the owner must confirm out of band. */
export interface GranteeKeyOffer extends GranteeCandidate {
  readonly publicKey: Uint8Array;
  readonly fingerprint: string;
}

export interface PolicyDto {
  id: string;
  granteeContactId: string;
  granteeUserId: string;
  waitingPeriodHours: number;
  status: string;
  requestedAt: string | null;
  releasesAt: string | null;
  requestCount: number;
}

export interface EscrowDto {
  configured: boolean;
  threshold: number | null;
  policies: PolicyDto[];
}

export interface GranteePolicyDto {
  id: string;
  ownerUserId: string;
  status: string;
  releasesAt: string | null;
}

/** Fetch the contacts this owner could name, already projected by the edge. */
export async function granteeCandidates(): Promise<ApiResult<GranteeCandidate[]>> {
  const result = await request<{ candidates?: GranteeCandidate[] }>('/api/grantee-candidates');
  return result.ok ? { ok: true, data: result.data.candidates ?? [] } : result;
}

/**
 * Publish this user's recovery public key so OTHERS can name them.
 *
 * The private half is wrapped under this user's own master key, so it can only
 * ever be opened by someone who can open this vault — which is what makes a
 * later release require the grantee to unlock their OWN vault rather than
 * merely hold a session.
 */
export async function publishRecoveryKey(
  userId: string,
  masterKey: CryptoKey,
): Promise<ApiResult<unknown>> {
  const pair = await generateRecoveryKeyPair();
  try {
    const wrapped = await seal(masterKey, pair.privateKey, recoveryPrivateKeyAad(userId));
    return await request('/api/vault/recovery-key', {
      method: 'POST',
      body: {
        publicKey: toBase64(pair.publicKey),
        wrappedPrivateKey: toBase64(wrapped),
      },
    });
  } finally {
    wipe(pair.privateKey);
  }
}

/**
 * This user's OWN recovery keypair, behind an open vault.
 *
 * The private half comes back wrapped under this user's master key, so the
 * route is guarded by an open vault rather than by a session alone — a leaked
 * vault session fetches an opaque blob it cannot unwrap.
 */
export function ownRecoveryKey(
  vaultSession: string,
): Promise<ApiResult<{ publicKey: string; wrappedPrivateKey: string }>> {
  return request<{ publicKey: string; wrappedPrivateKey: string }>('/api/vault/recovery-key', {
    vaultSession,
  });
}

/**
 * Fetch a candidate's published key and compute the fingerprint to confirm.
 *
 * Returns the OFFER rather than sealing anything: confirmation is a human step
 * that happens between these two calls, and collapsing them would remove the
 * only defence against key substitution.
 */
export async function offerFor(candidate: GranteeCandidate): Promise<ApiResult<GranteeKeyOffer>> {
  const served = await request<{ granteeUserId: string; publicKey: string }>(
    `/api/vault/recovery-key/${candidate.userId}`,
  );
  if (!served.ok) {
    return served;
  }
  // A KEY THAT WILL NOT PARSE IS A REFUSAL, NOT A THROW. `fromBase64` and
  // `publicKeyFingerprint` both reject malformed input by throwing, and this
  // input comes from the server — which Zone A's threat model treats as
  // hostile. An escaping exception would leave the row stuck on "not
  // confirmed" with nothing said, so the owner would keep pressing a button
  // that can never work. Refusing to fingerprint an unparseable key is also
  // the correct security answer: there is nothing here to seal a share to.
  try {
    const publicKey = fromBase64(served.data.publicKey);
    return {
      ok: true,
      data: { ...candidate, publicKey, fingerprint: await publicKeyFingerprint(publicKey) },
    };
  } catch {
    return { ok: false, code: 'INVALID_REQUEST' };
  }
}

export interface ConfigureInput {
  readonly ownerUserId: string;
  readonly masterKeyBytes: Uint8Array;
  readonly confirmed: readonly GranteeKeyOffer[];
  readonly threshold: number;
  readonly waitingPeriodHours: number;
}

export class EmergencyAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmergencyAccessError';
  }
}

/**
 * Split the recovery key and arm the escrow.
 *
 * Every grantee here must have had their fingerprint CONFIRMED by the owner —
 * the caller is responsible for that, and the screen makes it a per-row action.
 * `createEscrow` seals each share to the confirmed key and records the digest
 * of what it sealed to, so a later substitution is detectable.
 */
export async function configureEscrow(input: ConfigureInput): Promise<ApiResult<EscrowDto>> {
  if (input.confirmed.length === 0) {
    throw new EmergencyAccessError('at least one confirmed grantee is required');
  }
  if (input.threshold < 1 || input.threshold > input.confirmed.length) {
    throw new EmergencyAccessError('threshold must be between 1 and the number of grantees');
  }
  if (input.threshold !== 1) {
    // `releaseAndRecover` below passes ONE share to `recoverMasterKey`, so an
    // escrow needing more could never be opened by this client. The protocol
    // and the service both support M-of-N; this client does not, and refusing
    // to ARM is the only way to fail closed rather than storing an arrangement
    // that silently cannot work (M15 review).
    //
    // This used to carry a second reason — that release was one-shot, so the
    // first grantee to try would spend their policy learning it. M27 PR3a made
    // collection repeatable, so that half is void; the refusal rests on the
    // first reason, which is untouched by it.
    throw new EmergencyAccessError('this client can only complete a release with threshold 1');
  }

  const grantees: EscrowGrantee[] = input.confirmed.map((offer) => ({
    granteeUserId: offer.userId,
    publicKey: offer.publicKey,
  }));
  const material = await createEscrow({
    ownerUserId: input.ownerUserId,
    masterKey: input.masterKeyBytes,
    grantees,
    threshold: input.threshold,
  });

  // Line the sealed shares back up with the contact each belongs to. The
  // service stores `grantee_contact_id` as well as the user id, because the
  // owner's own list is by contact.
  const byUser = new Map(input.confirmed.map((offer) => [offer.userId, offer]));
  return request<EscrowDto>('/api/vault/emergency-access', {
    method: 'POST',
    body: {
      threshold: material.threshold,
      platformPart: material.platformPart,
      wrappedMasterKeyRecovery: material.wrappedMasterKeyRecovery,
      grantees: material.shares.map((share) => ({
        granteeContactId: byUser.get(share.granteeUserId)?.contactId,
        granteeUserId: share.granteeUserId,
        keyShare: share.sealedShare,
        granteePublicKeySha256: share.publicKeySha256,
        waitingPeriodHours: input.waitingPeriodHours,
      })),
    },
  });
}

export function describeEscrow(): Promise<ApiResult<EscrowDto>> {
  return request<EscrowDto>('/api/vault/emergency-access');
}

export function grantedToMe(): Promise<ApiResult<GranteePolicyDto[]>> {
  return request<GranteePolicyDto[]>('/api/vault/emergency-access/granted-to-me');
}

/** Owner actions. `deny` is CallerGuard-only server-side — one tap, no step-up. */
export function denyPolicy(policyId: string): Promise<ApiResult<PolicyDto>> {
  return request<PolicyDto>(`/api/vault/emergency-access/${policyId}/deny`, { method: 'POST' });
}

export function rearmPolicy(policyId: string): Promise<ApiResult<PolicyDto>> {
  return request<PolicyDto>(`/api/vault/emergency-access/${policyId}/rearm`, { method: 'POST' });
}

export function revokePolicy(policyId: string): Promise<ApiResult<unknown>> {
  return request(`/api/vault/emergency-access/${policyId}`, { method: 'DELETE' });
}

/** Grantee actions. `request` starts the clock and grants nothing by itself. */
export function requestAccess(policyId: string): Promise<ApiResult<PolicyDto>> {
  return request<PolicyDto>(`/api/vault/emergency-access/${policyId}/request`, { method: 'POST' });
}

export interface ReleaseDto {
  ownerUserId: string;
  platformPart: string;
  wrappedMasterKeyRecovery: string;
  keyShare: string;
  threshold: number;
}

/**
 * Collect the escrow and reconstruct the owner's master key.
 *
 * ONE-SHOT: handing over the platform half spends the escrow, so this can only
 * succeed once per arrangement. It needs the grantee's OWN recovery private
 * key, which is wrapped under the grantee's master key — so a grantee must have
 * their own vault open to complete a release, and a stolen session alone
 * achieves nothing.
 *
 * Returns the master key BYTES. The caller owns wiping them; nothing here
 * persists or transmits them, and there is deliberately no path that sends the
 * result anywhere.
 */
export async function releaseAndRecover(input: {
  readonly policyId: string;
  readonly granteeUserId: string;
  readonly granteeMasterKey: CryptoKey;
  /** Both base64, exactly as `ownRecoveryKey` serves them. */
  readonly granteePublicKey: string;
  readonly wrappedPrivateKey: string;
}): Promise<ApiResult<{ ownerUserId: string; masterKeyBytes: Uint8Array; threshold: number }>> {
  const released = await request<ReleaseDto>(
    `/api/vault/emergency-access/${input.policyId}/release`,
    { method: 'POST' },
  );
  if (!released.ok) {
    return released;
  }

  const privateKey = await open(
    input.granteeMasterKey,
    fromBase64(input.wrappedPrivateKey),
    recoveryPrivateKeyAad(input.granteeUserId),
  );
  try {
    const masterKeyBytes = await recoverMasterKey({
      ownerUserId: released.data.ownerUserId,
      platformPart: released.data.platformPart,
      wrappedMasterKeyRecovery: released.data.wrappedMasterKeyRecovery,
      // ONE share. `configureEscrow` refuses any threshold above 1 for exactly
      // this reason — see the note there.
      shares: [
        {
          granteeUserId: input.granteeUserId,
          sealedShare: released.data.keyShare,
          publicKey: fromBase64(input.granteePublicKey),
          privateKey,
        },
      ],
    });
    return {
      ok: true,
      data: {
        ownerUserId: released.data.ownerUserId,
        masterKeyBytes,
        threshold: released.data.threshold,
      },
    };
  } finally {
    wipe(privateKey);
  }
}
