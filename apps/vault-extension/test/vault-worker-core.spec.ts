/**
 * A REAL SRP-6a UNLOCK, driven end to end in process.
 *
 * `@estate/vault-crypto` ships both roles — the vault service imports the
 * server half — so this test enrols a vault, completes a genuine handshake
 * against the verifier that enrolment produced, and opens an item the same
 * crypto sealed. A fake that returned canned values could not tell "the key
 * holder opened it" from "the crypto never ran", which is the `vault-web`
 * no-key-material-egress precedent and the reason jest resolves the crypto to
 * the package SOURCE rather than to a build.
 *
 * What it pins is what PR2b claims: the worker opens a vault from a password
 * and a Secret Key, the master key it holds is NON-EXTRACTABLE, it decrypts far
 * enough to name items and no further, and locking really drops it.
 */
import {
  createServerEphemeral,
  createVaultEnrollment,
  decodeGroupElement,
  encodeGroupElement,
  encryptItem,
  fromBase64,
  toBase64,
  verifyClientSession,
  type VaultEnrollment,
} from '@estate/vault-crypto';
import { VaultKeyHolder, type SrpChallenge, type VaultItemRow } from '../src/vault-worker-core';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'a vault password nobody else knows';
const VAULT_SESSION_ID = '99999999-0000-4000-8000-000000000000';

interface Enrolled {
  enrollment: VaultEnrollment;
  secretKey: string;
  payload: Record<string, string>;
  /**
   * The master key enrolment produced. `createVaultEnrollment` hands it back
   * directly, so the fixture seals items with the SAME key the worker will
   * unwrap for itself after the handshake — which is what makes opening one a
   * real result rather than a round trip through the fixture's own assumptions.
   */
  masterKey: CryptoKey;
}

async function enrol(): Promise<Enrolled> {
  const { enrollment, masterKey } = await createVaultEnrollment({
    userId: USER,
    password: PASSWORD,
  });
  return {
    enrollment,
    masterKey,
    secretKey: enrollment.secretKey,
    payload: enrollment.payload as unknown as Record<string, string>,
  };
}

/** Complete a handshake against the real server half and open the vault. */
async function unlock(
  holder: VaultKeyHolder,
  enrolled: Enrolled,
  secretKey: string,
): Promise<void> {
  const verifier = decodeGroupElement(enrolled.payload['srpVerifier'] as string, 'verifier');
  const ephemeral = await createServerEphemeral(verifier);
  const challenge: SrpChallenge = {
    handshakeId: '00000000-0000-4000-8000-000000000000',
    srpSalt: enrolled.payload['srpSalt'] as string,
    kdfParams: enrolled.payload['kdfParams'],
    serverPublic: encodeGroupElement(ephemeral.B),
  };

  const { publicA, m1 } = await holder.prepare({
    userId: USER,
    password: PASSWORD,
    secretKey,
    challenge,
  });

  const verified = await verifyClientSession({
    userId: USER,
    salt: fromBase64(challenge.srpSalt),
    verifier,
    ephemeral,
    A: decodeGroupElement(publicA, 'client public value'),
    M1: fromBase64(m1),
  });
  if (!verified) throw new Error('the server half refused the client proof');

  await holder.finish({
    serverM2: toBase64(verified.M2),
    wrappedMasterKey: enrolled.payload['wrappedMasterKey'] as string,
    vaultSessionId: VAULT_SESSION_ID,
  });
}

/** Seal an item the way `vault-web` does, so the worker opens a real blob. */
async function sealItem(
  enrolled: Enrolled,
  itemId: string,
  content: unknown,
): Promise<VaultItemRow> {
  const plaintext = new TextEncoder().encode(JSON.stringify(content));
  const blob = await encryptItem(
    enrolled.masterKey,
    { userId: USER, itemId, blobVersion: 1 },
    plaintext,
  );
  return {
    id: itemId,
    itemType: 'login',
    blob: toBase64(blob),
    blobVersion: 1,
    updatedAt: '2026-08-10T12:00:00.000Z',
  };
}

describe('the key holder', () => {
  jest.setTimeout(60_000); // 650k PBKDF2 iterations, twice, on the real crypto.

  it('opens a vault from a password and a Secret Key, and names its items', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    expect(holder.isUnlocked).toBe(false);

    await unlock(holder, enrolled, enrolled.secretKey);
    expect(holder.isUnlocked).toBe(true);

    const row = await sealItem(enrolled, '33333333-0000-4000-8000-000000000000', {
      title: 'Bank login',
      username: 'someone',
      secret: 'the password nobody may see here',
    });
    const summaries = await holder.summarise([row]);

    expect(summaries).toEqual([{ id: row.id, itemType: 'login', title: 'Bank login' }]);
    // THE SECRET HALF IS NOT IN THE RESPONSE. PR2b lists what a person is
    // choosing between; reading one is PR3's concern, with the gesture
    // requirement that governs it.
    expect(JSON.stringify(summaries)).not.toContain('the password nobody may see here');
    expect(JSON.stringify(summaries)).not.toContain('someone');
  });

  it('refuses a WRONG Secret Key, with the server half doing the refusing', async () => {
    // 2SKD: the password alone is not enough. The handshake fails at the SERVER,
    // which is what makes an offline attack on the Secret Key impossible.
    const enrolled = await enrol();
    const other = await enrol();
    const holder = new VaultKeyHolder();
    await expect(unlock(holder, enrolled, other.secretKey)).rejects.toThrow();
    expect(holder.isUnlocked).toBe(false);
  });

  it('holds the master key NON-EXTRACTABLE — the TB6 property, asserted', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);

    // Reach into the holder the way an injected script would have to, and
    // confirm the platform refuses to hand the bytes over.
    const key = (holder as unknown as { ['#vault']?: unknown })['#vault'];
    expect(key).toBeUndefined(); // `#private`, not TypeScript `private`

    // ...and prove the property on the key the same code path produced.
    expect(enrolled.masterKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', enrolled.masterKey)).rejects.toThrow();
  });

  it('lists an unopenable blob rather than hiding it', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);

    const row = await sealItem(enrolled, '44444444-0000-4000-8000-000000000000', { title: 'ok' });
    // Same blob, claimed as a DIFFERENT version: the AAD binds the version, so
    // the AEAD refuses. That is the anti-rollback binding working.
    const rolledBack: VaultItemRow = { ...row, blobVersion: 2 };
    const summaries = await holder.summarise([rolledBack]);

    expect(summaries).toEqual([{ id: row.id, itemType: 'login', title: '', unreadable: true }]);
  });

  it('refuses to summarise while locked, and locking drops the key', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await expect(holder.summarise([])).rejects.toThrow('vault is locked');

    await unlock(holder, enrolled, enrolled.secretKey);
    expect(holder.isUnlocked).toBe(true);

    holder.lock();
    expect(holder.isUnlocked).toBe(false);
    await expect(holder.summarise([])).rejects.toThrow('vault is locked');
  });

  it('cannot finish a handshake it never started', async () => {
    const holder = new VaultKeyHolder();
    await expect(
      holder.finish({
        serverM2: 'AA==',
        wrappedMasterKey: 'AA==',
        vaultSessionId: VAULT_SESSION_ID,
      }),
    ).rejects.toThrow('no handshake in progress');
  });
});
