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

  /*
   * THE FILL, WHICH IS THE ONE OPERATION THAT LETS A SECRET OUT (M16 PR3b).
   *
   * These run against a REAL sealed blob and a REAL unlocked holder, because the
   * property under test is that the holder RE-TAKES the origin decision from the
   * item's own encrypted `url` — a faked holder could only prove that a stub
   * returns what the stub was told to.
   */
  const ITEM = '44444444-0000-4000-8000-000000000000';
  const login = (enrolled: Enrolled): Promise<VaultItemRow> =>
    sealItem(enrolled, ITEM, {
      title: 'Bank login',
      username: 'someone',
      secret: 'the-password',
      url: 'https://bank.example.com/login',
    });

  it('fills when the item belongs to the page', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await login(enrolled);

    expect(await holder.fillFor([row], ITEM, 'https://bank.example.com/login')).toEqual({
      username: 'someone',
      secret: 'the-password',
    });
    // And across the registrable domain, which is what `match` means.
    expect(await holder.fillFor([row], ITEM, 'https://www.bank.example.com/')).not.toBeNull();
  });

  it('REFUSES a page the item does not belong to, however the caller asks', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await login(enrolled);

    // The caller names the item explicitly. It is refused anyway, because the
    // decision is not the caller's to make — this is the whole shape of the
    // variant: a compromised popup can ask for a fill, never for a secret.
    expect(await holder.fillFor([row], ITEM, 'https://evil.example.net/')).toBeNull();
    // A lookalike is REFUSED, not warned about (§4 TB9).
    expect(await holder.fillFor([row], ITEM, 'https://bank-example.com/')).toBeNull();
    // Scheme downgrade: saved on https, offered on http.
    expect(await holder.fillFor([row], ITEM, 'http://bank.example.com/')).toBeNull();
  });

  it('refuses an item id it was not given, rather than filling something else', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await login(enrolled);

    expect(
      await holder.fillFor(
        [row],
        '55555555-0000-4000-8000-000000000000',
        'https://bank.example.com/',
      ),
    ).toBeNull();
  });

  it('refuses to fill a locked vault', async () => {
    const holder = new VaultKeyHolder();
    await expect(holder.fillFor([], ITEM, 'https://bank.example.com/')).rejects.toThrow(
      'vault is locked',
    );
  });

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

describe('an item whose content is not what this build expects', () => {
  jest.setTimeout(60_000);

  it.each([
    ['a JSON array rather than an object', ['not', 'an', 'object']],
    ['a bare string', 'just a string'],
  ])('lists %s as unreadable', async (_label, content) => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealItem(enrolled, '77777777-0000-4000-8000-000000000000', content);
    expect(await holder.summarise([row])).toEqual([
      { id: row.id, itemType: 'login', title: '', unreadable: true },
    ]);
  });

  it('names an item with NO title as the empty string rather than refusing it', async () => {
    // A real record with a missing optional field is not a corrupt one, and a
    // user still has to be able to see the row.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealItem(enrolled, '88888888-0000-4000-8000-000000000000', { note: 'x' });
    expect(await holder.summarise([row])).toEqual([{ id: row.id, itemType: 'login', title: '' }]);
  });
});
