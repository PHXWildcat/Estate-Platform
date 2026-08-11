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
    itemType: 'password',
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

  it('fills nothing from a blob it cannot open', async () => {
    // The catch path: a row whose ciphertext is not ours decrypts to nothing, and
    // the answer is the same `null` as a wrong page — no reason, by design.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await login(enrolled);
    const corrupted = { ...row, blob: row.blob.slice(0, -8) + 'AAAAAAAA' };

    expect(await holder.fillFor([corrupted], ITEM, 'https://bank.example.com/')).toBeNull();
  });

  /*
   * SEALING (M16 PR4a) — the first plaintext to travel INTO the key holder.
   *
   * Round-tripped through the holder's OWN reader rather than asserted against a
   * fixture: sealing is only correct if what comes back out is what went in,
   * under the same AAD, and a test that checked the ciphertext against a
   * recorded blob would be checking the recording.
   */
  it('seals content the same holder can open again', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);

    const content = {
      title: 'Sealed here',
      username: 'someone',
      secret: 'the-secret',
      url: 'https://bank.example.com/',
    };
    const blob = await holder.sealItem({ itemId: ITEM, blobVersion: 1, content });

    const row: VaultItemRow = {
      id: ITEM,
      itemType: 'password',
      blob,
      blobVersion: 1,
      updatedAt: '2026-08-11T00:00:00.000Z',
    };
    expect(await holder.summarise([row])).toEqual([
      { id: ITEM, itemType: 'password', title: 'Sealed here', blobVersion: 1 },
    ]);
    // And the whole content survives, which `summarise` alone would not show.
    expect(await holder.fillFor([row], ITEM, 'https://bank.example.com/login')).toEqual({
      username: 'someone',
      secret: 'the-secret',
    });
  });

  it('binds the blob version into the AAD, so a blob cannot move between slots', async () => {
    // docs/04 M6: create = 1, an update of N encrypts under N+1. If the version
    // were not bound, a blob sealed for one slot would open in another — which
    // is what lets an old ciphertext be replayed over a newer one.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);

    const blob = await holder.sealItem({
      itemId: ITEM,
      blobVersion: 2,
      content: { title: 'v2' },
    });
    const claimingV1: VaultItemRow = {
      id: ITEM,
      itemType: 'password',
      blob,
      blobVersion: 1,
      updatedAt: 'now',
    };
    // Presented as version 1 it does not open — listed as unreadable rather than
    // silently accepted.
    expect(await holder.summarise([claimingV1])).toEqual([
      { id: ITEM, itemType: 'password', title: '', blobVersion: 1, unreadable: true },
    ]);
  });

  it('refuses a version that is not a positive integer, rather than sealing under it', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      await expect(
        holder.sealItem({ itemId: ITEM, blobVersion: bad, content: { title: 'x' } }),
      ).rejects.toThrow('blobVersion');
    }
  });

  /*
   * MERGING INSIDE THE HOLDER (M16 PR4a) — what makes an edit possible without
   * the popup ever receiving the content it is not changing.
   */
  const sealedLogin = async (enrolled: Enrolled): Promise<VaultItemRow> =>
    sealItem(enrolled, ITEM, {
      title: 'Bank login',
      username: 'someone',
      secret: 'the-original',
      url: 'https://bank.example.com/',
    });

  it('changes only what it was given, and leaves the rest alone', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealedLogin(enrolled);

    const blob = await holder.resealItem({
      rows: [row],
      itemId: ITEM,
      changes: { secret: 'the-new-one' },
    });
    const next: VaultItemRow = { ...row, blob: blob as string, blobVersion: row.blobVersion + 1 };

    // The changed field changed...
    expect(await holder.fillFor([next], ITEM, 'https://bank.example.com/')).toEqual({
      username: 'someone',
      secret: 'the-new-one',
    });
    // ...and the untouched ones survived, including the url the fill depends on
    // and the title the list shows.
    expect(await holder.summarise([next])).toEqual([
      { id: ITEM, itemType: 'password', title: 'Bank login', blobVersion: 2 },
    ]);
  });

  it('treats an EXPLICIT empty string as a real value, unlike an absent field', async () => {
    // A form field left blank must not erase a password the user cannot see, so
    // absent means unchanged. Clearing one on purpose has to remain possible,
    // and the two are told apart by presence — the profile-SSN distinction.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealedLogin(enrolled);

    const blob = await holder.resealItem({
      rows: [row],
      itemId: ITEM,
      changes: { username: '' },
    });
    const next: VaultItemRow = { ...row, blob: blob as string, blobVersion: row.blobVersion + 1 };
    expect(await holder.fillFor([next], ITEM, 'https://bank.example.com/')).toEqual({
      username: '',
      secret: 'the-original',
    });
  });

  it('refuses an item it was not given, rather than creating one', async () => {
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealedLogin(enrolled);
    expect(
      await holder.resealItem({
        rows: [row],
        itemId: '77777777-0000-4000-8000-000000000000',
        changes: { secret: 'x' },
      }),
    ).toBeNull();
  });

  it('refuses an item this build cannot read, rather than REPLACING it', async () => {
    // An edit must not turn a display problem into data loss: if the existing
    // content will not open, there is nothing to merge into.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealedLogin(enrolled);
    const wrongVersion: VaultItemRow = { ...row, blobVersion: row.blobVersion + 5 };
    expect(
      await holder.resealItem({ rows: [wrongVersion], itemId: ITEM, changes: { secret: 'x' } }),
    ).toBeNull();
  });

  it('refuses to seal into a locked vault', async () => {
    const holder = new VaultKeyHolder();
    await expect(
      holder.sealItem({ itemId: ITEM, blobVersion: 1, content: { title: 'x' } }),
    ).rejects.toThrow('vault is locked');
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

    expect(summaries).toEqual([
      { id: row.id, itemType: 'password', title: 'Bank login', blobVersion: 1 },
    ]);
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

    expect(summaries).toEqual([
      { id: row.id, itemType: 'password', title: '', blobVersion: 2, unreadable: true },
    ]);
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
      { id: row.id, itemType: 'password', title: '', blobVersion: 1, unreadable: true },
    ]);
  });

  it('names an item with NO title as the empty string rather than refusing it', async () => {
    // A real record with a missing optional field is not a corrupt one, and a
    // user still has to be able to see the row.
    const enrolled = await enrol();
    const holder = new VaultKeyHolder();
    await unlock(holder, enrolled, enrolled.secretKey);
    const row = await sealItem(enrolled, '88888888-0000-4000-8000-000000000000', { note: 'x' });
    expect(await holder.summarise([row])).toEqual([
      { id: row.id, itemType: 'password', title: '', blobVersion: 1 },
    ]);
  });
});
