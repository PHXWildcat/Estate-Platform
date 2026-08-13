/**
 * THE PASSKEY MANAGEMENT VERTICAL, against real Postgres (M17 PR5).
 *
 * What lives in SQL here: the owner predicate riding the revoke/rename
 * UPDATEs, the `revoked_at IS NULL` predicates across every read — including
 * the `hasCredentials` fix, which is THE gate predicate `SecondFactorGate`
 * rests on — and the global `credential_id` uniqueness surfacing as a typed
 * outcome. The connection is search_path-pinned (the PR2/PR4 lesson).
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { WebAuthnRepo } from '../src/webauthn.repo';
import { Db } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('webauthn management (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitypasskey_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let repo: WebAuthnRepo;
  let user: string;
  const NOW = new Date();

  async function seedCredential(
    userId: string,
    credentialId: Buffer,
    nickname: string | null = null,
  ): Promise<string> {
    const outcome = await repo.insertCredential({
      userId,
      credentialId,
      publicKey: Buffer.from('pk'),
      signCount: 0,
      transports: null,
      aaguid: null,
      nickname,
      isHardwareKey: false,
    });
    if (outcome !== 'inserted') throw new Error(`seed failed: ${outcome}`);
    const rows = await admin.query<{ id: string }>(
      `SELECT id FROM ${schema}.webauthn_credentials WHERE credential_id = $1`,
      [credentialId],
    );
    return rows.rows[0]?.id as string;
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    await admin.query(`SET search_path TO ${schema}`);
    const migr = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migr.connect();
    try {
      await new Migrator(migr, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migr.end();
    }
    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    repo = new WebAuthnRepo(db);
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    await admin.query(
      `TRUNCATE ${schema}.webauthn_credentials, ${schema}.webauthn_challenges,
                ${schema}.users_versions, ${schema}.users CASCADE`,
    );
    user = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'h', $4)`,
      [user, Buffer.from('ct'), Buffer.from(randomUUID()), randomUUID()],
    );
  });

  it('REVOKING THE LAST PASSKEY DISARMS THE GATE — the hasCredentials fix, the reason this file exists', async () => {
    const id = await seedCredential(user, Buffer.from('cred-1'));
    expect(await repo.hasCredentials(user)).toBe(true);

    expect(await repo.revokeCredential(user, id, NOW)).toBe(true);

    // Before the fix this stayed true forever: `SecondFactorGate` would have
    // demanded a factor the user could no longer produce, permanently locking
    // enrolment AND every arming gate on a TOTP-less account.
    expect(await repo.hasCredentials(user)).toBe(false);
    expect(await repo.listForUser(user)).toEqual([]);
    // …and the revoked credential no longer authenticates.
    expect(await repo.findCredentialById(Buffer.from('cred-1'))).toBeNull();
  });

  it('the owner predicate rides the UPDATE — a stranger revokes and renames NOTHING', async () => {
    const id = await seedCredential(user, Buffer.from('cred-owner'));
    const stranger = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'h', $4)`,
      [stranger, Buffer.from('ct2'), Buffer.from(randomUUID()), randomUUID()],
    );
    expect(await repo.revokeCredential(stranger, id, NOW)).toBe(false);
    expect(await repo.renameCredential(stranger, id, 'mine now')).toBe(false);
    // The credential is untouched and still the owner's.
    expect(await repo.hasCredentials(user)).toBe(true);
    const rows = await repo.listForUser(user);
    expect(rows).toHaveLength(1);
    expect(rows[0]?.nickname).toBeNull();
  });

  it('rename labels the live row and refuses the revoked one', async () => {
    const id = await seedCredential(user, Buffer.from('cred-name'));
    expect(await repo.renameCredential(user, id, 'MacBook Touch ID')).toBe(true);
    expect((await repo.listForUser(user))[0]?.nickname).toBe('MacBook Touch ID');

    await repo.revokeCredential(user, id, NOW);
    expect(await repo.renameCredential(user, id, 'zombie')).toBe(false);
  });

  it('a SECOND ACCOUNT registering the same authenticator gets the typed duplicate, not a 500', async () => {
    await seedCredential(user, Buffer.from('shared-authenticator'));
    const other = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'h', $4)`,
      [other, Buffer.from('ct3'), Buffer.from(randomUUID()), randomUUID()],
    );
    const outcome = await repo.insertCredential({
      userId: other,
      credentialId: Buffer.from('shared-authenticator'),
      publicKey: Buffer.from('pk2'),
      signCount: 0,
      transports: null,
      aaguid: null,
      nickname: null,
      isHardwareKey: false,
    });
    expect(outcome).toBe('duplicate');
    // The first account's binding is untouched.
    expect(await repo.hasCredentials(user)).toBe(true);
  });

  it('the management projection returns labels and timestamps, never key material', async () => {
    await seedCredential(user, Buffer.from('cred-proj'), 'YubiKey');
    const rows = await repo.listForUser(user);
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(Object.keys(row).sort()).toEqual([
      'created_at',
      'id',
      'is_hardware_key',
      'last_used_at',
      'nickname',
    ]);
  });
});
