/**
 * Integration tests for WebAuthnRepo against a real Postgres, gated exactly
 * like identity.int.spec.ts: set PG_TEST_URL to run, otherwise skip. Runs the
 * service's real migrations into a scratch schema and exercises the two
 * WebAuthn tables directly (challenge single-use; credential insert/find;
 * sign_count update).
 *
 * The full registration/authentication ceremony (attestation + assertion
 * verification) is covered by unit tests with a mocked @simplewebauthn/server
 * — a real end-to-end ceremony needs a virtual authenticator, deferred; see
 * README. This suite covers the persistence half of that gap.
 */
import 'reflect-metadata';
import { randomUUID } from 'node:crypto';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import { WebAuthnRepo } from '../src/webauthn.repo';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('WebAuthnRepo against Postgres', () => {
  jest.setTimeout(60_000);

  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `idsvc_webauthn_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let repo: WebAuthnRepo;
  let userId: string;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);

    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      const migrator = new Migrator(migrClient, `${__dirname}/../migrations`);
      const { applied } = await migrator.migrate();
      expect(applied).toContain('001_auth_schema.sql');
    } finally {
      await migrClient.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    repo = new WebAuthnRepo(db);

    // webauthn_credentials.user_id references users(id) — create a user first.
    userId = randomUUID();
    const dekId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, dek_id)
       VALUES ($1, $2, $3, $4)`,
      [userId, Buffer.from('ct'), Buffer.from('bidx'), dekId],
    );
  });

  afterAll(async () => {
    if (db) {
      await db.onModuleDestroy();
    }
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
      await admin.end();
    }
  });

  it('consumes a challenge exactly once (single-use)', async () => {
    const future = new Date(Date.now() + 60_000);
    await repo.insertChallenge({
      userId,
      challenge: 'chal-abc',
      kind: 'registration',
      expiresAt: future,
    });

    const first = await repo.consumeChallenge(userId, 'registration', new Date());
    expect(first).toBe('chal-abc');

    // Second consume finds nothing — the row was deleted on first consumption.
    const second = await repo.consumeChallenge(userId, 'registration', new Date());
    expect(second).toBeNull();
  });

  it('does not return an expired challenge (but still deletes it)', async () => {
    const past = new Date(Date.now() - 1_000);
    await repo.insertChallenge({
      userId,
      challenge: 'chal-expired',
      kind: 'authentication',
      expiresAt: past,
    });

    const consumed = await repo.consumeChallenge(userId, 'authentication', new Date());
    expect(consumed).toBeNull();

    // Confirm it was deleted (single-use even when expired).
    const { rows } = await admin.query(
      `SELECT count(*)::int AS n FROM ${schema}.webauthn_challenges
        WHERE user_id = $1 AND kind = 'authentication'`,
      [userId],
    );
    expect((rows[0] as { n: number }).n).toBe(0);
  });

  it('inserts a credential and finds it by id and by user', async () => {
    const credentialId = Buffer.from(`cred-${randomUUID()}`);
    await repo.insertCredential({
      userId,
      credentialId,
      publicKey: Buffer.from('pk-bytes'),
      signCount: 0,
      transports: ['internal', 'hybrid'],
      aaguid: '00000000-0000-0000-0000-000000000000',
      nickname: null,
      isHardwareKey: false,
    });

    const byId = await repo.findCredentialById(credentialId);
    expect(byId).not.toBeNull();
    expect(byId?.user_id).toBe(userId);
    expect(byId?.transports).toEqual(['internal', 'hybrid']);
    expect(byId?.sign_count).toBe('0'); // BIGINT ⇒ string from pg

    const byUser = await repo.findCredentialsByUser(userId);
    expect(byUser.map((c) => c.credential_id.toString('utf8'))).toContain(
      credentialId.toString('utf8'),
    );
  });

  it('updates the sign_count and last_used_at', async () => {
    const credentialId = Buffer.from(`cred-${randomUUID()}`);
    await repo.insertCredential({
      userId,
      credentialId,
      publicKey: Buffer.from('pk-bytes-2'),
      signCount: 3,
      transports: null,
      aaguid: null,
      nickname: null,
      isHardwareKey: true,
    });

    const usedAt = new Date();
    await repo.updateSignCount(credentialId, 9, usedAt);

    const updated = await repo.findCredentialById(credentialId);
    expect(updated?.sign_count).toBe('9');
    const { rows } = await admin.query(
      `SELECT last_used_at FROM ${schema}.webauthn_credentials WHERE credential_id = $1`,
      [credentialId],
    );
    expect((rows[0] as { last_used_at: Date | null }).last_used_at).not.toBeNull();
  });
});
