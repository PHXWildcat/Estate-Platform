/**
 * THE PASSWORD CHANGE, against real Postgres (M17 PR2).
 *
 * Everything asserted here lives in SQL — a trigger body, a transaction, and a
 * status predicate inside an UPDATE — so a faked repo could not get any of it
 * wrong and therefore could not prove any of it right. That is the M13 rule
 * ("a fix whose defect lived in SQL must be pinned by a test that runs SQL")
 * and the M14 round-2 refinement (drive the SERVICE, not the repo, so what is
 * measured is the decision feeding the statement rather than the statement
 * alone).
 *
 * Four properties, each a way this could be present and wrong:
 *
 *  1. THE OLD HASH IS NOT KEPT. `users_versions` captures a row image on every
 *     `users` UPDATE and this is the first UPDATE that column has ever had. A
 *     redacting capture that shipped one release late would have written
 *     verifiers into an append-only table nothing can retract.
 *  2. THE CAPTURE STILL HAS A WHO. Redaction is only defensible because what
 *     survives is who and when; identity was the one service that never set
 *     `app.actor_id`, so before this the image had neither.
 *  3. THE TWO WRITES COMMIT TOGETHER. A hash without the revocation leaves
 *     every credential minted under the old password live.
 *  4. THE STATUS ALLOWLIST IS IN THE STATEMENT. `findById` carries no status
 *     predicate, so a check above the UPDATE would be a check-then-act on the
 *     one route that hands out a new credential for a settled account.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import type { SecondFactorGate } from '../src/second-factor-gate';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';
import { UsersRepo } from '../src/users.repo';
import { Db } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-12T12:00:00.000Z');
const OLD_HASH = '$argon2id$v=19$m=65536,t=3,p=4$OLDSALT$OLD_HASH_SENTINEL';
const NEW_HASH = '$argon2id$v=19$m=65536,t=3,p=4$NEWSALT$NEW_HASH_SENTINEL';

describeIfPg('password change (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitypw_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let sessions: SessionsRepo;
  let service: AuthService;
  let currentPasswordIsRight: boolean;
  let holdsFactor: boolean;
  let securitySends: Array<{ userId: string; kind: string }>;

  const user = randomUUID();
  const ownSession = randomUUID();
  const otherSession = randomUUID();

  async function seedUser(status = 'active'): Promise<void> {
    // TRUNCATE, NOT DELETE, and that is a correctness fix rather than a speed
    // one. `DELETE FROM users` fires `trg_users_versions`, whose function body
    // references `users_versions` UNQUALIFIED — so it resolves through the
    // CONNECTION's search_path, not through the schema in the statement. This
    // admin client has none, so on a database that happens to have a
    // `public.users_versions` (any machine running the stack) the reset wrote
    // its rows into the REAL table and passed; on CI's database, which has no
    // such table, it failed with `relation "users_versions" does not exist`.
    // Locally green for the wrong reason, and polluting live data while it was.
    // TRUNCATE fires no row triggers at all, so the reset cannot write anywhere.
    await admin.query(
      `TRUNCATE ${schema}.users_versions, ${schema}.sessions, ${schema}.auth_events, ${schema}.users CASCADE`,
    );
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id, status)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user, Buffer.from('ct'), Buffer.from(`bidx-${user}`), OLD_HASH, randomUUID(), status],
    );
    for (const [id, token] of [
      [ownSession, 'own'],
      [otherSession, 'other'],
    ] as const) {
      await sessions.create({
        id,
        userId: user,
        refreshTokenH: hashToken(`refresh-${token}`),
        accessTokenH: hashToken(`access-${token}`),
        accessExpiresAt: new Date(NOW.getTime() + 900_000),
        expiresAt: new Date(NOW.getTime() + 86_400_000),
        audience: 'account',
      });
    }
  }

  async function versionRows(): Promise<
    Array<{ row_data: Record<string, unknown>; actor_id: string | null }>
  > {
    const rows = await admin.query<{ row_data: Record<string, unknown>; actor_id: string | null }>(
      `SELECT row_data, actor_id FROM ${schema}.users_versions ORDER BY version_seq`,
    );
    return rows.rows;
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Unqualified names inside trigger bodies resolve against the CONNECTION's
    // search_path. Pinning it here keeps every such resolution inside the test
    // schema rather than reaching whatever `public` happens to hold — the same
    // hazard the TRUNCATE above avoids, closed a second way because a future
    // case that does need a DELETE should not have to rediscover it.
    await admin.query(`SET search_path TO ${schema}`);

    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    sessions = new SessionsRepo(db);
    currentPasswordIsRight = true;
    holdsFactor = false;
    securitySends = [];

    service = new AuthService(
      new UsersRepo(db),
      sessions,
      {} as unknown as MfaRepo,
      new AuthEventsRepo(db),
      {
        // Argon2 stubbed: this suite is about the SQL, and a real hash would
        // add seconds per case without changing an assertion.
        verifyPassword: (): Promise<boolean> => Promise.resolve(currentPasswordIsRight),
        hashPassword: (): Promise<string> => Promise.resolve(NEW_HASH),
      } as unknown as PasswordHasher,
      { passwordChanged: (): Promise<void> => Promise.resolve() } as unknown as EventsService,
      {} as unknown as FieldCrypto,
      {} as unknown as DekRepository,
      {} as unknown as IdentityConfig,
      () => NOW,
      {
        sendAccountSecurity: (input: {
          userId: string;
          kind: string;
        }): Promise<{
          accepted: boolean;
        }> => {
          securitySends.push(input);
          return Promise.resolve({ accepted: true });
        },
      } as never,
      {} as unknown as EmailVerificationService,
      {
        // The REAL gate has its own Postgres-backed spec; here the condition is
        // a switch, because what is under test is what happens after it passes.
        assertMayAddFactor: (): Promise<void> => Promise.resolve(),
        holdsVerifiedFactor: (): Promise<boolean> => Promise.resolve(holdsFactor),
      } as unknown as SecondFactorGate,
      db,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    currentPasswordIsRight = true;
    holdsFactor = false;
    securitySends = [];
    await seedUser();
  });

  it('THE OLD HASH IS NOT KEPT in the version image', async () => {
    // The load-bearing assertion of this PR. `to_jsonb(OLD)` would have written
    // the previous Argon2id verifier into a table this schema REVOKEs UPDATE
    // and DELETE on, outside the DEK envelope, so crypto-shredding would never
    // reach it. Migration 008 subtracts exactly that key.
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');

    const versions = await versionRows();
    expect(versions).toHaveLength(1);
    expect(versions[0]?.row_data).not.toHaveProperty('password_hash');
    // …and searching the whole serialized image, because a key could survive
    // under a different name or nested somewhere the property check misses.
    expect(JSON.stringify(versions[0]?.row_data)).not.toContain('OLD_HASH_SENTINEL');
    expect(JSON.stringify(versions[0]?.row_data)).not.toContain('NEW_HASH_SENTINEL');
  });

  it('KEEPS what the capture is FOR — the DEK-wrapped columns and the actor', async () => {
    // Redaction is only defensible if what survives has audit value. `email_ct`
    // and `dek_id` stay because they ARE under the envelope, so the shred
    // reaches them; and the actor is what makes the row evidence rather than a
    // note that something changed.
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');

    const versions = await versionRows();
    expect(versions[0]?.row_data).toHaveProperty('email_ct');
    expect(versions[0]?.row_data).toHaveProperty('dek_id');
    expect(versions[0]?.actor_id).toBe(user);
  });

  it('writes the new hash and REVOKES every other session, in one transaction', async () => {
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');

    const live = await admin.query<{ id: string }>(
      `SELECT id FROM ${schema}.sessions WHERE revoked_at IS NULL`,
    );
    expect(live.rows.map((r) => r.id)).toEqual([ownSession]);

    const revoked = await admin.query<{ revoke_reason: string }>(
      `SELECT revoke_reason FROM ${schema}.sessions WHERE id = $1`,
      [otherSession],
    );
    expect(revoked.rows[0]?.revoke_reason).toBe('password_changed');

    const hash = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    expect(hash.rows[0]?.password_hash).toBe(NEW_HASH);
  });

  it('the CALLER’S OWN session survives — the protective action is not the harder one', async () => {
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');
    const still = await sessions.findLiveByAccessHash(hashToken('access-own'), NOW);
    expect(still).toMatchObject({ id: ownSession });
  });

  it('a WRONG current password changes nothing at all', async () => {
    currentPasswordIsRight = false;
    await expect(
      service.changePassword(user, ownSession, {} as never, 'wrong', 'a-new-long-password'),
    ).rejects.toMatchObject({ response: { error: 'invalid_credentials' } });

    const hash = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    expect(hash.rows[0]?.password_hash).toBe(OLD_HASH);
    const live = await admin.query<{ id: string }>(
      `SELECT id FROM ${schema}.sessions WHERE revoked_at IS NULL`,
    );
    expect(live.rows).toHaveLength(2);
    expect(await versionRows()).toHaveLength(0);
    expect(securitySends).toEqual([]);
  });

  it('REFUSES for an account in settlement, from inside the UPDATE', async () => {
    // `findById` has no status predicate and the login gate is TypeScript at a
    // line this route never reaches, so a copy of the login flow would have
    // handed a fraudulent heir a working credential on a settled account. The
    // predicate is in the statement; nothing is written and no notice is sent.
    await seedUser('settlement');
    await expect(
      service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password'),
    ).rejects.toMatchObject({ response: { error: 'invalid_credentials' } });

    const hash = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    expect(hash.rows[0]?.password_hash).toBe(OLD_HASH);
    expect(await versionRows()).toHaveLength(0);
    expect(securitySends).toEqual([]);
  });

  it('PERMITS deceased_pending — the §5.1 rescue path must not be harder', async () => {
    // The living owner disputing a fraudulent death report is exactly the
    // person who may need to change a password, and their sessions deliberately
    // keep working at this status. Refusing here would make the rescue harder
    // for the one user the case targets.
    await seedUser('deceased_pending');
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');

    const hash = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    expect(hash.rows[0]?.password_hash).toBe(NEW_HASH);
  });

  it('records its OWN ledger kind, never the one the liveness interlock reads', async () => {
    // `stepup.granted` is hardcoded in `UsersRepo.updateStatusFrom`'s NOT
    // EXISTS, so emitting it here would silently void an open death case as a
    // side effect of a password change — a docs/03 §5.1 policy decision taken
    // by accident, and a capability handed to whoever completed the change.
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');

    const kinds = await admin.query<{ kind: string }>(
      `SELECT kind FROM ${schema}.auth_events WHERE user_id = $1`,
      [user],
    );
    expect(kinds.rows.map((r) => r.kind)).toEqual(['password.changed']);
    expect(kinds.rows.map((r) => r.kind)).not.toContain('stepup.granted');
  });

  it('tells the owner, on the account-security kind', async () => {
    await service.changePassword(user, ownSession, {} as never, 'old', 'a-new-long-password');
    expect(securitySends).toEqual([{ userId: user, kind: 'identity.password_changed' }]);
  });
});
