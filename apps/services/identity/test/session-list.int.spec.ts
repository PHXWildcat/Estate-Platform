/**
 * The paired-devices surface against real Postgres (M16).
 *
 * THE PROPERTY THIS FILE EXISTS FOR is the owner predicate on revocation, and
 * it lives in a statement — so a suite that fakes the repo cannot see it. Until
 * M16 the only revoke in the service took an id and no owner, which is correct
 * for its callers (logout already holds a verified session; the settlement lock
 * is a service credential acting on a whole account) and catastrophic for a
 * user-facing route, where the id arrives in the URL. The M13 `contact_in_use`
 * lesson says the predicate cannot live in a check above the update either.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('live session list + owned revocation (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitysesslist_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let sessions: SessionsRepo;

  const NOW = new Date('2026-08-10T12:00:00.000Z');
  const owner = randomUUID();
  const stranger = randomUUID();

  async function makeSession(
    userId: string,
    audience: 'account' | 'vault' | 'extension',
    opts: { expiresAt?: Date; revoked?: boolean } = {},
  ): Promise<string> {
    const id = randomUUID();
    const secret = randomUUID();
    await sessions.create({
      id,
      userId,
      refreshTokenH: hashToken(`r-${secret}`),
      accessTokenH: hashToken(`a-${secret}`),
      accessExpiresAt: new Date(NOW.getTime() + 900_000),
      expiresAt: opts.expiresAt ?? new Date(NOW.getTime() + 86_400_000),
      audience,
    });
    if (opts.revoked) {
      await sessions.revoke(id, 'test', NOW);
    }
    return id;
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }
    for (const id of [owner, stranger]) {
      await admin.query(
        `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
         VALUES ($1, $2, $3, 'x', $4)`,
        [id, Buffer.from(`ct-${id}`), Buffer.from(`bidx-${id}`), randomUUID()],
      );
    }
    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    sessions = new SessionsRepo(db);
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    await admin.query(`DELETE FROM ${schema}.extension_pairings`);
    await admin.query(`DELETE FROM ${schema}.sessions`);
  });

  it('lists only LIVE sessions, and carries the audience', async () => {
    const account = await makeSession(owner, 'account');
    const extension = await makeSession(owner, 'extension');
    await makeSession(owner, 'account', { revoked: true });
    await makeSession(owner, 'account', { expiresAt: new Date(NOW.getTime() - 1_000) });
    await makeSession(stranger, 'extension');

    const live = await sessions.listLiveForUser(owner, NOW);
    // The audience is what lets the surface say "browser extension" rather than
    // "a session", which is the whole reason the column crosses to the client.
    expect(live.map((r) => r.id).sort()).toEqual([account, extension].sort());
    expect(live.map((r) => r.audience).sort()).toEqual(['account', 'extension']);
  });

  it('REFUSES to revoke another user’s session, and leaves it live', async () => {
    // The defect this method exists to prevent. `revoke()` would have taken
    // this id happily.
    const victim = await makeSession(stranger, 'extension');
    expect(await sessions.revokeOwned(victim, owner, 'user_revoked', NOW)).toBe(false);

    const { rows } = await admin.query<{ revoked_at: Date | null }>(
      `SELECT revoked_at FROM ${schema}.sessions WHERE id = $1`,
      [victim],
    );
    expect(rows[0]?.revoked_at).toBeNull();
    // And it is still listed for its real owner — nothing was half-done.
    expect((await sessions.listLiveForUser(stranger, NOW)).map((r) => r.id)).toEqual([victim]);
  });

  it('revokes the caller’s own session, and a second attempt matches nothing', async () => {
    // The second `false` is what makes the route's uniform 404 honest: a
    // revoked session and a nonexistent one are the same answer, so a caller
    // cannot use repetition to learn that an id was real.
    const mine = await makeSession(owner, 'extension');
    expect(await sessions.revokeOwned(mine, owner, 'user_revoked', NOW)).toBe(true);
    expect(await sessions.revokeOwned(mine, owner, 'user_revoked', NOW)).toBe(false);
    expect(await sessions.listLiveForUser(owner, NOW)).toEqual([]);
  });

  it('an unknown id and someone else’s id are indistinguishable', async () => {
    const theirs = await makeSession(stranger, 'account');
    expect(await sessions.revokeOwned(randomUUID(), owner, 'user_revoked', NOW)).toBe(false);
    expect(await sessions.revokeOwned(theirs, owner, 'user_revoked', NOW)).toBe(false);
  });

  it('a revoked extension session stops resolving by its refresh token', async () => {
    // What revocation is FOR, end to end: the paired extension holds a refresh
    // token, and killing the row has to kill the credential rather than just
    // hide the row from a list.
    const id = randomUUID();
    const secret = randomUUID();
    await sessions.create({
      id,
      userId: owner,
      refreshTokenH: hashToken(`r-${secret}`),
      accessTokenH: hashToken(`a-${secret}`),
      accessExpiresAt: new Date(NOW.getTime() + 900_000),
      expiresAt: new Date(NOW.getTime() + 86_400_000),
      audience: 'extension',
    });
    expect(await sessions.findLiveByRefreshHash(hashToken(`r-${secret}`), NOW)).not.toBeNull();

    await sessions.revokeOwned(id, owner, 'user_revoked', NOW);
    expect(await sessions.findLiveByRefreshHash(hashToken(`r-${secret}`), NOW)).toBeNull();
  });
});
