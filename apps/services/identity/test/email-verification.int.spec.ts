/**
 * The verification-code store against real Postgres (M14).
 *
 * The unit suite fakes this repo, so every property that lives in SQL is
 * invisible there — the M13 lesson, stated plainly: a fix whose defect lives in
 * a statement must be pinned by a test that runs the statement. What is
 * asserted here is exactly that set: the "one live code per user" index, the
 * concurrent-redemption CAS, and the liveness predicates the service relies on.
 */
import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import type { NotificationsPort } from '@estate/notifications-client';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { EventsService } from '../src/events.service';
import { EmailVerificationService } from '../src/email-verification.service';
import {
  EmailVerificationRepo,
  MAX_VERIFY_ATTEMPTS,
  VerificationRaceError,
} from '../src/email-verification.repo';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const sha = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();

describeIfPg('email_verifications against Postgres (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identityverify_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let repo: EmailVerificationRepo;

  const NOW = new Date('2026-08-07T12:00:00.000Z');
  const LATER = new Date(NOW.getTime() + 60_000);
  const user = randomUUID();

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

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    repo = new EmailVerificationRepo(db);
    // email_verifications references users(id).
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [user, Buffer.from('ct'), Buffer.from('bidx'), randomUUID()],
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('permits exactly ONE live code per user', async () => {
    // Without the partial unique index, two concurrent logins would each
    // observe "no live code", mint two, mail the address twice and silently
    // orphan the first. The loser takes the violation and treats it as
    // "somebody already minted one", which is the idempotent outcome wanted.
    await repo.insert({ userId: user, codeSha256: sha('first'), expiresAt: LATER });
    await expect(
      repo.insert({ userId: user, codeSha256: sha('second'), expiresAt: LATER }),
    ).rejects.toBeInstanceOf(VerificationRaceError);
  });

  it('frees the slot once the live code is retired', async () => {
    expect(await repo.revokeLive(user, NOW)).toBe(true);
    await expect(
      repo.insert({ userId: user, codeSha256: sha('second'), expiresAt: LATER }),
    ).resolves.toEqual(expect.any(String));
  });

  it('treats a spent code as freeing the slot too', async () => {
    const row = await repo.findByCode(sha('second'));
    expect(await repo.markVerified(row!.id, NOW)).toBe(true);
    await expect(
      repo.insert({ userId: user, codeSha256: sha('third'), expiresAt: LATER }),
    ).resolves.toEqual(expect.any(String));
  });

  it('resolves a code by DIGEST alone, and never by user', async () => {
    const row = await repo.findByCode(sha('third'));
    expect(row?.user_id).toBe(user);
    expect(await repo.findByCode(sha('never-minted'))).toBeNull();
    // There is deliberately no repo method taking a user id to find a code:
    // one would let a route become an oracle for whether an account has a code
    // outstanding.
    expect(Object.getOwnPropertyNames(EmailVerificationRepo.prototype)).toEqual([
      'constructor',
      'findLive',
      // M14 review: the re-issue floor keys on the last MINT rather than on a
      // live code, so a failed send (which retires its code) cannot skip it.
      'lastMintedAt',
      'insert',
      'findByCode',
      'countAttempt',
      'markVerified',
      'revokeLive',
    ]);
  });

  it('spends a code EXACTLY ONCE under concurrency', async () => {
    // The CAS restates every liveness precondition in its own WHERE, so two
    // concurrent redemptions of one code produce exactly one success — the
    // check-then-act shape the M13 round-3 review closed in profile, avoided
    // here rather than repeated.
    const row = await repo.findByCode(sha('third'));
    const results = await Promise.all([
      repo.markVerified(row!.id, NOW),
      repo.markVerified(row!.id, NOW),
      repo.markVerified(row!.id, NOW),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  /**
   * THE M14 REVIEW'S WORST FINDING, pinned against a real database.
   *
   * `ux_email_verifications_live` is `WHERE revoked_at IS NULL AND verified_at
   * IS NULL` — a partial index cannot reference `now()`, so a LAPSED row still
   * occupies the live slot. `findLive` carries the clock and therefore sees
   * nothing. The service used to retire only when `findLive` returned a row, so
   * once a code lapsed nothing ever cleared it: the next insert took the unique
   * violation, the ceremony answered `too_soon` forever, and the account could
   * never be verified — permanently refusing every M14 arming gate. Ignoring
   * the first email was the whole trigger.
   *
   * The earlier version of this suite asserted only that `findLive` returns
   * null "so the service re-mints rather than waiting" — and never asserted the
   * re-mint. That is the M13 lesson (a test named for a property it never
   * touched) and it is why this shipped, so the assertion below is the one that
   * was missing: a LAPSED row must not block the next insert.
   */
  it('a LAPSED code does not wedge the live slot: retire then re-mint', async () => {
    const stuck = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [stuck, Buffer.from('ct'), Buffer.from('bidx-stuck'), randomUUID()],
    );
    await repo.insert({
      userId: stuck,
      codeSha256: sha('lapsed-wedge'),
      expiresAt: new Date(NOW.getTime() - 1),
    });
    // Backdate the MINT as well as the expiry: a code that has lapsed was by
    // definition minted longer ago than the re-issue floor, and the floor keys
    // on the mint. (That it blocks otherwise is the floor working.)
    await admin.query(
      `UPDATE ${schema}.email_verifications SET created_at = $2 WHERE user_id = $1`,
      [stuck, new Date(NOW.getTime() - 60 * 60 * 1000)],
    );

    // The state that used to be terminal: nothing live, but the slot is taken.
    expect(await repo.findLive(stuck, NOW)).toBeNull();
    await expect(
      repo.insert({ userId: stuck, codeSha256: sha('blocked'), expiresAt: LATER }),
    ).rejects.toBeInstanceOf(VerificationRaceError);

    // DRIVE THE SERVICE, NOT THE REPO. Round 2 of this review caught the first
    // version of this test calling `repo.revokeLive` explicitly — whose SQL the
    // fix never touched — so it proved the primitive that was always right and
    // asserted nothing about the DECISION that was wrong. That is the M13
    // lesson this test's own docstring invokes, committed inside the fix for
    // it. The service is what learned to retire unconditionally, so the service
    // is what has to be exercised against the real index.
    const service = new EmailVerificationService(
      repo,
      { insert: () => Promise.resolve() } as unknown as AuthEventsRepo,
      {
        emailVerificationSent: () => Promise.resolve(),
        emailVerified: () => Promise.resolve(),
        emailVerificationFailed: () => Promise.resolve(),
        emailVerificationUnavailable: () => Promise.resolve(),
      } as unknown as EventsService,
      {
        recipientStatus: () => Promise.resolve({ verified: false }),
        sendAddressVerification: () =>
          Promise.resolve({
            accepted: true,
            delivered: true,
            channel: 'email',
            recipientVerified: false,
          }),
      } as unknown as NotificationsPort,
      () => NOW,
    );

    await expect(service.reissue(stuck)).resolves.toBe('sent');

    // A NEW, USABLE code exists — the wedge is gone end to end, decision plus
    // index, which is the pair no test combined before.
    const live = await repo.findLive(stuck, NOW);
    expect(live).not.toBeNull();
  });

  it('an ATTEMPT-EXHAUSTED code does not read as live to the mint decision', async () => {
    // The third disagreeing predicate. `verify()` treats an exhausted code as
    // dead; `findLive` used to treat it as live, so a user who mistyped five
    // times waited out the re-issue floor for a code that could never work.
    const burned = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [burned, Buffer.from('ct'), Buffer.from('bidx-burned'), randomUUID()],
    );
    await repo.insert({ userId: burned, codeSha256: sha('burned'), expiresAt: LATER });
    for (let i = 0; i < MAX_VERIFY_ATTEMPTS; i += 1) {
      await repo.countAttempt(burned, NOW);
    }
    expect(await repo.findLive(burned, NOW)).toBeNull();
  });

  it('lastMintedAt sees a code whatever became of it — the floor cannot be skipped', async () => {
    // The floor used to be checked only when a live code existed, so a failed
    // send (which retires its code) left the resend route with no rate limit at
    // all. `lastMintedAt` answers "how recently did we mail this address",
    // which is the question the floor was always asking.
    const revoked = await repo.lastMintedAt(user);
    expect(revoked).not.toBeNull();
  });

  it('refuses to spend an expired code even when nothing else retired it', async () => {
    const lapsed = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [lapsed, Buffer.from('ct'), Buffer.from('bidx2'), randomUUID()],
    );
    await repo.insert({
      userId: lapsed,
      codeSha256: sha('lapsed'),
      expiresAt: new Date(NOW.getTime() - 1),
    });
    const row = await repo.findByCode(sha('lapsed'));
    expect(await repo.markVerified(row!.id, NOW)).toBe(false);
    // ...and `findLive` agrees, so the service re-mints rather than waiting.
    expect(await repo.findLive(lapsed, NOW)).toBeNull();
  });

  it('counts a failed guess against the caller LIVE code, whatever they submitted', async () => {
    // Round 2 of the M14 review found the cap decorative: it took a resolved
    // row id and only ever ran once the row was already dead, so `attempts`
    // could never move on a LIVE code — and a wrong guess produces a different
    // digest, so nothing resolved and no counter moved at all. Keyed on the
    // USER now, which is what makes `findLive`'s attempts predicate reachable
    // and gives the redeem route its only bound.
    const guessed = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [guessed, Buffer.from('ct'), Buffer.from('bidx-guess'), randomUUID()],
    );
    await repo.insert({ userId: guessed, codeSha256: sha('guess-target'), expiresAt: LATER });

    await repo.countAttempt(guessed, NOW);
    expect((await repo.findByCode(sha('guess-target')))?.attempts).toBe(1);
  });

  it('keeps every row: a retired code is evidence, not garbage', async () => {
    // "A code was mailed to this account at time T" is exactly what an
    // investigation needs when somebody's address was typed into a
    // registration by mistake or by design. The DDL revokes DELETE.
    const { rows } = await admin.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${schema}.email_verifications WHERE user_id = $1`,
      [user],
    );
    expect(Number(rows[0]?.n)).toBeGreaterThanOrEqual(3);
  });
});
