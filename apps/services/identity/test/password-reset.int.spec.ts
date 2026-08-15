/**
 * THE PASSWORD RESET, against real Postgres (M17 PR3).
 *
 * Everything load-bearing here lives in SQL — a partial unique index that cannot
 * carry a clock, a CAS spend, a status predicate inside an UPDATE, and a
 * transaction spanning three statements. A faked repo could not get any of it
 * wrong and so could not prove any of it right.
 *
 * TWO PROPERTIES HERE ARE OVER-DETERMINED, and mutation testing said so rather
 * than a comment claiming it. (1) An address with no account cannot be mailed,
 * and no mutation of the `!user` guard changes that — removing it makes the next
 * line throw, which the fire-and-forget catch absorbs, so the observable
 * outcome is identical. (2) An expired code is refused at TWO layers, the
 * service's liveness read and `markRedeemed`'s own predicate, so deleting
 * either alone still refuses. That is defence in depth working; what it means
 * for these cases is that they prove the PAIR, and the CAS layer is proven
 * independently by the concurrent case below.
 *
 * The connection's `search_path` is pinned and resets use TRUNCATE rather than
 * DELETE: unqualified names inside trigger bodies resolve against the
 * CONNECTION, not the schema in the statement, and the M17 PR2 spec learned that
 * the hard way by silently writing into the live `public.users_versions`.
 */
import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { emailBlindIndex, normalizeEmail } from '@estate/crypto';
import { Client, type QueryResultRow } from 'pg';
import { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { PasswordHasher } from '../src/password';
import { PasswordResetRepo } from '../src/password-reset.repo';
import { PasswordResetService, RESET_FLOOR_MS, RESET_TTL_MS } from '../src/password-reset.service';
import { canonicalCode, sha256 } from '../src/readable-code';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';
import { UsersRepo } from '../src/users.repo';
import { Db, type Queryable } from '../src/db';
import type { NotificationsPort, SendOutcome } from '@estate/notifications-client';
import { DELIVERED, UNDELIVERED } from './notifications-double';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

/**
 * THE CLOCK HERE TRACKS REAL TIME, and that is not laziness.
 *
 * `password_resets.created_at` is stamped by the DATABASE (`DEFAULT now()`)
 * while the re-issue floor compares it against the SERVICE's injected clock. In
 * production both are wall time and the comparison is sound; in a test a fixed
 * fake date sits hours away from the database's, so the floor silently
 * evaluates against a ten-hour-old "last mint" and never holds. Basing the fake
 * clock on real time keeps the two in the same frame, and advancing it is then
 * the only thing that moves them apart — which is exactly what these cases want
 * to vary.
 */
/** The refusal an awaited call threw, TYPED — `.catch((e) => e)` yields `any`,
 * and these cases assert an exact status and body. */
async function refusalFrom(promise: Promise<unknown>): Promise<HttpException> {
  let caught: unknown;
  try {
    await promise;
  } catch (err) {
    caught = err;
  }
  if (!(caught instanceof HttpException)) {
    throw new Error(`expected an HttpException refusal, got: ${String(caught)}`);
  }
  return caught;
}

const BASE = new Date();
/**
 * EACH CASE USES ITS OWN ADDRESS, which is how the per-address bound is
 * isolated without touching the clock.
 *
 * The bound lives on the service instance for the process's lifetime — exactly
 * as it does in production — so the eleventh `request()` in this file was
 * silently refused, the bound working correctly and the suite losing isolation
 * at the same time. The first fix tried was a per-case time window, and it
 * broke the re-issue floor: `created_at` is stamped by the DATABASE while the
 * floor compares against the SERVICE's clock, so pushing one forward pushed
 * them out of the same frame. Varying the ADDRESS separates the cases on the
 * axis the bound actually keys on and leaves both clocks alone.
 */
let testIndex = 0;
const EMAIL_KEY = Buffer.alloc(32, 13);
const emailFor = (n: number): string => `forgetful-${n}@example.com`;
const OLD_HASH = 'argon2-OLD';
const NEW_HASH = 'argon2-NEW';

describeIfPg('password reset (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identityreset_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let codes: PasswordResetRepo;
  let sessions: SessionsRepo;
  let service: PasswordResetService;
  let mailed: string[];
  /** What the notifications port answers; per-case, so a send can be made to fail. */
  let sendOutcome: SendOutcome;
  /** The `delivered` boolean each request-path audit event was given. */
  let requestedDelivered: boolean[];
  /** The `notified` boolean each completion-path audit event was given. */
  let completedNotified: boolean[];
  let now: Date;
  /**
   * EACH TEST GETS ITS OWN TIME WINDOW, because the per-address bound and the
   * per-account floor are BOTH stateful across calls — the bound lives on the
   * service instance for the process's lifetime, exactly as it does in
   * production. Sharing one clock made the eleventh `request()` in the file
   * silently refuse, which is the bound working correctly and a test-isolation
   * failure at the same time. Starting each case past the previous one's window
   * models what actually separates two real users' requests.
   */
  /** The address this case uses; a fresh one per case (see `testIndex`). */
  let email: string;
  const advance = (ms: number): void => {
    now = new Date(BASE.getTime() + ms);
  };

  const user = randomUUID();

  /** The code a mint handed to the notifications port, as the user would get it. */
  function lastCode(): string {
    const code = mailed[mailed.length - 1];
    if (code === undefined) throw new Error('no code was mailed');
    return code;
  }

  async function seed(status = 'active'): Promise<void> {
    testIndex += 1;
    email = emailFor(testIndex);
    await admin.query(
      `TRUNCATE ${schema}.password_resets, ${schema}.sessions, ${schema}.auth_events,
                ${schema}.users_versions, ${schema}.users CASCADE`,
    );
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id, status)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        user,
        Buffer.from('ct'),
        emailBlindIndex(EMAIL_KEY, normalizeEmail(email)),
        OLD_HASH,
        randomUUID(),
        status,
      ],
    );
    await sessions.create({
      id: randomUUID(),
      userId: user,
      refreshTokenH: hashToken('r'),
      accessTokenH: hashToken('a'),
      accessExpiresAt: new Date(BASE.getTime() + 86_400_000),
      expiresAt: new Date(BASE.getTime() + 30 * 86_400_000),
      audience: 'account',
    });
    mailed = [];
    sendOutcome = DELIVERED;
    requestedDelivered = [];
    completedNotified = [];
    now = new Date(BASE.getTime());
  }

  /**
   * Drive the request path to completion. `requestReset` is awaitable — the
   * fire-and-forget is the CONTROLLER's decision, not the service's — so this
   * awaits the real chain instead of racing it. The first version detached
   * inside the service and waited here with a 25ms sleep, which flaked in CI on
   * its second run: a bare sleep against four real Postgres round trips is the
   * exact shape the M8 PR4 determinism contract bans, forced into a test by a
   * service that made awaiting the work inexpressible.
   */
  async function request(target?: string): Promise<void> {
    await service.requestReset(target ?? email);
  }

  async function hashOf(): Promise<string> {
    const rows = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    return rows.rows[0]?.password_hash ?? '';
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
    codes = new PasswordResetRepo(db);
    sessions = new SessionsRepo(db);
    mailed = [];
    sendOutcome = DELIVERED;
    requestedDelivered = [];
    completedNotified = [];
    email = emailFor(0);
    now = new Date(BASE.getTime());

    service = new PasswordResetService(
      new UsersRepo(db),
      sessions,
      codes,
      new AuthEventsRepo(db),
      {
        hashPassword: (): Promise<string> => Promise.resolve(NEW_HASH),
      } as unknown as PasswordHasher,
      {
        // The `delivered` / `notified` booleans are CAPTURED rather than
        // discarded: each renders as the literal audit string `delivered` or
        // `failed`, so they are the fact the M20 PR0 defect got wrong, and a
        // double that threw them away is why no test could see it.
        passwordResetRequested: (_userId: string, delivered: boolean): Promise<void> => {
          requestedDelivered.push(delivered);
          return Promise.resolve();
        },
        passwordReset: (_userId: string, _revoked: number, notified: boolean): Promise<void> => {
          completedNotified.push(notified);
          return Promise.resolve();
        },
        passwordResetFailed: (): Promise<void> => Promise.resolve(),
        passwordResetThrottled: (): Promise<void> => Promise.resolve(),
      } as unknown as EventsService,
      db,
      { emailIndexKey: EMAIL_KEY } as unknown as IdentityConfig,
      () => now,
      {
        // FAITHFUL to `SendOutcome`. The previous double answered a bare
        // accepted-true object — a shape the real service CANNOT produce, since
        // the accepted arm carries `delivered`, `channel` and
        // `recipientVerified` — and typed itself loosely enough that the
        // compiler never said so. That generosity is what hid the defect.
        sendPasswordReset: (input: { code: string }): Promise<SendOutcome> => {
          mailed.push(input.code);
          return Promise.resolve(sendOutcome);
        },
        sendAccountSecurity: (): Promise<SendOutcome> => Promise.resolve(sendOutcome),
      } as unknown as NotificationsPort,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    await seed();
  });

  describe('the request path', () => {
    it('mints and mails a code for a real account', async () => {
      await request();
      expect(mailed).toHaveLength(1);
      expect(lastCode()).toMatch(/^PR1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/);
    });

    it('mails NOTHING for an address with no account, and leaves no trace', async () => {
      await request('nobody@example.com');
      expect(mailed).toEqual([]);
      const rows = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.password_resets`,
      );
      expect(rows.rows[0]?.n).toBe('0');
    });

    it('REFUSES an account in settlement — a decedent mailbox must not recover it', async () => {
      await seed('settlement');
      await request();
      expect(mailed).toEqual([]);
    });

    it('PERMITS deceased_pending — the §5.1 rescue path must not be harder', async () => {
      await seed('deceased_pending');
      await request();
      expect(mailed).toHaveLength(1);
    });

    it('A CARRIER REFUSAL IS RECORDED AS A NON-DELIVERY, and retires the code nobody holds', async () => {
      // THE M20 PR0 DEFECT. `SendOutcome` is a discriminated union whose
      // `accepted` is the DISCRIMINANT: the service answers
      // `accepted: true, delivered: false` for `no_recipient` (M9's recipient
      // feed is fire-and-forget, so a registration during a notifications
      // outage leaves no row — and that user is exactly the one who later
      // cannot sign in) and for `carrier_failure`. Reading the discriminant
      // alone type-checks perfectly and means "the service answered", so this
      // scored as a delivery: the append-only ledger row and the audit event
      // BOTH said `delivered` about a mail that never went.
      sendOutcome = UNDELIVERED;
      await request();

      // The port was called — the send was attempted, not skipped.
      expect(mailed).toHaveLength(1);

      // The audit fact, which is what was wrong. `false` here renders as the
      // literal string `failed` in `auth.password.reset_requested`.
      expect(requestedDelivered).toEqual([false]);

      // The append-only ledger says the same thing.
      const ledger = await admin.query<{ kind: string; decision: string | null }>(
        `SELECT kind, decision FROM ${schema}.auth_events WHERE user_id = $1 ORDER BY occurred_at`,
        [user],
      );
      expect(ledger.rows).toEqual([{ kind: 'password.reset_requested', decision: 'failed' }]);

      // And no live code is left behind. Not because it would otherwise lock
      // the account — `lastMintedAt` counts revoked rows, so retirement cannot
      // shorten the floor — but because a reset code that reached no mailbox
      // should not exist.
      const live = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.password_resets
          WHERE revoked_at IS NULL AND redeemed_at IS NULL`,
      );
      expect(live.rows[0]?.n).toBe('0');
    });

    it('holds the re-issue floor, then mints again once it lapses', async () => {
      await request();
      await request();
      expect(mailed).toHaveLength(1); // the second is inside the floor

      advance(RESET_FLOOR_MS + 60_000);
      await request();
      expect(mailed).toHaveLength(2);
    });

    it('A LAPSED CODE DOES NOT WEDGE THE LIVE SLOT — the M14 worst finding', async () => {
      // The partial unique index cannot reference now(), so an expired row still
      // occupies the slot. If retirement were conditional on a *usable* code,
      // the first ignored reset mail would make the account permanently
      // unrecoverable. Driven through the SERVICE against the real index, which
      // is the pair no unit test can exercise.
      await request();
      expect(mailed).toHaveLength(1);

      advance(RESET_TTL_MS + RESET_FLOOR_MS + 60_000);
      await request();
      expect(mailed).toHaveLength(2);
      // …and the newest code is the usable one.
      const live = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.password_resets
          WHERE revoked_at IS NULL AND redeemed_at IS NULL`,
      );
      expect(live.rows[0]?.n).toBe('1');
    });
  });

  describe('the completion path', () => {
    it('two redemptions of one code produce exactly ONE success', async () => {
      // NAMED FOR WHAT IT PROVES, which is the SERVICE's liveness read — not
      // the CAS. Two `completeReset` calls started together still serialize
      // before the statement that matters, so this stays green with
      // `markRedeemed`'s preconditions removed; measured by mutation, and
      // renamed rather than left claiming a layer it never reaches. The CAS has
      // its own case below.
      await request();
      const code = lastCode();

      const results = await Promise.allSettled([
        service.completeReset(code, 'password-one-aaaa'),
        service.completeReset(code, 'password-two-bbbb'),
      ]);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);

      const spent = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.password_resets WHERE redeemed_at IS NOT NULL`,
      );
      expect(spent.rows[0]?.n).toBe('1');
    });

    it('THE CAS ITSELF refuses a second spend, with both transactions open', async () => {
      // The layer the case above cannot reach. Two transactions are opened and
      // BOTH pass the service's liveness read before either commits — the only
      // shape in which `markRedeemed`'s own preconditions are what refuses. It
      // drives the repo directly and says so: the M14 round-2 rule is that a
      // test must name which layer it proves, and this one proves the statement
      // rather than the decision.
      await request();
      const row = await codes.findByCode(sha256(canonicalCode(lastCode())));
      expect(row).not.toBeNull();

      const a = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
      const b = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
      await a.connect();
      await b.connect();
      try {
        await a.query('BEGIN');
        await b.query('BEGIN');
        // THROUGH THE REPO, not hand-written SQL. The first version of this
        // case duplicated the UPDATE inline, so it proved that Postgres honours
        // a predicate — which was never in doubt — and stayed green when
        // `markRedeemed`'s own preconditions were deleted. Wrapping each open
        // client as a `Queryable` is what puts the repo's statement under test.
        const as = (c: Client): Queryable => ({
          query: async <R extends QueryResultRow>(text: string, values?: unknown[]): Promise<R[]> =>
            (await c.query<R>(text, values)).rows,
        });

        const first = await codes.markRedeemed(as(a), row?.id ?? '', now);
        await a.query('COMMIT');
        // b's UPDATE blocked on a's row lock until that COMMIT; it now
        // re-evaluates its own predicate against the committed row.
        const second = await codes.markRedeemed(as(b), row?.id ?? '', now);
        await b.query('COMMIT');

        expect(first).toBe(true);
        expect(second).toBe(false);
      } finally {
        await a.end();
        await b.end();
      }
    });

    it('sets the password, spends the code, and revokes EVERY session', async () => {
      await request();
      await service.completeReset(lastCode(), 'a-brand-new-password');

      expect(await hashOf()).toBe(NEW_HASH);
      const live = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.sessions WHERE revoked_at IS NULL`,
      );
      expect(live.rows[0]?.n).toBe('0');
      const spent = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.password_resets WHERE redeemed_at IS NOT NULL`,
      );
      expect(spent.rows[0]?.n).toBe('1');
    });

    it('records the COMPLETION notice as failed when the carrier refused it', async () => {
      // The same defect one route down: `auth.password.reset_completed` carries
      // `notified: delivered|failed`, and it was derived from the discriminant
      // too. This is the most consequential event identity emits about an
      // account it did not authenticate — the password changed on the strength
      // of a mailed code — so "we told the owner" has to be true when it says
      // so. The REQUEST is delivered here (a code must reach the user at all);
      // only the completion notice fails.
      await request();
      sendOutcome = UNDELIVERED;
      await service.completeReset(lastCode(), 'a-brand-new-password');

      expect(await hashOf()).toBe(NEW_HASH); // the reset itself still stands
      expect(completedNotified).toEqual([false]);
    });

    it('MINTS NO SESSION — there is nothing for a stolen code to become', async () => {
      await request();
      await service.completeReset(lastCode(), 'a-brand-new-password');
      const any = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.sessions WHERE revoked_at IS NULL`,
      );
      expect(any.rows[0]?.n).toBe('0');
    });

    it('accepts the code as a human RETYPES it', async () => {
      // Lowercase, grouping dashes dropped, an O typed for a zero. The canonical
      // fold is applied on both sides, so a security property (one uniform
      // refusal) does not hide a usability defect — the M13 lesson.
      await request();
      const retyped = lastCode().toLowerCase().replace(/-/g, '').replace(/0/g, 'O');
      await service.completeReset(retyped, 'a-brand-new-password');
      expect(await hashOf()).toBe(NEW_HASH);
    });

    it('REFUSES a replay, and the second attempt changes nothing', async () => {
      await request();
      const code = lastCode();
      await service.completeReset(code, 'a-brand-new-password');
      await expect(service.completeReset(code, 'another-password-x')).rejects.toMatchObject({
        response: { error: 'invalid_code' },
      });
      expect(await hashOf()).toBe(NEW_HASH);
    });

    it('REFUSES an expired code', async () => {
      await request();
      const code = lastCode();
      advance(RESET_TTL_MS + 60_000);
      await expect(service.completeReset(code, 'a-brand-new-password')).rejects.toMatchObject({
        response: { error: 'invalid_code' },
      });
      expect(await hashOf()).toBe(OLD_HASH);
    });

    it('REFUSES an unknown code, and one of the wrong shape, identically', async () => {
      const unknown = 'PR1-0000-0000-0000-0000-0000-0000-0000-0000';
      const misshapen = 'PR1-TOO-SHORT';
      const a = await refusalFrom(service.completeReset(unknown, 'a-brand-new-password'));
      const b = await refusalFrom(service.completeReset(misshapen, 'a-brand-new-password'));
      expect(a.getStatus()).toBe(b.getStatus());
      expect(a.getResponse()).toEqual(b.getResponse());
      expect(await hashOf()).toBe(OLD_HASH);
    });

    it('the code is stored as a DIGEST, never in the clear', async () => {
      await request();
      const rows = await admin.query<{ code_sha256: Buffer }>(
        `SELECT code_sha256 FROM ${schema}.password_resets`,
      );
      expect(rows.rows[0]?.code_sha256).toEqual(sha256(canonicalCode(lastCode())));
      const dump = JSON.stringify(rows.rows);
      expect(dump).not.toContain(lastCode());
    });

    it('records its OWN ledger kind, never the one the liveness interlock reads', async () => {
      await request();
      await service.completeReset(lastCode(), 'a-brand-new-password');
      const kinds = await admin.query<{ kind: string }>(
        `SELECT kind FROM ${schema}.auth_events WHERE user_id = $1 ORDER BY occurred_at`,
        [user],
      );
      expect(kinds.rows.map((r) => r.kind)).toContain('password.reset_completed');
      expect(kinds.rows.map((r) => r.kind)).not.toContain('stepup.granted');
    });

    it('does not keep the old password hash in the version image', async () => {
      // PR2's redaction covers this write too, because the trigger is per-ROW
      // and fires on any `users` UPDATE — asserted here rather than assumed,
      // since a reset is a second writer of that column.
      await request();
      await service.completeReset(lastCode(), 'a-brand-new-password');
      const rows = await admin.query<{ row_data: Record<string, unknown> }>(
        `SELECT row_data FROM ${schema}.users_versions WHERE row_id = $1`,
        [user],
      );
      expect(rows.rows).toHaveLength(1);
      expect(rows.rows[0]?.row_data).not.toHaveProperty('password_hash');
      expect(JSON.stringify(rows.rows[0]?.row_data)).not.toContain(OLD_HASH);
    });
  });
});
