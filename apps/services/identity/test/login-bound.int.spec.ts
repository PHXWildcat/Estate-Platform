/**
 * THE LOGIN BOUND, against real Postgres (M17).
 *
 * `auth.service.spec.ts` proves the DECISION over a faked repo. It cannot say
 * anything about the COUNT, because the count is a SQL predicate and a fake
 * repo has no SQL to get wrong — the M13 rule that both layers are owed when a
 * rule lives at both, and the M14 round-2 lesson that the test must drive the
 * layer whose behaviour was in question.
 *
 * Three properties, each a way this could be present and useless:
 *
 *  1. THE PREDICATE COUNTS THE RIGHT ROWS. Keyed on the user, inside the window,
 *     since the last success.
 *  2. THE BOUNDS DO NOT CLEAR EACH OTHER. This is the M17 measurement as a
 *     regression pin: the "since the last success" watermark is one shared
 *     subquery, so kind sets that overlap mean one bound's success is another's
 *     amnesty. Folding login's kinds into the step-up sets took a user from four
 *     denials to zero — a plain password login resetting the second-factor cap.
 *     `rate-bounds.spec.ts` asserts the DECLARATION is disjoint; this asserts the
 *     PREDICATE behaves, which is the half a declaration cannot promise.
 *  3. THE OWNER IS NOT LOCKED OUT OF WHAT THEY ALREADY HAVE. M16's escape from
 *     the renewable-lockout trap was a per-CREDENTIAL scope, and login has no
 *     credential to scope to, so the escape here is different and has to be
 *     shown rather than asserted: the bound touches the login route only, and a
 *     session that already exists keeps working while login is being refused.
 */
import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { emailBlindIndex, normalizeEmail } from '@estate/crypto';
import { Client } from 'pg';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import { LOGIN_BOUND, STEP_UP_BOUND } from '../src/rate-bounds';
import { SessionsRepo } from '../src/sessions.repo';
import type { AccountPasswordGate } from '../src/account-password-gate';
import type { SecondFactorGate } from '../src/second-factor-gate';
import { hashToken } from '../src/tokens';
import { UsersRepo } from '../src/users.repo';
import { Db } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-12T12:00:00.000Z');
const RECENT = new Date(NOW.getTime() - 60_000);
const STALE = new Date(NOW.getTime() - LOGIN_BOUND.windowMs - 60_000);

/** The refusal an awaited call threw, typed — see `auth.service.spec.ts`. */
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

const EMAIL_KEY = Buffer.alloc(32, 11);
const EMAIL = 'owner@example.com';

describeIfPg('login attempt bound (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitylogin_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let events: AuthEventsRepo;
  let sessions: SessionsRepo;
  let service: AuthService;
  let rateLimited: Array<{ userId: string | null; scope: string }>;
  let passwordIsCorrect: boolean;

  const user = randomUUID();

  async function ledger(
    userId: string | null,
    kind: string,
    at: Date,
    sessionId: string | null = null,
  ): Promise<void> {
    await admin.query(
      `INSERT INTO ${schema}.auth_events (user_id, session_id, kind, occurred_at)
       VALUES ($1, $2, $3, $4)`,
      [userId, sessionId, kind, at],
    );
  }

  async function clearLedger(): Promise<void> {
    await admin.query(`TRUNCATE ${schema}.auth_events`);
  }

  const loginKinds = { failures: LOGIN_BOUND.failures, successes: LOGIN_BOUND.successes };
  const stepUpKinds = { failures: STEP_UP_BOUND.failures, successes: STEP_UP_BOUND.successes };
  const windowStart = (): Date => new Date(NOW.getTime() - LOGIN_BOUND.windowMs);

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

    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'argon2-hash', $4)`,
      [user, Buffer.from('ct'), emailBlindIndex(EMAIL_KEY, normalizeEmail(EMAIL)), randomUUID()],
    );

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    events = new AuthEventsRepo(db);
    sessions = new SessionsRepo(db);
    rateLimited = [];
    passwordIsCorrect = false;

    service = new AuthService(
      new UsersRepo(db),
      sessions,
      {} as unknown as MfaRepo,
      events,
      {
        // Argon2 is stubbed: this suite is about the predicate and the
        // ordering, and a real hash would add seconds per case without
        // changing a single assertion.
        verifyPassword: (): Promise<boolean> => Promise.resolve(passwordIsCorrect),
        dummyVerify: (): Promise<void> => Promise.resolve(),
      } as unknown as PasswordHasher,
      {
        loginSucceeded: (): Promise<void> => Promise.resolve(),
        loginFailed: (): Promise<void> => Promise.resolve(),
        loginRateLimited: (userId: string | null, scope: string): Promise<void> => {
          rateLimited.push({ userId, scope });
          return Promise.resolve();
        },
      } as unknown as EventsService,
      {} as unknown as FieldCrypto,
      {} as unknown as DekRepository,
      { emailIndexKey: EMAIL_KEY } as unknown as IdentityConfig,
      () => NOW,
      {
        upsertRecipient: () => Promise.resolve({ ok: true }),
      } as never,
      {} as unknown as EmailVerificationService,
      {} as unknown as SecondFactorGate,
      {
        assertAttemptsAvailable: (): Promise<void> => Promise.resolve(),
      } as unknown as AccountPasswordGate,
      db,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    await clearLedger();
    await admin.query(`TRUNCATE ${schema}.sessions CASCADE`);
    rateLimited = [];
    passwordIsCorrect = false;
  });

  describe('the predicate counts the right rows', () => {
    it('counts failures inside the window and ignores older ones', async () => {
      await ledger(user, 'login.failed', RECENT);
      await ledger(user, 'login.failed', RECENT);
      await ledger(user, 'login.failed', STALE);

      expect(await events.failedAttempts(user, windowStart(), loginKinds)).toBe(2);
    });

    it('counts SINCE THE LAST SUCCESS, so a fumble-then-succeed carries nothing forward', async () => {
      await ledger(user, 'login.failed', new Date(NOW.getTime() - 300_000));
      await ledger(user, 'login.failed', new Date(NOW.getTime() - 240_000));
      await ledger(user, 'login.succeeded', new Date(NOW.getTime() - 180_000));
      await ledger(user, 'login.failed', RECENT);

      expect(await events.failedAttempts(user, windowStart(), loginKinds)).toBe(1);
    });

    it('CANNOT SEE a failure against an address with no account', async () => {
      // The documented blind spot, pinned so it is a known property rather than
      // a surprise: `recordLoginFailure(null, …)` writes a NULL user, and this
      // predicate keys on user_id. It is why the address-keyed half exists and
      // is the PRIMARY bound rather than a fallback.
      await ledger(null, 'login.failed', RECENT);
      await ledger(null, 'login.failed', RECENT);

      expect(await events.failedAttempts(user, windowStart(), loginKinds)).toBe(0);
    });
  });

  describe('the bounds do not clear each other', () => {
    it('a LOGIN success does not forgive step-up denials', async () => {
      // THE M17 MEASUREMENT. With login's kinds folded into the step-up sets
      // this reads 0 instead of 4 — a password login silently resetting the
      // second-factor cap, which is the whole reason the sets are parameters.
      await ledger(user, 'stepup.denied', new Date(NOW.getTime() - 600_000));
      await ledger(user, 'stepup.denied', new Date(NOW.getTime() - 540_000));
      await ledger(user, 'stepup.denied', new Date(NOW.getTime() - 480_000));
      await ledger(user, 'stepup.denied', new Date(NOW.getTime() - 420_000));
      await ledger(user, 'login.succeeded', new Date(NOW.getTime() - 300_000));

      const stepUpWindow = new Date(NOW.getTime() - STEP_UP_BOUND.windowMs);
      expect(await events.failedAttempts(user, stepUpWindow, stepUpKinds)).toBe(4);
    });

    it('a STEP-UP success does not forgive login failures', async () => {
      // The mirror. Both directions, because a shared kind breaks whichever
      // bound the shared success belongs to and only one of the two would be
      // caught by testing one direction.
      await ledger(user, 'login.failed', new Date(NOW.getTime() - 600_000));
      await ledger(user, 'login.failed', new Date(NOW.getTime() - 540_000));
      await ledger(user, 'stepup.granted', new Date(NOW.getTime() - 300_000));

      expect(await events.failedAttempts(user, windowStart(), loginKinds)).toBe(2);
    });
  });

  describe('the service refuses at the ceiling, and the owner keeps what they have', () => {
    it('refuses a CORRECT password at the account ceiling, with the ordinary 401', async () => {
      for (let i = 0; i < LOGIN_BOUND.maxPerAccount; i += 1) {
        await ledger(user, 'login.failed', RECENT);
      }
      passwordIsCorrect = true;

      const refused = await refusalFrom(service.login(EMAIL, 'correct-horse'));
      expect(refused.getStatus()).toBe(401);
      expect(refused.getResponse()).toEqual({ error: 'invalid_credentials' });
      expect(rateLimited).toEqual([{ userId: user, scope: 'account' }]);
    });

    it('the refusal writes a kind NO bound counts, so it cannot feed itself', async () => {
      for (let i = 0; i < LOGIN_BOUND.maxPerAccount; i += 1) {
        await ledger(user, 'login.failed', RECENT);
      }
      const before = await events.failedAttempts(user, windowStart(), loginKinds);

      await expect(service.login(EMAIL, 'x')).rejects.toBeDefined();

      // The refusal landed in the ledger…
      const rows = await admin.query<{ kind: string }>(
        `SELECT kind FROM ${schema}.auth_events WHERE kind = $1`,
        [LOGIN_BOUND.refusalKind],
      );
      expect(rows.rows).toHaveLength(1);
      // …and the count it is a bound on did not move.
      expect(await events.failedAttempts(user, windowStart(), loginKinds)).toBe(before);
    });

    it('THE OWNER’S LIVE SESSION SURVIVES an attacker exhausting the bound', async () => {
      // M16's per-credential escape does not port to login, so this is the
      // property that replaces it and it is shown rather than argued. An
      // attacker who knows the address can deny NEW logins; they cannot touch a
      // session that already exists, which is what keeps the bound a cooldown on
      // one route instead of an account-wide lockout.
      const sessionId = randomUUID();
      const accessToken = 'owner-access-token';
      await sessions.create({
        id: sessionId,
        userId: user,
        refreshTokenH: hashToken('owner-refresh-token'),
        accessTokenH: hashToken(accessToken),
        accessExpiresAt: new Date(NOW.getTime() + 900_000),
        expiresAt: new Date(NOW.getTime() + 86_400_000),
        audience: 'account',
      });

      for (let i = 0; i < LOGIN_BOUND.maxPerAccount; i += 1) {
        await ledger(user, 'login.failed', RECENT);
      }

      passwordIsCorrect = true;
      await expect(service.login(EMAIL, 'correct-horse')).rejects.toBeDefined();

      // The credential the owner is already holding still resolves…
      const live = await sessions.findLiveByAccessHash(hashToken(accessToken), NOW);
      expect(live).toMatchObject({ id: sessionId, user_id: user });
      // …and so does its refresh token, so they can stay signed in indefinitely.
      const byRefresh = await sessions.findLiveByRefreshHash(hashToken('owner-refresh-token'), NOW);
      expect(byRefresh).toMatchObject({ id: sessionId });
    });

    it('below the ceiling a correct password still logs in', async () => {
      // The permissive path must stay unchanged, or the bound has quietly
      // become a different control. One below is the interesting boundary.
      for (let i = 0; i < LOGIN_BOUND.maxPerAccount - 1; i += 1) {
        await ledger(user, 'login.failed', RECENT);
      }
      passwordIsCorrect = true;

      await expect(service.login(EMAIL, 'correct-horse')).resolves.toMatchObject({ userId: user });
      expect(rateLimited).toEqual([]);
    });
  });
});
