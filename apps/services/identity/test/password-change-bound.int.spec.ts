/**
 * THE CURRENT-PASSWORD GUESSING BOUND, against real Postgres (M17 PR6).
 *
 * WHY THIS FILE EXISTS. The M17 security review measured `POST
 * /v1/auth/password` on the running stack: twenty-five wrong current-password
 * guesses from one stolen session, twenty-five plain 401s, no refusal ever, and
 * the twenty-sixth guess — the right one — took the account over. The same
 * volume against `POST /v1/auth/login` produced ten `login.failed` and four
 * `login.rate_limited`. One credential-guessing action, two routes, one bound.
 *
 * The gap existed because M17 PR1 bounded the routes taking a password from an
 * UNAUTHENTICATED caller, and this route reads as authenticated — except that
 * the entire reason it asks for the current password is the stolen-session
 * threat, so its caller is exactly the party the bound is for.
 *
 * WHAT IS PROVEN HERE, and it is the pair no unit test can reach: the ledger
 * predicate over real rows AND the service decision that consumes it. The
 * per-session escape is the load-bearing half — a stolen session must exhaust
 * ITSELF while the owner's other sessions keep their own budget, or the fix
 * would be the owner-lockout the M16 review rejected a sticky cap for.
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
import { PASSWORD_CHANGE_BOUND } from '../src/rate-bounds';
import { SessionsRepo } from '../src/sessions.repo';
import type { SecondFactorGate } from '../src/second-factor-gate';
import { hashToken } from '../src/tokens';
import { UsersRepo } from '../src/users.repo';
import { Db } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-13T12:00:00.000Z');
const RECENT = new Date(NOW.getTime() - 60_000);
const STALE = new Date(NOW.getTime() - PASSWORD_CHANGE_BOUND.windowMs - 60_000);
const EMAIL_KEY = Buffer.alloc(32, 23);
const EMAIL = 'owner@example.com';

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

describeIfPg('password-change attempt bound (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitypwbound_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let events: AuthEventsRepo;
  let service: AuthService;
  let rateLimited: Array<{ sessionId: string; attempts: number }>;
  let passwordIsCorrect: boolean;

  const user = randomUUID();
  const STOLEN = randomUUID();
  const OWNERS = randomUUID();
  /** Step-up fresh, so the factor gate is a no-op and the password check runs
   * — the factorless case the gate deliberately lets through. */
  const caller = { mfaLevel: 'stepup' as const, stepupExpiresAt: new Date(NOW.getTime() + 60_000) };

  async function ledger(kind: string, at: Date, sessionId: string | null): Promise<void> {
    await admin.query(
      `INSERT INTO ${schema}.auth_events (user_id, session_id, kind, occurred_at)
       VALUES ($1, $2, $3, $4)`,
      [user, sessionId, kind, at],
    );
  }

  /** One wrong guess through the REAL service. */
  function guess(sessionId: string): Promise<unknown> {
    return service.changePassword(user, sessionId, caller, 'wrong-guess', 'a-new-password-1234');
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

    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'argon2-hash', $4)`,
      [user, Buffer.from('ct'), emailBlindIndex(EMAIL_KEY, normalizeEmail(EMAIL)), randomUUID()],
    );

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    events = new AuthEventsRepo(db);
    rateLimited = [];
    passwordIsCorrect = false;

    service = new AuthService(
      new UsersRepo(db),
      new SessionsRepo(db),
      {} as unknown as MfaRepo,
      events,
      {
        // Stubbed for the login-bound spec's reason: this suite is about the
        // predicate and the ordering, and a real Argon2 would add seconds per
        // case without changing an assertion.
        verifyPassword: (): Promise<boolean> => Promise.resolve(passwordIsCorrect),
        hashPassword: (): Promise<string> => Promise.resolve('argon2-NEW'),
        dummyVerify: (): Promise<void> => Promise.resolve(),
      } as unknown as PasswordHasher,
      {
        passwordChanged: (): Promise<void> => Promise.resolve(),
        passwordChangeRateLimited: (
          _userId: string,
          sessionId: string,
          attempts: number,
        ): Promise<void> => {
          rateLimited.push({ sessionId, attempts });
          return Promise.resolve();
        },
      } as unknown as EventsService,
      {} as unknown as FieldCrypto,
      {} as unknown as DekRepository,
      { emailIndexKey: EMAIL_KEY } as unknown as IdentityConfig,
      () => NOW,
      { sendAccountSecurity: () => Promise.resolve({ accepted: true, delivered: true }) } as never,
      {} as unknown as EmailVerificationService,
      // The factorless bootstrap: the gate returns without demanding step-up,
      // which is exactly the account class the review's exploit targeted.
      { assertMayAddFactor: (): Promise<void> => Promise.resolve() } as unknown as SecondFactorGate,
      db,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    await admin.query(`TRUNCATE ${schema}.auth_events`);
    await admin.query(`TRUNCATE ${schema}.sessions CASCADE`);
    rateLimited = [];
    passwordIsCorrect = false;
  });

  it('REFUSES a stolen session at its own cap, and the refusal is 429 with its own token', async () => {
    for (let i = 0; i < PASSWORD_CHANGE_BOUND.maxPerScope!; i += 1) {
      const refused = await refusalFrom(guess(STOLEN));
      // Every attempt below the cap is the ordinary uniform refusal.
      expect(refused.getResponse()).toEqual({ error: 'invalid_credentials' });
    }
    const capped = await refusalFrom(guess(STOLEN));
    expect(capped.getStatus()).toBe(429);
    expect(capped.getResponse()).toEqual({ error: 'too_many_attempts' });
    expect(rateLimited).toHaveLength(1);
  });

  it('THE OWNER IS NOT LOCKED OUT — the per-session escape, which is the whole design', async () => {
    // The stolen session grinds to its cap…
    for (let i = 0; i <= PASSWORD_CHANGE_BOUND.maxPerScope!; i += 1) {
      await refusalFrom(guess(STOLEN));
    }
    // …and the owner, from THEIR session, is refused for the ordinary reason
    // and not the cap: a bound that punished them for an attacker's grinding
    // would be the owner-lockout the M16 review rejected a sticky cap for.
    const ownerAttempt = await refusalFrom(guess(OWNERS));
    expect(ownerAttempt.getStatus()).toBe(401);

    // …and their CORRECT password still goes through.
    passwordIsCorrect = true;
    await expect(
      service.changePassword(user, OWNERS, caller, 'the-right-one', 'a-new-password-1234'),
    ).resolves.toBeUndefined();
  });

  it('the ACCOUNT ceiling still bounds somebody holding several stolen sessions', async () => {
    // Spread across many sessions so no single one reaches its own cap…
    for (let i = 0; i < PASSWORD_CHANGE_BOUND.maxPerAccount; i += 1) {
      await ledger('password.change_failed', RECENT, randomUUID());
    }
    // …and a fresh session is refused anyway, by the account ceiling.
    const capped = await refusalFrom(guess(randomUUID()));
    expect(capped.getStatus()).toBe(429);
  });

  it('the REFUSAL is not counted by its own bound — a retrying client cannot wedge the account', async () => {
    // The M16 lesson: a cap-refusal that feeds its own counter locks a user out
    // for as long as anything keeps retrying.
    for (let i = 0; i <= PASSWORD_CHANGE_BOUND.maxPerScope!; i += 1) {
      await refusalFrom(guess(STOLEN));
    }
    const before = await events.failedAttempts(user, STALE, {
      failures: PASSWORD_CHANGE_BOUND.failures,
      successes: PASSWORD_CHANGE_BOUND.successes,
    });
    // Ten more refusals, all past the cap.
    for (let i = 0; i < 10; i += 1) {
      await refusalFrom(guess(STOLEN));
    }
    const after = await events.failedAttempts(user, STALE, {
      failures: PASSWORD_CHANGE_BOUND.failures,
      successes: PASSWORD_CHANGE_BOUND.successes,
    });
    expect(after).toBe(before);
  });

  it('a SUCCESSFUL change clears the window — proving the password once is the remedy', async () => {
    // ONE CLOCK FRAME, deliberately. `auth_events.occurred_at` defaults to the
    // DATABASE's now() while the bound derives its window from the INJECTED
    // clock, so a fixture mixing service-written rows with ledger-written ones
    // compares two frames and silently proves nothing (the M17 PR3 lesson,
    // which cost that milestone a re-write of exactly this shape). The
    // predicate is what this case is about, so every row here is explicit.
    const older = new Date(NOW.getTime() - 300_000);
    const success = new Date(NOW.getTime() - 240_000);
    await ledger('password.change_failed', older, STOLEN);
    await ledger('password.change_failed', older, STOLEN);
    await ledger('password.changed', success, STOLEN);
    await ledger('password.change_failed', RECENT, STOLEN);

    const counted = {
      failures: PASSWORD_CHANGE_BOUND.failures,
      successes: PASSWORD_CHANGE_BOUND.successes,
      sessionId: STOLEN,
    };
    // Only the one AFTER the success: proving the current password once is the
    // remedy, and the two fumbles before it carry nothing forward.
    expect(
      await events.failedAttempts(
        user,
        new Date(NOW.getTime() - PASSWORD_CHANGE_BOUND.windowMs),
        counted,
      ),
    ).toBe(1);
  });

  it('the CAP RUNS BEFORE the verification — a capped caller never has their guess scored', async () => {
    for (let i = 0; i <= PASSWORD_CHANGE_BOUND.maxPerScope!; i += 1) {
      await refusalFrom(guess(STOLEN));
    }
    // The right password, from the capped session: still 429, never 204. A
    // bound evaluated after the guess is scored is not a bound.
    passwordIsCorrect = true;
    const before = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    const capped = await refusalFrom(
      service.changePassword(user, STOLEN, caller, 'the-right-one', 'a-new-password-1234'),
    );
    expect(capped.getStatus()).toBe(429);
    // UNCHANGED, not a literal: `beforeEach` truncates the ledger and sessions
    // but not `users`, and an earlier case in this file legitimately rotates
    // the hash. Asserting the constant made this depend on test ORDER — which
    // is how a green suite starts describing something other than the code.
    const after = await admin.query<{ password_hash: string }>(
      `SELECT password_hash FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    expect(after.rows[0]?.password_hash).toBe(before.rows[0]?.password_hash);
  });

  it('ignores failures older than the window', async () => {
    for (let i = 0; i < PASSWORD_CHANGE_BOUND.maxPerAccount + 5; i += 1) {
      await ledger('password.change_failed', STALE, randomUUID());
    }
    // All stale: the caller is refused for the ordinary reason, not the cap.
    const refused = await refusalFrom(guess(randomUUID()));
    expect(refused.getStatus()).toBe(401);
  });

  it('a session with a live token is unaffected by another session hitting the cap', async () => {
    // The property the login bound's spec asserts for its own route, restated
    // here: reaching the cap on one credential touches no other credential.
    const sessions = new SessionsRepo(db);
    await sessions.create({
      id: OWNERS,
      userId: user,
      refreshTokenH: hashToken('r'),
      accessTokenH: hashToken('a'),
      accessExpiresAt: new Date(NOW.getTime() + 86_400_000),
      expiresAt: new Date(NOW.getTime() + 30 * 86_400_000),
      audience: 'account',
    });
    for (let i = 0; i <= PASSWORD_CHANGE_BOUND.maxPerScope!; i += 1) {
      await refusalFrom(guess(STOLEN));
    }
    expect(await sessions.findLiveByAccessHash(hashToken('a'), NOW)).not.toBeNull();
  });
});
