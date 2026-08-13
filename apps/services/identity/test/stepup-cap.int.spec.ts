/**
 * THE STEP-UP ATTEMPT CAP, against real Postgres (M16).
 *
 * `auth.service.spec.ts` proves the DECISION — refuse at the cap, with its own
 * kind, before the secret is read — against a faked repo. That suite cannot say
 * anything about the COUNT, because the count is a SQL predicate and a fake repo
 * has no SQL to get wrong. This is the other layer, and the M13 rule is explicit
 * that both are owed when a rule exists at two of them.
 *
 * IT DRIVES THE SERVICE, not the repo. That is the M14 round-2 lesson applied
 * before it can bite: the wedge test written for that review called the repo
 * method directly and so proved the primitive that was already correct while
 * asserting nothing about the decision that was wrong. Here the real
 * `AuthEventsRepo` is wired into a real `AuthService` — every other collaborator
 * is a stub, because the cap path short-circuits before reaching them — so what
 * is measured is the pair: this predicate, feeding this decision.
 *
 * The four properties below are each a way the predicate could be wrong while
 * still looking like a rate limiter.
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
import type { SessionsRepo } from '../src/sessions.repo';
import { STEP_UP_BOUND } from '../src/rate-bounds';
import {
  STEPUP_DENIAL_WINDOW_MS,
  STEPUP_MAX_ACCOUNT_DENIALS,
  STEPUP_MAX_DENIALS,
} from '../src/stepup';

import { SecondFactorGate } from '../src/second-factor-gate';
import type { UsersRepo } from '../src/users.repo';
import { Db } from '../src/db';

/**
 * The kind sets are PARAMETERS now (M17), so a direct repo assertion has to say
 * which bound it is asking about. Taken from the declared bound rather than
 * written out, so a case here cannot measure a set the service does not use.
 */
const STEP_UP_KINDS = {
  failures: STEP_UP_BOUND.failures,
  successes: STEP_UP_BOUND.successes,
};

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-10T12:00:00.000Z');
/** Comfortably inside the window; used for "recent" denials. */
const RECENT = new Date(NOW.getTime() - 60_000);
/** Outside it, so it must not be counted. */
const STALE = new Date(NOW.getTime() - STEPUP_DENIAL_WINDOW_MS - 60_000);

describeIfPg('step-up attempt cap (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitycap_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let events: AuthEventsRepo;
  let service: AuthService;
  let rateLimited: Array<{ userId: string; denials: number }>;

  const user = randomUUID();
  const other = randomUUID();
  const session = randomUUID();
  /** A SECOND credential of the same user — the owner's own browser. */
  const ownerSession = randomUUID();

  /** Write a ledger row at a chosen instant — `insert` always stamps now(). */
  async function ledger(
    userId: string,
    kind: string,
    at: Date,
    sessionId: string | null = session,
  ): Promise<void> {
    await admin.query(
      `INSERT INTO ${schema}.auth_events (user_id, session_id, kind, occurred_at)
       VALUES ($1, $2, $3, $4)`,
      [userId, sessionId, kind, at],
    );
  }

  async function clearLedger(): Promise<void> {
    // The table REVOKEs UPDATE and DELETE from PUBLIC, but this connection is
    // the owner, so a truncate is available to the test harness and to nobody
    // the application runs as.
    await admin.query(`TRUNCATE ${schema}.auth_events`);
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

    for (const id of [user, other]) {
      await admin.query(
        `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
         VALUES ($1, $2, $3, 'x', $4)`,
        [id, Buffer.from(`ct-${id}`), Buffer.from(`bidx-${id}`), randomUUID()],
      );
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    events = new AuthEventsRepo(db);
    rateLimited = [];

    service = new AuthService(
      {} as unknown as UsersRepo,
      { grantStepUp: (): Promise<void> => Promise.resolve() } as unknown as SessionsRepo,
      // No active TOTP ⇒ any code is invalid, which is what makes the
      // BELOW-the-cap path land on an ordinary denial and write the row the
      // predicate then has to count.
      { findActiveTotp: (): Promise<null> => Promise.resolve(null) } as unknown as MfaRepo,
      events,
      {} as unknown as PasswordHasher,
      {
        stepUpGranted: (): Promise<void> => Promise.resolve(),
        stepUpRateLimited: (userId: string, _s: string, denials: number): Promise<void> => {
          rateLimited.push({ userId, denials });
          return Promise.resolve();
        },
      } as unknown as EventsService,
      {} as unknown as FieldCrypto,
      {} as unknown as DekRepository,
      {} as unknown as IdentityConfig,
      () => NOW,
      {} as never,
      {} as unknown as EmailVerificationService,
      {
        assertMayAddFactor: (): Promise<void> => Promise.resolve(),
        holdsVerifiedFactor: (): Promise<boolean> => Promise.resolve(false),
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
    await clearLedger();
    rateLimited = [];
  });

  const windowStart = (): Date => new Date(NOW.getTime() - STEPUP_DENIAL_WINDOW_MS);

  it('counts recent denials for this user', async () => {
    for (let i = 0; i < 3; i += 1) await ledger(user, 'stepup.denied', RECENT);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(3);
  });

  it('IGNORES denials older than the window — a rate limit, not a permanent ban', async () => {
    for (let i = 0; i < 9; i += 1) await ledger(user, 'stepup.denied', STALE);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(0);
  });

  it('IGNORES denials from before the last SUCCESSFUL step-up', async () => {
    // A user who fumbles and then succeeds starts clean. Without this a long
    // session of ordinary mistyping would eventually lock out someone who has
    // repeatedly PROVEN they hold the factor.
    for (let i = 0; i < 4; i += 1) {
      await ledger(user, 'stepup.denied', new Date(RECENT.getTime() - 10_000));
    }
    await ledger(user, 'stepup.granted', new Date(RECENT.getTime() - 5_000));
    await ledger(user, 'stepup.denied', RECENT);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(1);
  });

  it('IGNORES another user’s denials', async () => {
    // Keyed on the user, so one account under attack cannot lock out another.
    for (let i = 0; i < 8; i += 1) await ledger(other, 'stepup.denied', RECENT);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(0);
  });

  it('DOES NOT COUNT ITS OWN REFUSALS — the counter cannot feed itself', async () => {
    // Proven in SQL as well as in the service, because they are two different
    // ways to get it wrong: the service could emit the wrong kind, or the
    // predicate could match too broadly (`kind LIKE 'stepup.%'` would). Either
    // one turns a 15-minute cooldown into a permanent lockout that a retrying
    // client inflicts on its own user.
    for (let i = 0; i < 20; i += 1) await ledger(user, 'stepup.rate_limited', RECENT);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(0);
  });

  it('THE SERVICE refuses at the cap and admits below it, over this real predicate', async () => {
    // The pair, which is the point of the file. Nothing here stubs the count.
    for (let i = 0; i < STEPUP_MAX_DENIALS - 1; i += 1) {
      await ledger(user, 'stepup.denied', RECENT);
    }

    // One below the cap: an ordinary denial, and it writes the row that takes
    // the ledger TO the cap.
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({
      status: 401,
      response: { error: 'invalid_code' },
    });
    expect(rateLimited).toEqual([]);
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(
      STEPUP_MAX_DENIALS,
    );

    // At the cap: refused, with the distinct token and status.
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({
      status: 429,
      response: { error: 'too_many_attempts' },
    });
    expect(rateLimited).toEqual([{ userId: user, denials: STEPUP_MAX_DENIALS }]);

    // And the refusal did not raise the count it was refused by.
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(
      STEPUP_MAX_DENIALS,
    );

    const { rows } = await admin.query<{ kind: string; n: string }>(
      `SELECT kind, count(*)::text AS n FROM ${schema}.auth_events
        WHERE user_id = $1 GROUP BY kind ORDER BY kind`,
      [user],
    );
    expect(rows).toEqual([
      { kind: 'stepup.denied', n: String(STEPUP_MAX_DENIALS) },
      { kind: 'stepup.rate_limited', n: '1' },
    ]);
  });

  it('a successful step-up CLEARS the window, so the cooldown really rolls', async () => {
    for (let i = 0; i < STEPUP_MAX_DENIALS; i += 1) await ledger(user, 'stepup.denied', RECENT);
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 429 });

    await ledger(user, 'stepup.granted', new Date(NOW.getTime() - 1_000));
    // Back under the cap, so the next attempt is judged on its merits again —
    // here an ordinary denial, since the stub holds no TOTP method.
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 401 });
  });

  /**
   * THE M16 REVIEW'S TWO FINDINGS, each pinned at the layer it lived in.
   *
   * Both were invisible to every case above, and for the same reason: all seven
   * used ONE session and ONE route. A cap is a claim about who is bounded and
   * where, and a test that varies neither cannot see it.
   */
  it('a session that exhausts the cap does NOT refuse the OWNER’s other sessions', async () => {
    // The attacker's credential burns its five.
    for (let i = 0; i < STEPUP_MAX_DENIALS; i += 1) {
      await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 401 });
    }
    // It is now capped, and stays capped however long it keeps trying.
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 429 });
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 429 });

    // THE OWNER'S OWN SESSION IS UNAFFECTED. Before the fix this was a 429 —
    // measured against this database — which is docs/03 §5.1's rescue path
    // suppressed by anyone holding one stolen credential.
    await expect(service.stepUp(user, ownerSession, '000000')).rejects.toMatchObject({
      status: 401,
      response: { error: 'invalid_code' },
    });

    // And the attacker's refusals never fed the account total, so the ceiling
    // is still four exhausted-credentials away.
    expect(await events.failedAttempts(user, windowStart(), STEP_UP_KINDS)).toBe(
      STEPUP_MAX_DENIALS + 1,
    );
  });

  it('the ACCOUNT ceiling still bounds an attacker who can spread across sessions', async () => {
    // The per-session cap must not become an unlimited budget for whoever can
    // mint sessions. Seeded across distinct ids, which is what such an attacker
    // has.
    for (let i = 0; i < STEPUP_MAX_ACCOUNT_DENIALS; i += 1) {
      await ledger(user, 'stepup.denied', RECENT, randomUUID());
    }
    // A session with a clean slate of its own is still refused, on the account
    // number rather than its own.
    await expect(service.stepUp(user, ownerSession, '000000')).rejects.toMatchObject({
      status: 429,
      response: { error: 'too_many_attempts' },
    });
    expect(rateLimited).toEqual([{ userId: user, denials: STEPUP_MAX_ACCOUNT_DENIALS }]);
  });

  it('COUNTS totp/verify failures — the route that checks the same secret', async () => {
    // The uncapped oracle. Forty wrong codes here produced forty 401s and left
    // the step-up counter at zero, after which the code they found elevated on
    // the first try. Both kinds are one budget now.
    for (let i = 0; i < STEPUP_MAX_DENIALS; i += 1) {
      await expect(service.verifyTotp(user, session, '000000')).rejects.toMatchObject({
        status: 401,
      });
    }
    await expect(service.verifyTotp(user, session, '000000')).rejects.toMatchObject({
      status: 429,
      response: { error: 'too_many_attempts' },
    });
    // And the budget is SHARED, so guessing there does not buy fresh attempts here.
    await expect(service.stepUp(user, session, '000000')).rejects.toMatchObject({ status: 429 });
  });
});
