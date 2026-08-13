/**
 * THE ADDRESS CHANGE, against real Postgres (M17 PR4).
 *
 * Everything load-bearing lives in SQL — a partial unique index that cannot
 * carry a clock, a CAS spend, a dek_id predicate inside the switch UPDATE, the
 * `ux_users_email` backstop, and a transaction spanning five statements. A
 * faked repo could not get any of it wrong and so could not prove any of it
 * right. The decision layer above it is proven in
 * `email-change-decisions.spec.ts` with the repo faked; this file is the pair
 * (decision + index + transaction) no unit test can exercise.
 *
 * The connection's `search_path` is pinned and resets use TRUNCATE rather than
 * DELETE — the M17 PR2 lesson about trigger bodies resolving unqualified names
 * against the CONNECTION.
 */
import { randomUUID } from 'node:crypto';
import { HttpException } from '@nestjs/common';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { emailBlindIndex, normalizeEmail } from '@estate/crypto';
import { Client } from 'pg';
import { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import { EmailChangeRepo, MAX_CHANGE_ATTEMPTS } from '../src/email-change.repo';
import { EmailChangeService, CHANGE_FLOOR_MS, CHANGE_TTL_MS } from '../src/email-change.service';
import { EmailVerificationRepo } from '../src/email-verification.repo';
import type { EventsService } from '../src/events.service';
import type { PasswordHasher } from '../src/password';
import { PasswordResetRepo } from '../src/password-reset.repo';
import { sha256 } from '../src/readable-code';
import type { SecondFactorGate } from '../src/second-factor-gate';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';
import { UsersRepo } from '../src/users.repo';
import { Db, type Queryable } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

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

/** Real-time-based clock, for the PR3 reason: `created_at` is DB-stamped while
 * the floor compares the service's clock — a fixed fake date sits hours away
 * from the database's and the floor silently never holds. */
const BASE = new Date();
/** Each case uses its own DESTINATION address, isolating the per-address bound
 * on the axis it keys on (the PR3 lesson, inherited rather than relearned). */
let testIndex = 0;
const EMAIL_KEY = Buffer.alloc(32, 17);
const oldEmailFor = (n: number): string => `mover-${n}@example.com`;
const newEmailFor = (n: number): string => `moved-${n}@example.net`;
const PASSWORD = 'correct-horse-battery';
const OLD_HASH = 'argon2-CURRENT';

describeIfPg('email change (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitychange_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let changes: EmailChangeRepo;
  let sessions: SessionsRepo;
  let users: UsersRepo;
  let resets: PasswordResetRepo;
  let verifications: EmailVerificationRepo;
  let service: EmailChangeService;
  /** What the fake notifications port observed, in order. */
  let mailed: Array<{ code: string; email: string }>;
  let sideEffects: string[];
  let replacedWith: string[];
  let now: Date;
  let user: string;
  let sessionId: string;
  let oldEmail: string;
  let newEmail: string;
  const advance = (ms: number): void => {
    now = new Date(BASE.getTime() + ms);
  };
  const lastCode = (): string => {
    const entry = mailed[mailed.length - 1];
    if (!entry) throw new Error('no code was mailed');
    return entry.code;
  };
  /** The caller's session context: step-up fresh, so the gate is satisfied for
   * an account with factors and a no-op for one without. */
  const caller = {
    mfaLevel: 'stepup' as const,
    stepupExpiresAt: new Date(BASE.getTime() + 86_400_000),
  };

  async function seed(): Promise<void> {
    testIndex += 1;
    oldEmail = oldEmailFor(testIndex);
    newEmail = newEmailFor(testIndex);
    await admin.query(
      `TRUNCATE ${schema}.email_changes, ${schema}.password_resets, ${schema}.email_verifications,
                ${schema}.sessions, ${schema}.auth_events, ${schema}.users_versions, ${schema}.users CASCADE`,
    );
    user = randomUUID();
    sessionId = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id, status)
       VALUES ($1, $2, $3, $4, $5, 'active')`,
      [
        user,
        Buffer.from(`ct:${normalizeEmail(oldEmail)}`),
        emailBlindIndex(EMAIL_KEY, normalizeEmail(oldEmail)),
        OLD_HASH,
        randomUUID(),
      ],
    );
    await sessions.create({
      id: sessionId,
      userId: user,
      refreshTokenH: hashToken(`r-${testIndex}`),
      accessTokenH: hashToken(`a-${testIndex}`),
      accessExpiresAt: new Date(BASE.getTime() + 86_400_000),
      expiresAt: new Date(BASE.getTime() + 30 * 86_400_000),
      audience: 'account',
    });
    mailed = [];
    sideEffects = [];
    replacedWith = [];
    now = new Date(BASE.getTime());
  }

  /** Drive request + its detached half to completion — `staged()` is
   * awaitable by design (the PR3 flake's lesson), so no sleeps anywhere. */
  async function request(target?: string): Promise<void> {
    const { staged } = await service.requestChange(user, caller, PASSWORD, target ?? newEmail);
    await staged().catch(() => {});
  }

  async function userRow(): Promise<{ email_bidx: Buffer; email_ct: Buffer; dek_id: string }> {
    const rows = await admin.query<{ email_bidx: Buffer; email_ct: Buffer; dek_id: string }>(
      `SELECT email_bidx, email_ct, dek_id FROM ${schema}.users WHERE id = $1`,
      [user],
    );
    const row = rows.rows[0];
    if (!row) throw new Error('user vanished');
    return row;
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
    changes = new EmailChangeRepo(db);
    sessions = new SessionsRepo(db);
    users = new UsersRepo(db);
    resets = new PasswordResetRepo(db);
    verifications = new EmailVerificationRepo(db);

    service = new EmailChangeService(
      users,
      sessions,
      changes,
      resets,
      verifications,
      new AuthEventsRepo(db),
      {
        verifyPassword: (hash: string, pw: string): Promise<boolean> =>
          Promise.resolve(hash === OLD_HASH && pw === PASSWORD),
      } as unknown as PasswordHasher,
      // The gate's own decision is proven in second-factor-gate.spec.ts; here
      // it must not refuse, so the ceremony under test is the one that runs
      // AFTER the gate admits the caller.
      { assertMayAddFactor: (): Promise<void> => Promise.resolve() } as unknown as SecondFactorGate,
      {
        emailChangeRequested: (): Promise<void> => Promise.resolve(),
        emailChangeCompleted: (): Promise<void> => Promise.resolve(),
        emailChangeCancelled: (): Promise<void> => Promise.resolve(),
        emailChangeDenied: (): Promise<void> => Promise.resolve(),
        emailChangeFailed: (): Promise<void> => Promise.resolve(),
        emailChangeThrottled: (): Promise<void> => Promise.resolve(),
      } as unknown as EventsService,
      db,
      // Reversible stand-in crypto: this file proves SQL, and the ciphertext's
      // job here is to be recognizably THE STAGED BYTES when it lands on users.
      {
        encryptField: (_u: string, _f: string, v: string) =>
          Promise.resolve({ ciphertext: Buffer.from(`ct:${v}`), dekId: 'unused' }),
        decryptField: (input: { ciphertext: Buffer }) =>
          Promise.resolve(Buffer.from(input.ciphertext.toString('utf8').slice(3))),
      } as never,
      { emailIndexKey: EMAIL_KEY } as unknown as IdentityConfig,
      () => now,
      {
        sendEmailChange: (input: { code: string; email: string }) => {
          mailed.push({ code: input.code, email: input.email });
          sideEffects.push('challenge');
          return Promise.resolve({
            accepted: true,
            delivered: true,
            channel: 'email',
            recipientVerified: false,
          });
        },
        sendAccountSecurity: () => {
          sideEffects.push('security-to-old');
          return Promise.resolve({
            accepted: true,
            delivered: true,
            channel: 'email',
            recipientVerified: true,
          });
        },
        replaceRecipient: (input: { email: string }) => {
          sideEffects.push('replace');
          replacedWith.push(input.email);
          return Promise.resolve({ ok: true });
        },
      } as never,
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
    it('stages a change and mails the challenge TO THE NEW ADDRESS', async () => {
      await request();
      expect(mailed).toHaveLength(1);
      expect(mailed[0]?.email).toBe(normalizeEmail(newEmail));
      expect(lastCode()).toMatch(/^EC1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/);
      // …and nothing on the live row moved: verify-then-switch.
      const row = await userRow();
      expect(row.email_bidx.equals(emailBlindIndex(EMAIL_KEY, normalizeEmail(oldEmail)))).toBe(
        true,
      );
    });

    it('a TAKEN address stages nothing and mails nothing — register’s own silence', async () => {
      const other = randomUUID();
      await admin.query(
        `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id, status)
         VALUES ($1, $2, $3, $4, $5, 'active')`,
        [
          other,
          Buffer.from('ct:x'),
          emailBlindIndex(EMAIL_KEY, normalizeEmail(newEmail)),
          'h',
          randomUUID(),
        ],
      );
      await request();
      expect(mailed).toEqual([]);
      const staged = await admin.query(`SELECT count(*)::text AS n FROM ${schema}.email_changes`);
      expect(staged.rows[0]).toEqual({ n: '0' });
    });

    it('changing to the CURRENT address is refused openly — a no-op must not burn the floor', async () => {
      const refused = await refusalFrom(service.requestChange(user, caller, PASSWORD, oldEmail));
      expect(refused.getStatus()).toBe(400);
      expect(refused.getResponse()).toEqual({ error: 'invalid_request' });
      // …and a real request afterwards is NOT floor-blocked.
      await request();
      expect(mailed).toHaveLength(1);
    });

    it('a WRONG current password is refused before anything is staged', async () => {
      const refused = await refusalFrom(service.requestChange(user, caller, 'not-it', newEmail));
      expect(refused.getResponse()).toEqual({ error: 'invalid_credentials' });
      expect(mailed).toEqual([]);
    });

    it('holds the re-issue floor, then mints again once it lapses', async () => {
      await request();
      const refused = await refusalFrom(service.requestChange(user, caller, PASSWORD, newEmail));
      expect(refused.getResponse()).toEqual({ error: 'too_soon' });
      expect(mailed).toHaveLength(1);

      advance(CHANGE_FLOOR_MS + 60_000);
      await request();
      expect(mailed).toHaveLength(2);
    });

    it('A LAPSED CHANGE DOES NOT WEDGE THE LIVE SLOT — the M14 worst finding', async () => {
      await request();
      advance(CHANGE_TTL_MS + CHANGE_FLOOR_MS + 60_000);
      await request();
      expect(mailed).toHaveLength(2);
      const live = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.email_changes
          WHERE revoked_at IS NULL AND completed_at IS NULL`,
      );
      expect(live.rows[0]?.n).toBe('1');
    });
  });

  describe('the switch', () => {
    it('COMPLETES: flips the login selector, moves the staged ciphertext, sweeps and revokes', async () => {
      // A live reset code and a live verification code, both "mailed" to the
      // OLD address — the §6m obligation is that they die with it.
      await resets.insert({
        userId: user,
        codeSha256: sha256('stale-reset'),
        expiresAt: new Date(now.getTime() + 60 * 60_000),
      });
      await verifications.insert({
        userId: user,
        codeSha256: sha256('stale-verify'),
        expiresAt: new Date(now.getTime() + 60 * 60_000),
      });
      const otherSession = randomUUID();
      await sessions.create({
        id: otherSession,
        userId: user,
        refreshTokenH: hashToken('other-r'),
        accessTokenH: hashToken('other-a'),
        accessExpiresAt: new Date(now.getTime() + 86_400_000),
        expiresAt: new Date(now.getTime() + 30 * 86_400_000),
        audience: 'account',
      });

      await request();
      // RETYPED THE WAY A HUMAN RETYPES IT — lowercase, dashes dropped.
      const human = lastCode().toLowerCase().replace(/-/g, '');
      await service.completeChange(user, sessionId, human);

      const row = await userRow();
      expect(row.email_bidx.equals(emailBlindIndex(EMAIL_KEY, normalizeEmail(newEmail)))).toBe(
        true,
      );
      // The staged ciphertext moved byte-for-byte — no re-encrypt at switch.
      expect(row.email_ct.toString('utf8')).toBe(`ct:${normalizeEmail(newEmail)}`);

      // The sweep: both codes retired in the same commit.
      const liveCodes = await admin.query<{ n: string }>(
        `SELECT (SELECT count(*) FROM ${schema}.password_resets WHERE revoked_at IS NULL)::text AS n`,
      );
      expect(liveCodes.rows[0]?.n).toBe('0');
      const liveVerifs = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.email_verifications WHERE revoked_at IS NULL`,
      );
      expect(liveVerifs.rows[0]?.n).toBe('0');

      // Sessions: everything but the caller's.
      const liveSessions = await admin.query<{ id: string }>(
        `SELECT id FROM ${schema}.sessions WHERE revoked_at IS NULL`,
      );
      expect(liveSessions.rows.map((r) => r.id)).toEqual([sessionId]);

      // THE ORDERING IS THE CONTROL: the notice to the OLD address fires
      // before the store repoint, or it reaches the attacker instead of the
      // person who can dispute the takeover.
      expect(sideEffects).toEqual(['challenge', 'security-to-old', 'replace']);
      expect(replacedWith).toEqual([normalizeEmail(newEmail)]);
    });

    it('the versions trigger captured the OLD row, attributed to the user', async () => {
      await request();
      await service.completeChange(user, sessionId, lastCode());
      const versions = await admin.query<{ actor: string | null; email_ct_present: boolean }>(
        `SELECT actor_id::text AS actor, (row_data ? 'email_ct') AS email_ct_present
           FROM ${schema}.users_versions ORDER BY version_seq DESC LIMIT 1`,
      );
      expect(versions.rows[0]).toEqual({ actor: user, email_ct_present: true });
    });

    it('a WRONG code burns an attempt; exhaustion kills the change even for the right code', async () => {
      await request();
      for (let i = 0; i < MAX_CHANGE_ATTEMPTS; i += 1) {
        const refused = await refusalFrom(
          service.completeChange(user, sessionId, 'EC1-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH'),
        );
        expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
      }
      // The right code, too late: the cap is on the CHANGE, not the guess.
      const refused = await refusalFrom(service.completeChange(user, sessionId, lastCode()));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
      const row = await userRow();
      expect(row.email_bidx.equals(emailBlindIndex(EMAIL_KEY, normalizeEmail(oldEmail)))).toBe(
        true,
      );
    });

    it('an EXPIRED code is refused', async () => {
      await request();
      const code = lastCode();
      advance(CHANGE_TTL_MS + 1000);
      const refused = await refusalFrom(service.completeChange(user, sessionId, code));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
    });

    it('a CANCELLED change is dead — the ungated protective action works', async () => {
      await request();
      const code = lastCode();
      await service.cancelChange(user);
      const refused = await refusalFrom(service.completeChange(user, sessionId, code));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
    });

    it('a REPLAY is refused — the spend is once', async () => {
      await request();
      const code = lastCode();
      await service.completeChange(user, sessionId, code);
      const refused = await refusalFrom(service.completeChange(user, sessionId, code));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
    });

    it('a ROTATED KEY refuses the switch — staged ciphertext never lands under a different dek', async () => {
      await request();
      const code = lastCode();
      await admin.query(`UPDATE ${schema}.users SET dek_id = $2 WHERE id = $1`, [
        user,
        randomUUID(),
      ]);
      const refused = await refusalFrom(service.completeChange(user, sessionId, code));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
      // …and the change was NOT spent: the transaction rolled back whole.
      const spent = await admin.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM ${schema}.email_changes WHERE completed_at IS NOT NULL`,
      );
      expect(spent.rows[0]?.n).toBe('0');
    });

    it('an address REGISTERED DURING THE WINDOW refuses uniformly and burns no attempt', async () => {
      await request();
      const code = lastCode();
      // Somebody registers the candidate address mid-ceremony.
      await admin.query(
        `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id, status)
         VALUES ($1, $2, $3, $4, $5, 'active')`,
        [
          randomUUID(),
          Buffer.from('ct:squatter'),
          emailBlindIndex(EMAIL_KEY, normalizeEmail(newEmail)),
          'h',
          randomUUID(),
        ],
      );
      const refused = await refusalFrom(service.completeChange(user, sessionId, code));
      expect(refused.getResponse()).toEqual({ error: 'invalid_code' });
      const change = await admin.query<{ attempts: number; spent: boolean }>(
        `SELECT attempts, completed_at IS NOT NULL AS spent FROM ${schema}.email_changes
          ORDER BY created_at DESC LIMIT 1`,
      );
      // The code was right; the world changed. No attempt burned, nothing
      // spent — the transaction rolled back whole.
      expect(change.rows[0]).toEqual({ attempts: 0, spent: false });
    });

    it('TWO CONCURRENT COMPLETIONS spend the change exactly once — the CAS, driven raw', async () => {
      // Through the REPO against two open transactions, the PR3 shape: this
      // proves the statement's own predicate, which the service-level replay
      // case above cannot isolate (it re-reads before it spends).
      await request();
      const staged = await admin.query<{ id: string }>(
        `SELECT id FROM ${schema}.email_changes WHERE completed_at IS NULL LIMIT 1`,
      );
      const changeId = staged.rows[0]?.id as string;

      const a = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
      const b = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
      await a.connect();
      await b.connect();
      try {
        const wrap = (c: Client): Queryable => ({
          query: async <R extends Record<string, unknown>>(sql: string, params?: unknown[]) =>
            (await c.query(sql, params)).rows as R[],
        });
        await a.query('BEGIN');
        const first = await changes.markCompleted(wrap(a), changeId, now);
        // B blocks on A's row lock until A commits; issue it concurrently.
        await b.query('BEGIN');
        const second = changes.markCompleted(wrap(b), changeId, now);
        await a.query('COMMIT');
        const secondResult = await second;
        await b.query('COMMIT');
        expect(first).toBe(true);
        expect(secondResult).toBe(false);
      } finally {
        await a.end();
        await b.end();
      }
    });
  });
});
