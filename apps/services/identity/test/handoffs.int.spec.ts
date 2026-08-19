/**
 * The vault-handoff store against real Postgres (M15).
 *
 * The M13 rule, third application: a property that lives in a statement must be
 * pinned by a test that runs the statement. Everything asserted here is
 * invisible to a unit suite that fakes the repo —
 *
 *   · BURN ON THE ATTEMPT, expressed as a single UPDATE whose WHERE clause is
 *     the whole concurrency argument. A check-then-act pair passes every unit
 *     test and lets two redemptions of one code both succeed.
 *   · Expiry enforced IN SQL, so a lapsed code and an unknown one are
 *     indistinguishable at the only place that could tell them apart.
 *   · ONE UNSPENT HANDOFF PER USER, and — the part that is easy to get wrong —
 *     that the write path's `retireLive` is what keeps that index satisfiable,
 *     because the predicate cannot mention expiry.
 *
 * Also asserted: the migration's `audience` backfill, since "additive, no
 * session changes meaning" is exactly the kind of claim that turns out to be
 * wrong.
 */
import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import { isStepUpFresh } from '@estate/auth-guard';
import { type MfaLevel } from '@estate/contracts';
import { HandoffService } from '../src/handoff.service';
import { HandoffsRepo } from '../src/handoffs.repo';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const sha = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();

describeIfPg('auth_handoffs against Postgres (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identityhandoff_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let repo: HandoffsRepo;
  let sessions: SessionsRepo;

  const NOW = new Date('2026-08-07T12:00:00.000Z');
  const SOON = new Date(NOW.getTime() + 60_000);
  const user = randomUUID();
  const accountSession = randomUUID();

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
    repo = new HandoffsRepo(db);
    sessions = new SessionsRepo(db);

    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [user, Buffer.from('ct'), Buffer.from('bidx'), randomUUID()],
    );
    // auth_handoffs.minted_from references sessions(id). The audience is named
    // rather than defaulted (M16) and `account` is the only correct value here:
    // a handoff is minted FROM an account session, and the route that mints one
    // is account-only precisely so a vault session cannot chain forward.
    await sessions.create({
      id: accountSession,
      userId: user,
      refreshTokenH: hashToken('r'),
      accessTokenH: hashToken('a'),
      accessExpiresAt: SOON,
      expiresAt: SOON,
      audience: 'account',
    });
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  /**
   * One unspent handoff per user is a real constraint, so these tests contend
   * for a single slot and would otherwise leak into each other — the first
   * draft did exactly that, and an EXPIRED-but-unspent code from an earlier
   * case failed a later mint for the wrong reason. Clearing the slot first
   * makes each test state its own precondition.
   */
  beforeEach(async () => {
    await repo.retireLive(user, NOW);
  });

  const mint = (code: string, expiresAt = SOON): Promise<{ id: string }> =>
    repo.insert({
      userId: user,
      codeSha256: sha(code),
      audience: 'vault',
      mintedFrom: accountSession,
      expiresAt,
    });

  it('an INSERT that omits the audience column gets the migration’s DEFAULT', async () => {
    /*
     * WHAT THIS PROVES, and what it used to pretend to prove.
     *
     * The case was called "a session created without an audience IS an account
     * session" and it read the row seeded through `SessionsRepo.create` — which
     * bound `input.audience ?? 'account'`, so the INSERT ALWAYS named the
     * column and the DDL default was never once exercised. Its own comment said
     * "the migration's DEFAULT"; it was measuring the TypeScript fallback. M16
     * deleted that fallback (the audience is now a required argument), which
     * left the case asserting that a value written two lines earlier comes
     * back — the "test named for a property it never touched" shape, in the
     * file whose header cites that very rule.
     *
     * So it inserts in RAW SQL with no audience column, which is the only way
     * to reach the default. That default is not decoration: it is what made
     * M15's `ALTER TABLE … ADD COLUMN` additive for every session that already
     * existed, and `packages/auth-guard/test/session-audience.spec.ts` pins its
     * value to `DEFAULT_SESSION_AUDIENCE` on the TypeScript side.
     */
    const legacy = randomUUID();
    await admin.query(
      `INSERT INTO ${schema}.sessions
         (id, user_id, refresh_token_h, access_token_h, access_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [legacy, user, hashToken('legacy-r'), hashToken('legacy-a'), SOON, SOON],
    );
    const rows = await admin.query<{ audience: string }>(
      `SELECT audience FROM ${schema}.sessions WHERE id = $1`,
      [legacy],
    );
    expect(rows.rows[0]?.audience).toBe('account');
  });

  it('ROTATING TOKENS PRESERVES THE AUDIENCE, which is what makes refresh safe', async () => {
    /*
     * THE PROPERTY M16's CREDENTIAL MODEL RESTS ON, and it had no test.
     *
     * An extension session carries a long-lived refresh token, so it rides
     * `POST /v1/auth/refresh` repeatedly. That route is unauthenticated by
     * construction, has no guard, and applies no audience predicate anywhere —
     * `findLiveByRefreshHash` selects `audience` without filtering on it. What
     * keeps it from being an audience-blind mint of ORDINARY ACCOUNT SESSIONS
     * is that refresh does not create a session at all: `rotateTokens` is an
     * in-place `UPDATE … WHERE id = $1` whose SET list omits `audience`, so the
     * value survives because there is no new row to carry it to.
     *
     * That is a guarantee resting on the ABSENCE of a column from a statement.
     * Nothing checked it and nothing could: `IssuedTokens` carries no audience
     * field, so no caller of refresh can observe what it refreshed, and the two
     * existing refresh tests fake the repo — where there is no SET list to omit
     * anything from. The hardening a reviewer would reach for first (rotate the
     * session id, not just the tokens, so a stolen token cannot be shadowed)
     * replaces that UPDATE with an INSERT, and an INSERT that omits `audience`
     * mints an `account` session from two independent defaults.
     *
     * So: real Postgres, a non-account session, rotate, and read the column
     * back. Pinned at the repo because that is where the statement is.
     */
    const rotating = randomUUID();
    await sessions.create({
      id: rotating,
      userId: user,
      refreshTokenH: hashToken('rot-r1'),
      accessTokenH: hashToken('rot-a1'),
      accessExpiresAt: SOON,
      expiresAt: SOON,
      audience: 'vault',
    });

    await sessions.rotateTokens(rotating, {
      newRefreshTokenH: hashToken('rot-r2'),
      previousRefreshTokenH: hashToken('rot-r1'),
      newAccessTokenH: hashToken('rot-a2'),
      accessExpiresAt: SOON,
    });

    const { rows } = await admin.query<{ audience: string; id: string }>(
      `SELECT id, audience FROM ${schema}.sessions WHERE id = $1`,
      [rotating],
    );
    // Same row, same audience. Both halves matter: an implementation that
    // created a NEW row would leave this one behind with its audience intact
    // and still be the defect, so the id is asserted too.
    expect(rows).toEqual([{ id: rotating, audience: 'vault' }]);

    // And the rotation really happened — otherwise this passes over a no-op.
    const found = await sessions.findLiveByRefreshHash(hashToken('rot-r2'), NOW);
    expect(found?.id).toBe(rotating);
    expect(found?.audience).toBe('vault');
  });

  it('claims a live code exactly once — the second attempt gets nothing', async () => {
    await mint('alpha');
    await expect(repo.claim(sha('alpha'), NOW)).resolves.toEqual(
      expect.objectContaining({ user_id: user, audience: 'vault' }),
    );
    // Replay of a spent code. Same answer as an unknown one.
    await expect(repo.claim(sha('alpha'), NOW)).resolves.toBeNull();
  });

  it('CONCURRENT redemptions of one code produce exactly one winner', async () => {
    await mint('race');
    const [a, b] = await Promise.all([repo.claim(sha('race'), NOW), repo.claim(sha('race'), NOW)]);
    expect([a, b].filter((r) => r !== null)).toHaveLength(1);
  });

  it('refuses an EXPIRED code in SQL, indistinguishably from an unknown one', async () => {
    await mint('stale', new Date(NOW.getTime() - 1));
    expect(await repo.claim(sha('stale'), NOW)).toBeNull();
    expect(await repo.claim(sha('never-minted'), NOW)).toBeNull();
  });

  it('permits only ONE unspent handoff per user', async () => {
    await mint('live-one');
    await expect(mint('live-two')).rejects.toThrow();
  });

  it('retireLive is what makes re-issuing possible at all', async () => {
    // The index predicate cannot say "and not expired", so the write path has
    // to clear the slot. If `retireLive` regressed to a no-op, minting a second
    // code would fail forever for this user — the mint path would be dead, not
    // merely duplicated.
    await mint('live-before-reissue');
    expect(await repo.retireLive(user, NOW)).toBe(1);
    await expect(mint('live-three')).resolves.toEqual(expect.objectContaining({ user_id: user }));
  });

  it('an EXPIRED but unspent handoff still blocks, until retired', async () => {
    // The uncomfortable consequence of an immutable index predicate, asserted
    // rather than assumed: expiry alone does NOT free the slot.
    await mint('expired-blocker', new Date(NOW.getTime() - 1));
    await expect(mint('after-expiry')).rejects.toThrow();
    expect(await repo.retireLive(user, NOW)).toBe(1);
    await expect(mint('after-retire')).resolves.toEqual(expect.any(Object));
  });

  it('records the session a spent handoff produced', async () => {
    const handoff = await mint('linked');
    const vaultSession = randomUUID();
    await sessions.create({
      id: vaultSession,
      userId: user,
      refreshTokenH: hashToken('unissued'),
      accessTokenH: hashToken('vault-access'),
      accessExpiresAt: SOON,
      expiresAt: SOON,
      audience: 'vault',
    });
    await repo.recordSession(handoff.id, vaultSession);

    const rows = await admin.query<{ session_id: string; audience: string }>(
      `SELECT h.session_id, s.audience
         FROM ${schema}.auth_handoffs h JOIN ${schema}.sessions s ON s.id = h.session_id
        WHERE h.id = $1`,
      [handoff.id],
    );
    expect(rows.rows[0]).toEqual({ session_id: vaultSession, audience: 'vault' });
  });

  it('a REDEEMED session carries NO step-up (M15 review)', async () => {
    /*
     * THE FIX FOR THE STEP-UP BYPASS, pinned against a real database.
     *
     * `POST /v1/auth/handoff/redeem` is unauthenticated — the code IS the
     * authority — and `POST /v1/vault/reset` is gated on step-up ALONE, because
     * a lost vault password cannot be proven. So a redeemed session that
     * arrived step-up-fresh let whoever held a stolen 60-second code
     * crypto-shred the vault with no password and no Secret Key. Script on the
     * app origin cannot MINT a handoff (minting is step-up gated) but can read
     * one out of the hidden field it is posted in, which turned no-step-up into
     * step-up authority over Zone A.
     *
     * Asserted here rather than in a unit test because the property lives in a
     * column: `stepup_expires_at` must be NULL on the row the service wrote.
     */
    // Events are a fire-and-forget audit hop; the property under test is a
    // column, so a recording double keeps this spec about the database.
    const events = {
      handoffMinted: () => Promise.resolve(),
      handoffRedeemed: () => Promise.resolve(),
      handoffFailed: () => Promise.resolve(),
    };
    const service = new HandoffService(repo, sessions, events as never, () => NOW);
    // `minted_from` is a FK to sessions, so the mint must come from a real one.
    const minted = await service.mint(user, accountSession, 'vault');
    const redeemed = await service.redeem(minted.code);

    const rows = await admin.query<{ stepup_expires_at: Date | null; mfa_level: string }>(
      `SELECT stepup_expires_at, mfa_level FROM ${schema}.sessions WHERE id = $1`,
      [redeemed.sessionId],
    );
    expect(rows.rows[0]?.stepup_expires_at).toBeNull();
    // And `isStepUpFresh` — the one shared definition every guard reads — says
    // so too, which is what a StepUpGuard downstream will actually consult.
    expect(isStepUpFresh(rows.rows[0]?.mfa_level as MfaLevel, null, NOW)).toBe(false);
  });

  it('MINTS AN OPERATOR SESSION through the same ceremony, and the row says so', async () => {
    /*
     * M21 PR3a — the second audience this ceremony serves, pinned end to end.
     *
     * The audience is a property of the ROW rather than of the redemption:
     * `mint` writes it and `redeem` reads it back off the claimed handoff, so
     * there is no place in the unauthenticated redeem path where an audience
     * could be chosen. That is what this asserts — not that the service can be
     * asked for an operator session, but that the one it produces IS one, and
     * that redemption never had a say.
     *
     * Against a real database because migration 012's widened CHECK is half the
     * property: before it, this exact call raises 23514 and the ceremony's
     * uniform refusal would report it as `invalid_code`.
     */
    const events = {
      handoffMinted: () => Promise.resolve(),
      handoffRedeemed: () => Promise.resolve(),
      handoffFailed: () => Promise.resolve(),
    };
    const service = new HandoffService(repo, sessions, events as never, () => NOW);
    const minted = await service.mint(user, accountSession, 'operator');
    const redeemed = await service.redeem(minted.code);

    const rows = await admin.query<{
      audience: string;
      stepup_expires_at: Date | null;
      refresh_token_h: Buffer | string | null;
    }>(
      `SELECT audience, stepup_expires_at, refresh_token_h
         FROM ${schema}.sessions WHERE id = $1`,
      [redeemed.sessionId],
    );
    expect(rows.rows[0]?.audience).toBe('operator');
    // Everything the vault audience gets, the operator audience gets: no
    // step-up carried in (the M15 PR4 finding), and a refresh digest of a token
    // that was dropped on the floor — so `POST /v1/auth/refresh` cannot extend
    // an operator session past its 15 minutes. Both are asserted rather than
    // assumed to follow from sharing a code path, because sharing a code path
    // is exactly what a later refactor stops doing.
    expect(rows.rows[0]?.stepup_expires_at).toBeNull();
    expect(rows.rows[0]?.refresh_token_h).not.toBeNull();
  });

  it('a handoff minted for one origin cannot be redeemed as the other', async () => {
    // The audience travels ON THE ROW, so this is a property of the schema
    // rather than of the caller: there is no argument to `redeem`, and the two
    // ceremonies differ only in what `mint` wrote. Asserted because "the route
    // is the selector" is PR3a's whole reason for two routes instead of one
    // body field, and a redemption that could re-choose would undo it.
    const events = {
      handoffMinted: () => Promise.resolve(),
      handoffRedeemed: () => Promise.resolve(),
      handoffFailed: () => Promise.resolve(),
    };
    const service = new HandoffService(repo, sessions, events as never, () => NOW);
    const vaultCode = await service.mint(user, accountSession, 'vault');
    const vaultSession = await service.redeem(vaultCode.code);
    const operatorCode = await service.mint(user, accountSession, 'operator');
    const operatorSession = await service.redeem(operatorCode.code);

    const rows = await admin.query<{ id: string; audience: string }>(
      `SELECT id, audience FROM ${schema}.sessions WHERE id = ANY($1)`,
      [[vaultSession.sessionId, operatorSession.sessionId]],
    );
    const byId = new Map(rows.rows.map((r) => [r.id, r.audience]));
    expect({
      vault: byId.get(vaultSession.sessionId),
      operator: byId.get(operatorSession.sessionId),
    }).toEqual({ vault: 'vault', operator: 'operator' });
  });

  it('refuses an audience the CHECK does not know', async () => {
    // The vocabulary is closed in the DDL as well as in TypeScript, so a code
    // path that learned a new audience cannot quietly persist one.
    await expect(
      admin.query(
        `INSERT INTO ${schema}.sessions (id, user_id, refresh_token_h, expires_at, audience)
         VALUES ($1, $2, $3, $4, 'settlement-operator')`,
        [randomUUID(), user, hashToken('x'), SOON],
      ),
    ).rejects.toThrow();
  });
});
