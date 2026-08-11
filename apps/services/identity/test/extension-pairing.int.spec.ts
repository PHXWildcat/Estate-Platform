/**
 * The extension-pairing ceremony against real Postgres (M16).
 *
 * The M13 rule, fourth application: a property that lives in a statement must be
 * pinned by a test that runs the statement. Everything below is invisible to a
 * suite that fakes the repo —
 *
 *   · BURN ON THE ATTEMPT, as one UPDATE whose WHERE clause is the whole
 *     concurrency argument. A check-then-act pair passes every unit test and
 *     lets two redemptions of one code both succeed, which here would mean two
 *     extensions paired from a credential the owner authorised once.
 *   · Expiry enforced IN SQL, so a lapsed code and an unknown one are
 *     indistinguishable at the only place that could tell them apart.
 *   · ONE UNSPENT PAIRING PER USER — and the part that is easy to get wrong,
 *     that `retireLive` matching the INDEX rather than the clock is what keeps
 *     that index satisfiable. M14's worst finding was precisely this pair
 *     disagreeing, and it made an account permanently unverifiable.
 */
import { createHash, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import type { EventsService } from '../src/events.service';
import {
  CANONICAL_PAIRING_CODE_LENGTH,
  ExtensionPairingService,
  PAIRING_TTL_MS,
} from '../src/extension-pairing.service';
import { ExtensionPairingsRepo } from '../src/extension-pairings.repo';
import { canonicalCode } from '../src/readable-code';
import { SessionsRepo } from '../src/sessions.repo';
import { hashToken } from '../src/tokens';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const sha = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest();

describeIfPg('extension pairing (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `identitypair_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let repo: ExtensionPairingsRepo;
  let sessions: SessionsRepo;
  let service: ExtensionPairingService;
  let now: Date;

  const NOW = new Date('2026-08-10T12:00:00.000Z');
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

    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, password_hash, dek_id)
       VALUES ($1, $2, $3, 'x', $4)`,
      [user, Buffer.from('ct'), Buffer.from('bidx'), randomUUID()],
    );

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    repo = new ExtensionPairingsRepo(db);
    sessions = new SessionsRepo(db);

    // extension_pairings.minted_from references sessions(id).
    await sessions.create({
      id: accountSession,
      userId: user,
      refreshTokenH: hashToken('acct-r'),
      accessTokenH: hashToken('acct-a'),
      accessExpiresAt: new Date(NOW.getTime() + 60_000),
      expiresAt: new Date(NOW.getTime() + 60_000),
      audience: 'account',
    });

    service = new ExtensionPairingService(
      repo,
      sessions,
      {
        extensionPairingMinted: (): Promise<void> => Promise.resolve(),
        extensionPaired: (): Promise<void> => Promise.resolve(),
        extensionPairingFailed: (): Promise<void> => Promise.resolve(),
      } as unknown as EventsService,
      () => now,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    now = NOW;
    // These tests contend for a single live slot by design, so each states its
    // own precondition rather than inheriting the previous one's leftovers —
    // the handoff suite's lesson, where an expired-but-unspent code from an
    // earlier case failed a later mint for the wrong reason.
    await admin.query(`DELETE FROM ${schema}.extension_pairings`);
  });

  async function liveRows(): Promise<number> {
    const { rows } = await admin.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM ${schema}.extension_pairings
        WHERE redeemed_at IS NULL AND revoked_at IS NULL`,
    );
    return Number(rows[0]?.n ?? '0');
  }

  it('mints a readable 160-bit code that folds to the declared length', async () => {
    const { code, expiresAt } = await service.mint(user, accountSession);
    expect(code.startsWith('EP1-')).toBe(true);
    expect(canonicalCode(code)).toHaveLength(CANONICAL_PAIRING_CODE_LENGTH);
    expect(code.replace(/^EP1-/, '').replace(/-/g, '')).toHaveLength(32);
    expect(expiresAt.getTime()).toBe(NOW.getTime() + PAIRING_TTL_MS);
    // Only the digest is stored — never the code, never a reversible transform.
    const { rows } = await admin.query<{ code_sha256: Buffer }>(
      `SELECT code_sha256 FROM ${schema}.extension_pairings`,
    );
    expect(rows[0]?.code_sha256).toEqual(sha(canonicalCode(code)));
  });

  it('redeems into an EXTENSION session that carries a refresh token and NO step-up', async () => {
    const { code } = await service.mint(user, accountSession);
    const paired = await service.redeem(code);

    expect(paired.userId).toBe(user);
    expect(paired.refreshToken).toEqual(expect.any(String));
    expect(paired.refreshToken.length).toBeGreaterThan(20);

    const { rows } = await admin.query<{
      audience: string;
      mfa_level: string;
      stepup_expires_at: Date | null;
    }>(`SELECT audience, mfa_level, stepup_expires_at FROM ${schema}.sessions WHERE id = $1`, [
      paired.sessionId,
    ]);
    // The audience the whole route table is built around, and no step-up: an
    // unauthenticated redeem route must not mint a step-up-fresh session,
    // because `POST /v1/vault/reset` is gated on step-up ALONE (M15 PR4).
    expect(rows[0]).toEqual({ audience: 'extension', mfa_level: 'none', stepup_expires_at: null });

    // The pairing records what it produced, for the paired-devices surface.
    const { rows: pairing } = await admin.query<{ session_id: string; redeemed_at: Date }>(
      `SELECT session_id, redeemed_at FROM ${schema}.extension_pairings`,
    );
    expect(pairing[0]?.session_id).toBe(paired.sessionId);
    expect(pairing[0]?.redeemed_at).toBeInstanceOf(Date);
  });

  it('accepts a code retyped the way a human retypes it', async () => {
    // Lowercase, grouping dashes dropped, and an O typed for a zero. The
    // alphabet excludes I, L, O and U precisely so this survives; without the
    // fold at redemption the user's only remedy is a fresh code (the M13 review
    // finding, where a security property hid a usability defect).
    const { code } = await service.mint(user, accountSession);
    const retyped = code.toLowerCase().replace(/-/g, '').replace(/0/g, 'O');
    await expect(service.redeem(retyped)).resolves.toMatchObject({ userId: user });
  });

  it('refuses a replayed code, an expired one and a mis-shaped one identically', async () => {
    const { code } = await service.mint(user, accountSession);
    await service.redeem(code);
    // Spent.
    await expect(service.redeem(code)).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    // Unknown.
    await expect(
      service.redeem('EP1-0000-0000-0000-0000-0000-0000-0000-0000'),
    ).rejects.toMatchObject({ response: { error: 'invalid_code' } });
    // Mis-shaped — refused BEFORE any lookup, with the same answer, so the
    // shape check is not itself a distinguisher.
    await expect(service.redeem('EP1-XYZ')).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });

    // Expired: enforced in SQL, indistinguishable from unknown.
    const fresh = await service.mint(user, accountSession);
    now = new Date(NOW.getTime() + PAIRING_TTL_MS + 1_000);
    await expect(service.redeem(fresh.code)).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
  });

  it('CONCURRENT redemptions of one code produce exactly one winner', async () => {
    const { code } = await service.mint(user, accountSession);
    const digest = sha(canonicalCode(code));
    const [a, b] = await Promise.all([repo.claim(digest, NOW), repo.claim(digest, NOW)]);
    expect([a, b].filter((r) => r !== null)).toHaveLength(1);
  });

  it('permits only ONE unspent pairing per user — minting again retires the first', async () => {
    const first = await service.mint(user, accountSession);
    expect(await liveRows()).toBe(1);
    const second = await service.mint(user, accountSession);
    expect(await liveRows()).toBe(1);

    // The retired code is dead; the new one works.
    await expect(service.redeem(first.code)).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    await expect(service.redeem(second.code)).resolves.toMatchObject({ userId: user });
  });

  it('an EXPIRED but unspent pairing still occupies the slot, and re-minting clears it', async () => {
    // THE M14 WEDGE, which is why `retireLive` matches the index predicate and
    // not the clock. The partial unique index cannot reference now(), so a
    // lapsed row still occupies the slot; if the retire step carried the clock
    // it would decline to clear it, the next insert would take the unique
    // violation, and the ceremony would refuse forever.
    await service.mint(user, accountSession);
    now = new Date(NOW.getTime() + PAIRING_TTL_MS + 60_000);
    expect(await liveRows()).toBe(1);

    const reminted = await service.mint(user, accountSession);
    expect(await liveRows()).toBe(1);
    await expect(service.redeem(reminted.code)).resolves.toMatchObject({ userId: user });
  });
});
