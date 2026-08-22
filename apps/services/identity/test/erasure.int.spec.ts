/**
 * ACCOUNT ERASURE — THE DECISION HALF, against real Postgres (M25 PR2).
 *
 * Everything load-bearing here lives in SQL: the status allowlist rides inside
 * the INSERT's own `WHERE EXISTS`, the one-live-request rule is a partial
 * unique index inferred by `ON CONFLICT`, and the cancel is a conditional
 * UPDATE. A faked repo could not get any of that wrong and therefore could not
 * prove it right — the M13 rule, and the reason this suite exists rather than a
 * unit test with a stub repo.
 *
 * Five properties, each a way this could be present and wrong:
 *
 *  1. THE ALLOWLIST IS IN THE STATEMENT. A check above the INSERT would be a
 *     check-then-act on the verb that arms the most irreversible process in the
 *     product. Proved by moving the account's status and watching the same call
 *     refuse without the service re-reading anything first.
 *  2. THE REFUSALS DO NOT SHARE A TOKEN. `deceased_pending` is a control
 *     firing with a remedy the owner can take; everything else is not. One
 *     token for both would tell somebody whose account is being taken from them
 *     that the product is broken.
 *  3. REQUESTING IS IDEMPOTENT. A second press is the same intent, not a
 *     conflict — and it must not create a second row, which is what the partial
 *     unique index is for.
 *  4. CANCELLING IS UNGATED AND SAFE TO REPEAT. The protective verb must never
 *     be harder than the permissive one, and pressing it twice must not error.
 *  5. A CANCELLED REQUEST DOES NOT BLOCK THE NEXT ONE. The index is partial on
 *     `status = 'pending'`; if it were not, changing your mind once would lock
 *     you out of the feature permanently.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { ERASURE_DOMAINS } from '@estate/contracts';
import { emailBlindIndex, FieldCrypto, LocalKmsProvider } from '@estate/crypto';
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import type { IdentityConfig } from '../src/config';
import { Db } from '../src/db';
import { PgDekRepository } from '../src/dek.repository';
import { ErasureRepo } from '../src/erasure.repo';
import { ErasureService } from '../src/erasure.service';
import type { EventsService } from '../src/events.service';
import { SessionsRepo } from '../src/sessions.repo';
import { UsersRepo } from '../src/users.repo';

const KEK_ALIAS = 'test/auth-kek';
const INDEX_KEY = Buffer.alloc(32, 9);
const GRACE_MS = 7 * 24 * 60 * 60 * 1000;

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-21T12:00:00.000Z');

describeIfPg('account erasure requests (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `erasure_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let service: ErasureService;
  let repo: ErasureRepo;
  let users: UsersRepo;
  let deks: PgDekRepository;
  let crypto: FieldCrypto;
  let audited: Array<{ kind: string; userId: string; requestId: string }>;

  const user = randomUUID();
  const session = randomUUID();

  async function seedUser(status = 'active'): Promise<void> {
    await admin.query(`TRUNCATE ${schema}.erasure_requests_versions CASCADE`);
    await admin.query(`TRUNCATE ${schema}.erasure_requests CASCADE`);
    await admin.query(`TRUNCATE ${schema}.users_versions, ${schema}.users CASCADE`);
    await admin.query(
      `INSERT INTO ${schema}.users (id, email_ct, email_bidx, dek_id, status)
       VALUES ($1, $2, $3, $4, $5)`,
      [user, Buffer.from('ct'), Buffer.from(`bidx-${user}`), randomUUID(), status],
    );
  }

  async function setStatus(status: string): Promise<void> {
    await admin.query(`UPDATE ${schema}.users SET status = $2 WHERE id = $1`, [user, status]);
  }

  async function rowCount(): Promise<number> {
    const { rows } = await admin.query<{ n: string }>(
      `SELECT count(*) AS n FROM ${schema}.erasure_requests WHERE user_id = $1`,
      [user],
    );
    return Number(rows[0]?.n ?? '0');
  }

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    // Trigger bodies resolve unqualified names against the CONNECTION's
    // search_path, not the schema in the statement. Pinned so a capture cannot
    // reach whatever `public` happens to hold.
    await admin.query(`SET search_path TO ${schema}`);

    const migrClient = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await migrClient.connect();
    try {
      await new Migrator(migrClient, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await migrClient.end();
    }

    db = new Db({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    audited = [];
    repo = new ErasureRepo();
    users = new UsersRepo(db);
    deks = new PgDekRepository(db);
    crypto = new FieldCrypto(new LocalKmsProvider(Buffer.alloc(32, 3)), deks, () => undefined, {
      kekAlias: KEK_ALIAS,
    });
    service = new ErasureService(
      db,
      repo,
      {
        accountErasureRequested: (userId: string, _s: string | null, requestId: string) => {
          audited.push({ kind: 'requested', userId, requestId });
          return Promise.resolve();
        },
        accountErasureCancelled: (userId: string, _s: string | null, requestId: string) => {
          audited.push({ kind: 'cancelled', userId, requestId });
          return Promise.resolve();
        },
        userClosedForErasure: (userId: string, _from: string, requestId: string) => {
          audited.push({ kind: 'closed', userId, requestId });
          return Promise.resolve();
        },
        sessionsRevokedForErasure: (userId: string, _n: number, requestId: string) => {
          audited.push({ kind: 'sessions_revoked', userId, requestId });
          return Promise.resolve();
        },
        dekDestroyed: (userId: string, _dekId: string, requestId: string) => {
          audited.push({ kind: 'dek_destroyed', userId, requestId });
          return Promise.resolve();
        },
      } as unknown as EventsService,
      users,
      new SessionsRepo(db),
      crypto,
      deks,
      { erasureGracePeriodMs: GRACE_MS, emailIndexKey: INDEX_KEY } as unknown as IdentityConfig,
      () => NOW,
    );
  });

  afterAll(async () => {
    await db?.onModuleDestroy();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  beforeEach(async () => {
    audited = [];
    await seedUser();
  });

  it('records a request for an active account, and audits it', async () => {
    const state = await service.request(user, session);
    expect(state.status).toBe('pending');
    expect(await rowCount()).toBe(1);
    expect(audited.map((a) => a.kind)).toEqual(['requested']);
    expect(await service.get(user)).toEqual(state);
  });

  it('IS IDEMPOTENT — a second press answers with the same request, not a conflict', async () => {
    const first = await service.request(user, session);
    const second = await service.request(user, session);
    expect(second).toEqual(first);
    // The partial unique index is what makes this true; without it the second
    // INSERT would succeed and the account would carry two live requests.
    expect(await rowCount()).toBe(1);
  });

  it('REFUSES a reported-dead owner with its own token, naming a remedy they have', async () => {
    await setStatus('deceased_pending');
    await expect(service.request(user, session)).rejects.toMatchObject({
      response: { error: 'open_death_report' },
    });
    expect(await rowCount()).toBe(0);
    expect(audited).toEqual([]);
  });

  it('REFUSES every other status on a DIFFERENT token — two remedies, two answers', async () => {
    for (const status of ['locked', 'suspended', 'settlement', 'closed']) {
      await setStatus(status);
      await expect(service.request(user, session)).rejects.toMatchObject({
        response: { error: 'erasure_not_permitted' },
      });
    }
    expect(await rowCount()).toBe(0);
  });

  it('the allowlist rides INSIDE the statement, not above it', async () => {
    // The service does not read status before inserting — it inserts with the
    // allowlist in a `WHERE EXISTS` and re-reads only to explain a refusal. So
    // moving the status is enough to change the outcome of the identical call,
    // with no separate pre-check for a commit to land between.
    await setStatus('settlement');
    await expect(service.request(user, session)).rejects.toThrow();
    await setStatus('active');
    expect((await service.request(user, session)).status).toBe('pending');
  });

  it('CANCELS without a factor, and is safe to press twice', async () => {
    await service.request(user, session);
    audited = [];

    expect(await service.cancel(user, session)).toBeNull();
    expect(await service.get(user)).toBeNull();
    expect(audited.map((a) => a.kind)).toEqual(['cancelled']);

    // Pressing again is a no-op that does not throw and does not double-audit:
    // a protective verb a user is afraid to press twice is a worse control.
    expect(await service.cancel(user, session)).toBeNull();
    expect(audited.map((a) => a.kind)).toEqual(['cancelled']);
  });

  it('a CANCELLED request does not block the next one', async () => {
    await service.request(user, session);
    await service.cancel(user, session);
    const again = await service.request(user, session);
    expect(again.status).toBe('pending');
    // Two rows: one cancelled, one live. The index is partial on 'pending', so
    // changing your mind once does not lock you out of the feature forever.
    expect(await rowCount()).toBe(2);
  });

  it('CANCELLING SURVIVES the account becoming ineligible to request', async () => {
    // The de-escalating direction must not inherit the permissive direction's
    // allowlist: an owner reported dead while a request was live must still be
    // able to withdraw it, or the most dangerous record in the system is
    // stranded in its armed state by a control meant to protect them.
    await service.request(user, session);
    await setStatus('deceased_pending');
    expect(await service.cancel(user, session)).toBeNull();
    expect(await service.get(user)).toBeNull();
  });

  it('the cancel is captured with an actor, so the record has a who', async () => {
    await service.request(user, session);
    await service.cancel(user, session);
    const { rows } = await admin.query<{ actor_id: string | null; row_data: { status: string } }>(
      `SELECT actor_id, row_data FROM ${schema}.erasure_requests_versions ORDER BY version_seq`,
    );
    expect(rows).toHaveLength(1);
    // The image is the PRIOR row, so it reads 'pending' — the capture records
    // what was replaced, and the actor is the owner who replaced it.
    expect(rows[0]?.row_data.status).toBe('pending');
    expect(rows[0]?.actor_id).toBe(user);
  });

  /**
   * THE EXECUTION HALF (M25 PR3). Same rule as above: what is asserted here is
   * what only real SQL can decide — the grace-period predicate, the
   * eligibility restated inside the claim, the widened live index, the ledger's
   * completeness test, and the one that could not be checked anywhere else,
   * that erasing an address does not leave a copy of its blind index in the
   * append-only shadow that no later migration could retract.
   */
  describe('the destroy leg', () => {
    /** A user with a REAL DEK and a live session, ready to be erased. */
    async function seedErasable(email: string): Promise<{ dekId: string; sessionId: string }> {
      await seedUser();
      const dekId = await crypto.getOrCreateDek(user);
      await admin.query(`UPDATE ${schema}.users SET dek_id = $2, email_bidx = $3 WHERE id = $1`, [
        user,
        dekId,
        emailBlindIndex(INDEX_KEY, email),
      ]);
      const sessionId = randomUUID();
      await admin.query(
        `INSERT INTO ${schema}.sessions (id, user_id, refresh_token_h, access_token_h, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [sessionId, user, Buffer.from('r'), Buffer.from('a'), new Date(NOW.getTime() + 3_600_000)],
      );
      return { dekId, sessionId };
    }

    /** Backdate the live request so its grace period has lapsed. */
    async function backdate(byMs: number): Promise<void> {
      await admin.query(
        `UPDATE ${schema}.erasure_requests SET requested_at = $2
          WHERE user_id = $1 AND status = 'pending'`,
        [user, new Date(NOW.getTime() - byMs)],
      );
    }

    async function statusOf(): Promise<string> {
      const { rows } = await admin.query<{ status: string }>(
        `SELECT status FROM ${schema}.users WHERE id = $1`,
        [user],
      );
      return rows[0]?.status ?? 'missing';
    }

    it('WILL NOT TOUCH a request inside its grace period', async () => {
      // The whole cancel window is this predicate. If it were absent the driver
      // would execute a request the instant it was made, and PR2's ungated
      // cancel would be a button that can never be pressed in time.
      await seedErasable('inside@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS - 60_000);
      expect(await service.runDueErasures(NOW)).toBe(0);
      expect(await statusOf()).toBe('active');
      expect((await service.get(user))?.status).toBe('pending');
    });

    it('claims, closes, revokes, shreds — and the DEK is unusable afterwards', async () => {
      const { dekId, sessionId } = await seedErasable('erased@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);

      expect(await service.runDueErasures(NOW)).toBe(1);
      expect(await statusOf()).toBe('closed');

      const { rows: revoked } = await admin.query<{ revoke_reason: string | null }>(
        `SELECT revoke_reason FROM ${schema}.sessions WHERE id = $1 AND revoked_at IS NOT NULL`,
        [sessionId],
      );
      expect(revoked).toHaveLength(1);
      expect(revoked[0]?.revoke_reason).toBe('account_erased');

      // The key itself. Not "a column was set" — the crypto layer must now
      // REFUSE, which is the property `content_erased` answers on.
      const record = await deks.findById(dekId);
      expect(record?.destroyedAt).not.toBeNull();
      await expect(
        crypto.decryptField({
          userId: user,
          dekId,
          field: 'email',
          ciphertext: Buffer.alloc(64),
          actorId: user,
          actorType: 'user',
          purpose: 'test',
        }),
      ).rejects.toThrow();

      expect(audited.map((a) => a.kind)).toEqual([
        'requested',
        'closed',
        'sessions_revoked',
        'dek_destroyed',
      ]);
    });

    it('THE ADDRESS STOPS RESOLVING, and the shadow keeps no copy of the index', async () => {
      // The pairing PR1 exists for. `email_bidx` is an HMAC under a
      // service-wide key, so it lives OUTSIDE the envelope and survives the
      // shred untouched — an erased account still answerable to "is this
      // address registered". Overwriting it is the fix; PR1 landing FIRST is
      // what stops the overwrite from copying the old value into
      // `users_versions`, where REVOKE UPDATE, DELETE means nothing could ever
      // retract it. Erasure would have immortalised the value it was erasing.
      const address = 'findable@example.test';
      await seedErasable(address);
      const before = emailBlindIndex(INDEX_KEY, address);
      expect(await users.findByEmailBidx(before)).not.toBeNull();

      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      expect(await users.findByEmailBidx(before)).toBeNull();

      const { rows } = await admin.query<{ row_data: Record<string, unknown> }>(
        `SELECT row_data FROM ${schema}.users_versions ORDER BY version_seq`,
      );
      expect(rows.length).toBeGreaterThan(0);
      for (const captured of rows) {
        expect(Object.keys(captured.row_data)).not.toContain('email_bidx');
        // The ciphertext IS kept, deliberately: it is sealed under the DEK this
        // erasure destroyed, and crypto-shredding reaching every copy —
        // including the append-only ones — is why this repo destroys keys
        // instead of rows.
        expect(Object.keys(captured.row_data)).toContain('email_ct');
      }
    });

    it('opens a ledger row for EVERY participant domain, and finishes none of the others', async () => {
      await seedErasable('ledger@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      const { rows } = await admin.query<{ domain: string; state: string }>(
        `SELECT p.domain, p.state
           FROM ${schema}.erasure_domain_progress p
           JOIN ${schema}.erasure_requests r ON r.id = p.request_id
          WHERE r.user_id = $1 ORDER BY p.domain`,
        [user],
      );
      expect(rows.map((r) => r.domain)).toEqual([...ERASURE_DOMAINS].sort());
      expect(rows.filter((r) => r.state === 'done').map((r) => r.domain)).toEqual(['identity']);

      // And therefore NOT completed. Seven domains have no transport to report
      // in M25, so the request stays executing — the honest answer, and the
      // reason the ledger exists rather than a status that would imply the
      // whole account had been reached.
      const { rows: request } = await admin.query<{ status: string; completed_at: Date | null }>(
        `SELECT status, completed_at FROM ${schema}.erasure_requests WHERE user_id = $1`,
        [user],
      );
      expect(request[0]?.status).toBe('executing');
      expect(request[0]?.completed_at).toBeNull();
    });

    it('completes only once every domain reports — proved by finishing them by hand', async () => {
      // The positive control for the assertion above: without it, "not
      // completed" is equally consistent with a completeness test that can
      // never fire.
      await seedErasable('complete@example.test');
      const requested = await service.request(user, session);
      expect(requested.status).toBe('pending');
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      await admin.query(
        `UPDATE ${schema}.erasure_domain_progress SET state = 'done' WHERE state <> 'done'`,
      );
      const { rows } = await admin.query<{ id: string }>(
        `SELECT id FROM ${schema}.erasure_requests WHERE user_id = $1`,
        [user],
      );
      const requestId = rows[0]?.id as string;
      await expect(
        db.withTransaction('', (tx) => repo.completeIfAllDone(tx, requestId, NOW)),
      ).resolves.toBe(true);
    });

    it('an EXECUTING request cannot be cancelled, and says so instead of lying', async () => {
      await seedErasable('toolate@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      const remaining = await service.cancel(user, session);
      expect(remaining?.status).toBe('executing');
      expect(audited.map((a) => a.kind)).not.toContain('cancelled');
    });

    it('a second request DURING execution is refused by the status allowlist', async () => {
      // Not by the index — that is the point of splitting this from the test
      // below. By the time a second request can be made the account is
      // 'closed', so `insertIfPermitted` matches zero rows and the service
      // answers idempotently with the live request. Named for what actually
      // fires, because a test named for the index and passing on the allowlist
      // is a test that would stay green after the index was removed.
      await seedErasable('second@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      const again = await service.request(user, session);
      expect(again.status).toBe('executing');
      expect(await rowCount()).toBe(1);
    });

    it('THE INDEX ITSELF refuses a second live request, executing included', async () => {
      // PR2's index covered 'pending' alone. Widening it to 'executing' is a
      // SCHEMA invariant — at most one live request per owner — and no service
      // path can currently violate it, because the destroy leg closes the
      // account and the status allowlist stops the insert first. That makes
      // the widening survive a mutation test through the service, which is
      // exactly the situation the repo's rule says to name rather than paper
      // over: the test goes to the constraint directly instead.
      //
      // It matters because the service is not the only writer that will ever
      // exist. A repair script, a future operator path, or a fan-out that
      // leaves 'executing' standing for hours all reach this table, and a
      // second live request is the state the whole design assumes away.
      await seedErasable('index@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      await expect(
        admin.query(
          `INSERT INTO ${schema}.erasure_requests (user_id, status) VALUES ($1, 'pending')`,
          [user],
        ),
      ).rejects.toThrow(/ux_erasure_requests_live/);

      // The positive control: the same insert succeeds once nothing is live,
      // so the refusal above is the index firing and not a broken fixture.
      await admin.query(
        `UPDATE ${schema}.erasure_requests SET status = 'cancelled',
                         cancelled_at = now() WHERE user_id = $1`,
        [user],
      );
      await expect(
        admin.query(
          `INSERT INTO ${schema}.erasure_requests (user_id, status) VALUES ($1, 'pending')`,
          [user],
        ),
      ).resolves.toBeDefined();
    });

    it('RELEASES the claim, destroying nothing, when the account moved in the window', async () => {
      // Eligibility is restated inside the claim because the request may be
      // days old. A death report landing in the grace period must stop the
      // erasure, and must leave it CANCELLABLE rather than wedged.
      await seedErasable('moved@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await setStatus('deceased_pending');

      expect(await service.runDueErasures(NOW)).toBe(0);
      expect(await statusOf()).toBe('deceased_pending');
      expect((await service.get(user))?.status).toBe('pending');
      expect(await service.cancel(user, session)).toBeNull();
    });

    it('RESUMES a request the driver claimed and never finished', async () => {
      // THE CRASH CASE, produced honestly: claim the request through the real
      // repo — which is exactly the state a process killed between the claim
      // and the destroy leaves behind — and then ask the driver to sweep.
      //
      // Every step of the leg is individually idempotent, but that is worth
      // nothing if nothing ever re-drives them. An erasure stuck in 'executing'
      // is the state this whole design exists to prevent: uncancellable by
      // construction, blocked from being re-requested by the live index, and
      // holding an account that was promised destruction and did not get it.
      await seedErasable('resumed@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);

      const claimed = await db.withTransaction('', async (tx) => {
        const row = await repo.claimDue(tx, new Date(NOW.getTime()), NOW, ['active'], 'identity');
        await repo.seedDomains(tx, row?.id as string, ERASURE_DOMAINS);
        return row;
      });
      expect(claimed?.status).toBe('executing');
      audited.length = 0;

      expect(await service.runDueErasures(NOW)).toBe(1);
      expect(await statusOf()).toBe('closed');

      const { rows } = await admin.query<{ state: string }>(
        `SELECT p.state FROM ${schema}.erasure_domain_progress p
           JOIN ${schema}.erasure_requests r ON r.id = p.request_id
          WHERE r.user_id = $1 AND p.domain = 'identity'`,
        [user],
      );
      expect(rows[0]?.state).toBe('done');
    });

    it('AN ERASED ACCOUNT CANNOT BE REACHED by a ceremony holding a live code', async () => {
      // THE §6p PREDICTION, CHECKED RATHER THAN ASSUMED. M17's review recorded
      // a crypto-shredded DEK at email-change completion surfacing as a 500,
      // and filed it as a PRECONDITION on this milestone with a guess attached:
      // "once erasure exists, a shredded account cannot reach a ceremony route
      // at all". A prediction is not a mechanism, and the milestone that
      // inherits it owes an answer.
      //
      // IT IS TRUE, AND IT RESTS ON TWO SEPARATE THINGS. Session-guarded
      // ceremonies are unreachable because `findLiveByAccessHash` resolves a
      // session only for an 'active' or 'deceased_pending' account. The
      // UNAUTHENTICATED ones — password reset — hold a code that still names a
      // user id, so a session check protects nothing there; what stops them is
      // the status allowlist riding inside `updatePasswordHash`'s own UPDATE,
      // which is the layer this asserts. Named explicitly because the two
      // guards are at different layers and a test that proved one would look
      // like it had proved both.
      await seedErasable('ceremony@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);

      // The redeem path's write matches zero rows, which is what turns every
      // failure on that route into one uniform `invalid_code` rather than a
      // 500 about a destroyed key.
      await expect(
        db.withTransaction('', (tx) => users.updatePasswordHash(tx, user, 'argon2-whatever')),
      ).resolves.toBe(false);

      // And the request half never resolves the address to begin with.
      expect(
        await users.findByEmailBidx(emailBlindIndex(INDEX_KEY, 'ceremony@example.test')),
      ).toBeNull();

      // POSITIVE CONTROL: the same write succeeds on a live account, so the
      // refusal above is the allowlist firing and not a broken fixture.
      await seedUser();
      await expect(
        db.withTransaction('', (tx) => users.updatePasswordHash(tx, user, 'argon2-whatever')),
      ).resolves.toBe(true);
    });

    it('is SAFE TO RE-RUN: a second sweep shreds nothing and files nothing', async () => {
      const { dekId } = await seedErasable('resume@example.test');
      await service.request(user, session);
      await backdate(GRACE_MS + 1000);
      await service.runDueErasures(NOW);
      const first = (await deks.findById(dekId))?.destroyedAt;
      audited.length = 0;

      // Nothing is claimable — the request is no longer 'pending' — and even a
      // forced replay must not move the timestamp an investigator relies on.
      expect(await service.runDueErasures(NOW)).toBe(0);
      expect((await deks.findById(dekId))?.destroyedAt).toEqual(first);
      expect(audited).toEqual([]);
    });
  });
});
