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
import { Migrator } from '@estate/db';
import { Client } from 'pg';
import { Db } from '../src/db';
import { ErasureRepo } from '../src/erasure.repo';
import { ErasureService } from '../src/erasure.service';
import type { EventsService } from '../src/events.service';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

const NOW = new Date('2026-08-21T12:00:00.000Z');

describeIfPg('account erasure requests (auth cluster)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `erasure_test_${Date.now()}`;
  let admin: Client;
  let db: Db;
  let service: ErasureService;
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
    service = new ErasureService(
      db,
      new ErasureRepo(),
      {
        accountErasureRequested: (userId: string, _s: string | null, requestId: string) => {
          audited.push({ kind: 'requested', userId, requestId });
          return Promise.resolve();
        },
        accountErasureCancelled: (userId: string, _s: string | null, requestId: string) => {
          audited.push({ kind: 'cancelled', userId, requestId });
          return Promise.resolve();
        },
      } as unknown as EventsService,
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
});
