/**
 * RESET RETIRES EVERY ITEM A USER HAS, IN ONE STATEMENT (M27 PR1b).
 *
 * WHAT WENT WRONG, BECAUSE THE FIX IS ONLY LEGIBLE BESIDE IT. `reset` first
 * soft-deleted the LIVE rows (`WHERE deleted_at IS NULL`) and then relabelled
 * the RETIRED ones (`WHERE deleted_at IS NOT NULL`). Two predicates that look
 * exhaustive — every row is one or the other — and are only exhaustive if
 * nothing moves between the statements. PR1b's own `undeleteItem` is a verb
 * that moves a row from the second set to the first, so a row undeleted in that
 * gap is matched by NEITHER and survives the reset live, holding a blob the
 * keyset replaced in the same transaction has just made undecryptable.
 *
 * That is the precise failure migration 004's discriminator exists to prevent,
 * arriving from the other direction: not a dead row that says restorable, but a
 * dead row that says LIVE.
 *
 * WHY THIS NEEDS REAL POSTGRES AND TWO CONNECTIONS. The defect is a property of
 * concurrent STATEMENTS. A fake repo cannot have a race, and a single-connection
 * test cannot either — a suite that drove this through the service on one
 * connection would have been green against the broken version too. So the last
 * case here interleaves two real transactions and makes the undelete commit at
 * exactly the moment that used to be fatal.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { Migrator } from '@estate/db';
import { Client, type QueryResultRow } from 'pg';
import { ItemsRepo } from '../src/items.repo';
import type { Queryable } from '../src/db';

const describeIfPg = process.env['PG_TEST_URL'] ? describe : describe.skip;

describeIfPg('reset retirement is atomic (M27 PR1b)', () => {
  const pgUrl = process.env['PG_TEST_URL'] as string;
  const schema = `vaultretire_test_${Date.now()}`;
  const repo = new ItemsRepo();
  let admin: Client;

  /**
   * `Queryable` answers ROWS; a raw pg Client answers a QueryResult. Passing the
   * client straight in reads as if it worked and fails inside the repo, which
   * is a broken observer rather than a finding — it cost a debugging round here.
   */
  const asQueryable = (client: Client): Queryable => ({
    query: async <T extends QueryResultRow>(text: string, values?: unknown[]): Promise<T[]> =>
      (await client.query<T>(text, values)).rows,
  });

  const connect = async (): Promise<Client> => {
    const c = new Client({ connectionString: pgUrl, options: `-c search_path=${schema},public` });
    await c.connect();
    return c;
  };

  /** A row in a named state, so each case states its own fixture. */
  const insert = async (
    userId: string,
    state: { deletedAt: Date | null; reason: string | null },
  ): Promise<string> => {
    const id = randomUUID();
    await admin.query(
      `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version, deleted_at, deleted_reason)
       VALUES ($1, $2, 'password', '\\x00'::bytea, 1, $3, $4)`,
      [id, userId, state.deletedAt, state.reason],
    );
    return id;
  };

  const stateOf = async (id: string): Promise<{ deleted_at: Date | null; reason: string | null }> =>
    (
      await admin.query<{ deleted_at: Date | null; reason: string | null }>(
        `SELECT deleted_at, deleted_reason AS reason FROM vault_items WHERE id = $1`,
        [id],
      )
    ).rows[0]!;

  beforeAll(async () => {
    admin = new Client({ connectionString: pgUrl });
    await admin.connect();
    await admin.query(`CREATE SCHEMA ${schema}`);
    const m = new Client({ connectionString: pgUrl, options: `-c search_path=${schema}` });
    await m.connect();
    try {
      await new Migrator(m, join(__dirname, '..', 'migrations')).migrate();
    } finally {
      await m.end();
    }
    await admin.query(`SET search_path TO ${schema}, public`);
  }, 60000);

  afterAll(async () => {
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.end();
  });

  it('issues exactly ONE statement, which is the whole of why the gap is gone', async () => {
    // Anchored on what the runtime sends rather than on the source text: a
    // second statement reappearing here — however it were spelled — is the
    // defect returning, and no assertion about predicates would catch it.
    const sent: string[] = [];
    const recorder: Queryable = {
      query: (text: string) => {
        sent.push(text);
        return Promise.resolve([]);
      },
    };
    await repo.retireAllForUser(recorder, randomUUID(), new Date(), 'vault_reset');
    expect(sent).toHaveLength(1);
    // ANTI-VACUITY: one statement that does not retire anything would also be
    // length 1. It has to be the write.
    expect(sent[0]).toContain('UPDATE vault_items');
    expect(sent[0]).toContain('FOR UPDATE');
  });

  it('covers the live rows AND the already-retired ones, counting them apart', async () => {
    const owner = randomUUID();
    const at = new Date('2026-08-01T00:00:00.000Z');
    const earlier = new Date('2026-07-01T00:00:00.000Z');

    const live = await insert(owner, { deletedAt: null, reason: null });
    const userDeleted = await insert(owner, { deletedAt: earlier, reason: 'user_delete' });
    const alreadyReset = await insert(owner, { deletedAt: earlier, reason: 'vault_reset' });

    const result = await repo.retireAllForUser(asQueryable(admin), owner, at, 'vault_reset');

    // The two populations are counted under their own names — they mean
    // different things to anyone reading the audit trail, and one of them was
    // openable a moment ago.
    expect(result).toEqual({ destroyed: 1, relabelled: 1 });

    // Every row now says the same thing, whatever it said before.
    expect(await stateOf(live)).toEqual({ deleted_at: at, reason: 'vault_reset' });
    // `deleted_at` PRESERVED: when the owner retired it stays true, and only
    // its decryptability changed here.
    expect(await stateOf(userDeleted)).toEqual({ deleted_at: earlier, reason: 'vault_reset' });
    // Already correct, so not touched and NOT counted — a relabel count that
    // included it would overstate what this reset changed.
    expect(await stateOf(alreadyReset)).toEqual({ deleted_at: earlier, reason: 'vault_reset' });
  });

  it('leaves another user’s rows alone', async () => {
    const mine = randomUUID();
    const theirs = randomUUID();
    const myRow = await insert(mine, { deletedAt: null, reason: null });
    const theirRow = await insert(theirs, { deletedAt: null, reason: null });

    const result = await repo.retireAllForUser(asQueryable(admin), mine, new Date(), 'vault_reset');
    expect(result.destroyed).toBe(1);
    expect((await stateOf(myRow)).reason).toBe('vault_reset');
    expect(await stateOf(theirRow)).toEqual({ deleted_at: null, reason: null });
  });

  it('catches a row an UNDELETE commits into the middle of the reset', async () => {
    // THE RACE ITSELF, run rather than reasoned about.
    const owner = randomUUID();
    const at = new Date('2026-08-02T00:00:00.000Z');
    const contested = await insert(owner, {
      deletedAt: new Date('2026-07-02T00:00:00.000Z'),
      reason: 'user_delete',
    });

    const undeleter = await connect();
    const resetter = await connect();
    try {
      // The undelete starts and holds its lock WITHOUT committing.
      await undeleter.query('BEGIN');
      await undeleter.query(
        `UPDATE vault_items SET deleted_at = NULL, deleted_reason = NULL WHERE id = $1`,
        [contested],
      );

      // The reset now runs into that lock and waits. Under the old two-statement
      // shape it would already have passed the row over (it was retired when
      // the first statement ran) and would pass it over again (it is live by the
      // time the second one does).
      await resetter.query('BEGIN');
      const pending = repo.retireAllForUser(asQueryable(resetter), owner, at, 'vault_reset');

      // Let it actually block before releasing, or this proves nothing about
      // ordering. `pg_stat_activity` is the observation, not a timer.
      await expect(
        (async () => {
          for (let i = 0; i < 100; i += 1) {
            const { rows } = await admin.query<{ n: string }>(
              `SELECT count(*)::text AS n FROM pg_stat_activity
                WHERE wait_event_type = 'Lock' AND query ILIKE '%UPDATE vault_items%'`,
            );
            if (Number(rows[0]!.n) > 0) return 'blocked';
            await new Promise((r) => setTimeout(r, 50));
          }
          return 'never blocked';
        })(),
      ).resolves.toBe('blocked');

      await undeleter.query('COMMIT');
      const result = await pending;
      await resetter.query('COMMIT');

      // It re-read the row at the version the undelete committed — live, reason
      // NULL — and retired it. Counted as DESTROYED rather than relabelled,
      // because by the time the statement saw it, that is what it was.
      expect(result).toEqual({ destroyed: 1, relabelled: 0 });
      expect(await stateOf(contested)).toEqual({ deleted_at: at, reason: 'vault_reset' });
    } finally {
      await undeleter.query('ROLLBACK').catch(() => undefined);
      await resetter.query('ROLLBACK').catch(() => undefined);
      await undeleter.end();
      await resetter.end();
    }
  }, 30000);
});
