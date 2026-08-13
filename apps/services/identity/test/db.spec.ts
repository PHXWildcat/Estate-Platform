/**
 * `Db.withTransaction` — the CONTROL FLOW, without a database (M17 PR2).
 *
 * `password-change.int.spec.ts` proves the transaction does what a transaction
 * does against real Postgres. What it cannot isolate is the failure path: a
 * ROLLBACK that never runs, a connection never released, or an original error
 * masked by a failing rollback are all invisible when every case commits. Those
 * are ordinary control flow rather than SQL semantics, so they belong in a unit
 * test — and this is the layer that runs when CI evaluates identity's
 * database-free coverage gate.
 */
import { Db } from '../src/db';

interface FakeClient {
  query: jest.Mock;
  release: jest.Mock;
}

/** A pg-shaped double: the pool hands out one client and records what it saw. */
function fakeDb(clientBehaviour?: (sql: string) => Promise<unknown>): {
  db: Db;
  client: FakeClient;
  statements: () => string[];
} {
  const seen: string[] = [];
  const client: FakeClient = {
    query: jest.fn(async (sql: string) => {
      seen.push(sql);
      const result = await (clientBehaviour?.(sql) ?? Promise.resolve(undefined));
      return result ?? { rows: [] };
    }),
    release: jest.fn(),
  };
  const db = new Db({});
  // The pool is private and constructing a real one would open sockets; this
  // replaces it with the smallest thing the method actually uses.
  (db as unknown as { pool: { connect: () => Promise<FakeClient> } }).pool = {
    connect: (): Promise<FakeClient> => Promise.resolve(client),
  };
  return { db, client, statements: () => seen };
}

describe('Db.withTransaction', () => {
  it('BEGINs, sets the actor transaction-locally, and COMMITs', async () => {
    const { db, client, statements } = fakeDb();

    const result = await db.withTransaction('actor-1', async (tx) => {
      await tx.query('SELECT 1');
      return 'done';
    });

    expect(result).toBe('done');
    expect(statements()[0]).toBe('BEGIN');
    // `true` is the transaction-local flag: without it the GUC would leak to
    // the next caller that borrowed this pooled connection, and the version
    // trigger would attribute somebody else's write to this actor.
    expect(statements()[1]).toContain("set_config('app.actor_id', $1, true)");
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('set_config'), ['actor-1']);
    expect(statements()).toContain('COMMIT');
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  it('ROLLS BACK when the callback throws, and rethrows the original error', async () => {
    const { db, client, statements } = fakeDb();
    const boom = new Error('the callback failed');

    await expect(
      db.withTransaction('actor-1', () => {
        throw boom;
      }),
    ).rejects.toBe(boom);

    expect(statements()).toContain('ROLLBACK');
    expect(statements()).not.toContain('COMMIT');
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  it('does not let a FAILING ROLLBACK mask the error that caused it', async () => {
    // A broken connection fails the rollback too. The original error is the one
    // that explains what happened; surfacing the rollback's instead would send
    // an investigator to the wrong place entirely.
    const boom = new Error('the callback failed');
    const { db, client } = fakeDb((sql) =>
      sql === 'ROLLBACK' ? Promise.reject(new Error('connection is dead')) : Promise.resolve(),
    );

    await expect(
      db.withTransaction('actor-1', () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    expect(client.release).toHaveBeenCalledTimes(1);
  });

  it('RELEASES the connection on every path', async () => {
    // A pooled connection never returned is a leak that presents as the service
    // hanging under load rather than as an error, which is the hardest kind to
    // attribute later.
    const { db, client } = fakeDb();
    await db.withTransaction('a', () => Promise.resolve(undefined));
    await db.withTransaction('a', () => Promise.resolve(undefined)).catch(() => undefined);
    await db.withTransaction('a', () => Promise.reject(new Error('x'))).catch(() => undefined);
    expect(client.release).toHaveBeenCalledTimes(3);
  });

  it('the transaction surface returns ROWS, like the pooled one', async () => {
    // Repositories are written against `Queryable` and must not be able to tell
    // which they are running under — that is the whole reason the interface
    // exists. A tx that returned the pg result object would break every repo
    // the moment one was passed a transaction.
    const { db } = fakeDb(() => Promise.resolve({ rows: [{ id: 'r-1' }] }));
    const rows = await db.withTransaction('a', (tx) => tx.query('SELECT 1'));
    expect(rows).toEqual([{ id: 'r-1' }]);
  });
});
