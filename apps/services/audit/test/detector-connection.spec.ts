import { DetectorConnection, type DetectorClient } from '../src/detector-connection';

/**
 * The three M18-review properties of the detector's session, each pinned by
 * the failure it prevents rather than by its implementation:
 *   1. a connection-level 'error' event is ABSORBED (unhandled, it crashes
 *      the audit process — the advisory detector killing ingest);
 *   2. a dead session is REPLACED on the next use (a pg Client never
 *      reconnects, so a listener alone trades a crash for permanent silence);
 *   3. connecting is LAZY (an advisory component must not make boot
 *      load-bearing).
 */

interface FakeOptions {
  failConnect?: boolean;
  failQuery?: boolean;
}

class FakeClient implements DetectorClient {
  connects = 0;
  queries = 0;
  ended = 0;
  #handlers: Array<(err: Error) => void> = [];

  constructor(private readonly options: FakeOptions = {}) {}

  connect(): Promise<unknown> {
    this.connects += 1;
    return this.options.failConnect
      ? Promise.reject(new Error('ECONNREFUSED'))
      : Promise.resolve(undefined);
  }

  query(): Promise<{
    rows: Array<{ prefix: string | null; actor_type: string; actor_id: string | null; n: number }>;
  }> {
    this.queries += 1;
    return this.options.failQuery
      ? Promise.reject(new Error('Client has encountered a connection error'))
      : Promise.resolve({ rows: [] });
  }

  end(): Promise<void> {
    this.ended += 1;
    return Promise.resolve();
  }

  on(_event: 'error', listener: (err: Error) => void): unknown {
    this.#handlers.push(listener);
    return this;
  }

  /** Drive what pg does on connection-level death. */
  emitError(err = new Error('terminating connection due to administrator command')): void {
    for (const handler of this.#handlers) {
      handler(err);
    }
  }
}

describe('DetectorConnection', () => {
  it('does not connect until the first query (boot is never load-bearing)', async () => {
    const clients: FakeClient[] = [];
    const connection = new DetectorConnection(() => {
      const client = new FakeClient();
      clients.push(client);
      return client;
    });
    expect(clients).toHaveLength(0);
    await connection.query('select 1', []);
    expect(clients).toHaveLength(1);
    expect(clients[0]?.connects).toBe(1);
  });

  it('a failed connect rejects the query and is retried, never cached as a poisoned promise', async () => {
    const clients: FakeClient[] = [];
    let failing = true;
    const connection = new DetectorConnection(() => {
      const client = new FakeClient({ failConnect: failing });
      clients.push(client);
      return client;
    });
    await expect(connection.query('select 1', [])).rejects.toThrow('ECONNREFUSED');
    failing = false;
    // The M8 PR2 rule: a rejected in-flight connect must not be reused.
    await expect(connection.query('select 1', [])).resolves.toEqual({ rows: [] });
    expect(clients).toHaveLength(2);
  });

  it("ABSORBS a connection-level 'error' — the event that otherwise crashes the audit process", () => {
    const clients: FakeClient[] = [];
    const connection = new DetectorConnection(() => {
      const client = new FakeClient();
      clients.push(client);
      return client;
    });
    return connection.query('select 1', []).then(() => {
      // A listener must exist: with none, node's EventEmitter default turns
      // this into an uncaught exception (reproduced against a real cluster
      // during the review — 57P01, process exit).
      expect(() => clients[0]?.emitError()).not.toThrow();
    });
  });

  it('REPLACES a session that died, so alerting recovers instead of going permanently silent', async () => {
    const clients: FakeClient[] = [];
    const connection = new DetectorConnection(() => {
      const client = new FakeClient();
      clients.push(client);
      return client;
    });
    await connection.query('select 1', []);
    clients[0]?.emitError(); // the session is now unusable forever, in pg terms
    await connection.query('select 1', []);
    expect(clients).toHaveLength(2);
    expect(clients[1]?.queries).toBe(1);
    expect(clients[0]?.ended).toBe(1);
  });

  it('discards a session whose query failed (a timed-out socket must not be reused)', async () => {
    const clients: FakeClient[] = [];
    let failing = true;
    const connection = new DetectorConnection(() => {
      const client = new FakeClient({ failQuery: failing });
      clients.push(client);
      return client;
    });
    await expect(connection.query('select 1', [])).rejects.toThrow();
    failing = false;
    await expect(connection.query('select 1', [])).resolves.toEqual({ rows: [] });
    expect(clients).toHaveLength(2);
  });

  it('a late error from a REPLACED client never discards its successor', async () => {
    const clients: FakeClient[] = [];
    const connection = new DetectorConnection(() => {
      const client = new FakeClient();
      clients.push(client);
      return client;
    });
    await connection.query('select 1', []);
    clients[0]?.emitError();
    await connection.query('select 1', []); // builds client #2
    clients[0]?.emitError(); // the dead one coughs again
    await connection.query('select 1', []);
    expect(clients).toHaveLength(2); // #2 survived
    expect(clients[1]?.queries).toBe(2);
  });

  it('end() releases a live session and is safe when none was ever opened', async () => {
    const clients: FakeClient[] = [];
    const connection = new DetectorConnection(() => {
      const client = new FakeClient();
      clients.push(client);
      return client;
    });
    await expect(connection.end()).resolves.toBeUndefined(); // never connected
    await connection.query('select 1', []);
    await connection.end();
    expect(clients[0]?.ended).toBe(1);
  });
});
