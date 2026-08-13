import { log } from './logger';
import type { DetectorDb } from './decrypt-rate-detector';

/**
 * The detector's own Postgres session, made as advisory as the detector
 * claims to be. Three M18-review findings live here, and each is a property
 * of this class rather than a note in a docstring:
 *
 * 1. NO UNHANDLED 'error' EVENT. node-postgres Clients emit 'error' on
 *    connection-level death (failover, an idle-session reaper,
 *    pg_terminate_backend). With no listener, Node's default turns that into
 *    an uncaught exception and the whole audit process dies — so the ADVISORY
 *    detector's mostly-idle connection would kill INGEST, the paging signal,
 *    bypassing the fatal path's structured log entirely. Reproduced against
 *    a real cluster during the review (57P01 → uncaught → exit).
 *
 * 2. RECOVERY. A pg Client never reconnects: after a connection-level death
 *    every later query rejects with "Client has encountered a connection
 *    error and is not queryable", forever. A listener alone would therefore
 *    trade a crash for silent, permanent deafness — one warn line a minute
 *    and no alerting for the process lifetime. A dead client is DISCARDED and
 *    the next tick builds a fresh one.
 *
 * 3. BOOT IS NOT LOAD-BEARING. The connection is opened lazily on first use,
 *    so a detector that cannot reach Postgres degrades alerting instead of
 *    crash-looping the service that ingests the audit trail.
 *
 * The client is also built with a QUERY TIMEOUT, which is what keeps the
 * detector's re-entrancy guard honest: a black-holed socket (a dropped flow
 * with no RST) otherwise leaves a query pending for the OS keepalive interval
 * — hours — during which every tick returns at the guard, nothing faults, and
 * nothing is logged. That is the M8 dead-consumer shape, and the timeout is
 * what converts it into an ordinary logged fault the next tick retries.
 */

/** The slice of pg.Client this needs; the real Client satisfies it.
 * `connect` is typed loosely because pg's own overloads resolve to
 * `Promise<Client>` here — this class only ever awaits it. */
export interface DetectorClient {
  connect(): Promise<unknown>;
  query(
    text: string,
    values: unknown[],
  ): Promise<{
    rows: Array<{
      prefix: string | null;
      actor_type: string;
      actor_id: string | null;
      n: number;
    }>;
  }>;
  end(): Promise<void>;
  on(event: 'error', listener: (err: Error) => void): unknown;
}

export class DetectorConnection implements DetectorDb {
  #client: DetectorClient | null = null;
  #connecting: Promise<DetectorClient> | null = null;

  constructor(private readonly create: () => DetectorClient) {}

  async query(
    text: string,
    values: unknown[],
  ): Promise<{
    rows: Array<{
      prefix: string | null;
      actor_type: string;
      actor_id: string | null;
      n: number;
    }>;
  }> {
    const client = await this.#ensure();
    try {
      return await client.query(text, values);
    } catch (err) {
      // Any query failure discards the session. A timeout leaves the server
      // still processing the old statement on that connection, and a
      // connection-level failure makes it permanently unqueryable — either
      // way reuse is what turns one bad tick into permanent deafness. A
      // wasted reconnect after a merely transient error is the cheap
      // direction of this trade.
      this.#discard(client);
      throw err;
    }
  }

  /** Release the session (shutdown). Safe to call when never connected. */
  async end(): Promise<void> {
    const client = this.#client;
    this.#client = null;
    this.#connecting = null;
    if (client) {
      await client.end().catch(() => {
        // Already going away; a close error must not mask the shutdown.
      });
    }
  }

  async #ensure(): Promise<DetectorClient> {
    if (this.#client) {
      return this.#client;
    }
    // Shared in-flight connect, cleared on rejection — the M8 PR2 rule: a
    // cached REJECTED promise poisons every later attempt.
    this.#connecting ??= (async (): Promise<DetectorClient> => {
      const client = this.create();
      client.on('error', (err: Error) => {
        // The listener's existence is the control; discarding is the
        // recovery. Never rethrow — that is the crash this exists to stop.
        log({
          level: 'warn',
          msg: 'decrypt_rate_connection_lost',
          error: `${err.name}: ${err.message}`,
        });
        this.#discard(client);
      });
      await client.connect();
      this.#client = client;
      this.#connecting = null;
      return client;
    })().catch((err: unknown) => {
      this.#connecting = null;
      throw err;
    });
    return this.#connecting;
  }

  /** Drop the session if it is still the current one (a late 'error' from an
   * already-replaced client must not discard its successor). */
  #discard(client: DetectorClient): void {
    if (this.#client !== client) {
      return;
    }
    this.#client = null;
    void client.end().catch(() => {
      // Best effort: this socket is already gone.
    });
  }
}
