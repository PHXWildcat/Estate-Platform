import { Injectable } from '@nestjs/common';
import type { Queryable } from './db';

/**
 * The append-only write model (`asset_events`). Methods take an explicit
 * Queryable so appends run inside the command transaction while reads can use
 * the pool. There is deliberately no update/delete surface — the table
 * REVOKEs both.
 */

export interface LedgerRow {
  seq: string; // BIGINT arrives as string from pg
  event_id: string;
  asset_id: string;
  user_id: string;
  event_type: string;
  payload_ct: Buffer;
  actor_id: string;
  actor_role: string | null;
  occurred_at: Date;
}

const COLUMNS =
  'seq, event_id, asset_id, user_id, event_type, payload_ct, actor_id, actor_role, occurred_at';

export interface AppendInput {
  eventId: string;
  assetId: string;
  userId: string;
  eventType: string;
  payloadCt: Buffer;
  actorId: string;
  actorRole?: string | null;
}

@Injectable()
export class LedgerRepo {
  /** Append one event; seq and occurred_at are assigned by the database. */
  async append(q: Queryable, input: AppendInput): Promise<{ seq: string; occurredAt: Date }> {
    const rows = await q.query<{ seq: string; occurred_at: Date }>(
      `INSERT INTO asset_events (event_id, asset_id, user_id, event_type, payload_ct, actor_id, actor_role)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING seq, occurred_at`,
      [
        input.eventId,
        input.assetId,
        input.userId,
        input.eventType,
        input.payloadCt,
        input.actorId,
        input.actorRole ?? null,
      ],
    );
    const row = rows[0]!;
    return { seq: row.seq, occurredAt: row.occurred_at };
  }

  /**
   * Idempotency lookup: the CALLER'S OWN original append for a retried client
   * eventId. Scoped by `user_id`, which since migration `002` is half of the
   * uniqueness — an unscoped lookup could return an arbitrary one of the users
   * now permitted to share an event id, so a caller's own retry could be
   * answered from a stranger's row (and, finding a mismatch, re-append).
   *
   * The owner predicate rides the statement rather than sitting in a check
   * above it: the M13 `contact_in_use` lesson, where a check-then-act read left
   * a window between deciding and acting.
   */
  async findOwnByEventId(q: Queryable, userId: string, eventId: string): Promise<LedgerRow | null> {
    const rows = await q.query<LedgerRow>(
      `SELECT ${COLUMNS} FROM asset_events WHERE user_id = $1 AND event_id = $2`,
      [userId, eventId],
    );
    return rows[0] ?? null;
  }

  /**
   * Latest seq per asset for one OWNER, in one round trip and WITHOUT being
   * given the ids — which is what lets a list read its versions BEFORE its
   * rows. Pairing rows read first with versions read second lets a version
   * describe a newer state than the row beside it, and an `If-Match` carrying
   * one passes; see `AssetsService.getAsset` for why the order is the control.
   */
  async latestSeqByUser(q: Queryable, userId: string): Promise<Map<string, string>> {
    const rows = await q.query<{ asset_id: string; seq: string }>(
      `SELECT asset_id, MAX(seq) AS seq FROM asset_events WHERE user_id = $1 GROUP BY asset_id`,
      [userId],
    );
    return new Map(rows.map((r) => [r.asset_id, r.seq]));
  }

  /** The asset's latest seq — the optimistic-concurrency version token. */
  async latestSeq(q: Queryable, assetId: string): Promise<string | null> {
    const rows = await q.query<{ seq: string }>(
      `SELECT seq FROM asset_events WHERE asset_id = $1 ORDER BY seq DESC LIMIT 1`,
      [assetId],
    );
    return rows[0]?.seq ?? null;
  }

  /** Full history of one asset, oldest first. */
  async listByAsset(q: Queryable, assetId: string): Promise<LedgerRow[]> {
    return q.query<LedgerRow>(
      `SELECT ${COLUMNS} FROM asset_events WHERE asset_id = $1 ORDER BY seq ASC`,
      [assetId],
    );
  }

  /**
   * All of one owner's events, optionally bounded in time (as-of replay),
   * grouped per asset in fold order.
   */
  async listByUser(q: Queryable, userId: string, upTo?: Date): Promise<LedgerRow[]> {
    if (upTo) {
      return q.query<LedgerRow>(
        `SELECT ${COLUMNS} FROM asset_events
          WHERE user_id = $1 AND occurred_at <= $2
          ORDER BY asset_id ASC, seq ASC`,
        [userId, upTo],
      );
    }
    return q.query<LedgerRow>(
      `SELECT ${COLUMNS} FROM asset_events WHERE user_id = $1 ORDER BY asset_id ASC, seq ASC`,
      [userId],
    );
  }

  /** Every event in fold order — the rebuild's input. */
  async listAll(q: Queryable): Promise<LedgerRow[]> {
    return q.query<LedgerRow>(`SELECT ${COLUMNS} FROM asset_events ORDER BY asset_id ASC, seq ASC`);
  }
}
