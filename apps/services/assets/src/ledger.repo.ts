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

  /** Idempotency lookup: the original append for a retried client eventId. */
  async findByEventId(q: Queryable, eventId: string): Promise<LedgerRow | null> {
    const rows = await q.query<LedgerRow>(
      `SELECT ${COLUMNS} FROM asset_events WHERE event_id = $1`,
      [eventId],
    );
    return rows[0] ?? null;
  }

  /** The asset's latest seq — the optimistic-concurrency version token. */
  async latestSeq(q: Queryable, assetId: string): Promise<string | null> {
    const rows = await q.query<{ seq: string }>(
      `SELECT seq FROM asset_events WHERE asset_id = $1 ORDER BY seq DESC LIMIT 1`,
      [assetId],
    );
    return rows[0]?.seq ?? null;
  }

  /** Latest seq per asset in one round-trip (list responses). */
  async latestSeqByAssets(q: Queryable, assetIds: readonly string[]): Promise<Map<string, string>> {
    if (assetIds.length === 0) {
      return new Map();
    }
    const rows = await q.query<{ asset_id: string; seq: string }>(
      `SELECT asset_id, MAX(seq) AS seq FROM asset_events
        WHERE asset_id = ANY($1::uuid[])
        GROUP BY asset_id`,
      [assetIds],
    );
    return new Map(rows.map((r) => [r.asset_id, r.seq]));
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
