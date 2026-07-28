import { Injectable } from '@nestjs/common';
import { DekConflictError, type DekRecord, type DekRepository } from '@estate/crypto';
import { Db, isUniqueViolation } from './db';

interface DekRow {
  dek_id: string;
  user_id: string;
  kek_alias: string;
  wrapped_key: Buffer;
  created_at: Date;
  destroyed_at: Date | null;
}

/**
 * DekRepository backed by THIS service's `settlement_deks` table — deliberately
 * separate from profile's `deks` on the same core cluster, because these DEKs
 * are wrapped under the dedicated 'settlement/kek' alias (docs/03 §5.3: the
 * KMS grant, not the database, is the chokepoint). Profile's grant can never
 * unwrap a distribution amount, and vice versa.
 *
 * Keyed by the DECEDENT, so crypto-shredding an estate's key retires every
 * amount recorded for it in one operation.
 *
 * `ux_settlement_deks_user_active` guarantees at most one active DEK per user;
 * a lost first-write race surfaces as a unique violation, translated here to
 * DekConflictError so @estate/crypto adopts the winner instead of minting a
 * duplicate.
 */
@Injectable()
export class PgSettlementDekRepository implements DekRepository {
  constructor(private readonly db: Db) {}

  async findActiveByUser(userId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM settlement_deks
        WHERE user_id = $1 AND destroyed_at IS NULL
        -- Stable tiebreak: created_at is a client Date (ms), so resolve ties
        -- deterministically by dek_id (consistency with the other clusters).
        ORDER BY created_at DESC, dek_id DESC
        LIMIT 1`,
      [userId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async findById(dekId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM settlement_deks
        WHERE dek_id = $1`,
      [dekId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async insert(record: DekRecord): Promise<void> {
    try {
      await this.db.query(
        `INSERT INTO settlement_deks (dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          record.dekId,
          record.userId,
          record.kekAlias,
          record.wrappedKey,
          record.createdAt,
          record.destroyedAt,
        ],
      );
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new DekConflictError();
      }
      throw err;
    }
  }

  async markDestroyed(dekId: string, at: Date): Promise<void> {
    await this.db.query(`UPDATE settlement_deks SET destroyed_at = $2 WHERE dek_id = $1`, [
      dekId,
      at,
    ]);
  }
}

function toRecord(row: DekRow): DekRecord {
  return {
    dekId: row.dek_id,
    userId: row.user_id,
    kekAlias: row.kek_alias,
    wrappedKey: row.wrapped_key,
    createdAt: row.created_at,
    destroyedAt: row.destroyed_at,
  };
}
