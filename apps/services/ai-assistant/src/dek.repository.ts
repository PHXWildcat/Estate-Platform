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
 * DekRepository backed by THIS service's `assistant_deks` table, keyed by the
 * OWNER user — deliberately separate from profile's `deks`, settlement's
 * `settlement_deks` and notifications' `notification_deks` on the same core
 * cluster, because these DEKs are wrapped under the dedicated
 * 'ai-assistant/kek' alias (docs/03 §5.3: the KMS grant, not the database, is
 * the chokepoint). A co-tenant with SELECT on this table still holds no grant
 * that can unwrap what it reads.
 *
 * Keying by the owner means crypto-shredding a user's key erases every
 * conversation this service holds for them in one operation — including the
 * estate content quoted inside those turns, which is the whole reason the
 * transcript is ciphertext rather than a convenience log.
 *
 * `ux_assistant_deks_user_active` guarantees at most one active DEK per user;
 * a lost first-write race surfaces as a unique violation, translated to
 * DekConflictError so @estate/crypto adopts the winner instead of minting a
 * duplicate.
 */
@Injectable()
export class PgAssistantDekRepository implements DekRepository {
  constructor(private readonly db: Db) {}

  async findActiveByUser(userId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM assistant_deks
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
         FROM assistant_deks
        WHERE dek_id = $1`,
      [dekId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async insert(record: DekRecord): Promise<void> {
    try {
      await this.db.query(
        `INSERT INTO assistant_deks (dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at)
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
    await this.db.query(`UPDATE assistant_deks SET destroyed_at = $2 WHERE dek_id = $1`, [
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
