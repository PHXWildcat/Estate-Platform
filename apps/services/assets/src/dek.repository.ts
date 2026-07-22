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
 * DekRepository backed by the financial cluster's `deks` table. Unlike the
 * older clusters, `ux_deks_user_active` guarantees at most one active DEK
 * per user at the database; a lost first-write race surfaces as a unique
 * violation, translated here to DekConflictError so @estate/crypto adopts
 * the winner's DEK instead of minting a duplicate.
 */
@Injectable()
export class PgDekRepository implements DekRepository {
  constructor(private readonly db: Db) {}

  async findActiveByUser(userId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM deks
        WHERE user_id = $1 AND destroyed_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async findById(dekId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM deks
        WHERE dek_id = $1`,
      [dekId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async insert(record: DekRecord): Promise<void> {
    try {
      await this.db.query(
        `INSERT INTO deks (dek_id, user_id, kek_alias, wrapped_key, created_at, destroyed_at)
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
    await this.db.query(`UPDATE deks SET destroyed_at = $2 WHERE dek_id = $1`, [dekId, at]);
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
