import { Injectable } from '@nestjs/common';
import { DekConflictError, type DekRecord, type DekRepository } from '@estate/crypto';
import { Db, isUniqueViolation } from './db';

interface DekRow {
  dek_id: string;
  document_id: string;
  kek_alias: string;
  wrapped_key: Buffer;
  created_at: Date;
  destroyed_at: Date | null;
}

/**
 * DekRepository backed by the documents cluster's `document_deks` table.
 *
 * THE KEY SUBJECT HERE IS THE DOCUMENT, NOT THE USER (docs/01 §4: documents
 * get per-object DEKs). @estate/crypto's DekRepository interface names its
 * subject `userId`; in this repository that value is a document id — mapped
 * to/from the `document_id` column below. Crypto-shredding one document's DEK
 * erases exactly that document's content, every version, nothing else.
 *
 * `ux_document_deks_document_active` guarantees at most one active DEK per
 * document; a lost first-write race surfaces as a unique violation,
 * translated here to DekConflictError so @estate/crypto adopts the winner's
 * DEK instead of minting a duplicate.
 */
@Injectable()
export class PgDocumentDekRepository implements DekRepository {
  constructor(private readonly db: Db) {}

  async findActiveByUser(documentId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, document_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM document_deks
        WHERE document_id = $1 AND destroyed_at IS NULL
        -- Stable tiebreak: created_at is a client Date (ms), so resolve ties
        -- deterministically by dek_id (consistency with the other clusters).
        ORDER BY created_at DESC, dek_id DESC
        LIMIT 1`,
      [documentId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async findById(dekId: string): Promise<DekRecord | null> {
    const rows = await this.db.query<DekRow>(
      `SELECT dek_id, document_id, kek_alias, wrapped_key, created_at, destroyed_at
         FROM document_deks
        WHERE dek_id = $1`,
      [dekId],
    );
    return rows[0] ? toRecord(rows[0]) : null;
  }

  async insert(record: DekRecord): Promise<void> {
    try {
      await this.db.query(
        `INSERT INTO document_deks (dek_id, document_id, kek_alias, wrapped_key, created_at, destroyed_at)
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
    await this.db.query(`UPDATE document_deks SET destroyed_at = $2 WHERE dek_id = $1`, [
      dekId,
      at,
    ]);
  }
}

function toRecord(row: DekRow): DekRecord {
  return {
    dekId: row.dek_id,
    // DekRecord.userId is the generic key subject; here it is the document id.
    userId: row.document_id,
    kekAlias: row.kek_alias,
    wrappedKey: row.wrapped_key,
    createdAt: row.created_at,
    destroyedAt: row.destroyed_at,
  };
}
