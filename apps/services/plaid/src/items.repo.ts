import { Injectable } from '@nestjs/common';
import type { PlaidItemStatus } from '@estate/contracts';
import { Db, type Queryable } from './db';

export interface PlaidItemRow {
  id: string;
  user_id: string;
  access_token_ct: Buffer;
  institution_id: string;
  institution_name: string | null;
  sync_cursor: string | null;
  status: PlaidItemStatus;
  dek_id: string;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, user_id, access_token_ct, institution_id, institution_name,
                 sync_cursor, status, dek_id, created_at, updated_at`;

/** plaid_items persistence. Live rows only — soft delete is the only delete. */
@Injectable()
export class ItemsRepo {
  constructor(private readonly db: Db) {}

  async insert(input: {
    id: string;
    userId: string;
    accessTokenCt: Buffer;
    institutionId: string;
    institutionName: string | null;
    itemIdCt: Buffer;
    itemBidx: Buffer;
    dekId: string;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO plaid_items
         (id, user_id, access_token_ct, institution_id, institution_name, item_id_ct, item_bidx, dek_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        input.id,
        input.userId,
        input.accessTokenCt,
        input.institutionId,
        input.institutionName,
        input.itemIdCt,
        input.itemBidx,
        input.dekId,
      ],
    );
  }

  async findLiveById(id: string): Promise<PlaidItemRow | null> {
    const rows = await this.db.query<PlaidItemRow>(
      `SELECT ${COLUMNS} FROM plaid_items WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  /** Webhook routing: look up by the blind index of Plaid's item_id. */
  async findLiveByItemBidx(itemBidx: Buffer): Promise<PlaidItemRow | null> {
    const rows = await this.db.query<PlaidItemRow>(
      `SELECT ${COLUMNS} FROM plaid_items WHERE item_bidx = $1 AND deleted_at IS NULL`,
      [itemBidx],
    );
    return rows[0] ?? null;
  }

  async listLiveByUser(userId: string): Promise<PlaidItemRow[]> {
    return this.db.query<PlaidItemRow>(
      `SELECT ${COLUMNS} FROM plaid_items
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY created_at`,
      [userId],
    );
  }

  async setStatus(tx: Queryable, id: string, status: PlaidItemStatus): Promise<void> {
    await tx.query(`UPDATE plaid_items SET status = $2 WHERE id = $1 AND deleted_at IS NULL`, [
      id,
      status,
    ]);
  }

  async setCursor(tx: Queryable, id: string, cursor: string | null): Promise<void> {
    await tx.query(`UPDATE plaid_items SET sync_cursor = $2 WHERE id = $1 AND deleted_at IS NULL`, [
      id,
      cursor,
    ]);
  }

  /** Revocation: status flip + soft delete in one statement (never row deletion). */
  async markRevoked(tx: Queryable, id: string, at: Date): Promise<void> {
    await tx.query(
      `UPDATE plaid_items SET status = 'revoked', deleted_at = $2
        WHERE id = $1 AND deleted_at IS NULL`,
      [id, at],
    );
  }
}
