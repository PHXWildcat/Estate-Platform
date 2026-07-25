import { Injectable } from '@nestjs/common';
import type { VaultItemType } from './schemas';
import type { Db, Queryable } from './db';

export interface ItemRow {
  id: string;
  user_id: string;
  item_type: VaultItemType;
  blob_ct: Buffer;
  blob_version: number;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
}

const COLUMNS = `id, user_id, item_type, blob_ct, blob_version, created_at, updated_at, deleted_at`;

/**
 * `vault_items` access. `blob_ct` is client ciphertext end to end: this service
 * stores and returns it without ever being able to look inside, which is why
 * there is no search, no server-side validation of contents, and no filtering
 * by anything but the plaintext item_type.
 */
@Injectable()
export class ItemsRepo {
  /**
   * Keyset-paginated list of live items. Ordered by (updated_at DESC, id) to
   * match the covering index and give a stable cursor.
   */
  async listByUser(
    q: Queryable | Db,
    input: { userId: string; limit: number; cursor?: { updatedAt: Date; id: string } },
  ): Promise<ItemRow[]> {
    if (input.cursor) {
      return q.query<ItemRow>(
        `SELECT ${COLUMNS} FROM vault_items
          WHERE user_id = $1 AND deleted_at IS NULL
            AND (updated_at, id) < ($2, $3)
          ORDER BY updated_at DESC, id DESC
          LIMIT $4`,
        [input.userId, input.cursor.updatedAt, input.cursor.id, input.limit],
      );
    }
    return q.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY updated_at DESC, id DESC
        LIMIT $2`,
      [input.userId, input.limit],
    );
  }

  async findLiveById(q: Queryable | Db, id: string): Promise<ItemRow | null> {
    const rows = await q.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items WHERE id = $1 AND deleted_at IS NULL`,
      [id],
    );
    return rows[0] ?? null;
  }

  async lockLiveById(tx: Queryable, id: string): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
      [id],
    );
    return rows[0] ?? null;
  }

  /**
   * Insert with a CLIENT-supplied id. The id is part of the blob's AAD, so the
   * client has to know it before it can encrypt; a collision is a unique
   * violation, which also makes a retried create idempotent (the M3 client
   * eventId precedent).
   */
  async insert(
    tx: Queryable,
    input: { id: string; userId: string; itemType: VaultItemType; blob: Buffer },
  ): Promise<ItemRow> {
    const rows = await tx.query<ItemRow>(
      `INSERT INTO vault_items (id, user_id, item_type, blob_ct, blob_version)
       VALUES ($1, $2, $3, $4, 1)
       RETURNING ${COLUMNS}`,
      [input.id, input.userId, input.itemType, input.blob],
    );
    return rows[0]!;
  }

  /** Update a locked row to the next blob version. */
  async update(
    tx: Queryable,
    input: { id: string; itemType: VaultItemType; blob: Buffer; nextVersion: number },
  ): Promise<ItemRow> {
    const rows = await tx.query<ItemRow>(
      `UPDATE vault_items
          SET item_type = $2, blob_ct = $3, blob_version = $4
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING ${COLUMNS}`,
      [input.id, input.itemType, input.blob, input.nextVersion],
    );
    return rows[0]!;
  }

  async softDelete(tx: Queryable, id: string, at: Date): Promise<void> {
    await tx.query(`UPDATE vault_items SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL`, [
      id,
      at,
    ]);
  }

  /** Soft-delete every live item for a user; returns how many were affected. */
  async softDeleteAllForUser(tx: Queryable, userId: string, at: Date): Promise<number> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE vault_items SET deleted_at = $2
        WHERE user_id = $1 AND deleted_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    return rows.length;
  }
}
