import { Injectable } from '@nestjs/common';
import type { VaultItemType } from './schemas';
import type { Db, Queryable } from './db';

export interface ItemRow {
  id: string;
  user_id: string;
  item_type: VaultItemType;
  blob_ct: Buffer;
  /**
   * The AEAD binding, and ONLY that (migration 005). `itemContentAad` seals a
   * blob against this number, so it travels with its ciphertext and a restore
   * puts BOTH back — which means this value can legitimately go DOWN. It is not
   * a concurrency token; `revision` is.
   */
  blob_version: number;
  /**
   * The concurrency token. Trigger-maintained, strictly increasing, never
   * reused, and unforgeable by any caller: `trg_vault_items_revision` assigns
   * `OLD.revision + 1` on every UPDATE rather than validating one the statement
   * supplied. `If-Match` compares against this.
   */
  revision: number;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
  deleted_reason: DeletedReason | null;
}

/**
 * WHY a soft-deleted item was retired, and therefore whether it can ever be
 * decrypted again (migration 004, docs/03 §6uu).
 *
 * `user_delete` leaves the keyset alone, so the blob is still openable and the
 * row is restorable. `vault_reset` replaces the keyset in the same transaction
 * that retires the row, so the blob is cryptographically dead. `unknown_pre_m27`
 * is the honest backfill for rows retired before the column existed.
 *
 * NOT the restorable set — that is DERIVED from the DDL by
 * `test/restorable-corpus.spec.ts`. This union exists so a caller cannot pass a
 * string the CHECK will refuse at runtime; asking it which rows may be restored
 * would be a second copy of the answer.
 */
export const DELETED_REASONS = ['user_delete', 'vault_reset', 'unknown_pre_m27'] as const;
export type DeletedReason = (typeof DELETED_REASONS)[number];

/**
 * Whether a retirement reason leaves a row a restore surface may offer.
 *
 * A TOTAL MAP, and the totality is the mechanism. The first draft of this was
 * `RESTORABLE_REASONS = ['user_delete']` with the complement computed by
 * `filter`, and its fence asserted "the partition is total" — which was true by
 * CONSTRUCTION and therefore asserted nothing. A fourth DDL value would have
 * defaulted silently to unrestorable while the comment claimed the decision was
 * forced. Found by the M27 PR0 review, which is also the reason this now leans
 * on the compiler rather than on a test: `Record<DeletedReason, …>` means a
 * fourth member of `DELETED_REASONS` fails `pnpm typecheck` with TS2741 until
 * somebody classifies it. A test can be satisfied by deleting a case; a missing
 * key cannot be.
 *
 * ZERO RUNTIME CALLERS UNTIL M27 PR1, stated rather than left to be found. The
 * repo's rule is to ship a capability with its caller; this ships a PR early
 * because the fence's claim — "a restore may offer exactly these rows" — needs
 * a subject that exists, and because the alternative is PR1 inventing the
 * classification beside the query that reads it. docs/04's M27 PR split records
 * the gap.
 */
export const REASON_DISPOSITION: Readonly<Record<DeletedReason, 'restorable' | 'unrestorable'>> = {
  // The keyset is untouched by `deleteItem`, so the blob is still openable.
  user_delete: 'restorable',
  // `reset` replaces the keyset in the same transaction. Dead ciphertext.
  vault_reset: 'unrestorable',
  // Retired before the column existed, so the answer is not recoverable from
  // the row. Unrestorable is the fail-closed direction: never offer a row whose
  // decryptability nobody recorded.
  unknown_pre_m27: 'unrestorable',
};

/** Derived, never hand-listed — the arms cannot drift from the map above. */
export const RESTORABLE_REASONS: readonly DeletedReason[] = DELETED_REASONS.filter(
  (r) => REASON_DISPOSITION[r] === 'restorable',
);

const COLUMNS = `id, user_id, item_type, blob_ct, blob_version, revision, created_at, updated_at, deleted_at, deleted_reason`;

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

  /**
   * OWNERSHIP IS FUSED INTO THE STATEMENT, and that is the point of the
   * signature (M27 PR1a). These read by (id, owner) together, so "no such item"
   * and "not your item" produce the same empty result and the caller cannot
   * tell them apart even in principle — docs/03's uniform-404 rule, and
   * CLAUDE.md's "any read placed before the authz gate answers a question about
   * someone else's data".
   *
   * The earlier signature took an id alone and left ownership to
   * `VaultAuthz.assertCan` AFTER the row was in hand, which answered `403
   * forbidden` for another user's item and `404 not_found` for a missing one —
   * a distinguishable pair, and an existence oracle for any item UUID that
   * leaks. Cedar still runs: it decides whether this PRINCIPAL may take this
   * ACTION, which is the layer M27 PR3's grantee read will need. What it no
   * longer decides is ownership, because the row never arrives.
   */
  async findLiveById(q: Queryable | Db, userId: string, id: string): Promise<ItemRow | null> {
    const rows = await q.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
      [id, userId],
    );
    return rows[0] ?? null;
  }

  async lockLiveById(tx: Queryable, userId: string, id: string): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL FOR UPDATE`,
      [id, userId],
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

  /**
   * Update a locked row to the next blob version.
   *
   * `revision` is absent from this statement DELIBERATELY: the trigger owns it,
   * so a writer cannot forget to advance it and cannot choose what it advances
   * to. `blob_version` stays a caller-supplied parameter because the client
   * sealed its ciphertext against a specific number and the server must store
   * exactly that one.
   */
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

  /**
   * Retire one item. `reason` is REQUIRED and has no default on purpose: the
   * two callers mean different things by a soft delete, and a default here
   * would let a third caller inherit whichever one was written first. The
   * paired CHECK in migration 004 refuses the row if this disagrees with
   * `deleted_at`, so a forgotten reason is a failed statement, not a NULL.
   */
  async softDelete(tx: Queryable, id: string, at: Date, reason: DeletedReason): Promise<void> {
    await tx.query(
      `UPDATE vault_items SET deleted_at = $2, deleted_reason = $3
        WHERE id = $1 AND deleted_at IS NULL`,
      [id, at, reason],
    );
  }

  /** Soft-delete every live item for a user; returns how many were affected. */
  async softDeleteAllForUser(
    tx: Queryable,
    userId: string,
    at: Date,
    reason: DeletedReason,
  ): Promise<number> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE vault_items SET deleted_at = $2, deleted_reason = $3
        WHERE user_id = $1 AND deleted_at IS NULL
        RETURNING id`,
      [userId, at, reason],
    );
    return rows.length;
  }
}
