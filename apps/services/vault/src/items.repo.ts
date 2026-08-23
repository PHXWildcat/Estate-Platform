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
 * One captured image of an item, as `listVersions` projects it out of
 * `row_data` (M27 PR1b).
 *
 * `blob_ct` and `blob_version` are a MATCHED PAIR and never travel apart: a
 * blob sealed at version N opens only under an AAD carrying N, so a client
 * handed the ciphertext at any other number gets something that will never
 * decrypt and no error saying why.
 */
export interface VersionRow {
  /** The per-row handle. NULL images are excluded by the reader, never surfaced. */
  revision: number;
  blob_ct: Buffer;
  blob_version: number;
  item_type: VaultItemType;
  versioned_at: Date;
  operation: 'UPDATE' | 'DELETE';
  /**
   * The owner recorded INSIDE the captured image. Projected so the service can
   * assert it against the live row it drove from — see `assertImageOwners`.
   * It is not part of the DTO and never reaches a client.
   */
  image_user_id: string;
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

/** The same list qualified to the target of an UPDATE ... FROM, whose RETURNING
 * is otherwise ambiguous: `vault_items_versions` also has a `revision` column
 * since migration 006, and an unqualified `revision` there is a syntax error
 * rather than a silently wrong value — but `row_data` and the rest would not
 * be, so the whole list is qualified rather than the one column that errors. */
const I_COLUMNS = COLUMNS.split(', ')
  .map((c) => `i.${c}`)
  .join(', ');

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

  /**
   * PRIOR IMAGES OF ONE ITEM, newest first (M27 PR1b).
   *
   * DRIVEN FROM `vault_items`, NEVER FROM THE SHADOW TABLE. `vault_items_versions`
   * has no `user_id` column — ownership lives inside `row_data` — so a reader
   * keyed on `row_id` alone answers a question about somebody else's data and
   * then filters, which is the ordering CLAUDE.md forbids. Here the live row is
   * the driver and its ownership is fused (`id = $1 AND user_id = $2`), so the
   * shadow table is only ever reached with a `row_id` the caller has already
   * been proven to own. Zero rows therefore means "no such item OR not yours",
   * one uniform answer; a null-extended row means "yours, no history yet".
   *
   * `LEFT JOIN LATERAL`, not a plain `LEFT JOIN`, and the difference is not
   * style. With the cursor in a join condition the LIMIT applies AFTER the
   * join, so every page materialises the row's entire history and top-N sorts
   * it — measured at 77 shared buffers against this shape's 5, on a row with
   * 5,000 images, and the gap grows with history on every page. The LATERAL
   * lets `ix_vault_items_versions_row_revision` serve the ORDER BY and the
   * LIMIT together.
   *
   * TWO EXCLUSIONS, BOTH FAIL-CLOSED, BOTH ABSENCES RATHER THAN FILTERS:
   *  · `revision IS NOT NULL` drops images captured before migration 005. They
   *    have no handle, so they cannot be named — and an image that cannot be
   *    named cannot be restored by mistake.
   *  · the captured `deleted_at` must be NULL. An image taken at an UNDELETE
   *    holds the row as it was WHILE RETIRED, so writing it forward would
   *    re-delete the item — a "restore" that deletes. Excluding it at the
   *    source is what keeps `vault.item.restored` truthful by construction
   *    rather than by a check at the call site.
   */
  async listVersions(
    q: Queryable | Db,
    input: { userId: string; itemId: string; limit: number; cursor?: number },
  ): Promise<VersionRow[]> {
    return q.query<VersionRow>(
      `SELECT v.revision,
              v.versioned_at,
              v.operation,
              v.row_data->>'item_type'                AS item_type,
              (v.row_data->>'blob_version')::int      AS blob_version,
              (v.row_data->>'blob_ct')::bytea         AS blob_ct,
              v.row_data->>'user_id'                  AS image_user_id
         FROM vault_items i
         LEFT JOIN LATERAL (
           SELECT s.revision, s.versioned_at, s.operation, s.row_data
             FROM vault_items_versions s
            WHERE s.row_id = i.id
              AND s.revision IS NOT NULL
              AND s.row_data->>'deleted_at' IS NULL
              AND ($3::int IS NULL OR s.revision < $3)
            ORDER BY s.revision DESC
            LIMIT $4
         ) v ON true
        WHERE i.id = $1 AND i.user_id = $2 AND v.revision IS NOT NULL`,
      [input.itemId, input.userId, input.cursor ?? null, input.limit],
    );
  }

  /**
   * Does an item exist and belong to this caller, ignoring liveness? The
   * versions reader needs this to tell "no such item / not yours" (404) from
   * "yours, no history" (200 empty), which the row-returning query cannot
   * distinguish once its LATERAL produces nothing.
   */
  async existsForOwner(q: Queryable | Db, userId: string, id: string): Promise<boolean> {
    const rows = await q.query<{ one: number }>(
      `SELECT 1 AS one FROM vault_items WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );
    return rows.length > 0;
  }

  /**
   * The RETIRED rows a restore surface may offer, newest retirement first.
   *
   * ONE ORDERED INDEX SCAN PER REASON, MERGED — not `deleted_reason = ANY($2)`.
   * `= ANY` cannot use `ix_vault_items_user_retired`'s ordering, so it sorts
   * the user's whole retired set on every page; a scalar `= $2` would be a
   * frozen one-member copy of a set the compiler derives. Unnesting the derived
   * set and taking one bounded, ordered scan per member is O(members x page) at
   * any set size and keeps `RESTORABLE_REASONS` the single source of the
   * policy.
   *
   * `deleted_at IS NOT NULL` is spelled VERBATIM even though 004's CHECK makes
   * it equivalent to `deleted_reason IS NOT NULL`: Postgres matches a partial
   * index by its predicate, not through a CHECK's equivalence, so the other
   * spelling is a sequential scan that returns the right answer.
   */
  async listRestorable(
    q: Queryable | Db,
    input: {
      userId: string;
      restorable: readonly DeletedReason[];
      limit: number;
      cursor?: { deletedAt: Date; id: string };
    },
  ): Promise<ItemRow[]> {
    return q.query<ItemRow>(
      `SELECT ${COLUMNS} FROM (
         SELECT s.*
           FROM unnest($2::text[]) AS r(reason),
           LATERAL (
             SELECT ${COLUMNS}
               FROM vault_items
              WHERE user_id = $1
                AND deleted_at IS NOT NULL
                AND deleted_reason = r.reason
                AND ($3::timestamptz IS NULL OR (deleted_at, id) < ($3, $4))
              ORDER BY deleted_at DESC, id DESC
              LIMIT $5
           ) s
       ) merged
       ORDER BY deleted_at DESC, id DESC
       LIMIT $5`,
      [
        input.userId,
        [...input.restorable],
        input.cursor?.deletedAt ?? null,
        input.cursor?.id ?? null,
        input.limit,
      ],
    );
  }

  /**
   * Write one prior image forward onto the live row (M27 PR1b).
   *
   * THREE COLUMNS, AND THE REST IS AN ABSENCE RATHER THAN A FILTER. `blob_ct`
   * and `blob_version` are the matched pair that decrypts; `item_type` moves
   * with them because it is what the ordinary update writes alongside the blob,
   * so a restore that left it behind would render the recovered item under the
   * wrong type forever with nothing failing. Everything else in `row_data` is
   * excluded BY NOT BEING NAMED: `id` and `user_id` (identity — writing them
   * would transplant a row), `created_at` (a fact about the original),
   * `updated_at` and `revision` (trigger-owned), and `deleted_at` /
   * `deleted_reason`, which are non-NULL in any image captured at an undelete
   * and would turn a restore into a deletion.
   *
   * THE CAST HAPPENS IN SQL. `row_data` is `to_jsonb(OLD)`, so `blob_ct` is
   * rendered as text by whatever `bytea_output` was in force at CAPTURE time,
   * and `::bytea` on the way out inverts either rendering. Parsing it in
   * TypeScript would be a second decoder that has to agree with a server
   * setting it cannot see.
   *
   * The source image is addressed by `(row_id, revision)` with `row_id` bound
   * to the already-fused live row, so a caller cannot name another user's image
   * by guessing a handle; `revision` is per-row, so a handle from one item does
   * not resolve against another.
   */
  async restoreVersion(
    tx: Queryable,
    input: { id: string; userId: string; revision: number },
  ): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `UPDATE vault_items i
          SET item_type   = v.row_data->>'item_type',
              blob_ct     = (v.row_data->>'blob_ct')::bytea,
              blob_version = (v.row_data->>'blob_version')::int
         FROM vault_items_versions v
        WHERE i.id = $1
          AND i.user_id = $2
          AND i.deleted_at IS NULL
          AND v.row_id = i.id
          AND v.revision = $3
          AND v.row_data->>'deleted_at' IS NULL
          AND v.row_data->>'user_id' = i.user_id::text
        RETURNING ${I_COLUMNS}`,
      [input.id, input.userId, input.revision],
    );
    return rows[0] ?? null;
  }

  /**
   * RELABEL ROWS THAT WERE ALREADY RETIRED WHEN THE KEYSET WENT (M27 PR1b).
   *
   * `softDeleteAllForUser` carries `WHERE deleted_at IS NULL`, so an item the
   * owner deleted BEFORE a reset is not touched by it and keeps
   * `deleted_reason = 'user_delete'`. Its blob is just as dead as every row the
   * reset retired — the keyset is replaced in that same transaction — but the
   * column says restorable, and PR1b's list believes the column. That is the
   * failure migration 004 exists to prevent, arriving through the one door 004
   * left open: a silent AEAD error on click, where a control firing and an
   * outage wear the same face.
   *
   * `deleted_at` is DELIBERATELY not touched. When the row was retired is a
   * fact about the owner's action and stays true; what changes is the answer to
   * "can this ever be decrypted again", which the reset has just made no.
   */
  async relabelRetiredForUser(
    tx: Queryable,
    userId: string,
    reason: DeletedReason,
  ): Promise<number> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE vault_items SET deleted_reason = $2
        WHERE user_id = $1 AND deleted_at IS NOT NULL AND deleted_reason <> $2
        RETURNING id`,
      [userId, reason],
    );
    return rows.length;
  }

  /**
   * Lock a RETIRED row by (id, owner). The mirror of `lockLiveById`, and the
   * predicate is inverted rather than dropped: a caller that means "the retired
   * one" must not silently accept a live one, or undelete becomes a no-op that
   * reports success.
   */
  async lockRetiredById(tx: Queryable, userId: string, id: string): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items
        WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL FOR UPDATE`,
      [id, userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Lock a row by (id, owner) REGARDLESS of whether it is live, so a caller can
   * tell "no such item / not yours" from "yours, in the other state" and answer
   * each correctly. Both other lockers pin liveness; this one is the three-way
   * dispatch's input and deliberately does not.
   */
  async lockAnyById(tx: Queryable, userId: string, id: string): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `SELECT ${COLUMNS} FROM vault_items
        WHERE id = $1 AND user_id = $2 FOR UPDATE`,
      [id, userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Bring a retired row back. Clears BOTH columns in one statement because
   * migration 004's CHECK ties them — `(deleted_at IS NULL) = (deleted_reason
   * IS NULL)` — so clearing either alone is a refused statement rather than a
   * half-done restore.
   *
   * The restorable set is RESTATED in the WHERE rather than trusted from the
   * caller's earlier read. A pre-transaction check and the write it guards are
   * separated by every commit that lands between them, and the reset that makes
   * a row unrestorable is exactly the concurrent writer in question. The
   * predicate is the same derived set the list uses, passed as an array, so
   * there is no second copy of the policy in SQL.
   */
  async undelete(
    tx: Queryable,
    input: { id: string; userId: string; restorable: readonly DeletedReason[] },
  ): Promise<ItemRow | null> {
    const rows = await tx.query<ItemRow>(
      `UPDATE vault_items SET deleted_at = NULL, deleted_reason = NULL
        WHERE id = $1 AND user_id = $2
          AND deleted_at IS NOT NULL
          AND deleted_reason = ANY($3::text[])
        RETURNING ${COLUMNS}`,
      [input.id, input.userId, [...input.restorable]],
    );
    return rows[0] ?? null;
  }
}
