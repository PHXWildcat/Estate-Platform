-- ---------------------------------------------------------------------------
-- M27 PR0: a soft-deleted vault item says WHY, because two routes retire rows
-- with the same stamp and only one of them leaves a decryptable blob.
--
-- `VaultService.deleteItem` soft-deletes ONE item and changes no key material,
-- so the ciphertext is still openable by the vault's master key. `reset`
-- soft-deletes EVERY item with the same `deleted_at` write and then replaces
-- the keyset and clears the recovery keypair — so those blobs are
-- cryptographically dead and can never be opened again by anyone, including
-- their owner. Until this migration nothing in the row distinguished them.
--
-- WHY THAT MATTERS NOW: M27 ships a restore surface. A restore list built as
-- `WHERE deleted_at IS NOT NULL` would offer reset-retired rows, and the
-- failure would arrive as a silent AEAD error when the owner clicked one — a
-- control firing dressed as an outage, which docs/03 forbids sharing a face.
-- The corpus a restore may offer is therefore DERIVED from this CHECK
-- (apps/services/vault/test/restorable-corpus.spec.ts), never hand-listed.
--
-- WHY A COLUMN AND NOT `app.change_reason`: the version trigger already reads
-- that GUC into `vault_items_versions.reason`, which looks like the same fact.
-- It is not. The GUC lands in the SHADOW table while a restore list queries
-- LIVE rows; the shadow row for a soft delete is captured BEFORE the UPDATE, so
-- it holds an image whose `deleted_at` is still NULL; and no service in this
-- repo has ever set that GUC, in any cluster, so every `reason` ever captured
-- is NULL and nothing went red. A CHECK cannot be forgotten. docs/03 §6uu.
--
-- BACKFILL POSTURE, chosen against the four this repo has already used.
-- `identity/004` backfilled a DEFAULT that was true of every existing row;
-- there is no such value here, because the reason a row was retired is not
-- recoverable from the row. `settlement/004` argues that `NOT VALID` beats
-- writing a false attribution, and it is right that a false attribution is the
-- worst option — backfilling 'user_delete' would OFFER dead blobs, the exact
-- defect this column exists to prevent. But a third option is available that
-- neither lies nor leaves the constraint unvalidated: say we do not know.
-- `unknown_pre_m27` is honest, it is excluded from the restorable corpus so the
-- failure direction is closed (a legacy row is never offered), and the
-- constraint ships VALID rather than deferring its enforcement to nobody.
-- Fresh databases get none of these rows: the int suites migrate into an empty
-- scratch schema, so the backfill is a no-op there and matters only to a
-- developer stack that has already retired an item.
--
-- WIDENING, so no pre-flight (.claude/rules/db-migrations.md): every existing
-- row remains legal, and the CHECK constrains a column that did not exist.
-- ---------------------------------------------------------------------------

ALTER TABLE vault_items
  ADD COLUMN deleted_reason TEXT
    CHECK (deleted_reason IN ('user_delete', 'vault_reset', 'unknown_pre_m27'));

-- Rows retired before this column existed. Written before the paired CHECK
-- below so that constraint can ship VALID.
--
-- THIS BACKFILL FIRES BOTH ROW TRIGGERS ON vault_items, and that is stated here
-- rather than discovered by whoever next reads `vault_items_versions` and finds
-- a burst of rows nobody wrote. `001_vault_schema.sql` puts two BEFORE UPDATE
-- FOR EACH ROW triggers on this table, so on any database that already holds
-- retired items this statement:
--   * inserts one `vault_items_versions` row per legacy retired item, with
--     `actor_id` NULL and `reason` NULL — a migration has no actor, and no
--     service sets `app.change_reason` — and that shadow row is PERMANENT,
--     because the table carries REVOKE UPDATE, DELETE; and
--   * rewrites `updated_at` to now() on every row it touches. Harmless to the
--     live listing (`ix_vault_items_user_live` and every read filter on
--     `deleted_at IS NULL`, so these rows are not in it), but a restore surface
--     ordering by `updated_at` will see every legacy row clustered at the
--     moment this migration ran rather than when it was deleted. Order a
--     restore list by `deleted_at`.
-- Suppressing either trigger was rejected: `DISABLE TRIGGER` on an append-only
-- shadow is a bigger promise to break than an unattributed row is to explain.
-- On a fresh database this statement touches nothing and none of the above
-- happens, which is why the int suites cannot show it to you.
UPDATE vault_items
   SET deleted_reason = 'unknown_pre_m27'
 WHERE deleted_at IS NOT NULL AND deleted_reason IS NULL;

-- THE TWO FACTS AGREE OR THE ROW IS REFUSED. Without this a live row could
-- carry a reason (meaningless) and — the one that matters — a retired row could
-- carry none, which is exactly the state this migration exists to make
-- unrepresentable. Stated as an equivalence rather than two one-way checks so
-- neither direction can be relaxed without deleting the other.
ALTER TABLE vault_items
  ADD CONSTRAINT vault_items_deleted_reason_agrees
    CHECK ((deleted_at IS NULL) = (deleted_reason IS NULL));
