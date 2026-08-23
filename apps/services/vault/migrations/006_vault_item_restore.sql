-- M27 PR1b — the restore reader: a per-item handle on the shadow table, and
-- the two indexes the restore queries need.
--
-- WHAT PR1b READS, AND WHY NEITHER READ IS INDEXED TODAY.
--
--   1. THE VERSIONS READER. `vault_items_versions` has carried exactly one
--      index since 001: the `version_seq` identity primary key. A reader keyed
--      on an item is therefore a scan of every image in the table, for every
--      user, on a table that grows by one row per write and is never pruned.
--   2. THE RESTORABLE LIST. `ix_vault_items_user_live` is PARTIAL on
--      `deleted_at IS NULL`, so it answers the live list and is structurally
--      unable to answer its complement. The restorable list is exactly the
--      complement.
--
-- THE HANDLE IS `revision`, NOT `version_seq`, AND THAT IS A SECURITY CHOICE
-- RATHER THAN AN ERGONOMIC ONE. A reader has to name an image — to page, and
-- to say which one a restore should put back. `version_seq` is a BIGINT
-- IDENTITY shared by every user of this table, and `vault.service.ts`'s
-- cursors are base64url of PLAINTEXT rather than opaque or signed. Paging on
-- it would hand every caller a decodable platform-wide write counter and put a
-- sequential id on the wire, against CLAUDE.md's "all IDs are UUIDs; never
-- expose sequential IDs". `revision` is per-row, trigger-assigned since 005,
-- and never reused within a row — it is already the client's `If-Match` token,
-- so this is ONE handle for both halves rather than a second spelling of
-- "which image".
--
-- GENERATED, NOT TRIGGER-POPULATED. The obvious shape is a plain column filled
-- by `vault_items_capture_version`. This is better for three reasons and the
-- third is the one that matters. It needs no change to that function, which is
-- emitted by the SHARED `versionsTableSql` generator in packages/db — a local
-- edit to one copy of a generated body is precisely the drift this repo keeps
-- closing. `CREATE OR REPLACE FUNCTION` only affects FUTURE captures
-- (.claude/rules/db-migrations.md), so a trigger column would need a backfill
-- to be true of the rows already here, and this needs none. And a generated
-- column CANNOT disagree with `row_data`: Postgres computes it from the image
-- itself, so the handle and the thing it names are one fact, not two that a
-- later writer could set inconsistently.
ALTER TABLE vault_items_versions
  ADD COLUMN revision INT GENERATED ALWAYS AS ((row_data->>'revision')::int) STORED;

-- IMAGES CAPTURED BEFORE 005 GET NULL, AND NULL MEANS NOT ADDRESSABLE. They
-- predate the column, so `row_data` has no `revision` key and there is no
-- honest value to invent. The reader excludes them (`revision IS NOT NULL`)
-- rather than ordering them arbitrarily: an image nobody can name is an image
-- nobody can restore by mistake, which is the fail-closed direction. Stated
-- here because the exclusion is invisible at the call site — it looks like an
-- ordinary NOT NULL guard and is actually a statement about a migration
-- boundary.

-- THE VERSIONS READER'S INDEX. `(row_id, revision DESC)` is the exact shape of
-- `WHERE row_id = $1 AND revision IS NOT NULL AND revision < $cursor ORDER BY
-- revision DESC LIMIT $n`, which is how the reader is spelled — a LEFT JOIN
-- LATERAL so the LIMIT reaches the index rather than being applied after the
-- join. Measured on 55,000 images with 5,000 on the target row: 5 shared
-- buffers on page 2. The same page through a plain LEFT JOIN with the cursor
-- in the ON clause materialises 3,001 rows and top-N sorts them, at 77
-- buffers, because the LIMIT cannot reach inside — a cost that grows with the
-- row's whole history on every page.
CREATE INDEX IF NOT EXISTS ix_vault_items_versions_row_revision
  ON vault_items_versions (row_id, revision DESC);

-- THE RESTORABLE LIST'S INDEX, and `deleted_reason` is a KEY COLUMN rather
-- than part of the predicate DELIBERATELY. The restorable set is derived in
-- TypeScript (`REASON_DISPOSITION` in items.repo.ts, a total map the compiler
-- checks). Encoding that set in a partial index predicate would freeze a copy
-- of it in SQL, where nothing can see it drift: add a fourth restorable reason
-- and the index silently stops covering the query — right answers, no error,
-- and a plan that has quietly become a sequential scan. As a key column the
-- index encodes no policy at all, so there is no second copy and no fence is
-- owed for one.
--
-- The predicate that IS here is the one 004's CHECK makes safe to state, and
-- the reader must spell it verbatim: Postgres will not match a partial index
-- through the CHECK's equivalence, so a reader that filters on
-- `deleted_reason IS NOT NULL` instead gets a sequential scan.
CREATE INDEX IF NOT EXISTS ix_vault_items_user_retired
  ON vault_items (user_id, deleted_reason, deleted_at DESC, id DESC)
  WHERE deleted_at IS NOT NULL;

-- EVERY STATEMENT WIDENS AND NONE CONSTRAINS DATA, so this migration owes no
-- pre-flight (.claude/rules/db-migrations.md: a migration that WIDENS what is
-- permitted needs none; one that narrows does).
--
-- THE TWO `IF NOT EXISTS` CLAUSES DO NOT MEAN THE SAME THING, and stating that
-- they did was wrong. The rule requires an index on a populated table to be
-- built out of band with CONCURRENTLY, which the migrator's BEGIN/COMMIT makes
-- structurally inexpressible — but only ONE of these can be built that way:
--
--   · `ix_vault_items_user_retired` is over columns `vault_items` has carried
--     since 004, so an operator CAN build it concurrently ahead of this file
--     and find the statement a no-op. That is the case the rule is about.
--   · `ix_vault_items_versions_row_revision` is over `revision`, which does not
--     exist until the ALTER TABLE eleven lines above. Nobody can have built it
--     in advance, because there was nothing to build it on. Its `IF NOT EXISTS`
--     is worth no more than tolerance of a re-run after a partial failure.
--
-- THE `ADD COLUMN` IS DELIBERATELY NOT `IF NOT EXISTS`. A hand-added column of
-- the same name with a different generation expression is the one state this
-- file must not accept silently: the handle would still be called `revision`
-- and would name something else, which is the whole failure the GENERATED
-- clause exists to make impossible. Failing loudly is the fail-closed answer.
