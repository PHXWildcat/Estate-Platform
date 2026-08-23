-- M27 PR1a — `vault_items.revision`: a concurrency token that is not also an
-- AEAD binding.
--
-- WHY THIS EXISTS. `blob_version` has been doing two jobs, and they only stay
-- compatible while no operation ever repeats a version value:
--
--   1. AEAD BINDING. `itemContentAad` (packages/vault-crypto/src/items.ts) is
--      `estate.vault.item.v1|<user>|<item>|<blobVersion>`, so a blob sealed at
--      N opens ONLY when the caller is told N. The version must therefore
--      travel with its ciphertext wherever that ciphertext goes.
--   2. CONCURRENCY TOKEN. `updateItem` compares `If-Match` to `blob_version`
--      by strict equality and writes `blob_version + 1`. Equality is a sound
--      change detector only because a value occurs at most once per row's
--      life; nothing in the schema said so — the invariant lived in a single
--      `+ 1` at one call site.
--
-- M27's version restore is the first operation that forces those apart. It
-- writes a prior row image forward INCLUDING its captured `blob_version` (the
-- pair is what decrypts; the ciphertext alone at a fresh version never will),
-- which moves the live version BACKWARDS. A row restored from 5 to 3 and then
-- edited twice is at 5 again, and a client still holding the first 5 passes
-- `If-Match` with a stale blob: no conflict, no error, and the restore plus
-- both edits are silently overwritten. That is the lost update `If-Match`
-- exists to prevent, and it is unreachable while versions only ever increase.
--
-- `revision` takes job 2. `blob_version` keeps job 1 alone and is then FREE to
-- move backwards, which is not a defect but a signal: a version that goes down
-- is a restore, and docs/03 §6a's rollback-detection residual (now M39) has
-- nothing else to look at today.
--
-- Checked as a category rather than as an instance: `itemContentAad` is the
-- ONLY additional-authenticated-data builder in this repo that binds a mutable
-- per-write counter. `fieldAad`, `aliasAad`, `itemKeyAad`, `masterKeyAad`,
-- `recoveryWrapAad` and `shareAad` bind stable identities only, so no other
-- table carries this conflation and no other migration is owed.

ALTER TABLE vault_items
  ADD COLUMN revision INT NOT NULL DEFAULT 1,
  ADD CONSTRAINT vault_items_revision_positive CHECK (revision >= 1);

-- NO BACKFILL, DELIBERATELY, and the contrast with migration 004 is the reason
-- rather than an inconsistency. 004 added a column describing the PAST (why a
-- row was retired), so existing rows had to be given an honest answer and the
-- backfill's cost — one permanent unattributed `vault_items_versions` row per
-- legacy item, `updated_at` rewritten — was the price of not lying about them.
-- `revision` describes only the FUTURE: it counts writes from here on, and
-- every row starting at 1 is already true. `ADD COLUMN ... DEFAULT` does not
-- fire row triggers, so this migration captures no version rows at all.

-- THE INVARIANT MOVES OUT OF THE CALL SITE AND INTO THE TABLE. The trigger
-- assigns the next revision itself rather than validating one a caller
-- supplied, so no writer can forget to bump it and no writer can choose it:
-- soft delete, undelete, keyset-driven retirement and the ordinary update all
-- advance it for free, and a restore cannot reuse a value it has already
-- issued. A CHECK cannot express this — it sees one row version, not the
-- transition — which is why this is a trigger and not a constraint.
CREATE OR REPLACE FUNCTION vault_items_bump_revision() RETURNS trigger AS $$
BEGIN
  NEW.revision := OLD.revision + 1;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- BEFORE UPDATE row triggers fire in NAME order, so this one runs first
-- (revision < updated_at < versions). That ordering is not load-bearing:
-- `vault_items_capture_version` reads OLD, which no BEFORE trigger can alter,
-- so the captured image always carries the revision the row had BEFORE this
-- write — which is the number a reader of that image needs.
CREATE TRIGGER trg_vault_items_revision
BEFORE UPDATE ON vault_items
FOR EACH ROW EXECUTE FUNCTION vault_items_bump_revision();
