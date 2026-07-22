-- Backfill of the financial cluster's active-DEK uniqueness onto the core
-- cluster (M2 follow-up, docs/04): at most one ACTIVE DEK per user, enforced
-- by the database. `getOrCreateDek` is find-then-insert, so before this index
-- two concurrent first-writes for the same brand-new user could each mint a
-- DEK; this migration first retires any such doubles, then creates the index.
--
-- Safety rules. `destroyed_at` means CRYPTO-SHREDDED — every ciphertext under
-- the key becomes permanently unreadable — so retirement must be proven safe,
-- never guessed:
--   * A DEK counts as REFERENCED if any ciphertext could need it to decrypt.
--     In this cluster every ciphertext-bearing row carries an explicit dek_id:
--     `profiles`/`family_members`/`contacts` (live AND soft-deleted rows — no
--     hard deletes) plus the historical row images in their `*_versions`
--     shadow tables (`row_data->>'dek_id'`).
--   * Only DEKs verified unreferenced by the above are retired
--     (destroyed_at = now()); the kept DEK is the referenced one, or the
--     newest when none is referenced. No rows are deleted.
--   * If more than one ACTIVE DEK of the same user is referenced, this
--     migration RAISEs and rolls back: a SQL migration has no KMS access and
--     must not choose which ciphertexts to shred. Runbook: re-encrypt the
--     affected user's rows onto a single DEK with KMS tooling, then re-run.

DO $$
DECLARE
  conflicted UUID[];
BEGIN
  CREATE TEMP TABLE dedupe_referenced ON COMMIT DROP AS
    SELECT dek_id FROM profiles
    UNION
    SELECT dek_id FROM family_members
    UNION
    SELECT dek_id FROM contacts
    UNION
    SELECT (row_data->>'dek_id')::uuid FROM profiles_versions WHERE row_data ? 'dek_id'
    UNION
    SELECT (row_data->>'dek_id')::uuid FROM family_members_versions WHERE row_data ? 'dek_id'
    UNION
    SELECT (row_data->>'dek_id')::uuid FROM contacts_versions WHERE row_data ? 'dek_id';

  SELECT array_agg(x.user_id) INTO conflicted FROM (
    SELECT d.user_id
      FROM deks d
      JOIN dedupe_referenced r USING (dek_id)
     WHERE d.destroyed_at IS NULL
     GROUP BY d.user_id
    HAVING count(*) > 1
  ) x;
  IF conflicted IS NOT NULL THEN
    RAISE EXCEPTION 'DEK dedupe blocked: user(s) % hold multiple ACTIVE referenced DEKs. '
      'Re-encrypt each user''s rows onto a single DEK (KMS tooling), then re-run.',
      conflicted;
  END IF;

  UPDATE deks d
     SET destroyed_at = now()
    FROM (
      SELECT DISTINCT ON (a.user_id) a.user_id, a.dek_id
        FROM deks a
       WHERE a.destroyed_at IS NULL
       ORDER BY a.user_id,
                (a.dek_id IN (SELECT dek_id FROM dedupe_referenced)) DESC,
                a.created_at DESC,
                a.dek_id DESC
    ) keeper
   WHERE d.user_id = keeper.user_id
     AND d.destroyed_at IS NULL
     AND d.dek_id <> keeper.dek_id;
END $$;

-- Matches the financial cluster's ux_deks_user_active. A lost first-write
-- race now surfaces as a 23505 unique violation, translated by the service's
-- PgDekRepository to DekConflictError so @estate/crypto adopts the winner.
CREATE UNIQUE INDEX ux_deks_user_active ON deks (user_id) WHERE destroyed_at IS NULL;

-- Superseded: the unique index serves the same partial (user_id) lookups.
DROP INDEX ix_deks_user_active;
