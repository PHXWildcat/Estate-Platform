-- ---------------------------------------------------------------------------
-- 004 — one live designation per (owner, contact, role, scope, condition).
--
-- WHY THIS IS ITS OWN FILE. It was first appended to 003, which is wrong for a
-- reason worth writing down: the migrator keys on FILENAME, so editing a file it
-- has already recorded is a change that silently never runs. Proven rather than
-- reasoned about — the local stack had 003 applied and never grew the index, so
-- a claim that the constraint was live would have been false. Migrations are
-- append-only for the same reason event tables are.
--
-- WHAT IT FIXES. `role_assignments` had no uniqueness of any kind, so two clicks
-- (or one click and a retry) minted two identical live designations. Nothing
-- downstream breaks — every resolver uses EXISTS/LIMIT 1 — which is exactly why
-- it would have gone unnoticed, and exactly why it matters: revoking "the"
-- designation leaves the duplicate conferring everything it conferred before,
-- and on the docs/03 §5.1 executor-resolution chain "revoked" has to mean
-- revoked.
--
-- COALESCE on the nullable scope, because SQL uniqueness treats NULLs as
-- distinct and `scope_id IS NULL` (the whole estate) is the commonest case —
-- without it the constraint would permit unlimited duplicates of precisely the
-- broadest designation.
-- ---------------------------------------------------------------------------

-- PRE-FLIGHT: refuse rather than choose. The `002_dek_unique_active.sql`
-- precedent, and the same reasoning: duplicates are identical as designations
-- but NOT as rows — each has its own id, and `permission_grants.role_assignment_id`
-- references it. Retiring the "spare" would silently revoke every grant hanging
-- off it, so a migration must not pick which one dies. It stops with the
-- offending pairs named; the runbook is to consolidate the grants onto one
-- assignment, revoke the other through the API (which audits it), and re-run.
DO $$
DECLARE
  offending TEXT;
BEGIN
  SELECT string_agg(
           format('owner=%s contact=%s role=%s scope=%s/%s cond=%s count=%s',
                  owner_user_id, contact_id, role, scope_type,
                  COALESCE(scope_id::text, 'estate'), effective_condition, n),
           E'\n')
    INTO offending
    FROM (
      SELECT owner_user_id, contact_id, role, scope_type, scope_id,
             effective_condition, count(*) AS n
        FROM role_assignments
       WHERE deleted_at IS NULL
       GROUP BY 1, 2, 3, 4, 5, 6
      HAVING count(*) > 1
    ) dupes;

  IF offending IS NOT NULL THEN
    RAISE EXCEPTION
      'duplicate live role_assignments exist; consolidate permission_grants onto one assignment and revoke the others through the API, then re-run:%s%s',
      E'\n', offending;
  END IF;
END $$;

CREATE UNIQUE INDEX ux_role_assignments_live
  ON role_assignments (
    owner_user_id, contact_id, role, scope_type,
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid),
    effective_condition
  )
  WHERE deleted_at IS NULL;
