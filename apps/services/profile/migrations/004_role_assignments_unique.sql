-- ---------------------------------------------------------------------------
-- 004 — one live designation per (owner, contact, role, scope, condition).
--
-- WHY THIS IS ITS OWN FILE. It was first appended to 003, which is wrong — but
-- not for the reason first written here. The migrator CHECKSUMS every applied
-- file and raises MigrationDriftError on an edit (packages/db/src/migrator.ts),
-- so appending to 003 fails LOUDLY on the next run rather than silently doing
-- nothing. The original claim ("silently never runs") came from watching a
-- container whose image still held the pre-edit 003, which is the second time in
-- that session a stale image was mistaken for evidence. Either way migrations are
-- append-only, and here the enforcement is real rather than conventional: even
-- editing a COMMENT in an applied file changes its checksum and blocks the next
-- migration until the file is restored.
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
-- broadest designation. The sentinel is the nil UUID, which no `gen_random_uuid`
-- ever produces, so it cannot collide with a real scope.
--
-- THE KEY DELIBERATELY OMITS starts_at/ends_at. Two designations differing only
-- by a time window are refused as "already granted", which is a real cost: an
-- owner cannot pre-schedule a successor window today. That is the conservative
-- direction — it refuses rather than permitting a shape whose overlap semantics
-- nothing in the platform yet interprets (no resolver reads these columns except
-- `effectiveContactReadGrants`'s single-window check). Adding windows to the key
-- would let two OVERLAPPING windows coexist, which is worse than refusing both;
-- proper support wants an exclusion constraint over a tstzrange, and that is a
-- schema change with its own reasoning, not a widening of this index.
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
    -- plpgsql's placeholder is a bare `%`, not C's `%s`. The first version wrote
    -- `%s%s` with two arguments, which plpgsql reads as placeholder-then-literal-s
    -- twice: the list came through with stray "s" characters wedged into it. And
    -- `%%` is an ESCAPED percent — zero placeholders — which is a hard error
    -- ("too many parameters specified for RAISE") the moment the branch fires.
    -- Both were caught by making the branch actually fire in a test, which is the
    -- only way to find a bug in an error path.
    RAISE EXCEPTION 'duplicate live role_assignments exist; consolidate permission_grants onto one assignment and revoke the others through the API, then re-run:%',
      E'\n' || offending;
  END IF;
END $$;

CREATE UNIQUE INDEX ux_role_assignments_live
  ON role_assignments (
    owner_user_id, contact_id, role, scope_type,
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid),
    effective_condition
  )
  WHERE deleted_at IS NULL;
