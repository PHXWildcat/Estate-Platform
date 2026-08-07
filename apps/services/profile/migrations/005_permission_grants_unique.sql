-- ---------------------------------------------------------------------------
-- 005 — one live permission grant per (role_assignment, resource, action).
--
-- The sibling of 004, and found the same way: `permission_grants` had no
-- uniqueness either, and the UI's "Allow: …" buttons were the one retried action
-- with no in-flight guard, so two clicks issued two POSTs and wrote two rows.
-- Nothing reads more than one — `effectiveContactReadGrants` joins and DISTINCTs
-- — so the duplicate is invisible until the owner withdraws the grant they can
-- see and the other one silently keeps conferring it. That is the same shape as
-- the duplicate designation 004 closes: "revoked" has to mean revoked.
--
-- A SEPARATE FILE rather than an edit to 004, because 004 has already been
-- applied somewhere (the local stack) and the migrator CHECKSUMS applied files
-- and raises MigrationDriftError on an edit. Migrations are append-only, and the
-- enforcement is real rather than conventional.
--
-- No pre-flight here, deliberately. Unlike a duplicate designation, a duplicate
-- GRANT has no dependants — nothing references `permission_grants.id` — so if a
-- deployment ever did hold duplicates the safe repair is mechanical rather than a
-- judgement call, and CREATE UNIQUE INDEX naming the offending row is a good
-- enough error for a table with no rows in any deployment today. 004's pre-flight
-- exists because retiring a duplicate DESIGNATION would silently take grants with
-- it; that reasoning does not transfer.
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX ux_permission_grants_live
  ON permission_grants (role_assignment_id, resource, action)
  WHERE revoked_at IS NULL;
