-- Settlement PR4e — the forensic marker 001 states backwards.
--
-- `001_settlement_schema.sql` declares the column as
--
--     granted_by UUID,                               -- NULL: granted via the ops CLI
--
-- and that sentence has been false since M21 PR1. `granted_by` had existed
-- since M7 with nothing ever writing it, so a NULL genuinely did mean "the CLI
-- did this". PR1 made the ceremony DEMAND attribution: `--by` is required for
-- both writes and `operator-cli.ts` always records it. So a NULL now means the
-- OPPOSITE — a row that did NOT come through the ceremony, written straight
-- against the database by somebody holding the connection.
--
-- That inversion is exactly the signal `operator-cli.ts` (§2 of its docstring),
-- `operator-cli.spec.ts` and `operator-cli.int.spec.ts` all rely on, and the
-- schema told an investigator the reverse — during an incident, which is the
-- only time anybody reads it.
--
-- WHY A COMMENT ON A COLUMN RATHER THAN A FIX IN 001. Migrations are
-- append-only and checksummed; editing an applied file raises
-- MigrationDriftError and blocks the next migration. But a `--` comment in an
-- old migration file was the wrong home for this anyway: nobody reading
-- `\d+ settlement_operators` during an incident is also reading migration 001.
-- `COMMENT ON` puts the truth in the catalog, where `\d+` and
-- `col_description()` both show it — and where the fence in
-- `operator-cli.int.spec.ts` can assert it, so the next inversion fails a test
-- instead of waiting for a review. (The identity 004 precedent.)
--
-- No DDL, no data change. This migration is a sentence.

COMMENT ON COLUMN settlement_operators.granted_by IS
  'The administrator named by --by on the operator-cli ceremony, which has '
  'REQUIRED it for grant and revoke since M21 PR1. NULL therefore marks a row '
  'that did NOT come through the ceremony: attribution, not authentication, so '
  'a NULL is a row to investigate rather than a sanctioned CLI footprint. The '
  'comment in 001 says the reverse and predates PR1.';

COMMENT ON TABLE settlement_operators IS
  'The allowlist that decides who may perform the mandatory human review of a '
  'death case. Being on this table IS the authority. operator-cli.ts is the '
  'only sanctioned write path and it refuses to write what it cannot audit.';
