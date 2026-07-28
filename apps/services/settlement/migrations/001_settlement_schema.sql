-- Settlement service — core cluster schema (PR1: cases, contact attempts,
-- operators, settings). Source of truth: docs/02-database-schema.md §7,
-- applied with the table conventions from that document. Convention SQL
-- matches the @estate/db generators in structure (checkConventions-auditable).
--
-- Cluster co-ownership note: this service shares the core cluster with the
-- profile service (docs/02 §7 places settlement in core because its rows
-- reference core contacts) but owns a DISJOINT table set and its own
-- migrations dir. The shared schema_migrations table tolerates this: the
-- Migrator ignores rows not present in its own dir, the advisory lock
-- serializes runners, and file names are disjoint. Settlement additionally
-- holds READ access to profile's contacts/role_assignments (reporter
-- legitimacy, reportable estates) and NEVER writes them — the flagged
-- extension of the Plaid co-tenancy precedent (CLAUDE.md 2026-07-22).
--
-- Deviations from docs/02 §7 (all additive, called out inline + README):
--   * settlement_cases.resolution/resolved_at — rejected_fraud is one terminal
--     status but two very different events (operator rejected the evidence vs.
--     the living owner voided the case); law-enforcement preservation (§5.1
--     control 6) wants that distinction durable in the row, not only in audit.
--   * settlement_cases.verified_at — the estate-timeline anchor (PR2 task
--     checklists date from verification; date-of-death is deliberately not
--     stored in M7).
--   * settlement_cases has NO deleted_at BY DESIGN: a case — especially a
--     fraudulent one — is evidence and is never deletable (§5.1 control 6).
--     Excluded from checkConventions businessTables; conventions asserted
--     by hand in the integration suite.
--   * settlement_contact_attempts, settlement_operators, settlement_settings
--     are M7 additions: the §5.1 control 3 contact trail, the interim
--     human-review allowlist (decision log: ops-CLI-managed until the TB7
--     operator platform), and the owner's configurable-UP waiting period.
--   * CHECK constraints encode the §5.1 controls the schema can carry:
--     reviewer ≠ reporter; no privileged status without recorded human review;
--     waiting_period requires its deadline; resolution exactly on
--     rejected_fraud.
--
-- PR2 (staged access, tasks, distributions, settlement_deks) ships its DDL
-- with its feature — no dormant schema (CLAUDE.md 2026-07-21).

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
-- CREATE OR REPLACE: the profile service's migration defines the identical
-- function on this cluster; either service may run first.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- settlement_cases (docs/02 §7 + additive columns above)
-- The row is the docs/03 §5.1 state machine; every transition is performed by
-- an authenticated actor through the service (the workflow driver can only
-- record contact attempts — it holds no transition power).
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  decedent_user_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'reported'
    CHECK (status IN ('reported','verifying','waiting_period','verified','active',
                      'distributing','closed','rejected_fraud')),
  reported_by UUID NOT NULL,
  report_source TEXT NOT NULL
    CHECK (report_source IN ('trusted_contact','data_provider','death_certificate_upload')),
  -- Refs to evidence only, never content: document ids/versions uploaded via
  -- the documents service (under the ATTACHER's own account) and provider
  -- match ids. Each entry records addedBy — the documents service cross-checks
  -- it against the document's real owner before decrypting for an operator.
  verification_evidence JSONB NOT NULL DEFAULT '[]',
  human_review_by UUID, human_review_at TIMESTAMPTZ,   -- mandatory before status='verified'
  waiting_period_ends TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,                             -- additive: estate-timeline anchor
  resolution TEXT
    CHECK (resolution IN ('operator_rejected','owner_voided') OR resolution IS NULL),
  resolved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Dual control at the schema layer: the reviewer can never be the reporter.
  CONSTRAINT settlement_cases_reviewer_not_reporter
    CHECK (human_review_by IS NULL OR human_review_by <> reported_by),
  -- Review fields travel together.
  CONSTRAINT settlement_cases_review_pair
    CHECK ((human_review_by IS NULL) = (human_review_at IS NULL)),
  -- No privileged status without recorded human review (§5.1 control 2).
  CONSTRAINT settlement_cases_review_before_privilege
    CHECK (status IN ('reported','verifying','rejected_fraud') OR human_review_by IS NOT NULL),
  -- A waiting period always has a deadline.
  CONSTRAINT settlement_cases_waiting_has_deadline
    CHECK (status <> 'waiting_period' OR waiting_period_ends IS NOT NULL),
  -- verified_at exactly on post-verification statuses.
  CONSTRAINT settlement_cases_verified_at_matches
    CHECK ((verified_at IS NOT NULL) = (status IN ('verified','active','distributing','closed'))),
  -- resolution/resolved_at exactly on rejected_fraud.
  CONSTRAINT settlement_cases_resolution_matches
    CHECK ((resolution IS NOT NULL) = (status = 'rejected_fraud')),
  CONSTRAINT settlement_cases_resolution_pair
    CHECK ((resolution IS NULL) = (resolved_at IS NULL))
);

-- One OPEN case per decedent (docs/03 §5.1: provider matches and reports open
-- A case, not cases). Terminal statuses free the slot.
CREATE UNIQUE INDEX ux_settlement_cases_open ON settlement_cases (decedent_user_id)
WHERE status NOT IN ('closed','rejected_fraud');

CREATE INDEX ix_settlement_cases_status ON settlement_cases (status);
CREATE INDEX ix_settlement_cases_reporter ON settlement_cases (reported_by);
CREATE INDEX ix_settlement_cases_decedent ON settlement_cases (decedent_user_id);

-- The evidence-read authority check filters with `verification_evidence @> ...`;
-- btree cannot serve jsonb containment, and this table never shrinks (cases are
-- evidence and are never deleted), so the lookup would seq-scan forever.
CREATE INDEX ix_settlement_cases_evidence ON settlement_cases
USING gin (verification_evidence jsonb_path_ops);

CREATE TRIGGER trg_settlement_cases_updated_at
BEFORE UPDATE ON settlement_cases
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS settlement_cases_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON settlement_cases_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION settlement_cases_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO settlement_cases_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.id,
    TG_OP,
    to_jsonb(OLD),
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_settlement_cases_versions
BEFORE UPDATE OR DELETE ON settlement_cases
FOR EACH ROW EXECUTE FUNCTION settlement_cases_capture_version();

-- ---------------------------------------------------------------------------
-- settlement_contact_attempts — the §5.1 control 3 trail: every owner-contact
-- attempt during a case, append-only. seq 0 is the report-time notification;
-- the waiting-period schedule starts at seq 1. UNIQUE (case_id, seq) makes the
-- driver idempotent: a concurrent sweep loses the insert race and skips.
-- No delivered_at: the stub notifier reaches nobody, and delivery tracking
-- arrives with the notifications milestone rather than as dead columns.
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_contact_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  seq INT NOT NULL CHECK (seq >= 0),
  channel TEXT NOT NULL CHECK (channel IN ('push','email','sms','voice')),
  attempted_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_settlement_contact_attempts_seq
ON settlement_contact_attempts (case_id, seq);

REVOKE UPDATE, DELETE ON settlement_contact_attempts FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- settlement_operators — the interim human-review allowlist (decision log:
-- managed ONLY by the ops CLI; no runtime grant API; replaced by the TB7
-- operator platform). Modeled on permission_grants: append + revoke, no
-- versions table — the rows themselves are the history.
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_operators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  granted_by UUID,                               -- NULL: granted via the ops CLI
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_settlement_operators_active ON settlement_operators (user_id)
WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- settlement_settings — the owner's waiting period, configurable UP only
-- (docs/03 §5.1: "default 5 days, configurable up"). Keyed by user_id on the
-- profiles/vault_keysets precedent; versioned so a lowered setting is visible
-- history. The service refuses changes while the owner has a non-terminal
-- case: a pending case's parameters are frozen.
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_settings (
  user_id UUID PRIMARY KEY,
  waiting_period_days INT NOT NULL DEFAULT 5
    CHECK (waiting_period_days >= 5 AND waiting_period_days <= 60),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_settlement_settings_updated_at
BEFORE UPDATE ON settlement_settings
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS settlement_settings_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON settlement_settings_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION settlement_settings_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO settlement_settings_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.user_id,
    TG_OP,
    to_jsonb(OLD),
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_settlement_settings_versions
BEFORE UPDATE OR DELETE ON settlement_settings
FOR EACH ROW EXECUTE FUNCTION settlement_settings_capture_version();
