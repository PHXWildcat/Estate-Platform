-- Settlement PR2 — post-verification administration: staged executor access,
-- the task checklist, distribution tracking with dual control, and this
-- service's own DEK domain. Source of truth: docs/02-database-schema.md §7 and
-- docs/03-threat-model.md §5.1 control 5 ("executor access post-verification is
-- STAGED: inventory first, vault emergency-access last, each stage separately
-- approved").
--
-- Ships with its feature, not ahead of it (CLAUDE.md 2026-07-21): PR1
-- deliberately created none of this.
--
-- Deviations from docs/02 §7 (all additive, called out inline + README):
--   * settlement_access_stages is new — §5.1 control 5 has no table in docs/02,
--     but staged access needs durable per-stage approval state.
--   * distributions.created_by (the RECORDER) is additive and required by
--     docs/02's own dual-control note: "approver ≠ recorder" cannot be checked
--     without recording who the recorder was.
--   * distributions.dek_id is additive per the docs/02 conventions ("each row
--     carries a dek_id referencing a wrapped per-user data key") — amount_ct is
--     ciphertext and needs its key reference.
--   * settlement_deks mirrors plaid_deks: this service's DEKs are wrapped under
--     a DEDICATED KEK alias ('settlement/kek'), so no other service's KMS grant
--     can unwrap a distribution amount (docs/03 §5.3 — the KMS grant, not the
--     database, is the chokepoint).
--
-- DUAL CONTROL, implemented as a CHECK rather than a trigger. docs/02 §7 says
-- "approver ≠ recorder enforced by trigger", written before `created_by` was on
-- the row. Now that both parties are columns of the SAME row, a CHECK is the
-- stronger primitive: it is evaluated immediately on every INSERT and UPDATE,
-- cannot be deferred, disabled per-session, or bypassed by a trigger-owner, and
-- there is no window in which a violating row exists. The intent of the doc is
-- preserved exactly; only the mechanism is simpler and harder to defeat.

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
-- CREATE OR REPLACE: profile co-owns this cluster and defines the identical
-- function; either service may run first.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- settlement_access_stages — docs/03 §5.1 control 5. One row per (case, stage).
-- The executor REQUESTS a stage; an operator APPROVES it; the two can never be
-- the same person (CHECK). Stage ORDER (inventory → documents → vault) is
-- enforced in the service under the case row lock, because it is a predicate
-- over sibling rows rather than a row-local invariant.
--
-- Not a soft-delete business table: a stage grant is an access record and is
-- revoked, never deleted (the settlement_cases precedent). Excluded from
-- checkConventions businessTables; asserted by hand in the integration suite.
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_access_stages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  stage TEXT NOT NULL CHECK (stage IN ('inventory','documents','vault')),
  status TEXT NOT NULL DEFAULT 'requested'
    CHECK (status IN ('requested','approved','denied','revoked')),
  requested_by UUID NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  decided_by UUID, decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Dual control: the operator who approves a stage is never the executor who
  -- requested it.
  CONSTRAINT settlement_access_stages_approver_not_requester
    CHECK (decided_by IS NULL OR decided_by <> requested_by),
  CONSTRAINT settlement_access_stages_decision_pair
    CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
  -- A decided status must record who decided it.
  CONSTRAINT settlement_access_stages_decided_has_decider
    CHECK (status = 'requested' OR decided_by IS NOT NULL)
);

-- One live stage record per (case, stage): a revoked/denied stage is re-requestable.
CREATE UNIQUE INDEX ux_settlement_access_stages_live
ON settlement_access_stages (case_id, stage)
WHERE status IN ('requested','approved');

CREATE INDEX ix_settlement_access_stages_case ON settlement_access_stages (case_id);
CREATE INDEX ix_settlement_access_stages_requester ON settlement_access_stages (requested_by);

CREATE TRIGGER trg_settlement_access_stages_updated_at
BEFORE UPDATE ON settlement_access_stages
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS settlement_access_stages_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON settlement_access_stages_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION settlement_access_stages_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO settlement_access_stages_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_settlement_access_stages_versions
BEFORE UPDATE OR DELETE ON settlement_access_stages
FOR EACH ROW EXECUTE FUNCTION settlement_access_stages_capture_version();

-- ---------------------------------------------------------------------------
-- settlement_tasks (docs/02 §7, verbatim shape) — the estate checklist,
-- generated at verification from the in-repo template and completed by the
-- executor. court_doc_version_id references a document_versions row in the
-- DOCUMENTS cluster: no FK across clusters (docs/02 §8).
-- A full soft-delete business table (docs/02 §7 gives it deleted_at).
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  title TEXT NOT NULL, category TEXT, assigned_role TEXT,
  due_at DATE, completed_at TIMESTAMPTZ, completed_by UUID,
  court_doc_version_id UUID,                    -- uploaded letters testamentary, etc.
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  CONSTRAINT settlement_tasks_completion_pair
    CHECK ((completed_at IS NULL) = (completed_by IS NULL))
);

CREATE INDEX ix_settlement_tasks_case ON settlement_tasks (case_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_settlement_tasks_updated_at
BEFORE UPDATE ON settlement_tasks
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS settlement_tasks_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON settlement_tasks_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION settlement_tasks_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO settlement_tasks_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_settlement_tasks_versions
BEFORE UPDATE OR DELETE ON settlement_tasks
FOR EACH ROW EXECUTE FUNCTION settlement_tasks_capture_version();

-- ---------------------------------------------------------------------------
-- distributions (docs/02 §7 + created_by + dek_id) — who gets what, tracked
-- under DUAL CONTROL. amount_ct is envelope ciphertext under this service's own
-- DEK; the plaintext amount never touches a column, a log, or an audit event.
-- No deleted_at (docs/02 §7 gives none): a distribution is financial record
-- keeping and is disputed or superseded, never deleted. Excluded from
-- checkConventions businessTables; asserted by hand.
-- ---------------------------------------------------------------------------
CREATE TABLE distributions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  asset_id UUID, beneficiary_contact_id UUID NOT NULL,
  amount_ct BYTEA, dek_id UUID,                 -- additive: ciphertext needs its key ref
  status TEXT NOT NULL DEFAULT 'planned'
    CHECK (status IN ('planned','approved','in_progress','completed','disputed')),
  created_by UUID NOT NULL,                     -- additive: the RECORDER (dual control)
  approved_by UUID, approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- THE dual-control invariant (docs/02 §7): the approver is never the
  -- recorder. Row-local, so a CHECK enforces it immediately and undeferrably.
  CONSTRAINT distributions_approver_not_recorder
    CHECK (approved_by IS NULL OR approved_by <> created_by),
  CONSTRAINT distributions_approval_pair
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
  -- Nothing past 'planned' without a recorded approval.
  CONSTRAINT distributions_approved_has_approver
    CHECK (status = 'planned' OR approved_by IS NOT NULL),
  -- Ciphertext and its key reference travel together.
  CONSTRAINT distributions_amount_pair
    CHECK ((amount_ct IS NULL) = (dek_id IS NULL))
);

CREATE INDEX ix_distributions_case ON distributions (case_id);
CREATE INDEX ix_distributions_beneficiary ON distributions (beneficiary_contact_id);

CREATE TRIGGER trg_distributions_updated_at
BEFORE UPDATE ON distributions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS distributions_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON distributions_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION distributions_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO distributions_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_distributions_versions
BEFORE UPDATE OR DELETE ON distributions
FOR EACH ROW EXECUTE FUNCTION distributions_capture_version();

-- ---------------------------------------------------------------------------
-- settlement_deks — wrapped per-user data keys for THIS service only, under the
-- dedicated 'settlement/kek' alias (the plaid_deks precedent). UNIQUE partial
-- index from day one: at most one active DEK per user; a lost first-write race
-- surfaces as a 23505 that @estate/crypto resolves by adopting the winner.
-- destroyed_at non-null = crypto-shredded (legal erasure primitive).
-- Keyed by the DECEDENT, so shredding an estate's key retires its amounts.
-- ---------------------------------------------------------------------------
CREATE TABLE settlement_deks (
  dek_id       UUID PRIMARY KEY,
  user_id      UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_settlement_deks_user_active ON settlement_deks (user_id)
WHERE destroyed_at IS NULL;
