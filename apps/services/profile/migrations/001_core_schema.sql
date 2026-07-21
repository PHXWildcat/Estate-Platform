-- Profile & Contacts service — core cluster schema.
-- Source of truth: docs/02-database-schema.md §2, applied with the table
-- conventions from that document's conventions section. The convention SQL
-- below (set_updated_at, *_versions shadow table, append-only REVOKEs,
-- soft-delete-aware unique index) matches the output of the @estate/db
-- generators (updatedAtFunctionSql / updatedAtTriggerSql / versionsTableSql /
-- softDeleteUniqueIndexSql / appendOnlySql) in structure so the conventions
-- stay auditable against one implementation (checkConventions).
--
-- Deviations from docs/02 §2 (all additive/faithful, called out inline + README):
--   * profiles versions its rows by user_id (its PRIMARY KEY) rather than a
--     surrogate `id`, because docs/02 §2 defines profiles with `user_id UUID
--     PRIMARY KEY` and no `id`. It is therefore verified in tests by a custom
--     check rather than the generic id-based checkConventions().
--   * deks table (backs @estate/crypto's DekRepository), mirroring identity.
--   * plain lookup indexes (owner_user_id, linked_user_id, FKs).

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- profiles (docs/02 §2, verbatim — 1:1 with auth.users; no cross-cluster FK)
-- ---------------------------------------------------------------------------
CREATE TABLE profiles (
  user_id        UUID PRIMARY KEY,            -- 1:1 with auth.users (no FK across clusters; consistency via events)
  legal_name_ct  BYTEA NOT NULL,
  dob_ct         BYTEA,
  ssn_ct         BYTEA,                       -- last4 stored separately for display
  ssn_last4_ct   BYTEA,
  address_ct     BYTEA, phone_ct BYTEA,
  occupation_ct  BYTEA,
  marital_status TEXT CHECK (marital_status IN ('single','married','domestic_partnership','divorced','widowed')),
  state_of_residence CHAR(2),                 -- drives document template selection; plaintext by design
  dek_id         UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TRIGGER trg_profiles_updated_at
BEFORE UPDATE ON profiles
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- versionsTableSql shape, but capturing OLD.user_id (profiles' PK) as row_id.
CREATE TABLE IF NOT EXISTS profiles_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON profiles_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION profiles_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO profiles_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_profiles_versions
BEFORE UPDATE OR DELETE ON profiles
FOR EACH ROW EXECUTE FUNCTION profiles_capture_version();

-- ---------------------------------------------------------------------------
-- family_members (docs/02 §2, verbatim)
-- ---------------------------------------------------------------------------
CREATE TABLE family_members (                  -- children, parents, spouse: needed for wills/guardianship
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  relation TEXT NOT NULL CHECK (relation IN ('spouse','child','parent','sibling','other')),
  name_ct BYTEA NOT NULL, dob_ct BYTEA, is_minor BOOLEAN,
  notes_ct BYTEA, dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX ix_family_members_user_id ON family_members (user_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_family_members_updated_at
BEFORE UPDATE ON family_members
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS family_members_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON family_members_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION family_members_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO family_members_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_family_members_versions
BEFORE UPDATE OR DELETE ON family_members
FOR EACH ROW EXECUTE FUNCTION family_members_capture_version();

-- ---------------------------------------------------------------------------
-- contacts (docs/02 §2, verbatim) — the estate contact repository
-- ---------------------------------------------------------------------------
CREATE TABLE contacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL,
  name_ct BYTEA NOT NULL, email_ct BYTEA, email_bidx BYTEA,
  phone_ct BYTEA, address_ct BYTEA,
  relationship TEXT, professional_kind TEXT
    CHECK (professional_kind IN ('attorney','cpa','financial_advisor','doctor','other') OR professional_kind IS NULL),
  linked_user_id UUID,                         -- set when contact accepts an invite and becomes a platform user
  notes_ct BYTEA, dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- Soft-delete-aware uniqueness: one live contact per (owner, email) — email
-- equality via the blind index, so no decryption is needed to dedupe.
CREATE UNIQUE INDEX ux_contacts_owner_email ON contacts (owner_user_id, email_bidx)
WHERE deleted_at IS NULL AND email_bidx IS NOT NULL;

CREATE INDEX ix_contacts_owner ON contacts (owner_user_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_contacts_linked_user ON contacts (linked_user_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_contacts_updated_at
BEFORE UPDATE ON contacts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS contacts_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON contacts_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION contacts_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO contacts_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_contacts_versions
BEFORE UPDATE OR DELETE ON contacts
FOR EACH ROW EXECUTE FUNCTION contacts_capture_version();

-- ---------------------------------------------------------------------------
-- role_assignments (docs/02 §2, verbatim) — who is trustee/executor/etc. of what
-- ---------------------------------------------------------------------------
CREATE TABLE role_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL,
  contact_id    UUID NOT NULL REFERENCES contacts(id),
  role TEXT NOT NULL CHECK (role IN
    ('trustee','successor_trustee','executor','beneficiary','guardian','agent_financial',
     'agent_medical','attorney','cpa','financial_advisor','family_member','viewer')),
  scope_type TEXT NOT NULL CHECK (scope_type IN ('estate','trust','document','asset','account')),
  scope_id   UUID,                             -- NULL = whole estate
  effective_condition TEXT NOT NULL DEFAULT 'immediate'
    CHECK (effective_condition IN ('immediate','on_incapacity','on_death_verified')),
  starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX ix_role_assignments_owner ON role_assignments (owner_user_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_role_assignments_contact ON role_assignments (contact_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_role_assignments_updated_at
BEFORE UPDATE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS role_assignments_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON role_assignments_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION role_assignments_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO role_assignments_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_role_assignments_versions
BEFORE UPDATE OR DELETE ON role_assignments
FOR EACH ROW EXECUTE FUNCTION role_assignments_capture_version();

-- ---------------------------------------------------------------------------
-- permission_grants (docs/02 §2, verbatim) — ABAC field/resource visibility.
-- Not a mutable business table (no updated_at/deleted_at); revocation is via
-- revoked_at, so it carries no updated_at trigger or versions shadow table.
-- ---------------------------------------------------------------------------
CREATE TABLE permission_grants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_assignment_id UUID NOT NULL REFERENCES role_assignments(id),
  resource TEXT NOT NULL,                      -- e.g. 'asset','document','vault_item','dashboard.networth','contact'
  action   TEXT NOT NULL,                      -- 'read','download','manage'
  constraint_expr JSONB,                       -- Cedar-compatible condition, e.g. {"only_if_named_beneficiary": true}
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX ix_permission_grants_role_assignment ON permission_grants (role_assignment_id)
WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- deks — wrapped per-user data keys (backs @estate/crypto DekRepository).
-- Required by the conventions section ("each row carries dek_id referencing a
-- wrapped per-user data key"). destroyed_at non-null = crypto-shredded.
-- ---------------------------------------------------------------------------
CREATE TABLE deks (
  dek_id       UUID PRIMARY KEY,
  user_id      UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

CREATE INDEX ix_deks_user_active ON deks (user_id) WHERE destroyed_at IS NULL;
