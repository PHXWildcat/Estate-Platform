-- Plaid isolating service — financial cluster schema (plaid_items/accounts).
-- Source of truth: docs/02-database-schema.md §3, applied with the table
-- conventions from that document. Convention SQL matches the @estate/db
-- generators in structure (checkConventions-auditable).
--
-- Cluster co-ownership note: this service shares the financial cluster with
-- the asset service (same bounded context, docs/01 §2 #3) but owns a DISJOINT
-- table set and its own migrations dir. The shared schema_migrations table
-- tolerates this: the Migrator ignores rows not present in its own dir, the
-- advisory lock serializes runners, and file names are disjoint.
--
-- Deviations from docs/02 §3 (all additive, called out inline + README):
--   * plaid_items.item_id_ct + UNIQUE item_bidx — Plaid webhooks are routed
--     by Plaid's item_id; equality lookup justifies a blind index per the
--     docs/02 conventions. The raw item_id is never stored in plaintext.
--   * plaid_deks table (same shape as the asset service's deks) — the TB5
--     isolation boundary: this service's DEKs are wrapped under a DEDICATED
--     KEK alias ('plaid/kek'), so the asset service's KMS grant can never
--     unwrap a Plaid token DEK even with full database access. A separate
--     table (rather than sharing `deks`) keeps the one-active-DEK-per-user
--     invariant independent per KEK domain.
--   * Plain soft-delete-aware lookup indexes (user_id, plaid_item_id).

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
-- CREATE OR REPLACE: the asset service's migration defines the identical
-- function on this cluster; either service may run first.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- plaid_items (docs/02 §3 + additive item_id_ct/item_bidx)
-- access_token_ct: envelope-encrypted under the user's plaid DEK; decryption
-- happens ONLY inside this service, at sync time, and is an audited event.
-- ---------------------------------------------------------------------------
CREATE TABLE plaid_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  access_token_ct BYTEA NOT NULL,              -- envelope-encrypted; decrypt only inside sync worker
  institution_id TEXT NOT NULL, institution_name TEXT,
  sync_cursor TEXT, status TEXT NOT NULL DEFAULT 'healthy'
    CHECK (status IN ('healthy','login_required','error','revoked')),
  item_id_ct BYTEA NOT NULL,                   -- encrypted Plaid item_id (additive)
  item_bidx  BYTEA NOT NULL,                   -- blind index: webhook routing lookup (additive)
  dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- Soft-delete-aware uniqueness: one live item per Plaid item id.
CREATE UNIQUE INDEX ux_plaid_items_item_bidx ON plaid_items (item_bidx)
WHERE deleted_at IS NULL;

CREATE INDEX ix_plaid_items_user ON plaid_items (user_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_plaid_items_updated_at
BEFORE UPDATE ON plaid_items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS plaid_items_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON plaid_items_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION plaid_items_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO plaid_items_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_plaid_items_versions
BEFORE UPDATE OR DELETE ON plaid_items
FOR EACH ROW EXECUTE FUNCTION plaid_items_capture_version();

-- ---------------------------------------------------------------------------
-- accounts (docs/02 §3, verbatim) — bank/brokerage accounts behind an item.
-- plaid_item_id is NULL for manual accounts (a future assets-service feature;
-- only Plaid-linked rows are written today).
-- ---------------------------------------------------------------------------
CREATE TABLE accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  plaid_item_id UUID REFERENCES plaid_items(id),   -- NULL for manual accounts
  kind TEXT NOT NULL CHECK (kind IN ('checking','savings','brokerage','retirement','loan',
        'credit_card','mortgage','investment','other')),
  name TEXT NOT NULL, mask TEXT,
  account_number_ct BYTEA,
  current_balance_ct BYTEA, balance_as_of TIMESTAMPTZ,
  is_liability BOOLEAN NOT NULL DEFAULT false,
  dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX ix_accounts_user ON accounts (user_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_accounts_plaid_item ON accounts (plaid_item_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_accounts_updated_at
BEFORE UPDATE ON accounts
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS accounts_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON accounts_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION accounts_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO accounts_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_accounts_versions
BEFORE UPDATE OR DELETE ON accounts
FOR EACH ROW EXECUTE FUNCTION accounts_capture_version();

-- ---------------------------------------------------------------------------
-- plaid_deks — wrapped per-user data keys for THIS service only, under the
-- dedicated 'plaid/kek' KEK alias (TB5 isolation: the KMS grant, not the
-- database, is the chokepoint). UNIQUE partial index from day one: at most
-- one active DEK per user; a lost first-write race surfaces as a 23505 that
-- @estate/crypto resolves by adopting the winner.
-- destroyed_at non-null = crypto-shredded (legal erasure primitive).
-- ---------------------------------------------------------------------------
CREATE TABLE plaid_deks (
  dek_id       UUID PRIMARY KEY,
  user_id      UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_plaid_deks_user_active ON plaid_deks (user_id) WHERE destroyed_at IS NULL;
