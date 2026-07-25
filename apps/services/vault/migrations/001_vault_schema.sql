-- Vault service (Zone A) - vault cluster schema.
-- Source of truth: docs/02-database-schema.md §5, applied with the table
-- conventions from that document's conventions section. The convention SQL
-- below (set_updated_at, *_versions shadow table, append-only REVOKEs)
-- matches the output of the @estate/db generators (updatedAtFunctionSql /
-- updatedAtTriggerSql / versionsTableSql / appendOnlySql) in structure so the
-- conventions stay auditable against one implementation (checkConventions).
--
-- WHAT MAKES THIS CLUSTER DIFFERENT: every sensitive value here is encrypted
-- on the user's device before it arrives. There is no dek_id column anywhere,
-- no KMS involvement, and no blind index, because there is nothing in this
-- schema the server could decrypt or search even if it wanted to. A full dump
-- of this cluster yields verifiers, salts, and opaque blobs (docs/01 §1,
-- Zone A). Any future column that would let the server read item contents is
-- a zone violation, not a feature.
--
-- Deviations from docs/02 §5 (all additive or faithful, called out inline and
-- in the service README):
--   * vault_keysets versions its rows by user_id (its PRIMARY KEY) rather than
--     a surrogate `id`, because docs/02 §5 defines it with `user_id UUID
--     PRIMARY KEY` and no `id` - the profiles precedent (profile service
--     001_core_schema.sql). It is therefore verified by a custom check rather
--     than the generic id-based checkConventions().
--   * the vault_keysets row image REDACTS wrapped_master_key and srp_verifier
--     (see the trigger below for why).
--   * two operational tables docs/02 §5 does not enumerate
--     (vault_srp_handshakes, vault_sessions), in the same spirit as
--     auth.sessions: short-lived protocol state, not versioned business data.
--   * a size CHECK on blob_ct, since an opaque blob is the one thing the
--     server can measure but not inspect.
--   * emergency_access_policies from docs/02 §5 is deliberately NOT created
--     here. It ships with the emergency-access feature (M6 PR2) so no dormant
--     schema sits under migration drift detection - the M3 Plaid-DDL decision
--     (CLAUDE.md 2026-07-21).

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- vault_keysets (docs/02 §5, verbatim - SRP verifier + wrapped keys)
-- ---------------------------------------------------------------------------
CREATE TABLE vault_keysets (
  user_id UUID PRIMARY KEY,
  srp_verifier BYTEA NOT NULL, srp_salt BYTEA NOT NULL,
  wrapped_master_key BYTEA NOT NULL,            -- wrapped by client-derived key; opaque to server
  kdf_params JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_vault_keysets_updated_at
BEFORE UPDATE ON vault_keysets
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- versionsTableSql shape, capturing OLD.user_id (the PK) as row_id.
CREATE TABLE IF NOT EXISTS vault_keysets_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON vault_keysets_versions FROM PUBLIC;

-- The row image deliberately OMITS wrapped_master_key and srp_verifier.
--
-- Everywhere else in the platform, keeping the full prior row is exactly right:
-- it is the audit trail, and the ciphertext in it is readable with the same
-- key as the live row. Here the opposite is true. A superseded
-- wrapped_master_key is not history, it is a live attack asset: the master key
-- does not change when the vault password does, so an attacker who later
-- phishes a RETIRED password could use a retained old wrapping to unwrap the
-- CURRENT master key - and the whole point of changing a vault password is
-- that doing so ends the old password's power. The verifier is dropped for the
-- same reason (it is the offline-attack target).
--
-- What survives is everything with audit value: who changed the keyset, when,
-- under which KDF parameters and salt. Same instinct as the audit firewall -
-- record the event, never the secret. This is also what lets a password change
-- stay a simple atomic replace instead of forcing a master-key rotation and a
-- full-vault rewrap every time.
CREATE OR REPLACE FUNCTION vault_keysets_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO vault_keysets_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.user_id,
    TG_OP,
    to_jsonb(OLD) - 'wrapped_master_key' - 'srp_verifier',
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vault_keysets_versions
BEFORE UPDATE OR DELETE ON vault_keysets
FOR EACH ROW EXECUTE FUNCTION vault_keysets_capture_version();

-- ---------------------------------------------------------------------------
-- vault_items (docs/02 §5, verbatim + a blob size bound)
-- ---------------------------------------------------------------------------
-- item_type is plaintext by design (docs/02 §5 defines it as a CHECK-ed enum):
-- it lets the client render a list without decrypting everything first. The
-- accepted leak is per-user item-type counts and nothing else - titles, URLs,
-- usernames and secrets all live inside blob_ct.
CREATE TABLE vault_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  item_type TEXT NOT NULL CHECK (item_type IN ('password','pin','recovery_codes','seed_phrase',
    'private_key','secure_note','license','attachment')),
  blob_ct BYTEA NOT NULL,                       -- client-encrypted; includes item metadata
  blob_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
  -- 68 KiB: the API cap, restated where the data lives. Leaves ~64 KiB of item
  -- content after the envelope overhead. Large attachments need a separate
  -- streaming path and are a follow-up, not a silent allowance here.
  CONSTRAINT vault_items_blob_size CHECK (octet_length(blob_ct) BETWEEN 1 AND 69632),
  CONSTRAINT vault_items_blob_version_positive CHECK (blob_version >= 1)
);

CREATE INDEX ix_vault_items_user_live ON vault_items(user_id, updated_at DESC, id)
  WHERE deleted_at IS NULL;

CREATE TRIGGER trg_vault_items_updated_at
BEFORE UPDATE ON vault_items
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Full row image here, unlike vault_keysets: an old blob is ciphertext under
-- the same master key as the live row, so retaining it grants no extra power,
-- and item version history is a product feature (password history).
CREATE TABLE IF NOT EXISTS vault_items_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON vault_items_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION vault_items_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO vault_items_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_vault_items_versions
BEFORE UPDATE OR DELETE ON vault_items
FOR EACH ROW EXECUTE FUNCTION vault_items_capture_version();

-- ---------------------------------------------------------------------------
-- vault_srp_handshakes (operational; the auth.sessions precedent)
-- ---------------------------------------------------------------------------
-- One row per in-flight SRP exchange, single-use and short-lived. Holding the
-- server's ephemeral secret `b` for two minutes gives an attacker with the
-- database nothing the verifier in vault_keysets did not already give them.
-- Not a business table: no soft delete, no version shadow, swept by age.
CREATE TABLE vault_srp_handshakes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  server_public BYTEA NOT NULL,                 -- B, sent to the client
  server_secret BYTEA NOT NULL,                 -- b, never leaves the server
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ                       -- set on the FIRST verify attempt, pass or fail
);

CREATE INDEX ix_vault_srp_handshakes_expires ON vault_srp_handshakes(expires_at);

-- ---------------------------------------------------------------------------
-- vault_sessions (operational; mirrors auth.sessions' token handling)
-- ---------------------------------------------------------------------------
-- Proof that this user completed an SRP exchange recently. The token is stored
-- as a SHA-256 digest only, like identity's access tokens: the preimage has
-- 256 bits of entropy, so brute force is the attack that does not exist.
--
-- account_session_id binds the vault session to the account session that
-- opened it, so a stolen vault token is useless from a different login.
-- keyset_auth_key is derived from the SRP session key and authenticates a
-- later keyset replacement; it is a per-session value that reveals nothing
-- about the password or the master key (the server computes the SRP session
-- key by construction).
CREATE TABLE vault_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  token_h BYTEA NOT NULL,
  account_session_id UUID NOT NULL,
  keyset_auth_key BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT
);

CREATE INDEX ix_vault_sessions_token_h ON vault_sessions(token_h);
CREATE INDEX ix_vault_sessions_user ON vault_sessions(user_id);
