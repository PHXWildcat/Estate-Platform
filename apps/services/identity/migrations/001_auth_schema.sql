-- Identity & Access service — auth cluster schema.
-- Source of truth: docs/02-database-schema.md §1, applied with the table
-- conventions from that document's conventions section. The convention SQL
-- below (set_updated_at, *_versions shadow table, append-only REVOKEs,
-- soft-delete-aware unique indexes) matches the output of the @estate/db
-- generators (updatedAtFunctionSql / updatedAtTriggerSql / versionsTableSql /
-- softDeleteUniqueIndexSql / appendOnlySql) byte-for-byte in structure so the
-- conventions stay auditable against one implementation.
--
-- Deviations from docs/02 §1 (all additive, called out inline and in README):
--   * sessions.access_token_h / sessions.access_expires_at
--   * sessions.refresh_token_prev_h
--   * deks table (backs @estate/crypto's DekRepository)
--   * webauthn_challenges table
--   * plain lookup indexes on session token hashes and deks.user_id

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- users (docs/02 §1, verbatim)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_ct          BYTEA NOT NULL,           -- encrypted
  email_bidx        BYTEA NOT NULL,           -- blind index for login lookup
  email_verified_at TIMESTAMPTZ,
  password_hash     TEXT,                     -- Argon2id; NULL if passkey-only
  status            TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','locked','suspended','deceased_pending','settlement','closed')),
  dek_id            UUID NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at        TIMESTAMPTZ
);

-- Matches softDeleteUniqueIndexSql('users', ['email_bidx'], 'ux_users_email').
CREATE UNIQUE INDEX ux_users_email ON users (email_bidx)
WHERE deleted_at IS NULL;

-- Matches updatedAtTriggerSql('users').
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Matches versionsTableSql('users').
CREATE TABLE IF NOT EXISTS users_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON users_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION users_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO users_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_users_versions
BEFORE UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION users_capture_version();

-- ---------------------------------------------------------------------------
-- webauthn_credentials (docs/02 §1, verbatim)
-- ---------------------------------------------------------------------------
CREATE TABLE webauthn_credentials (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id),
  credential_id   BYTEA NOT NULL UNIQUE,
  public_key      BYTEA NOT NULL,
  sign_count      BIGINT NOT NULL DEFAULT 0,
  transports      TEXT[],
  aaguid          UUID,
  nickname        TEXT,
  is_hardware_key BOOLEAN NOT NULL DEFAULT false,
  last_used_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- mfa_methods (docs/02 §1, verbatim)
-- ---------------------------------------------------------------------------
CREATE TABLE mfa_methods (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id),
  kind        TEXT NOT NULL CHECK (kind IN ('totp','sms_recovery','recovery_codes')),
  secret_ct   BYTEA NOT NULL,
  verified_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- devices (docs/02 §1, verbatim)
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES users(id),
  fingerprint_hash BYTEA NOT NULL,
  platform         TEXT, ua_family TEXT,
  first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  trusted_at       TIMESTAMPTZ,
  revoked_at       TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- sessions (docs/02 §1 plus three additive M1 columns, commented below)
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID NOT NULL REFERENCES users(id),
  device_id        UUID REFERENCES devices(id),
  refresh_token_h  BYTEA NOT NULL,            -- hash only; rotation on every use
  ip_ct            BYTEA, geo TEXT,
  risk_score       SMALLINT NOT NULL DEFAULT 0,
  mfa_level        TEXT NOT NULL DEFAULT 'none' CHECK (mfa_level IN ('none','mfa','stepup')),
  stepup_expires_at TIMESTAMPTZ,              -- 5-min freshness window for sensitive ops
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  revoked_at       TIMESTAMPTZ,
  revoke_reason    TEXT,
  -- M1 additions beyond docs/02 §1: Milestone 1 issues opaque server-side
  -- access tokens (only their SHA-256 hash is stored at rest); OIDC/JWT
  -- issuance arrives with the BFF milestone and will retire these columns.
  access_token_h    BYTEA,
  access_expires_at TIMESTAMPTZ,
  -- M1 addition beyond docs/02 §1: previous refresh-token hash, retained for
  -- exactly one rotation so that presenting an already-rotated refresh token
  -- is detectable and revokes the session (rotation-reuse detection).
  refresh_token_prev_h BYTEA
);

CREATE INDEX ix_sessions_refresh_h ON sessions (refresh_token_h);
CREATE INDEX ix_sessions_access_h ON sessions (access_token_h);
CREATE INDEX ix_sessions_refresh_prev_h ON sessions (refresh_token_prev_h);
CREATE INDEX ix_sessions_user_id ON sessions (user_id);

-- ---------------------------------------------------------------------------
-- auth_events (docs/02 §1, verbatim; append-only per conventions)
-- ---------------------------------------------------------------------------
CREATE TABLE auth_events (                     -- login/logout/step-up/risk decisions (also mirrored to audit cluster)
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID, session_id UUID, kind TEXT NOT NULL,
  risk_score SMALLINT, decision TEXT, ip_ct BYTEA, geo TEXT, device_id UUID,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Matches appendOnlySql('auth_events').
REVOKE UPDATE, DELETE ON auth_events FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- deks — wrapped per-user data keys (backs @estate/crypto DekRepository).
-- Not in docs/02 §1 explicitly; required by the conventions section
-- ("each row carries dek_id referencing a wrapped per-user data key").
-- destroyed_at non-null = crypto-shredded (legal erasure primitive).
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

-- ---------------------------------------------------------------------------
-- webauthn_challenges — short-lived server-side challenge storage for
-- WebAuthn ceremonies. Not in docs/02 §1; additive, required so challenges
-- are single-use and server-verified rather than client-supplied.
-- ---------------------------------------------------------------------------
CREATE TABLE webauthn_challenges (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID,
  challenge  TEXT NOT NULL,
  kind       TEXT CHECK (kind IN ('registration','authentication')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
