-- ---------------------------------------------------------------------------
-- Notifications service schema (M9) — co-tenant of the CORE cluster with
-- disjoint tables (the settlement/profile precedent; docs/02 §8 note on
-- co-tenancy). Three tables:
--
--   notification_deks        this service's OWN wrapped DEKs under the
--                            dedicated 'notifications/kek' alias — profile and
--                            settlement share the cluster and can never unwrap
--                            a recipient address (docs/03 §5.3: the KMS grant,
--                            not the database, is the chokepoint).
--   notification_recipients  the recipient store: per-user delivery address as
--                            AEAD ciphertext. Fed by identity at registration
--                            and login (the two moments the user themselves
--                            supplies the plaintext), NEVER by a ciphertext
--                            read from another cluster. No blind index: the
--                            only lookup is by user_id — an email-equality
--                            search surface here would be pure attack surface.
--   notification_sends       append-only operational log of what was handed to
--                            a carrier: ids and enums only, never an address,
--                            never content (docs/01 Zone C "notifications
--                            metadata"; the audit-table discipline).
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- notification_deks — same shape as settlement_deks; keyed by the RECIPIENT
-- user. Crypto-shredding a user's notification DEK erases their address from
-- this service in one operation (the erasure story's notifications chapter).
-- ---------------------------------------------------------------------------
CREATE TABLE notification_deks (
  dek_id       UUID PRIMARY KEY,
  user_id      UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

-- At most one ACTIVE DEK per user from day one (the M6 DEK-race rule):
-- a lost first-write race surfaces as a unique violation and the loser
-- adopts the winner (DekConflictError in @estate/crypto).
CREATE UNIQUE INDEX ux_notification_deks_user_active ON notification_deks (user_id)
WHERE destroyed_at IS NULL;

-- ---------------------------------------------------------------------------
-- notification_recipients — one row per user; upsert-in-place with history.
-- ---------------------------------------------------------------------------
CREATE TABLE notification_recipients (
  user_id    UUID PRIMARY KEY,
  email_ct   BYTEA NOT NULL,
  dek_id     UUID NOT NULL REFERENCES notification_deks(dek_id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TRIGGER trg_notification_recipients_updated_at
BEFORE UPDATE ON notification_recipients
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS notification_recipients_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON notification_recipients_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION notification_recipients_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO notification_recipients_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_notification_recipients_versions
BEFORE UPDATE OR DELETE ON notification_recipients
FOR EACH ROW EXECUTE FUNCTION notification_recipients_capture_version();

-- ---------------------------------------------------------------------------
-- notification_sends — what the platform handed a carrier, append-only.
-- `outcome` is the truth the callers' bookkeeping records: 'sent' reached the
-- carrier; 'no_recipient' means the store had no address; 'carrier_failure'
-- means the carrier refused or the transport failed. provider_message_id is
-- the carrier's receipt (not PII — an SES message id), kept for the
-- delivery-channel leakage review and for support triage.
-- ---------------------------------------------------------------------------
CREATE TABLE notification_sends (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID NOT NULL,
  kind                TEXT NOT NULL CHECK (kind IN (
    'emergency.requested','emergency.blocked','emergency.reminder',
    'emergency.released','emergency.revoked',
    'vault.reset','vault.grantees_changed',
    'settlement.case_opened','settlement.owner_contact'
  )),
  requested_channel   TEXT NOT NULL CHECK (requested_channel IN ('push','email','sms','voice')),
  channel             TEXT NOT NULL CHECK (channel IN ('email')),
  outcome             TEXT NOT NULL CHECK (outcome IN ('sent','no_recipient','carrier_failure')),
  provider_message_id TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON notification_sends FROM PUBLIC;

CREATE INDEX ix_notification_sends_user ON notification_sends (user_id, created_at DESC);
