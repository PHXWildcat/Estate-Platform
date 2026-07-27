-- Emergency access (docs/01 §2.5, docs/02 §5, docs/03 §5.2).
--
-- The vault's answer to "the owner cannot open it any more". Designated
-- contacts hold Shamir shares of one half of a recovery key; the platform holds
-- the other half and releases it only after a waiting period the owner can
-- interrupt. The crypto lives in @estate/vault-crypto; this schema stores the
-- state machine and the opaque halves.
--
-- Deviations from docs/02 §5, all additive and called out in the README:
--   * emergency_access_policies gains grantee_user_id (docs/02 has only
--     grantee_contact_id). The vault service cannot dereference a contact -
--     contacts live in the core cluster and there are no cross-cluster reads
--     (docs/02 §8) - but it MUST be able to authorize the grantee when they
--     request access. So the owner's client resolves contact ->
--     contacts.linked_user_id and submits both: the contact id is kept as the
--     documented, opaque back-reference, and the user id is what this service
--     authorizes on.
--   * grantee_public_key_sha256 records which key each share was sealed to, so
--     a later key change is detectable rather than silent (docs/03 §5.2 key
--     substitution).
--   * cooldown/re-arm columns for the sticky-deny rule below.
--   * emergency_access_configs is new: docs/02 §5 keeps everything per-grantee,
--     but the two-level split has owner-level material (the platform half, the
--     recovery-wrapped master key, the threshold) that belongs to the escrow as
--     a whole, not to any one grantee.
--   * vault_keysets gains the grantee keypair columns.

-- ---------------------------------------------------------------------------
-- vault_keysets: the grantee keypair
-- ---------------------------------------------------------------------------
-- Every user who might be named as someone's emergency contact needs a
-- public key others can seal shares to. public_key is plaintext by definition
-- (it is a public key); the private half is wrapped under this user's OWN
-- master key, so only they can ever use it.
ALTER TABLE vault_keysets
  ADD COLUMN public_key BYTEA,                 -- raw P-256 point, publishable
  ADD COLUMN wrapped_private_key BYTEA;        -- wrapped under this user's MK

-- Either both or neither: a public key with no matching private half would be
-- an invitation to seal shares nobody can open.
ALTER TABLE vault_keysets
  ADD CONSTRAINT vault_keysets_recovery_keypair_complete
  CHECK ((public_key IS NULL) = (wrapped_private_key IS NULL));

-- ---------------------------------------------------------------------------
-- emergency_access_configs (owner-level escrow material)
-- ---------------------------------------------------------------------------
-- platform_part is the half that makes the waiting period real: colluding
-- grantees hold only the other half, which is information-theoretically
-- useless on its own. Releasing this column early is the one server-side action
-- that would defeat the control, which is why every release is audited.
CREATE TABLE emergency_access_configs (
  user_id UUID PRIMARY KEY,
  threshold INT NOT NULL CHECK (threshold >= 1),
  platform_part BYTEA NOT NULL,
  wrapped_master_key_recovery BYTEA NOT NULL,   -- MK wrapped by the recovery key
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_emergency_access_configs_updated_at
BEFORE UPDATE ON emergency_access_configs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS emergency_access_configs_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON emergency_access_configs_versions FROM PUBLIC;

-- Same redaction rule as vault_keysets, for the same reason: a superseded
-- platform half plus a superseded recovery wrap would together reconstruct an
-- escrow the owner has already replaced. History records that the escrow
-- changed, when, by whom, and at what threshold - never the material.
CREATE OR REPLACE FUNCTION emergency_access_configs_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO emergency_access_configs_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.user_id,
    TG_OP,
    to_jsonb(OLD) - 'platform_part' - 'wrapped_master_key_recovery',
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_emergency_access_configs_versions
BEFORE UPDATE OR DELETE ON emergency_access_configs
FOR EACH ROW EXECUTE FUNCTION emergency_access_configs_capture_version();

-- ---------------------------------------------------------------------------
-- emergency_access_policies (docs/02 §5 + the additions above)
-- ---------------------------------------------------------------------------
CREATE TABLE emergency_access_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  grantee_contact_id UUID NOT NULL,             -- docs/02 §5; opaque here
  grantee_user_id UUID NOT NULL,                -- who this service authorizes
  waiting_period_hours INT NOT NULL CHECK (waiting_period_hours >= 24),
  key_share_ct BYTEA NOT NULL,                  -- Shamir share, sealed to grantee
  grantee_public_key_sha256 BYTEA NOT NULL,     -- which key it was sealed to
  status TEXT NOT NULL DEFAULT 'configured'
    CHECK (status IN ('configured','requested','waiting','denied_by_owner','released','revoked')),
  requested_at TIMESTAMPTZ, releases_at TIMESTAMPTZ,
  -- Sticky deny (docs/03 §5.2): a denial holds until the owner explicitly
  -- re-arms, so a grantee cannot simply re-request every week until the owner
  -- is hospitalised or offline. denied_at also drives the request cooldown.
  denied_at TIMESTAMPTZ,
  released_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  request_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- One live policy per (owner, grantee): re-configuring replaces rather than
-- accumulating, so there is never an ambiguous set of shares for one contact.
CREATE UNIQUE INDEX ux_emergency_access_policies_owner_grantee
  ON emergency_access_policies(user_id, grantee_user_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_emergency_access_policies_grantee
  ON emergency_access_policies(grantee_user_id) WHERE deleted_at IS NULL;
-- Drives the sweep that moves matured requests from 'waiting' to releasable.
CREATE INDEX ix_emergency_access_policies_releases_at
  ON emergency_access_policies(releases_at) WHERE status = 'waiting';

CREATE TRIGGER trg_emergency_access_policies_updated_at
BEFORE UPDATE ON emergency_access_policies
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Full row image here: key_share_ct is sealed to the grantee's public key, so
-- the server gains nothing by retaining it, and the history of who was granted
-- emergency access and when is exactly the audit record docs/03 §5.2 wants the
-- owner to be able to review afterwards.
CREATE TABLE IF NOT EXISTS emergency_access_policies_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON emergency_access_policies_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION emergency_access_policies_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO emergency_access_policies_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_emergency_access_policies_versions
BEFORE UPDATE OR DELETE ON emergency_access_policies
FOR EACH ROW EXECUTE FUNCTION emergency_access_policies_capture_version();

-- ---------------------------------------------------------------------------
-- emergency_access_notifications (operational)
-- ---------------------------------------------------------------------------
-- What the owner was told, and when. docs/03 §5.2's control is "multi-channel
-- owner notification with one-tap deny", so the fact that a notification was
-- attempted is itself evidence and belongs next to the state machine. Content
-- is never stored - only the event kind and the channel - mirroring docs/01
-- §2.10: notifications carry pointers, never estate content.
CREATE TABLE emergency_access_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_id UUID NOT NULL REFERENCES emergency_access_policies(id),
  user_id UUID NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('requested','blocked','reminder','released','revoked')),
  channel TEXT NOT NULL,
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_emergency_access_notifications_policy
  ON emergency_access_notifications(policy_id, created_at DESC);
