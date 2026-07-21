-- Asset service — financial cluster schema (manual-asset ledger only).
-- Source of truth: docs/02-database-schema.md §3, applied with the table
-- conventions from that document. Convention SQL matches the @estate/db
-- generators in structure (checkConventions-auditable).
--
-- Scope note: plaid_items and accounts (docs/02 §3) are DELIBERATELY absent —
-- they land with the Plaid isolating service (next M3 PR). Shipping dormant
-- DDL now would freeze it under the migrator's drift detection before the
-- service that owns its semantics exists.
--
-- Deviations from docs/02 §3 (all additive, called out inline + README):
--   * ux_asset_events_event_id — idempotency: command retries carrying the
--     same client event_id become no-ops instead of duplicate ledger entries.
--   * ix_asset_events_user — temporal replay per owner (as-of queries,
--     projection rebuild) without scanning other tenants' events.
--   * ux_asset_beneficiaries_live — one live designation row per
--     (asset, contact, designation class).
--   * ux_deks_user_active is UNIQUE (docs' identity/profile clusters use a
--     plain index) — closes the getOrCreateDek cross-request race (M2
--     follow-up) at the database for this cluster from day one.
--   * share-sum CONSTRAINT TRIGGER enforces <= 100 per (asset, designation),
--     not == 100: strict equality is unenforceable while designations are
--     entered incrementally. The API reports per-designation completeness;
--     the async conflict analyzer (docs/02 §3 comment) owns "exactly 100".
--
-- Conventions note: assets_view is a REBUILDABLE PROJECTION of asset_events
-- (docs/02 §8) — its full history IS the ledger, so it carries no _versions
-- shadow table and is exempt from the business-table checkConventions profile
-- (verified by custom assertions in assets.int.spec.ts). asset_events is
-- append-only: no updated_at/deleted_at/versions; UPDATE/DELETE revoked.

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- asset_events (docs/02 §3, verbatim) — the event-sourced write model.
-- The ledger IS the source of truth; everything else in this cluster is a
-- projection of it.
-- ---------------------------------------------------------------------------
CREATE TABLE asset_events (
  seq        BIGINT GENERATED ALWAYS AS IDENTITY,
  event_id   UUID NOT NULL DEFAULT gen_random_uuid(),
  asset_id   UUID NOT NULL,
  user_id    UUID NOT NULL,
  event_type TEXT NOT NULL,                    -- AssetCreated, ValuationRecorded, OwnershipChanged,
                                               -- BeneficiaryDesignated, BeneficiaryRemoved,
                                               -- AssetDetailsUpdated, AssetRetired
  payload_ct BYTEA NOT NULL,                   -- encrypted event body (AAD binds user_id + event_id)
  actor_id   UUID NOT NULL, actor_role TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (asset_id, seq)
);
REVOKE UPDATE, DELETE ON asset_events FROM PUBLIC;   -- append-only

-- Additive: idempotency guard (client-supplied event_id retries are no-ops).
CREATE UNIQUE INDEX ux_asset_events_event_id ON asset_events (event_id);
-- Additive: per-owner temporal replay (as-of queries, rebuild verification).
CREATE INDEX ix_asset_events_user ON asset_events (user_id, occurred_at);

-- ---------------------------------------------------------------------------
-- assets_view (docs/02 §3, verbatim) — projected read model for
-- dashboard/search. Rebuildable from asset_events at any time; the rebuild
-- CLI (rebuild-cli.ts) is the disaster-recovery integrity check.
-- ---------------------------------------------------------------------------
CREATE TABLE assets_view (
  asset_id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('cash','gold','silver','jewelry','art','collectible',
    'business','llc','private_equity','crypto','real_estate','vehicle','aircraft','boat',
    'intellectual_property','life_insurance','ltc_insurance','annuity','safe_deposit_box','digital_asset','other')),
  title TEXT NOT NULL,
  est_value_ct BYTEA, valuation_as_of DATE, valuation_source TEXT,
  ownership_pct NUMERIC(6,3) NOT NULL DEFAULT 100.000,
  cost_basis_ct BYTEA, location_ct BYTEA, notes_ct BYTEA,
  in_trust BOOLEAN NOT NULL DEFAULT false,     -- drives "estate funding %" metric
  funding_status TEXT CHECK (funding_status IN ('unfunded','in_progress','funded','na')),
  dek_id UUID NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX ix_assets_view_user ON assets_view (user_id) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- asset_beneficiaries (docs/02 §3, verbatim + conventions) — beneficiary
-- designations per asset. Rows are written ONLY inside the command
-- transaction as the projection of Beneficiary* ledger events (remove =
-- soft delete), but as a mutable business table it carries the full
-- conventions (updated_at trigger, versions shadow, REVOKEs).
-- contact_id references the core cluster's contacts — no FK across clusters;
-- consistency via events (docs/02 §8).
-- ---------------------------------------------------------------------------
CREATE TABLE asset_beneficiaries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID NOT NULL, contact_id UUID NOT NULL,
  designation TEXT NOT NULL CHECK (designation IN ('primary','contingent')),
  share_pct NUMERIC(6,3) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- Additive: one live designation row per (asset, contact, class).
CREATE UNIQUE INDEX ux_asset_beneficiaries_live
ON asset_beneficiaries (asset_id, contact_id, designation)
WHERE deleted_at IS NULL;

CREATE INDEX ix_asset_beneficiaries_asset ON asset_beneficiaries (asset_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_asset_beneficiaries_updated_at
BEFORE UPDATE ON asset_beneficiaries
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS asset_beneficiaries_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON asset_beneficiaries_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION asset_beneficiaries_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO asset_beneficiaries_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_asset_beneficiaries_versions
BEFORE UPDATE OR DELETE ON asset_beneficiaries
FOR EACH ROW EXECUTE FUNCTION asset_beneficiaries_capture_version();

-- Share-sum invariant (docs/02 §3: "application invariant + CHECK constraint
-- via trigger"): live shares per (asset, designation) may never exceed 100.
-- The application pre-validates and returns 422; this trigger is the last
-- line of defense against bugs and direct writes.
CREATE OR REPLACE FUNCTION asset_beneficiaries_check_share_sum() RETURNS trigger AS $$
DECLARE
  total NUMERIC(9,3);
BEGIN
  SELECT COALESCE(SUM(share_pct), 0) INTO total
  FROM asset_beneficiaries
  WHERE asset_id = NEW.asset_id AND designation = NEW.designation AND deleted_at IS NULL;
  IF total > 100 THEN
    RAISE EXCEPTION 'share_pct sum for asset % designation % exceeds 100', NEW.asset_id, NEW.designation
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER trg_asset_beneficiaries_share_sum
AFTER INSERT OR UPDATE ON asset_beneficiaries
FOR EACH ROW EXECUTE FUNCTION asset_beneficiaries_check_share_sum();

-- ---------------------------------------------------------------------------
-- deks — wrapped per-user data keys (backs @estate/crypto DekRepository).
-- UNIQUE partial index (vs. the plain index on older clusters): the database
-- guarantees at most one active DEK per user; concurrent first-writes race
-- to a unique-violation that @estate/crypto resolves by adopting the winner.
-- ---------------------------------------------------------------------------
CREATE TABLE deks (
  dek_id       UUID PRIMARY KEY,
  user_id      UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_deks_user_active ON deks (user_id) WHERE destroyed_at IS NULL;
