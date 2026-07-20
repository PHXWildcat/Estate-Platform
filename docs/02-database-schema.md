# Estate Planning Platform — Database Schema

**Version:** 1.0 · PostgreSQL 16 (Aurora). Six physically separate clusters: `auth`, `core` (profile/contacts), `financial`, `documents`, `vault`, `audit`. Analytics is a downstream projection (Redshift/Snowflake) fed by Kafka, never queried by the app.

## Conventions applied to every table

- `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` — no sequential IDs exposed anywhere.
- `created_at / updated_at TIMESTAMPTZ NOT NULL` maintained by triggers.
- **No hard deletes.** `deleted_at TIMESTAMPTZ` soft delete; partial unique indexes exclude deleted rows; a privileged retention job (not the app role) performs crypto-shredding for legal erasure (destroy the row's DEK — see below).
- **Versioning:** every mutable business table has a `<table>_versions` shadow table written by trigger on UPDATE/DELETE, storing the full prior row, actor, and reason. Version tables are INSERT-only (REVOKE UPDATE/DELETE from all roles).
- **Field-level encryption:** sensitive columns are `BYTEA` holding AEAD ciphertext; each row carries `dek_id` referencing a wrapped per-user data key. Equality search uses blind-index columns (`*_bidx BYTEA`, HMAC of normalized plaintext). "Right to delete" = destroy DEK ⇒ ciphertext is irrecoverable, audit structure preserved.
- App connects via per-service roles with least privilege; `SECURITY DEFINER` functions gate cross-schema access; RLS on every multi-tenant table keyed to `app.current_user_id` / grant context.

---

## 1. `auth` cluster

```sql
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
CREATE UNIQUE INDEX ux_users_email ON users(email_bidx) WHERE deleted_at IS NULL;

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

CREATE TABLE mfa_methods (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID NOT NULL REFERENCES users(id),
  kind        TEXT NOT NULL CHECK (kind IN ('totp','sms_recovery','recovery_codes')),
  secret_ct   BYTEA NOT NULL,
  verified_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at  TIMESTAMPTZ
);

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
  revoke_reason    TEXT
);

CREATE TABLE auth_events (                     -- login/logout/step-up/risk decisions (also mirrored to audit cluster)
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID, session_id UUID, kind TEXT NOT NULL,
  risk_score SMALLINT, decision TEXT, ip_ct BYTEA, geo TEXT, device_id UUID,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 2. `core` cluster — profile, contacts, grants

```sql
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

CREATE TABLE family_members (                  -- children, parents, spouse: needed for wills/guardianship
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  relation TEXT NOT NULL CHECK (relation IN ('spouse','child','parent','sibling','other')),
  name_ct BYTEA NOT NULL, dob_ct BYTEA, is_minor BOOLEAN,
  notes_ct BYTEA, dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE contacts (                        -- the estate contact repository
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

CREATE TABLE role_assignments (                -- who is trustee/executor/beneficiary/etc. of what
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

CREATE TABLE permission_grants (               -- ABAC: field/resource-level visibility for a role_assignment
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role_assignment_id UUID NOT NULL REFERENCES role_assignments(id),
  resource TEXT NOT NULL,                      -- e.g. 'asset','document','vault_item','dashboard.networth'
  action   TEXT NOT NULL,                      -- 'read','download','manage'
  constraint_expr JSONB,                       -- Cedar-compatible condition, e.g. {"only_if_named_beneficiary": true}
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
```

## 3. `financial` cluster — Plaid + manual assets (event-sourced)

```sql
CREATE TABLE plaid_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  access_token_ct BYTEA NOT NULL,              -- envelope-encrypted; decrypt only inside sync worker
  institution_id TEXT NOT NULL, institution_name TEXT,
  sync_cursor TEXT, status TEXT NOT NULL DEFAULT 'healthy'
    CHECK (status IN ('healthy','login_required','error','revoked')),
  dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

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

-- Event-sourced asset ledger: the write model
CREATE TABLE asset_events (
  seq        BIGINT GENERATED ALWAYS AS IDENTITY,
  event_id   UUID NOT NULL DEFAULT gen_random_uuid(),
  asset_id   UUID NOT NULL,
  user_id    UUID NOT NULL,
  event_type TEXT NOT NULL,                    -- AssetCreated, ValuationRecorded, OwnershipChanged,
                                               -- BeneficiaryDesignated, DocumentAttached, AssetRetired...
  payload_ct BYTEA NOT NULL,                   -- encrypted event body
  actor_id   UUID NOT NULL, actor_role TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (asset_id, seq)
);
REVOKE UPDATE, DELETE ON asset_events FROM PUBLIC;   -- append-only

-- Projected read model for dashboard/search
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

CREATE TABLE asset_beneficiaries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID NOT NULL, contact_id UUID NOT NULL,
  designation TEXT NOT NULL CHECK (designation IN ('primary','contingent')),
  share_pct NUMERIC(6,3) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);
-- Application invariant + CHECK constraint via trigger: shares per (asset, designation) sum to 100
-- Conflict detection (will vs. beneficiary designation mismatches) runs as an async analyzer over this table.
```

## 4. `documents` cluster

```sql
CREATE TABLE document_templates (               -- versioned like code; attorney sign-off required to activate
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_type TEXT NOT NULL CHECK (doc_type IN ('will','revocable_trust','irrevocable_trust','pour_over_will',
    'durable_poa','financial_poa','medical_poa','mental_health_poa','living_will','hipaa_auth',
    'guardian_designation','certification_of_trust','property_assignment','funding_letter','beneficiary_letter')),
  state CHAR(2) NOT NULL,                       -- 50-state matrix
  version INT NOT NULL,
  body_ref TEXT NOT NULL,                       -- S3 pointer to template source
  legal_review_by TEXT NOT NULL, legal_review_at TIMESTAMPTZ NOT NULL,
  execution_requirements JSONB NOT NULL,        -- witnesses, notarization, self-proving affidavit rules per state
  active BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (doc_type, state, version)
);

CREATE TABLE documents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  doc_type TEXT NOT NULL,
  template_id UUID REFERENCES document_templates(id),  -- NULL for uploads
  source TEXT NOT NULL CHECK (source IN ('generated','uploaded')),
  title TEXT NOT NULL,
  current_version INT NOT NULL DEFAULT 1,
  execution_status TEXT NOT NULL DEFAULT 'draft'
    CHECK (execution_status IN ('draft','generated','signed','witnessed','notarized','executed','revoked','superseded')),
  executed_at DATE,
  legal_hold BOOLEAN NOT NULL DEFAULT false,
  sealed BOOLEAN NOT NULL DEFAULT false,        -- user moved it to Zone A: server loses read access
  dek_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE document_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  version INT NOT NULL,
  object_key TEXT NOT NULL,                     -- S3, per-object DEK, content-addressed (sha256)
  content_sha256 BYTEA NOT NULL,
  ocr_indexed BOOLEAN NOT NULL DEFAULT false,
  created_by UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (document_id, version)
);
REVOKE UPDATE, DELETE ON document_versions FROM PUBLIC;
```

## 5. `vault` cluster (Zone A — server stores opaque blobs only)

```sql
CREATE TABLE vault_keysets (                    -- SRP verifier + wrapped keys; never plaintext keys
  user_id UUID PRIMARY KEY,
  srp_verifier BYTEA NOT NULL, srp_salt BYTEA NOT NULL,
  wrapped_master_key BYTEA NOT NULL,            -- wrapped by client-derived key; opaque to server
  kdf_params JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vault_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  item_type TEXT NOT NULL CHECK (item_type IN ('password','pin','recovery_codes','seed_phrase',
    'private_key','secure_note','license','attachment')),
  blob_ct BYTEA NOT NULL,                       -- client-encrypted; includes item metadata
  blob_version INT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE emergency_access_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  grantee_contact_id UUID NOT NULL,
  waiting_period_hours INT NOT NULL CHECK (waiting_period_hours >= 24),
  key_share_ct BYTEA NOT NULL,                  -- Shamir share, encrypted to grantee
  status TEXT NOT NULL DEFAULT 'configured'
    CHECK (status IN ('configured','requested','waiting','denied_by_owner','released','revoked')),
  requested_at TIMESTAMPTZ, releases_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6. `audit` cluster (append-only, hash-chained)

```sql
CREATE TABLE audit_events (
  seq          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id     UUID NOT NULL DEFAULT gen_random_uuid(),
  occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id     UUID, actor_type TEXT NOT NULL CHECK (actor_type IN ('user','service','operator','system')),
  on_behalf_of UUID,                             -- for delegated/role access
  action       TEXT NOT NULL,                    -- 'document.viewed','vault.item.accessed','role.granted',
                                                 -- 'field.decrypted','settlement.triggered', ...
  resource_type TEXT NOT NULL, resource_id UUID,
  session_id   UUID, device_id UUID,
  ip_ct        BYTEA, geo TEXT, user_agent TEXT,
  detail       JSONB NOT NULL DEFAULT '{}',      -- entity IDs and enums only; NEVER plaintext PII
  prev_hash    BYTEA NOT NULL,                   -- SHA-256 chain for tamper evidence
  event_hash   BYTEA NOT NULL
) PARTITION BY RANGE (occurred_at);
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;
-- Hourly: anchor head-of-chain hash to S3 Object Lock (compliance mode) in the log-archive account.
-- Retention: 7 years online, then archived; legal_hold flag on partitions blocks archival.
```

## 7. Settlement (lives in `core` cluster, workflow state in Temporal)

```sql
CREATE TABLE settlement_cases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  decedent_user_id UUID NOT NULL,
  status TEXT NOT NULL DEFAULT 'reported'
    CHECK (status IN ('reported','verifying','waiting_period','verified','active','distributing','closed','rejected_fraud')),
  reported_by UUID NOT NULL, report_source TEXT NOT NULL
    CHECK (report_source IN ('trusted_contact','data_provider','death_certificate_upload')),
  verification_evidence JSONB NOT NULL DEFAULT '[]',   -- refs to cert uploads, provider match IDs
  human_review_by UUID, human_review_at TIMESTAMPTZ,   -- mandatory before status='verified'
  waiting_period_ends TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE settlement_tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  title TEXT NOT NULL, category TEXT, assigned_role TEXT,
  due_at DATE, completed_at TIMESTAMPTZ, completed_by UUID,
  court_doc_version_id UUID,                    -- uploaded letters testamentary, etc.
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE TABLE distributions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id UUID NOT NULL REFERENCES settlement_cases(id),
  asset_id UUID, beneficiary_contact_id UUID NOT NULL,
  amount_ct BYTEA, status TEXT NOT NULL DEFAULT 'planned'
    CHECK (status IN ('planned','approved','in_progress','completed','disputed')),
  approved_by UUID, approved_at TIMESTAMPTZ,    -- dual-control: approver ≠ recorder enforced by trigger
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 8. Design notes worth arguing about

- **Cross-cluster referential integrity is by convention + events, not FKs.** Auth's `users.id` is the universal key; each cluster validates existence via cached identity events. The cost (eventual consistency on user lifecycle) buys the isolation the security model demands.
- **Crypto-shredding as the deletion primitive** reconciles "no deletes / immutable audit" with GDPR/CCPA erasure: structure and hashes survive, meaning does not.
- **Blind indexes leak equality patterns** (same email ⇒ same index). Acceptable for login lookup; not used for SSN (no legitimate SSN-equality search exists in-product, so SSNs get no index at all).
- **`assets_view` is a projection and can be rebuilt** from `asset_events` at any time — this is also the disaster-recovery integrity check: rebuild and diff.
- **`sealed` documents** flip storage to client-side encryption; the server keeps only version metadata. Search/OCR/AI features are disabled for sealed items and the UI says so explicitly.
