-- Document service — documents cluster schema.
-- Source of truth: docs/02-database-schema.md §4, applied with the table
-- conventions from that document. Convention SQL matches the @estate/db
-- generators in structure (checkConventions-auditable).
--
-- Deviations from docs/02 §4 (all additive, called out inline + docs/04):
--   * document_templates.variables — the template's typed intake declaration
--     (which variables a generation request must supply). The renderer builds
--     its validation schema from this, so an intake payload can never carry
--     undeclared data into a rendered instrument.
--   * document_templates.body_sha256 — content pin for the template source in
--     the object store. The renderer verifies the fetched body against this
--     hash before use, so a tampered/replaced template object fails closed.
--   * document_templates gains updated_at/deleted_at + a versions shadow
--     table: activation flips `active`, which is exactly the kind of mutation
--     that must capture who/when (attorney sign-off gates are audit surface).
--   * ux_document_templates_active — at most ONE active version per
--     (doc_type, state): the generation resolver must be deterministic.
--   * document_versions.size_bytes / mime — download metadata; the content
--     itself lives in the object store as ciphertext.
--   * ix_documents_user — per-owner listing without scanning other tenants.
--
-- Per-object DEKs (docs/01 §4: "per-user (and per-object for documents)
-- DEKs"): this cluster's DEK subject is the DOCUMENT, not the user —
-- document_deks keys wrapped DEKs by document_id, and documents.dek_id
-- references the document's active content DEK. Crypto-shredding one
-- document's DEK erases that document's every version without touching the
-- rest of the estate. Content ciphertext AAD additionally binds the owner's
-- user_id, the version number, and the plaintext sha256 (see
-- documents.service.ts contentField).

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- document_templates (docs/02 §4 + additive columns) — the 50-state template
-- matrix. Rows are published from in-repo sources by the publish CLI
-- (template-publish-cli.ts); there is deliberately NO runtime mutation API.
-- "Versioned like code with legal sign-off gates" is implemented literally:
-- template sources live in git, sign-off metadata is required by schema, and
-- a published (doc_type, state, version) is immutable.
-- ---------------------------------------------------------------------------
CREATE TABLE document_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  doc_type TEXT NOT NULL CHECK (doc_type IN ('will','revocable_trust','irrevocable_trust','pour_over_will',
    'durable_poa','financial_poa','medical_poa','mental_health_poa','living_will','hipaa_auth',
    'guardian_designation','certification_of_trust','property_assignment','funding_letter','beneficiary_letter')),
  state CHAR(2) NOT NULL,                       -- 50-state matrix (+DC)
  version INT NOT NULL,
  body_ref TEXT NOT NULL,                       -- object-store pointer to template source
  body_sha256 BYTEA NOT NULL,                   -- additive: content pin, verified on load
  legal_review_by TEXT NOT NULL, legal_review_at TIMESTAMPTZ NOT NULL,
  execution_requirements JSONB NOT NULL,        -- witnesses, notarization, self-proving affidavit rules per state
  variables JSONB NOT NULL,                     -- additive: typed intake declaration
  active BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),  -- additive: conventions column
  deleted_at TIMESTAMPTZ,                         -- additive: conventions column
  UNIQUE (doc_type, state, version)
);

-- Additive: the generation resolver must be deterministic — at most one
-- active version per (doc_type, state) pair.
CREATE UNIQUE INDEX ux_document_templates_active
ON document_templates (doc_type, state)
WHERE active AND deleted_at IS NULL;

CREATE TRIGGER trg_document_templates_updated_at
BEFORE UPDATE ON document_templates
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS document_templates_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON document_templates_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION document_templates_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO document_templates_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_document_templates_versions
BEFORE UPDATE OR DELETE ON document_templates
FOR EACH ROW EXECUTE FUNCTION document_templates_capture_version();

-- ---------------------------------------------------------------------------
-- documents (docs/02 §4, verbatim + conventions) — one row per estate
-- document. Metadata only: content lives in the object store as ciphertext
-- referenced by document_versions. No FK across clusters for user_id
-- (docs/02 §8).
-- ---------------------------------------------------------------------------
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

-- Additive: per-owner listing.
CREATE INDEX ix_documents_user ON documents (user_id) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_documents_updated_at
BEFORE UPDATE ON documents
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS documents_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON documents_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION documents_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO documents_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_documents_versions
BEFORE UPDATE OR DELETE ON documents
FOR EACH ROW EXECUTE FUNCTION documents_capture_version();

-- ---------------------------------------------------------------------------
-- document_versions (docs/02 §4, verbatim + additive size/mime) — the
-- content-addressed version history. APPEND-ONLY: a version, once written,
-- is history; supersession happens by writing the next version, never by
-- editing this one. content_sha256 is the hash of the PLAINTEXT content —
-- the object store holds ciphertext, and decrypt-then-hash is the
-- disaster-recovery integrity check.
-- ---------------------------------------------------------------------------
CREATE TABLE document_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  document_id UUID NOT NULL REFERENCES documents(id),
  version INT NOT NULL,
  object_key TEXT NOT NULL,                     -- object store, per-document DEK, content-addressed (sha256)
  content_sha256 BYTEA NOT NULL,
  size_bytes BIGINT NOT NULL,                   -- additive: ciphertext-independent plaintext size
  mime TEXT NOT NULL,                           -- additive: download metadata
  ocr_indexed BOOLEAN NOT NULL DEFAULT false,
  created_by UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (document_id, version)
);
REVOKE UPDATE, DELETE ON document_versions FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- document_deks — wrapped PER-DOCUMENT data keys (docs/01 §4's per-object
-- DEKs for documents). Backs @estate/crypto's DekRepository with the
-- document as the key subject; the UNIQUE partial index guarantees at most
-- one active DEK per document, and a lost first-write race resolves by
-- adopting the winner (DekConflictError), exactly like the per-user tables
-- on the other clusters.
-- ---------------------------------------------------------------------------
CREATE TABLE document_deks (
  dek_id       UUID PRIMARY KEY,
  document_id  UUID NOT NULL,
  kek_alias    TEXT NOT NULL,
  wrapped_key  BYTEA NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX ux_document_deks_document_active
ON document_deks (document_id) WHERE destroyed_at IS NULL;
