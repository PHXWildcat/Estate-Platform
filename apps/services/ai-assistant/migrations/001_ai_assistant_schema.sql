-- AI estate assistant service — core cluster schema (M10 PR1).
-- Source of truth: docs/00 feature 6, docs/01 §2.8, and the M10 record in
-- docs/04-monorepo-and-milestones.md. Convention SQL matches the @estate/db
-- generators in structure (checkConventions-auditable).
--
-- docs/02 has NO section for an AI assistant — the whole table set below is
-- additive, and the milestone doc rather than docs/02 is its authority:
--   * assistant_deks          this service's OWN wrapped DEKs under the
--                             dedicated 'ai-assistant/kek' alias. profile,
--                             settlement and notifications share this cluster
--                             and can never unwrap a conversation (docs/03
--                             §5.3: the KMS grant, not the database, is the
--                             chokepoint).
--   * assistant_consents      per-feature consent, the docs/01 §2.8 and
--                             docs/03 §4 TB5 "per-feature consent"
--                             requirement. Deny by default: consent is the
--                             PRESENCE of an unrevoked row, never a column
--                             default, so a missing row and a revoked row are
--                             the same answer.
--   * assistant_conversations the only mutable business table here.
--   * assistant_messages      append-only turn log; bodies are ciphertext.
--   * assistant_tool_calls    append-only record of every retrieval the
--                             assistant performed, with the consent scope that
--                             admitted it and the outcome that a refusal
--                             produces. This table is the audit-visible half
--                             of "tool scopes are read-only" (docs/03 §4 TB5).
--
-- Cluster co-ownership note: this is the FOURTH tenant of the core cluster
-- (profile, settlement, notifications), owning a DISJOINT table set and its own
-- migrations dir. The shared schema_migrations table tolerates this: the
-- Migrator ignores rows not present in its own dir, its advisory lock
-- serializes runners, and file names are disjoint. Unlike settlement, this
-- service reads NOTHING from a co-tenant's tables — every estate fact it shows
-- a user is fetched over HTTP on that user's own forwarded bearer, so it holds
-- no cross-tenant read grant and a compromised assistant cannot widen its
-- reach by querying the cluster directly.
--
-- Conventions note: assistant_messages and assistant_tool_calls are APPEND-ONLY
-- (created_at only, no updated_at/deleted_at/_versions, UPDATE/DELETE revoked)
-- — the rows ARE the history, the notification_sends precedent.
-- assistant_consents follows profile's permission_grants: a consent is an
-- access record that is REVOKED, never deleted, so it carries no updated_at
-- trigger and no _versions shadow table either. Both exclusions are asserted by
-- hand in ai-assistant.int.spec.ts; only assistant_conversations is passed to
-- checkConventions as a business table.

-- Shared updated_at trigger function (matches updatedAtFunctionSql()).
-- CREATE OR REPLACE: profile, settlement and notifications each define the
-- identical function on this cluster; any of the four may run first.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- assistant_deks — same shape as notification_deks; keyed by the OWNER user.
-- Crypto-shredding a user's assistant DEK erases every conversation this
-- service holds for them in one operation, including the retrieved estate
-- content quoted inside those turns.
-- ---------------------------------------------------------------------------
CREATE TABLE assistant_deks (
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
CREATE UNIQUE INDEX ux_assistant_deks_user_active ON assistant_deks (user_id)
WHERE destroyed_at IS NULL;

-- ---------------------------------------------------------------------------
-- assistant_consents — per-feature consent, modeled on profile's
-- permission_grants: append + revoke, no versions table, the rows themselves
-- are the history. There is deliberately NO 'granted' boolean and no default:
-- the only affirmative state is an unrevoked row, so a service that forgets to
-- check consent reads nothing rather than reading a permissive default.
--
-- The scope vocabulary is closed and mirrors CONSENT_SCOPES in src/consent.ts.
-- Widening it is a migration AND a code change, which is the intent: each
-- scope is a distinct grant of estate data to a third-party model provider.
-- ---------------------------------------------------------------------------
CREATE TABLE assistant_consents (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL,
  scope      TEXT NOT NULL CHECK (scope IN (
    'assistant.enabled',
    'assistant.assets',
    'assistant.profile',
    'assistant.documents.metadata',
    'assistant.documents.content'
  )),
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by UUID NOT NULL,                      -- the step-up-verified owner
  revoked_at TIMESTAMPTZ,
  revoked_by UUID,
  -- Revocation fields travel together.
  CONSTRAINT assistant_consents_revocation_pair
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- At most one ACTIVE grant per (user, scope): re-granting a live scope is a
-- no-op rather than a second row, so "is this scope granted?" is a single
-- unambiguous row and revocation cannot leave a shadow grant behind.
CREATE UNIQUE INDEX ux_assistant_consents_user_scope_active
  ON assistant_consents (user_id, scope)
WHERE revoked_at IS NULL;

CREATE INDEX ix_assistant_consents_user ON assistant_consents (user_id, granted_at DESC);

-- ---------------------------------------------------------------------------
-- assistant_conversations — the one mutable business table. It carries no
-- title and no summary: a user-authored conversation title would be a
-- plaintext free-text column, and the only one of those in the product
-- (documents.title) had to be argued for in the M4 review. Listing shows
-- timestamps; the content lives in assistant_messages as ciphertext.
-- ---------------------------------------------------------------------------
CREATE TABLE assistant_conversations (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

CREATE INDEX ix_assistant_conversations_user ON assistant_conversations (user_id, updated_at DESC)
WHERE deleted_at IS NULL;

CREATE TRIGGER trg_assistant_conversations_updated_at
BEFORE UPDATE ON assistant_conversations
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS assistant_conversations_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON assistant_conversations_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION assistant_conversations_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO assistant_conversations_versions (row_id, operation, row_data, actor_id, reason)
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

CREATE TRIGGER trg_assistant_conversations_versions
BEFORE UPDATE OR DELETE ON assistant_conversations
FOR EACH ROW EXECUTE FUNCTION assistant_conversations_capture_version();

-- ---------------------------------------------------------------------------
-- assistant_messages — append-only turn log. Bodies are AEAD ciphertext under
-- the owner's per-user DEK; there is no plaintext prompt or completion column
-- anywhere, because a turn quotes whatever estate content the tools returned.
--
-- Persisting the transcript is a SECURITY decision, not a convenience one: if
-- the client supplied the history on each turn it could forge prior assistant
-- turns and prior tool results, and a forged tool result is indistinguishable
-- from a real one — a self-service prompt-injection channel that no amount of
-- untrusted-input framing closes.
-- ---------------------------------------------------------------------------
CREATE TABLE assistant_messages (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES assistant_conversations(id),
  seq             INTEGER NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('user','assistant')),
  content_ct      BYTEA NOT NULL,                -- AAD binds user + message id
  dek_id          UUID NOT NULL REFERENCES assistant_deks(dek_id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON assistant_messages FROM PUBLIC;

-- Turn ordering is the conversation's spine, and UNIQUE makes an interrupted
-- retry idempotent: a re-sent turn loses the insert race rather than
-- duplicating itself into the model's context.
CREATE UNIQUE INDEX ux_assistant_messages_conversation_seq
  ON assistant_messages (conversation_id, seq);

-- ---------------------------------------------------------------------------
-- assistant_tool_calls — append-only record of every retrieval the assistant
-- attempted. `scope` is the consent scope the executor required, and `outcome`
-- records a refusal as loudly as a success: a control firing must be visible
-- as a control, not as an absence (the M9 rule that a 503 gate audits itself).
--
-- `tool_name` deliberately carries NO CHECK constraint, unlike
-- notification_sends.kind. The tool vocabulary is closed in code — the registry
-- in src/tools/ plus its completeness spec — and a CHECK here would put that
-- list in two places, making every new tool a schema migration. The registry
-- test is the control; this column is evidence.
-- ---------------------------------------------------------------------------
CREATE TABLE assistant_tool_calls (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id UUID NOT NULL REFERENCES assistant_conversations(id),
  message_id      UUID REFERENCES assistant_messages(id),
  tool_name       TEXT NOT NULL,
  scope           TEXT NOT NULL,
  outcome         TEXT NOT NULL CHECK (outcome IN ('ok','denied_no_consent','error')),
  result_ct       BYTEA,                         -- NULL unless outcome = 'ok'
  dek_id          UUID REFERENCES assistant_deks(dek_id),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Ciphertext and its key reference travel together.
  CONSTRAINT assistant_tool_calls_result_pair
    CHECK ((result_ct IS NULL) = (dek_id IS NULL)),
  -- A refused or failed call has no result to carry. Without this, a denial
  -- could still ship retrieved content — the outcome column would say the
  -- control fired while the row proved it had not.
  CONSTRAINT assistant_tool_calls_refusal_is_empty
    CHECK (outcome = 'ok' OR result_ct IS NULL)
);
REVOKE UPDATE, DELETE ON assistant_tool_calls FROM PUBLIC;

CREATE INDEX ix_assistant_tool_calls_conversation
  ON assistant_tool_calls (conversation_id, created_at DESC);
