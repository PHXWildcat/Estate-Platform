-- =============================================================================
-- 001_audit_schema.sql — append-only, hash-chained audit store
--
-- Source of truth: docs/02-database-schema.md §6 (`audit` cluster).
--
-- Tamper evidence: every row carries
--   event_hash = SHA-256(prev_hash || canonical(event))
-- and the current head of the chain lives in `audit_chain_head`. Hourly
-- anchoring of the head hash to S3 Object Lock (compliance mode, log-archive
-- account) is a deploy-time follow-up per docs/02 §6 — tracked in the service
-- README, not implemented in this migration.
--
-- Retention per docs/02 §6: 7 years online, then archived; a legal_hold flag
-- on partitions blocks archival (follow-up alongside partition automation).
-- =============================================================================

CREATE TABLE audit_events (
  seq           BIGINT GENERATED ALWAYS AS IDENTITY,
  event_id      UUID NOT NULL,
  occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id      UUID,
  actor_type    TEXT NOT NULL CHECK (actor_type IN ('user','service','operator','system')),
  on_behalf_of  UUID,                        -- delegated/role access (trustee for owner, ...)
  action        TEXT NOT NULL,               -- enum-token action catalog (@estate/contracts AUDIT_ACTIONS)
  resource_type TEXT NOT NULL,
  resource_id   UUID,
  session_id    UUID,
  device_id     UUID,                        -- per docs/02 §6; not yet populated by producers in M1
  ip_ct         BYTEA,                       -- encrypted IP; NULL in M1 (no network context on the bus yet)
  geo           TEXT,
  user_agent    TEXT,
  detail        JSONB NOT NULL DEFAULT '{}', -- entity IDs and enums only; NEVER plaintext PII
  prev_hash     BYTEA NOT NULL,              -- SHA-256 chain for tamper evidence
  event_hash    BYTEA NOT NULL,
  -- PK choice: a partitioned table's primary key must include the partition
  -- key, so `seq` alone (as written in the docs/02 logical model) cannot be
  -- the PK. We use (seq, occurred_at), leading with `seq` so chain-order
  -- scans and seq lookups use the index efficiently; `occurred_at` is present
  -- only to satisfy the partitioning rule.
  PRIMARY KEY (seq, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Idempotent ingest: consumers may redeliver a Kafka message; event_id is the
-- dedup key. A unique index on a partitioned table must include the partition
-- key, hence (event_id, occurred_at). Cross-partition uniqueness of event_id
-- alone is enforced by the ingestor's existence check, which runs serialized
-- under the audit_chain_head row lock; this index makes that check fast and
-- guards the common case.
CREATE UNIQUE INDEX ux_audit_events_event_id_occurred_at
  ON audit_events (event_id, occurred_at);

-- M1: a single DEFAULT partition. Monthly RANGE partitions plus automation
-- (pg_partman or a scheduled maintenance job) are a required follow-up before
-- production traffic; new monthly partitions must also get the REVOKE below.
CREATE TABLE audit_events_default PARTITION OF audit_events DEFAULT;

-- Append-only enforcement (docs/02 §6). Tables grant nothing to PUBLIC by
-- default; these REVOKEs make the intent explicit and are asserted by the
-- integration tests. App roles must be granted INSERT/SELECT only.
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE ON audit_events_default FROM PUBLIC;

-- Single-row chain head. `id BOOLEAN PRIMARY KEY CHECK (id)` admits exactly
-- one row (TRUE). Writers take `SELECT ... FOR UPDATE` on this row, so chain
-- extension is fully serialized — the hash chain never forks.
CREATE TABLE audit_chain_head (
  id         BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  last_seq   BIGINT NOT NULL DEFAULT 0,
  head_hash  BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Genesis: the chain starts from 32 zero bytes (GENESIS_HASH in src/chain.ts).
-- last_seq = 0 means "no events yet"; seq generation starts at 1.
INSERT INTO audit_chain_head (id, last_seq, head_hash)
VALUES (TRUE, 0, '\x0000000000000000000000000000000000000000000000000000000000000000');
