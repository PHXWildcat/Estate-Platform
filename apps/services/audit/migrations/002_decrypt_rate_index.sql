-- =============================================================================
-- 002_decrypt_rate_index.sql — index for the M18 decrypt-rate detector
--
-- The detector (docs/03 §4 TB4, M18) derives per-principal decrypt counts
-- from the append-only ledger by windowed query — the M16/M17 rate-bounds
-- shape: no counter state an attacker can reset. Its sweep is
--
--   WHERE action = 'crypto.field.decrypted' AND occurred_at >= <window start>
--   GROUP BY actor_type, actor_id, <first dotted token of detail->>'field'>
--
-- Before this index the only paths into audit_events were the PK
-- (seq, occurred_at) and the event_id dedup index, so that sweep was a
-- sequential scan over the whole table on every tick.
--
-- Column order: occurred_at LEADS because the sweep is a pure time-range
-- over all principals — an index led by actor_id cannot serve it without
-- walking every actor. actor_id second is nearly free and serves the
-- per-principal probes the detector's episode dedup may add. The grouped
-- detail extraction still heap-fetches the narrowed rows; at detector
-- volumes (a window's worth of decrypts) that is the right trade against
-- indexing a jsonb expression.
--
-- Partial on the action: decrypt events are a minority of the stream, and
-- the detector never reads anything else through this path.
--
-- Created on the PARTITIONED PARENT, so it propagates to
-- audit_events_default and to every future monthly partition automatically —
-- unlike the REVOKEs in 001, which each new partition must re-state.
--
-- HAZARD (the identity 005 precedent): the migrator wraps every file in
-- BEGIN/COMMIT, so CREATE INDEX CONCURRENTLY is structurally inexpressible
-- here. Fine against the empty/small tables this repo has today; whoever
-- first runs this against a POPULATED production audit store must build the
-- index out of band (CONCURRENTLY, per partition, then attach) and let
-- IF NOT EXISTS make this migration a no-op.
-- =============================================================================

CREATE INDEX IF NOT EXISTS ix_audit_events_decrypt_rate
  ON audit_events (occurred_at, actor_id)
  WHERE action = 'crypto.field.decrypted';
