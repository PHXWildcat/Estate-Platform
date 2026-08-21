-- M25 PR2 — the erasure request record. The DECISION half of erasure.
--
-- WHAT THIS TABLE IS FOR. Erasure cannot be synchronous: it has to reach eight
-- DEK domains across four clusters with no distributed transaction available,
-- so the owner's decision and its execution are necessarily separated in time.
-- That gap is a durable record or it is nothing — a request held in a request
-- handler dies with the process, and an erasure that half-happened with no row
-- saying so is the worst state this feature can reach.
--
-- NOTHING HERE DESTROYS ANYTHING, and that is the point of shipping it alone.
-- `destroyDek` still has no production caller; the fan-out and the destroy leg
-- are M25 PR3. This is reviewable on its own because it answers exactly one
-- question — may this account be erased, and has its owner changed their mind —
-- which is the question that decides whether the irreversible half ever runs.
--
-- THE STATUS VOCABULARY IS DELIBERATELY TWO VALUES. 'pending' and 'cancelled'
-- are the only states reachable in this PR, and a CHECK listing states nothing
-- can produce is dormant schema — the M7 rule ("settlement_tasks/distributions
-- ship with PR2, no dormant schema"). PR3 WIDENS this constraint in its own
-- migration, which needs no pre-flight because widening what is permitted
-- cannot invalidate a row that already exists.
--
-- ONE LIVE REQUEST PER OWNER, as a partial unique index rather than a check in
-- code. Two concurrent requests are not a conflict worth surfacing to a user —
-- the second is the same intent — so the service infers this index with
-- ON CONFLICT DO NOTHING and reads back the winner. Catching a unique violation
-- inside a transaction would abort it and refuse every later statement, which
-- is the trap `.claude/rules/db-migrations.md` names.
--
-- THE PAIRED-STATE CHECK exists because `cancelled_at` is the evidence and
-- `status` is the index key: a row claiming one and not the other is a row two
-- readers disagree about.

CREATE TABLE erasure_requests (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending','cancelled')),
  -- The session that proved step-up. Kept for the audit trail, not for authz:
  -- nothing re-reads it to make a decision.
  requested_by_session UUID,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  cancelled_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at   TIMESTAMPTZ,
  CONSTRAINT erasure_requests_cancelled_pairing
    CHECK ((status = 'cancelled') = (cancelled_at IS NOT NULL))
);

-- Matches softDeleteUniqueIndexSql-style partial uniqueness, narrowed to the
-- live state: a cancelled request must not block a later one.
CREATE UNIQUE INDEX ux_erasure_requests_live ON erasure_requests (user_id)
WHERE status = 'pending' AND deleted_at IS NULL;

CREATE INDEX ix_erasure_requests_user ON erasure_requests (user_id)
WHERE deleted_at IS NULL;

-- Matches updatedAtTriggerSql('erasure_requests').
CREATE TRIGGER trg_erasure_requests_updated_at
BEFORE UPDATE ON erasure_requests
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Matches versionsTableSql('erasure_requests') AS OF M25 PR1 — the capture body
-- carries the blind-index redaction. This table has no `*_bidx` column today,
-- so the redaction is inert here; it is copied verbatim rather than trimmed
-- because a capture function that differs from every other one is the drift the
-- convention exists to prevent, and because a blind index added to this table
-- later must not depend on somebody noticing this file.
CREATE TABLE IF NOT EXISTS erasure_requests_versions (
  version_seq  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  row_id       UUID NOT NULL,
  operation    TEXT NOT NULL CHECK (operation IN ('UPDATE','DELETE')),
  row_data     JSONB NOT NULL,
  actor_id     UUID,
  reason       TEXT,
  versioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE ON erasure_requests_versions FROM PUBLIC;

CREATE OR REPLACE FUNCTION erasure_requests_capture_version() RETURNS trigger AS $$
DECLARE
  image jsonb := to_jsonb(OLD);
  blind text[];
BEGIN
  SELECT array_agg(k) INTO blind
  FROM jsonb_object_keys(image) AS k
  WHERE right(k, 5) = '_bidx';
  IF blind IS NOT NULL THEN
    image := image - blind;
  END IF;

  INSERT INTO erasure_requests_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.id,
    TG_OP,
    image,
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_erasure_requests_versions
BEFORE UPDATE OR DELETE ON erasure_requests
FOR EACH ROW EXECUTE FUNCTION erasure_requests_capture_version();
