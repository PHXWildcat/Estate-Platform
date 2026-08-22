-- M25 PR3 — the execution half of erasure: states, and a per-domain ledger.
--
-- WIDENING THE REQUEST STATES needs no pre-flight. A migration that widens what
-- is permitted cannot invalidate a row that already exists
-- (`.claude/rules/db-migrations.md`), which is why PR2 could ship two states
-- and leave this to the PR that produces the others.
--
-- 'executing' is the driver's CLAIM and 'completed' means every domain in the
-- ledger below reported done. There is deliberately no 'failed' request state:
-- a domain that refuses or errors leaves the REQUEST executing and its own row
-- carrying the reason, because an erasure that stopped is not an erasure that
-- finished, and a terminal-looking status would invite somebody to stop
-- retrying the one thing in this product that must not be left half done.
--
-- THE LIVE INDEX HAS TO FOLLOW THE STATES. PR2's partial unique index covered
-- 'pending' alone, which was complete then and is a hole now: an executing
-- request would stop blocking a second one, and two live requests against one
-- account is the state the index exists to forbid. Dropped and recreated over
-- both live states rather than left to "nobody would" — the same reasoning that
-- puts the status allowlist inside the INSERT rather than above it.

ALTER TABLE erasure_requests DROP CONSTRAINT erasure_requests_status_check;
ALTER TABLE erasure_requests ADD CONSTRAINT erasure_requests_status_check
  CHECK (status IN ('pending','cancelled','executing','completed'));

-- The claim instant and the finish instant. `started_at` is what makes a stuck
-- request visible as "executing since when" rather than only as a state — an
-- erasure that wedged is indistinguishable from one running slowly without it.
ALTER TABLE erasure_requests ADD COLUMN started_at TIMESTAMPTZ;
ALTER TABLE erasure_requests ADD COLUMN completed_at TIMESTAMPTZ;

DROP INDEX ux_erasure_requests_live;
CREATE UNIQUE INDEX ux_erasure_requests_live ON erasure_requests (user_id)
WHERE status IN ('pending','executing') AND deleted_at IS NULL;

-- WHY PROGRESS IS PER DOMAIN AND DURABLE. Erasure has to reach eight DEK
-- domains across four clusters and there is no distributed transaction
-- available. Without a row per domain, an erasure that succeeded in some and
-- failed in others is indistinguishable from one that never ran — and "half
-- erased, and nothing says which half" is the worst state this feature can
-- reach. The row is what makes a retry safe and an incomplete erasure VISIBLE.
--
-- SEVEN OF THE EIGHT SIT AT 'pending' AFTER M25, and that is the honest answer
-- rather than a gap. This milestone ships identity's own destroy leg; the other
-- seven have no transport to ask (`estate.auth.events.v1` has a producer and no
-- consumer, and the audit service is the repo's only Kafka consumer), so a
-- request does not reach 'completed' here. These rows are NOT the dormant
-- schema PR2 refused: dormant means a value nothing can produce, and every row
-- below is written on every request. What they record is true.
--
-- THE VOCABULARY IS A HAND-LIST HERE AND A DERIVED SET IN THE FENCE. Postgres
-- cannot CHECK against another project's source, so the eight names appear
-- literally. `packages/contracts/test/erasure-domains.spec.ts` derives the
-- participant set from `apps/stack/src/topology.ts` (services with a non-null
-- `kekAlias`) and compares it to THIS CONSTRAINT'S OWN VOCABULARY as sets, so a
-- ninth KEK-holding service turns that fence red until it is named here. Sets,
-- not counts: a swap preserves a count and changes the meaning.

CREATE TABLE erasure_domain_progress (
  request_id UUID NOT NULL REFERENCES erasure_requests(id),
  domain     TEXT NOT NULL
             CHECK (domain IN ('identity','profile','assets','plaid','documents',
                               'settlement','notifications','ai-assistant')),
  -- TWO STATES, for PR2's reason. 'refused' and 'failed' are real states in the
  -- design and neither is PRODUCIBLE here: the refusals that exist are
  -- account-level and stop the claim before a row is ever touched, and there is
  -- no remote call yet that could fail. A CHECK listing values nothing can
  -- write is dormant schema, and widening one later needs no pre-flight — so
  -- they arrive with the fan-out that produces them, together with the closed
  -- `reason` vocabulary that makes a non-advance actionable.
  state      TEXT NOT NULL DEFAULT 'pending'
             CHECK (state IN ('pending','done')),
  -- The instant this domain last moved. Erasure's own liveness signal.
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, domain)
);

-- The driver's whole question is "what is still open for this request", so the
-- index is on exactly that predicate.
CREATE INDEX ix_erasure_domain_progress_open ON erasure_domain_progress (request_id)
WHERE state <> 'done';

-- Matches updatedAtTriggerSql('erasure_domain_progress').
CREATE TRIGGER trg_erasure_domain_progress_updated_at
BEFORE UPDATE ON erasure_domain_progress
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
