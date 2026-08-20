-- Settlement PR3b — who is working this case.
--
-- `markReviewStarted` moves a case reported → verifying and records the
-- claiming operator NOWHERE: `human_review_by` is first written at APPROVAL,
-- so between the claim and the decision the row says a review is under way and
-- cannot say by whom. That was invisible while nothing listed the queue. M21
-- PR3b puts a shared work queue on a screen, and a shared work queue with no
-- claim marker is how two operators independently run one docs/03 §5.1 review
-- — the reviewer-≠-reporter CHECK does not stop that, it only stops the
-- REPORTER reviewing.
--
-- Deliberately a SECOND pair rather than an early write of the review pair:
-- claiming and deciding are different acts by possibly different people
-- (operator A claims, is called away, operator B approves), and collapsing
-- them would make `human_review_by` — the column three CHECKs and docs/03
-- §5.1 control 2 all read as "who performed the mandatory human review" —
-- mean "who opened it first" instead.
--
-- No pre-flight and no backfill: these are new nullable columns, so no
-- existing row can violate either constraint, and a case claimed before this
-- migration legitimately has no claimer to record. That is the OPPOSITE of
-- `002_dek_unique_active`'s situation (which narrows what is permitted and
-- must therefore refuse rather than guess), and it is stated here so the
-- pattern is not cargo-culted into a migration that does need one.
--
-- The version trigger captures both columns with no trigger change: its row
-- image is whole-row `to_jsonb(OLD)` (001), so the audit capture follows the
-- table rather than a hand-maintained column list.

ALTER TABLE settlement_cases
  ADD COLUMN claimed_by UUID,
  ADD COLUMN claimed_at TIMESTAMPTZ;

-- The pair travels together, exactly as the review pair does.
ALTER TABLE settlement_cases
  ADD CONSTRAINT settlement_cases_claim_pair
  CHECK ((claimed_by IS NULL) = (claimed_at IS NULL));

-- Dual control, one step earlier than it used to bite. The reporter has always
-- been refused at the DECISION (`settlement_cases_reviewer_not_reporter` plus
-- the readable `reviewer_is_reporter` 403 in decideReview and
-- confirmVerification) — but nothing stopped a reporter-operator CLAIMING the
-- case first, which moved it to `verifying`, put their name on it, and left a
-- claim they could never discharge. Refusing at the claim keeps the marker
-- honest: a claim is an assertion that you may decide this case.
ALTER TABLE settlement_cases
  ADD CONSTRAINT settlement_cases_claimer_not_reporter
  CHECK (claimed_by IS NULL OR claimed_by <> reported_by);
