-- The operator action ledger — the counter the breadth bound reads.
--
-- WHY A TABLE AND NOT SOMETHING THAT ALREADY EXISTS. Three candidates were
-- examined and each mis-measures:
--
--   * The AUDIT CLUSTER already records every operator action, but it is a
--     different Postgres cluster. A settlement read against it would cross a
--     trust-zone boundary to enforce a settlement control, and the control
--     would then fail whenever the audit cluster was unreachable — an outage
--     wearing the face of a bound.
--   * The `*_versions` tables are append-only and DO stamp `actor_id` from
--     `app.actor_id`. But they capture `UPDATE`/`DELETE` only, so an operator's
--     CREATIONS are invisible to them, and one action touching three rows
--     writes three version rows. Counting them measures row churn, not actions.
--   * The domain tables themselves record the current state, not who reached it
--     how often, and a status that moves twice leaves one row.
--
-- So the ledger is explicit, written in the SAME TRANSACTION as the action it
-- describes, which is what stops it drifting from the thing it counts.
--
-- It is deliberately NOT the audit trail and does not replace it: this is a
-- local operational counter, and `AUDIT_ACTIONS` remains the record of what
-- happened. Identity's `auth_events` is the same shape and the same reason.

CREATE TABLE settlement_operator_actions (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id  UUID NOT NULL,
  case_id      UUID NOT NULL,
  action       TEXT NOT NULL,
  occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The bound's only query is "distinct case_id for this operator since T", so
-- the index carries case_id to keep it index-only.
CREATE INDEX settlement_operator_actions_breadth
  ON settlement_operator_actions (operator_id, occurred_at DESC, case_id);

COMMENT ON TABLE settlement_operator_actions IS
  'Local operational ledger of PERMISSIVE operator actions, one row per action, '
  'written in the same transaction as the action. Read only by the breadth '
  'bound. Protective actions (revoke, deny) are deliberately NOT recorded here: '
  'the bound must never make the protective path costlier than the permissive '
  'one. Not the audit trail — see AUDIT_ACTIONS for that.';

COMMENT ON COLUMN settlement_operator_actions.case_id IS
  'The estate the action touched. The bound counts DISTINCT values of this per '
  'operator per window: the threat modelled is breadth (one operator sweeping '
  'many estates), not depth (a legitimate reviewer working one estate hard).';
