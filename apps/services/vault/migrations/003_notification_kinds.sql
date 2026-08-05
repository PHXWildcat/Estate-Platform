-- ---------------------------------------------------------------------------
-- M9: two new owner-notification kinds, closing the M6 review's recorded
-- follow-ups — 'reset' (the vault was destroyed; the one bearer-token-
-- destructive route gains its promised compensating notification) and
-- 'grantees_changed' (a reconfiguration retired the previous grantees).
--
-- 'reset' outlives every policy, so policy_id becomes nullable — but ONLY for
-- vault-level kinds: the original policy-scoped kinds keep requiring their
-- anchor, restated as a CHECK so the loosened column cannot quietly admit an
-- unanchored 'requested'.
-- ---------------------------------------------------------------------------

ALTER TABLE emergency_access_notifications
  ALTER COLUMN policy_id DROP NOT NULL;

ALTER TABLE emergency_access_notifications
  DROP CONSTRAINT emergency_access_notifications_kind_check;

ALTER TABLE emergency_access_notifications
  ADD CONSTRAINT emergency_access_notifications_kind_check
  CHECK (kind IN ('requested','blocked','reminder','released','revoked','reset','grantees_changed'));

ALTER TABLE emergency_access_notifications
  ADD CONSTRAINT emergency_access_notifications_policy_anchor_check
  CHECK (policy_id IS NOT NULL OR kind IN ('reset'));
