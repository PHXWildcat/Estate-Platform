-- ---------------------------------------------------------------------------
-- M27 PR3b: 'read_by_grantee' — the owner is told when a released grantee
-- actually OPENS their items, which is a different fact from the collection
-- that made it possible ('released', migration 002).
--
-- The kind CHECK is widened in a LATER migration rather than edited into 002
-- for the reason 003 exists: applied migrations are checksummed, and editing
-- one raises MigrationDriftError and blocks every migration after it.
--
-- ONCE PER COLLECTION, NOT PER READ, and this table is what makes that
-- derivable without a new column: the emitter asks whether a 'read_by_grantee'
-- row already exists for this policy with `created_at >= released_at`. Since
-- M27 PR3a made release RE-collectable, that predicate re-arms by itself on
-- every fresh collection — a stored `notified` flag would have had to be reset
-- by each of the three writers that move a policy in and out of 'released'
-- ('markDenied' and 'markRevoked' out, 'markReleased' in; 'markRearmed' cannot,
-- because 'rearm' refuses a released policy before reaching the repo).
--
-- The existing `ix_emergency_access_notifications_policy` index on
-- (policy_id, created_at DESC) already answers that query; no index is added.
--
-- 'read_by_grantee' is policy-scoped, so it is deliberately NOT added to
-- `emergency_access_notifications_policy_anchor_check`'s exemption list: a
-- read always has a policy that authorized it, and a row without one would be
-- a bug rather than a vault-level event.
-- ---------------------------------------------------------------------------

ALTER TABLE emergency_access_notifications
  DROP CONSTRAINT emergency_access_notifications_kind_check;

ALTER TABLE emergency_access_notifications
  ADD CONSTRAINT emergency_access_notifications_kind_check
  CHECK (kind IN ('requested','blocked','reminder','released','revoked','reset',
                  'grantees_changed','read_by_grantee'));
