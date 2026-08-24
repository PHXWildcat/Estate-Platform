-- M27 PR3b — `notification_sends.kind` learns the grantee-read notice.
--
-- A NEW FILE, never an edit to 008: the migrator checksums applied migrations
-- and raises MigrationDriftError on a mismatch.
--
-- THE SECOND HALF OF A TWO-CLUSTER CHANGE. The vault has its own kind CHECK on
-- `emergency_access_notifications` (its migration 008), and M13 shipped a kind
-- to one of these lists and not the other: the send succeeded and the record
-- of it did not, so owners were mailed while their trail said they were not.
-- `notifications.int.spec.ts` inserts every member of `NOTIFICATION_KINDS` and
-- compares the resulting SET, so that particular pair can no longer drift
-- silently — but the DDL still has to be written on both sides, here and in
-- `apps/services/vault/migrations/008_notification_kind_read_by_grantee.sql`.
--
-- 'vault.*' rather than 'emergency.*' deliberately, matching 'vault.reset' and
-- 'vault.grantees_changed': the emergency.* kinds are all steps of the ACCESS
-- ceremony (requested / blocked / reminder / released / revoked), and this one
-- is about the vault's contents having been read.
ALTER TABLE notification_sends DROP CONSTRAINT notification_sends_kind_check;

ALTER TABLE notification_sends
  ADD CONSTRAINT notification_sends_kind_check CHECK (kind IN (
    'emergency.requested',
    'emergency.blocked',
    'emergency.reminder',
    'emergency.released',
    'emergency.revoked',
    'vault.reset',
    'vault.grantees_changed',
    -- M27 PR3b: a released grantee opened the owner's items. Emitted once per
    -- collection rather than once per read — see the vault-side migration.
    'vault.read_by_grantee',
    'settlement.case_opened',
    'settlement.owner_contact',
    'contact.link_claimed',
    -- M14.
    'identity.address_verification',
    -- M17 PR2.
    'identity.password_changed',
    -- M17 PR3.
    'identity.password_reset',
    -- M17 PR4.
    'identity.email_change',
    'identity.email_changed',
    -- M17 follow-up.
    'identity.passkey_clone_detected'
  ));
