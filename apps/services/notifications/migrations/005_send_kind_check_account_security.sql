-- M17 PR2 — `notification_sends.kind` learns the account-security kind.
--
-- A NEW FILE, NEVER AN EDIT TO 003. `packages/db/src/migrator.ts` records a
-- sha256 of every applied migration and raises MigrationDriftError on a
-- mismatch, so editing the file that currently owns this constraint would fail
-- every deployment that has already run it.
--
-- WHY THIS IS NOT OPTIONAL PAPERWORK. The send log is written AFTER the carrier
-- hand-off and OUTSIDE the try/catch that absorbs carrier failures, so a kind
-- missing from this CHECK produces the M14 PR0 sequence exactly: the mail
-- genuinely reaches the user, the INSERT violates the constraint, the exception
-- escapes `send()`, no `notification.sent` event is emitted, and the CALLER
-- records that the user was not told. The owner WAS told and their own trail
-- says they were not — an inverted audit claim rather than a lost row, and on
-- this kind it would be worse than on M13's: `identity.password_changed` exists
-- precisely so a user learns their credentials moved, and the failure mode
-- would be "we mailed them and recorded that we could not".
--
-- The regression pin is `notifications.int.spec.ts`, which drives EVERY member
-- of NOTIFICATION_KINDS and asserts the recorded rows equal that list — derived
-- from the enum, never a list of its own, so a kind added to the wire without
-- widening this CHECK turns red on the first run.

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
    'settlement.case_opened',
    'settlement.owner_contact',
    'contact.link_claimed',
    -- M14.
    'identity.address_verification',
    -- M17. A SYSTEM kind: excluded from the estate send schema, so the
    -- broadly-held send credential cannot fire it.
    'identity.password_changed'
  ));
