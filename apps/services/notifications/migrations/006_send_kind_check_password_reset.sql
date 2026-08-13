-- M17 PR3 — `notification_sends.kind` learns the password-reset kind.
--
-- A NEW FILE, never an edit to 005: the migrator checksums applied migrations
-- and raises MigrationDriftError on a mismatch.
--
-- The consequence of forgetting this is the M14 PR0 sequence, and on THIS kind
-- it is at its worst: the send row is written after the carrier hand-off and
-- outside the try/catch, so a missing CHECK value means the reset code genuinely
-- reaches the user, the INSERT then violates the constraint, and identity
-- records that the mail failed — so the operator sees a reset that was never
-- sent while somebody holds a working code.
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
    -- M17 PR2.
    'identity.password_changed',
    -- M17 PR3. A SYSTEM kind on its own credential: the estate send wire, the
    -- verification wire and the account-security wire each build from a
    -- different closed list, so none of them can fire this one.
    'identity.password_reset'
  ));
