-- M17 PR4 — `notification_sends.kind` learns the two email-change kinds.
--
-- A NEW FILE, never an edit to 006: the migrator checksums applied migrations
-- and raises MigrationDriftError on a mismatch.
--
-- Same consequence class as 006's warning if forgotten, split across the two
-- kinds. `identity.email_change` is recorded after the carrier hand-off, so a
-- missing CHECK value means the challenge genuinely reaches the prospective
-- mailbox while the log INSERT throws — a code in the world with no record of
-- the send. `identity.email_changed` is the takeover notice to the address
-- being LEFT; losing its row means the one delivery an investigator most needs
-- evidence of is the one with no evidence.
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
    -- M17 PR3.
    'identity.password_reset',
    -- M17 PR4. The challenge to a PROSPECTIVE address — the one send whose
    -- destination comes from the wire, on its own credential and closed list.
    'identity.email_change',
    -- M17 PR4. The change notice to the address being LEFT, on the
    -- account-security wire; carries nothing, and identity sends it BEFORE the
    -- recipient store is repointed so it reaches the old mailbox.
    'identity.email_changed'
  ));
