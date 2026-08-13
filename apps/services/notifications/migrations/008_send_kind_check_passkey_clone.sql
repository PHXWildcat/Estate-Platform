-- M17 follow-up — `notification_sends.kind` learns the passkey-clone notice.
--
-- A NEW FILE, never an edit to 007: the migrator checksums applied migrations
-- and raises MigrationDriftError on a mismatch.
--
-- The M14 PR0 consequence applies here with a particular sting. This kind is
-- sent from inside a REFUSAL path — identity has already decided to reject the
-- assertion — so a missing CHECK value would mean the owner genuinely receives
-- the warning while the INSERT throws, and the audit event that rides the send
-- outcome records `notified: failed` about somebody who was in fact warned.
-- The one event an investigator reads to decide whether the owner knew would
-- say the opposite of the truth.
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
    -- M17 PR4.
    'identity.email_change',
    'identity.email_changed',
    -- M17 follow-up: a passkey failed the FIDO signature-counter check. The
    -- account-security wire, carrying nothing — the answer to the PR6 review's
    -- clone-detection item is to TELL the owner, never to revoke their factor
    -- on a heuristic.
    'identity.passkey_clone_detected'
  ));
