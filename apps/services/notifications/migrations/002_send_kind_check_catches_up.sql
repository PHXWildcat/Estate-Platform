-- ---------------------------------------------------------------------------
-- notification_sends.kind — catch the CHECK up with the wire enum.
--
-- THE DEFECT THIS CLOSES WAS LIVE, AND SILENT, AND IT INVERTED AN AUDIT CLAIM.
--
-- M13 added `contact.link_claimed` to NOTIFICATION_KINDS
-- (packages/notifications-client), gave it a template, and made profile a
-- holder of the send credential. It did NOT add the value here — this
-- directory contained only 001 — so the CHECK still listed the nine M9 kinds.
--
-- `NotificationsService.send` records the row AFTER handing the message to the
-- carrier, and outside the try/catch that absorbs carrier failures. So the
-- sequence for every real link claim was:
--
--   1. resolve the recipient, decrypt the address (audited), render, SEND —
--      the mail genuinely reaches the owner;
--   2. INSERT INTO notification_sends → check constraint violation;
--   3. the exception escapes send(), so `notification.sent` is never emitted
--      and the operational log has no row;
--   4. the caller sees a 500, HttpNotificationsClient narrows it to
--      `{accepted:false}`, HttpLinkNotifier throws, and ContactLinksService
--      records `contact.link.claimed {"ownerNotified":"failed"}`.
--
-- The owner WAS told and their own trail says they were not. That is worse
-- than a lost row: `ownerNotified:'failed'` exists so an operator can re-drive
-- a notification the owner never got (docs/03 §6g), and here it would send a
-- duplicate warning about a link the owner had already been warned about,
-- while the real signal — that the send path is broken for this kind — looked
-- like an ordinary carrier failure.
--
-- Measured on the running local stack rather than reasoned about: LocalStack's
-- SES inbox held the link-claimed body, `notification_sends` held no row of
-- that kind, no `notification.sent` event existed, and both
-- `contact.link.claimed` events carried ownerNotified "failed".
--
-- WHY NOTHING CAUGHT IT. The unit suite fakes the repo, so no CHECK exists to
-- violate; the int suite exercised three kinds by hand and none was the new
-- one; and the stack e2e asserts the `contact.link.claimed` audit event, whose
-- shape is identical either way. `notifications.int.spec.ts` now drives EVERY
-- kind in the enum, derived from the enum itself, so the next kind is covered
-- without anyone remembering to add it (docs/04 boundary rule 6).
--
-- A NEW FILE, NEVER AN EDIT TO 001. The migrator checksums applied files and
-- raises MigrationDriftError on a mismatch (packages/db/src/migrator.ts), so
-- appending to an applied migration fails loudly on the next run — which is
-- the correct behaviour and the reason this is 002.
--
-- The REVOKE UPDATE, DELETE on this table is untouched and unaffected:
-- redefining a constraint is a DDL privilege of the table owner, not a row
-- privilege, so the append-only guarantee survives verbatim.
-- ---------------------------------------------------------------------------

ALTER TABLE notification_sends DROP CONSTRAINT notification_sends_kind_check;

ALTER TABLE notification_sends ADD CONSTRAINT notification_sends_kind_check
  CHECK (kind IN (
    'emergency.requested','emergency.blocked','emergency.reminder',
    'emergency.released','emergency.revoked',
    'vault.reset','vault.grantees_changed',
    'settlement.case_opened','settlement.owner_contact',
    -- M13, missing since it was introduced.
    'contact.link_claimed'
  ));
