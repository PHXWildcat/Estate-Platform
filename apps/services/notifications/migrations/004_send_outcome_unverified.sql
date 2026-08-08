-- ---------------------------------------------------------------------------
-- M14 PR2 — `sent_unverified`: the mail went, to an address nobody proved.
--
-- The gate classification splits M14's call sites in two (docs/03 §6c). The
-- ARMING actions — vault escrow configure, vault rearm, profile link-code mint
-- — require a verified recipient and refuse without one. The others PROCEED
-- and RECORD, because in those the ACTOR and the NOTIFICATION RECIPIENT are
-- different people: blocking a grantee's emergency request, a redeemer's claim
-- or a reporter's death report on the OWNER's unverified address would let an
-- owner's own typo permanently deny a legitimate third party, and applied to
-- §5.1 intake it becomes a denial of service against exactly the unverified
-- dormant owner the anti-correlation makes most vulnerable.
--
-- So there has to be somewhere the fact lands. This is it: the send log's own
-- vocabulary, in the store that KNOWS — rather than a parallel table nobody
-- would join against. `sent` now means "delivered to a proved address" and
-- `sent_unverified` means "delivered to an address the user never confirmed".
-- Both are deliveries; `delivered: true` is returned for both, because the
-- carrier accepted the message either way and a caller's retry logic must not
-- treat an unverified recipient as a transport failure.
--
-- The distinction is evidence, not a control. A §5.1 investigation reading a
-- case trail can now tell "the owner was mailed and had confirmed that mailbox"
-- from "the owner was mailed at an address we have no proof they read", which
-- is precisely the difference between a waiting period the owner could have
-- interrupted and one they could not.
--
-- Same append-only-safe DROP/ADD as 002 and 003, and the same reason it is a
-- new file: the migrator checksums applied migrations. `REVOKE UPDATE, DELETE`
-- is untouched — redefining a constraint is a DDL privilege of the table owner,
-- not a row privilege.
--
-- NOT backfilled, deliberately. Every existing `sent` row predates the ceremony
-- and was therefore delivered to an unproved address, but rewriting history in
-- an append-only log to say so would be a worse lie than the one it corrects —
-- and `REVOKE UPDATE` means the table's own grants forbid it. The absence of
-- `sent_unverified` before this migration IS the marker.
-- ---------------------------------------------------------------------------

ALTER TABLE notification_sends DROP CONSTRAINT notification_sends_outcome_check;

ALTER TABLE notification_sends ADD CONSTRAINT notification_sends_outcome_check
  CHECK (outcome IN ('sent', 'sent_unverified', 'no_recipient', 'carrier_failure'));
