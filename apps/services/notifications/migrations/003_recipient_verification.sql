-- ---------------------------------------------------------------------------
-- M14 — address ownership. The delivery store learns whether it can PROVE it
-- reaches a user, and gains the kind that asks them.
--
-- WHY THE BIT LIVES HERE AND NOT ON `users`. Three shipped fail-closed
-- controls — M6 emergency access (§5.2), M7 settlement intake/review-approve
-- (§5.1) and M13's link ceremony (§6g) — refuse in production rather than
-- proceed silently, on the rule that a waiting period nobody can be told about
-- is not a control. Every one of them tests `deliversToRealChannels`, which is
-- a hardcoded literal on whichever adapter class the service's own NOTIFY_MODE
-- selected: it asks whether SES is wired. It never asks whether the stored
-- address belongs to the owner, and could not, because it never looks at a
-- recipient.
--
-- Putting `verified_at` on `notification_recipients` means the delivery store
-- structurally cannot hold an unproven address without saying so, and the
-- question "can we actually reach this owner?" is answered by the store that
-- would have to do the reaching. An `email_verified_at` flag on identity's
-- `users` — the column that has existed since M1 with no reader and no writer
-- — would have let the gates keep reading a local boolean and bolt a lookup
-- beside it, leaving the shape that made the defect invisible in place.
--
-- TWO PROPERTIES COME FREE, AND THE SPECS ASSERT THEM RATHER THAN ASSUME:
--   · the versions trigger captures `to_jsonb(OLD)`, a whole-row image, so the
--     new column is versioned with no trigger change;
--   · the bit shares the row's lifecycle, so a crypto-shredded or soft-deleted
--     recipient loses its verification along with its address and the arming
--     gates then refuse — fail-closed by construction, not by a second check.
--
-- IT IS NULLABLE AND STARTS NULL FOR EVERYONE, including existing rows. That
-- is the correct backfill: no address in this store has ever been proved, so
-- claiming otherwise for rows that predate the ceremony would be the exact
-- false assurance the milestone exists to remove. Users heal at their next
-- login, which is where the code is minted.
--
-- NO BLIND INDEX AND NO NEW LOOKUP PATH. The only selector remains user_id
-- (001's own note). Verification is driven by identity, which resolves the user
-- from `email_bidx` before it ever calls here, so nothing in this service needs
-- to search by address.
-- ---------------------------------------------------------------------------

ALTER TABLE notification_recipients ADD COLUMN verified_at TIMESTAMPTZ;

-- ---------------------------------------------------------------------------
-- The new kind. Same append-only-safe DROP/ADD as 002, and the same reason it
-- is a new file: the migrator checksums applied migrations.
--
-- `identity.address_verification` is deliberately NOT reachable through
-- `POST /internal/v1/notifications/send` — its schema is built from
-- ESTATE_NOTIFICATION_KINDS, which excludes it — because its template needs a
-- CODE and a send-credential holder has no field to put one in. It travels on
-- its own route behind its own credential. The log's vocabulary is wider than
-- the send route's on purpose: every send of every kind gets a row.
-- ---------------------------------------------------------------------------

ALTER TABLE notification_sends DROP CONSTRAINT notification_sends_kind_check;

ALTER TABLE notification_sends ADD CONSTRAINT notification_sends_kind_check
  CHECK (kind IN (
    'emergency.requested','emergency.blocked','emergency.reminder',
    'emergency.released','emergency.revoked',
    'vault.reset','vault.grantees_changed',
    'settlement.case_opened','settlement.owner_contact',
    'contact.link_claimed',
    -- M14.
    'identity.address_verification'
  ));
