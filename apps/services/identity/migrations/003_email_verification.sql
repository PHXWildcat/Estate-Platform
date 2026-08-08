-- ---------------------------------------------------------------------------
-- M14 — address ownership: the ceremony's secret half.
--
-- The codes live in the AUTH cluster because they are auth secrets. Identity
-- already owns password hashes, TOTP secrets and session tokens; a single-use
-- proof-of-possession code is the same kind of thing, and putting it in the
-- notifications service would give the delivery boundary the power to mint the
-- proof it is meant to be the subject of.
--
-- THE PATTERN IS M13's CONTACT-LINK CEREMONY, deliberately and near-verbatim:
-- mint from randomBytes, store ONLY the sha256 of the canonical form, a TTL, an
-- attempt cap, and one uniform refusal for unknown/expired/spent/revoked/raced.
-- The differences are what the two ceremonies are for:
--
--   · M13's code travels OUT OF BAND, delivered by the owner. This one travels
--     IN BAND, to the address it is testing — which is the whole point: the
--     code is a challenge to that mailbox, so delivering it there is the proof.
--   · M13's redeemer is a different person. Here the redeemer is the account
--     holder, so redemption requires their own live session (`user_id` must
--     match the caller), and the code's job is to prove the MAILBOX rather than
--     the person.
--
-- WHAT IS NOT STORED: never the code, never a reversible transform of it, and
-- never the address (identity already holds `users.email_ct`; this table adds
-- no second copy and no new blind index).
--
-- `users.email_verified_at` is deliberately NOT written by any of this. It has
-- been dead schema since M1 (one DDL line, no reader, no writer) and M14's
-- decision is that the verified bit belongs on `notification_recipients` — the
-- store that would have to do the reaching — so that the delivery store cannot
-- structurally hold an unproven address without saying so. Leaving the column
-- unwritten keeps a single source of truth; retiring it belongs to whichever
-- change is willing to migrate docs/02 §1.
-- ---------------------------------------------------------------------------

CREATE TABLE email_verifications (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id),
  -- sha256 of the CANONICAL form of the code (see canonicalCode in
  -- email-verification.service.ts). Storing the digest means a database read
  -- does not yield a usable code, and the canonical form means a human can
  -- retype what they were shown.
  code_sha256  BYTEA NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  -- Bounds guessing against a LIVE code. It is not a general rate limit: an
  -- unknown code leaves no trace by construction, because there is no row to
  -- count against (M13's reasoning, restated because the shape is the same).
  attempts     INT NOT NULL DEFAULT 0,
  -- Set when the send failed, when the owner re-issued, or when it was used.
  -- Three columns rather than one status, so "why is this code dead" is
  -- answerable from the row: a code retired because SES refused is an
  -- operational fact, and a code retired because a newer one was minted is a
  -- user action.
  revoked_at   TIMESTAMPTZ,
  verified_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Redemption's ONLY selector. Unique because two live codes hashing the same
-- is a collision we would rather see as an error than resolve arbitrarily.
CREATE UNIQUE INDEX ux_email_verifications_code ON email_verifications (code_sha256);

-- At most ONE live code per user, enforced rather than checked-then-inserted.
-- Without it, two concurrent logins would each observe "no live code" and mint
-- two, so the address gets two mails and the second silently orphans the first.
-- The loser of the race takes the unique violation and treats it as "somebody
-- already minted one", which is exactly the idempotent outcome wanted.
CREATE UNIQUE INDEX ux_email_verifications_live ON email_verifications (user_id)
WHERE revoked_at IS NULL AND verified_at IS NULL;

CREATE INDEX ix_email_verifications_user ON email_verifications (user_id, created_at DESC);

-- Append-mostly: rows are inserted and then transition once (revoked or
-- verified). Nothing deletes them — the trail of "a code was mailed to this
-- account at time T" is evidence for exactly the case where somebody's address
-- was typed into a registration by mistake or by design.
REVOKE DELETE ON email_verifications FROM PUBLIC;
