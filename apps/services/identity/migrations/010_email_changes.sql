-- M17 PR4 — the email-change ceremony's staging table.
--
-- VERIFY-THEN-SWITCH, and the ordering is the design: login resolves users by
-- `email_bidx`, so a change that stored an unproven address would lock its
-- owner out of LOGIN ITSELF the moment their sessions lapsed — a typo'd new
-- address must never reach `users` until a code mailed to it comes back. This
-- table holds the candidate: the address encrypted under the user's live DEK
-- with the SAME field id `users.email` register uses, so at the switch the
-- ciphertext moves into `users.email_ct` byte-for-byte with no decrypt on the
-- identity side of the transaction.
--
-- WHAT IS NOT STORED: never the code (sha256 of its canonical form only), and
-- never the plaintext address.
--
-- THE SELECTOR IS THE USER, NOT THE DIGEST — the opposite of `password_resets`,
-- and deliberately: the redeemer here is AUTHENTICATED (they are changing
-- their own address from their own session), so completion resolves this
-- user's live row and compares digests. That is also what makes the attempt
-- cap attributable (the M14 round-2 lesson: a cap that can only count what it
-- can attribute was decorative until keyed on the user) — a wrong guess of ANY
-- shape burns one attempt on the caller's own live change. Consequently there
-- is no unique index on code_sha256: no digest lookup exists to serve.
CREATE TABLE email_changes (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id),
  -- The candidate address, encrypted as `users.email` under the user's live
  -- DEK. `dek_id` is recorded so the switch can refuse if the account's key
  -- changed between mint and redemption (the M4 rule: a shredded record is
  -- Gone, never silently re-keyed).
  new_email_ct    BYTEA NOT NULL,
  new_email_bidx  BYTEA NOT NULL,
  dek_id          UUID NOT NULL,
  code_sha256     BYTEA NOT NULL,
  attempts        INT NOT NULL DEFAULT 0,
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ONE live change per user, enforced rather than check-then-inserted. A
-- partial unique index cannot reference now(), so a lapsed row still occupies
-- the slot — which is why the service retires UNCONDITIONALLY before every
-- mint (the M14 review's worst finding: retire-only-when-usable answered
-- too_soon forever after one ignored email).
CREATE UNIQUE INDEX ux_email_changes_live ON email_changes (user_id)
WHERE revoked_at IS NULL AND completed_at IS NULL;

-- Mint-decision and completion reads resolve by user.
CREATE INDEX ix_email_changes_user ON email_changes (user_id, created_at DESC);

-- Rows are evidence (who staged which address digest, when): append + state
-- flips only, never removal.
REVOKE DELETE ON email_changes FROM PUBLIC;
