-- ---------------------------------------------------------------------------
-- M17 PR3 — password reset: the ceremony's secret half.
--
-- THE PATTERN IS M14's `email_verifications`, near-verbatim, because the two
-- ceremonies are the same shape: mint from randomBytes, store ONLY the sha256
-- of the canonical form, a TTL, one live code per user enforced by a partial
-- unique index, and one uniform refusal for every way a redemption can fail.
-- What differs is what the code is FOR, and every difference below follows from
-- that.
--
--   · M14's redeemer is SIGNED IN — the code proves the MAILBOX and the session
--     proves the person. Here the redeemer has neither, by construction: a user
--     who has forgotten their password cannot present one. So the code is the
--     ONLY selector, there is nowhere in the request to name an account, and
--     the anti-enumeration property of §6g's link ceremony applies verbatim.
--   · M14's code proves an address. THIS one replaces the credential the whole
--     platform rests on. It is the more valuable secret of the two and it is
--     mailed to the same place, which is why it lives behind its own
--     notifications credential rather than sharing the verification one.
--
-- NO `attempts` COLUMN, and that is a decision rather than an omission.
-- M14 has one because its redeemer is authenticated, so a wrong guess can be
-- attributed to the CALLER and counted. Redemption here is unauthenticated and
-- a wrong guess produces a different digest, so it resolves no row — there is
-- nothing to increment, and a column keyed on the resolved row would be exactly
-- the decorative cap the M14 round-2 review found and re-keyed. M16's
-- `extension_pairings` reached the same conclusion for the same reason and says
-- so in its own DDL. The bound is 160 bits of entropy, a short TTL, and
-- burn-on-attempt in the service.
--
-- WHAT IS NOT STORED: never the code, never a reversible transform of it, and
-- never the address. Identity already holds `users.email_ct`; this table adds
-- no second copy and no new blind index.
-- ---------------------------------------------------------------------------

CREATE TABLE password_resets (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id),
  -- sha256 of the CANONICAL form (see canonicalCode in readable-code.ts), so a
  -- database read yields nothing usable and a human can retype what they were
  -- mailed.
  code_sha256  BYTEA NOT NULL,
  expires_at   TIMESTAMPTZ NOT NULL,
  -- Three columns rather than one status, on M14's reasoning: "why is this code
  -- dead" should be answerable from the row. Retired because the send failed is
  -- an operational fact; retired because a newer one was requested is a user
  -- action; redeemed is the ceremony completing.
  revoked_at   TIMESTAMPTZ,
  redeemed_at  TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Redemption's ONLY selector. Unique because two live codes hashing the same is
-- a collision we would rather see as an error than resolve arbitrarily.
CREATE UNIQUE INDEX ux_password_resets_code ON password_resets (code_sha256);

-- At most ONE live code per user, enforced rather than checked-then-inserted:
-- two concurrent requests would each observe "no live code" and mint two, so the
-- address gets two mails and the second silently orphans the first.
--
-- THE PREDICATE CANNOT REFERENCE now(), and that is the M14 review's worst
-- finding restated here so the next reader does not have to rediscover it. A
-- partial index is immutable, so a LAPSED row still occupies this slot. The
-- service must therefore retire the previous row UNCONDITIONALLY — matching
-- THIS predicate, not a clock-carrying "is there a live code" read — or the
-- first ignored reset email wedges the slot forever and the account can never
-- be recovered. On M14's ceremony that bug made verification impossible; here
-- it would make RECOVERY impossible, which is strictly worse.
CREATE UNIQUE INDEX ux_password_resets_live ON password_resets (user_id)
WHERE revoked_at IS NULL AND redeemed_at IS NULL;

CREATE INDEX ix_password_resets_user ON password_resets (user_id, created_at DESC);

-- Append-mostly: rows are inserted and transition once. Nothing deletes them —
-- "a reset was requested for this account at time T" is evidence for exactly the
-- case this ceremony is most likely to be abused in, where somebody who is not
-- the owner is probing or has mailbox access.
REVOKE DELETE ON password_resets FROM PUBLIC;
