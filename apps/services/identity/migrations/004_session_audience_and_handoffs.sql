-- ---------------------------------------------------------------------------
-- M15 — the vault surface: what a session is FOR, and the ceremony that mints
-- one for another origin.
--
-- Zone A moves to an ISOLATED ORIGIN (docs/03 TB6, risk #4). The main app's
-- session cookies are host-only on the app origin, so they are not sent to the
-- vault origin — MEASURED in a real browser rather than assumed, and the same
-- measurement showed the rejected alternative failing: cookie scope ignores the
-- PORT, so a vault surface at `localhost:3010` would have received the app's
-- full session on every request. Only a different HOST isolates.
--
-- Authority therefore has to cross deliberately, and this migration is the two
-- halves of that:
--
--   1. `sessions.audience` — what a session may be spent on. The handoff
--      redeems for a `vault` session, and `CallerGuard` admits it at the vault
--      service alone (deny by default, `AUDIENCE_ADMITTERS` in
--      @estate/auth-guard). So a leaked handoff is not authority over assets,
--      documents, profile or identity.
--   2. `auth_handoffs` — the single-use code itself.
--
-- THE PATTERN IS M13's CONTACT LINK AND M14's ADDRESS VERIFICATION, third time:
-- mint from randomBytes, store ONLY the sha256, a hard TTL, burn on the
-- ATTEMPT, and one uniform refusal for unknown/expired/spent/revoked/raced.
-- What is different here is the lifetime and what it buys. This code is not
-- handled by a human — it travels in a top-level form POST from one origin to
-- the other and is redeemed server-side — so it needs no retyping affordance,
-- no canonical fold, and no generous window. 60 seconds is not a usability
-- number; it is the exposure.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- 1. Session audience
-- ---------------------------------------------------------------------------

-- DEFAULT 'account' backfills every existing row to exactly what it already
-- was, so this is additive: no session changes meaning, and no service that has
-- not opted in changes behaviour. NOT NULL because "unknown audience" must not
-- be representable — the guard would then have to decide what a NULL means, and
-- a nullable security column is a decision deferred to whoever reads it next.
ALTER TABLE sessions
  ADD COLUMN audience TEXT NOT NULL DEFAULT 'account'
    CHECK (audience IN ('account', 'vault'));

-- The vocabulary is closed in THREE places that must agree: this CHECK, the
-- `SESSION_AUDIENCES` union in @estate/auth-guard, and the zod enum on the
-- introspection response. A spec reads this file to pin the first to the
-- second, rather than pinning either to a comment (the M10 consent-scope
-- precedent).

COMMENT ON COLUMN sessions.audience IS
  'What this session may be spent on. account = the ordinary session every '
  'surface uses. vault = minted only by handoff redemption, carries no usable '
  'refresh token, 15 minutes, and admitted by the vault service alone.';

-- ---------------------------------------------------------------------------
-- 2. The handoff
-- ---------------------------------------------------------------------------

CREATE TABLE auth_handoffs (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES users(id),
  -- sha256 of the code. A database read yields no usable code, which matters
  -- more here than in M13/M14: this one redeems for a live session with no
  -- further proof, so the digest is the only thing standing between a dump of
  -- this table and a vault-origin session.
  code_sha256    BYTEA NOT NULL,
  -- What redemption will mint. Stored rather than assumed so a second audience
  -- can never be introduced by changing the redeeming CODE PATH alone — the
  -- grant is a property of the issued row, decided under step-up at mint.
  audience       TEXT NOT NULL CHECK (audience IN ('vault')),
  -- The session that asked. Recorded so an owner reviewing their trail can see
  -- which login opened the vault origin, and so revoking a session can later
  -- retire its outstanding handoffs.
  minted_from    UUID NOT NULL REFERENCES sessions(id),
  -- The session redemption produced, once it has. Null until then; this is the
  -- only link between the ceremony and its result.
  session_id     UUID REFERENCES sessions(id),
  expires_at     TIMESTAMPTZ NOT NULL,
  -- BURNED ON THE ATTEMPT, not on success — the vault SRP-handshake rule
  -- (docs/04 M6). A wrong-but-live guess must cost the attacker the code,
  -- otherwise one issued handoff underwrites unlimited attempts.
  consumed_at    TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Redemption's ONLY selector: the code. There is no user id and no session id
-- in the redeem request, and nothing in that route can name an account — the
-- M13 §6b anti-enumeration property, which survives only while the code is the
-- sole selector. UNIQUE because two live codes with one digest is a collision
-- better seen as an error than resolved arbitrarily.
CREATE UNIQUE INDEX ux_auth_handoffs_code ON auth_handoffs (code_sha256);

-- AT MOST ONE UNSPENT HANDOFF PER USER. Without it a page that re-renders
-- mints a fresh 60-second credential each time and every one stays redeemable
-- until it lapses, so the exposure is the number of times a button was pressed
-- rather than the TTL.
--
-- The predicate is `consumed_at IS NULL` ALONE, deliberately, even though what
-- it means to say is "no live one". An index predicate must be immutable, so it
-- cannot mention `expires_at > now()` — and a predicate that could would leave
-- an expired row blocking the user forever. The invariant is therefore closed
-- from the WRITE side instead: minting RETIRES the caller's outstanding handoff
-- in the same transaction before inserting (`consumed_at = now()`), which the
-- index then enforces. That also gives re-issue the behaviour it should have —
-- a new code kills the previous one, the M13/M14 rule — rather than leaving two
-- live credentials because someone double-clicked.
CREATE UNIQUE INDEX ux_auth_handoffs_live
  ON auth_handoffs (user_id)
  WHERE consumed_at IS NULL;

CREATE INDEX ix_auth_handoffs_expiry ON auth_handoffs (expires_at);
