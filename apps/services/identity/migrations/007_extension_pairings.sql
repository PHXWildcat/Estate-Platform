-- ---------------------------------------------------------------------------
-- M16 — extension pairing: the ceremony that mints the browser extension's
-- credential.
--
-- THE PATTERN IS M13's CONTACT LINK AND M14's ADDRESS VERIFICATION, third
-- application: mint from randomBytes, store ONLY the sha256 of the CANONICAL
-- form, a TTL, one live row per user, and one uniform refusal for
-- unknown/expired/spent/revoked/raced. What differs is what the code is FOR,
-- and that shapes three columns.
--
--   · IT IS TYPED BY A HUMAN, unlike M15's handoff — which is why it gets a
--     readable alphabet and a fold, and why its TTL is minutes rather than the
--     handoff's sixty seconds. It crosses from a screen to an extension popup
--     in one sitting; it does not cross a mailbox (M14) or a phone call (M13).
--   · IT IS REDEEMED UNAUTHENTICATED, like the handoff and unlike M13/M14.
--     The extension has no session yet — acquiring one is the point — so the
--     CODE IS THE ONLY SELECTOR. There is nowhere in the redeem request to name
--     an account, which is what keeps the route from becoming an enumeration
--     oracle (docs/03 §6g's rule).
--   · WHAT IT PRODUCES IS A SESSION, recorded here, so the paired-devices
--     surface can show what a pairing became and revoking the session is
--     traceable back to the ceremony that created it.
--
-- NO ATTEMPT CAP COLUMN, deliberately, and this is the M14 round-2 lesson
-- applied rather than repeated. A cap can only count attempts it can ATTRIBUTE;
-- redemption here is unauthenticated and a wrong guess produces a different
-- digest, so it resolves no row and there is nothing to increment — exactly the
-- shape that made M14's cap decorative until it was re-keyed onto the user.
-- There is no user to key on before redemption succeeds. The bound is
-- therefore the code's 160 bits and the short TTL, which is the same argument
-- `auth_handoffs` makes and the same one that holds there.
--
-- ONE LIVE PAIRING PER USER, and the predicate deliberately OMITS EXPIRY.
-- A partial unique index cannot reference now(), so a predicate that tried to
-- would be rejected outright — and the trap M14's review found is subtler than
-- that: if the index counts a LAPSED row as occupying the slot while the code
-- that decides whether to retire carries the clock, the two disagree and the
-- ceremony wedges permanently. So the index predicate is `redeemed_at IS NULL
-- AND revoked_at IS NULL`, and `retireLive` matches THE INDEX rather than the
-- clock: minting retires any previous row unconditionally.
-- ---------------------------------------------------------------------------

CREATE TABLE extension_pairings (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID NOT NULL REFERENCES users(id),
  -- sha256 of the CANONICAL form. Never the code, never a reversible transform.
  code_sha256  BYTEA NOT NULL,
  -- The account session that minted it, for the trail. A pairing is authority
  -- crossing from one credential to another, so both ends are recorded.
  minted_from  UUID NOT NULL REFERENCES sessions(id),
  expires_at   TIMESTAMPTZ NOT NULL,
  redeemed_at  TIMESTAMPTZ,
  -- The extension session redemption produced. NULL until spent.
  session_id   UUID REFERENCES sessions(id),
  revoked_at   TIMESTAMPTZ,
  revoke_reason TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The redemption selector. UNIQUE so one digest backs at most one code.
CREATE UNIQUE INDEX ux_extension_pairings_code ON extension_pairings (code_sha256);

-- One unspent pairing per user. See the header for why expiry is absent here.
CREATE UNIQUE INDEX ux_extension_pairings_live ON extension_pairings (user_id)
  WHERE redeemed_at IS NULL AND revoked_at IS NULL;

-- The paired-devices surface reads by user, newest first.
CREATE INDEX ix_extension_pairings_user ON extension_pairings (user_id, created_at DESC);

-- Operational state, not versioned business data — the `auth_handoffs` and
-- `sessions` precedent. There is no soft delete and no _versions shadow table:
-- a spent or revoked pairing is a row whose columns already say so, and the
-- durable record of what happened lives in the append-only auth_events ledger.
