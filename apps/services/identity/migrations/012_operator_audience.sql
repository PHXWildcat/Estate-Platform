-- ---------------------------------------------------------------------------
-- M21 PR3a — the fourth session audience: `operator`.
--
-- WHAT IT IS FOR. The TB7 operator platform gets an ISOLATED ORIGIN, on the
-- M15 vault precedent: a settlement operator reviewing a death case is doing
-- the most consequential work in the product, and doing it on the same origin
-- as the owner's own estate means one XSS on the app surface reaches both. The
-- session minted for that origin is admitted by identity's three
-- self-referential routes and by nothing else in the product.
--
-- THE AUDIENCE IS NOT A CLAIM ABOUT WHO IS HOLDING IT, and that is the whole
-- design. Identity cannot ask whether a caller is an operator: it holds no
-- settlement credential, there is no dblink between the auth and core clusters,
-- and it has no concept of a role. So the mint is ROLE-BLIND — any account
-- holder may mint one under step-up — and it is safe precisely because minting
-- one is a DE-ESCALATION. `settlement_operators`, read through `OperatorGate`,
-- remains the only thing that decides who may act on a death case.
--
-- WHY THE HANDOFF TABLE RATHER THAN A FOURTH CEREMONY. M16 DELETED `mint()`'s
-- `audience` parameter and recorded why, in a sentence that reads like it was
-- written for this migration: "If a future audience does need a handoff, it
-- adds the parameter back in the same change as the DDL widening — which is
-- strictly better than finding the parameter already there and assuming the
-- database agrees." This is that change. The operator journey is the vault
-- journey — a person at a keyboard crossing from the app origin to an isolated
-- one — so it wants the 60-second single-use code, not M16's typed
-- human-readable pairing code, whose window is calibrated for a code somebody
-- reads aloud.
--
-- CONSTRAINT NAMES VERIFIED AGAINST THE RUNNING AUTH CLUSTER, not guessed —
-- 006 set that rule because a wrong name fails the DROP and takes the whole
-- migration with it. Measured:
--   sessions       | sessions_audience_check
--   auth_handoffs  | auth_handoffs_audience_check
--
-- ONE THING TO KNOW BEFORE "CORRECTING" ANYTHING HERE. Postgres NORMALIZES a
-- single-member `IN` to an equality, so `pg_get_constraintdef` reports the
-- shipped `CHECK (audience IN ('vault'))` as `CHECK (audience = 'vault')`.
-- Both are true at their own layer, and the difference matters: the fence in
-- `packages/auth-guard/test/session-audience.spec.ts` parses THIS FILE, not the
-- database, and can only read the `IN (…)` form. A reader who checks the docs
-- against `psql` will see the equality and be tempted to make the source match
-- it — which would blind the fence that guards the whole vocabulary. M21 PR2.5
-- added a refusal for any audience CHECK the parser cannot read, so that edit
-- now turns the suite red instead of going quietly green. Write `IN (…)`.
-- ---------------------------------------------------------------------------

ALTER TABLE sessions DROP CONSTRAINT sessions_audience_check;

ALTER TABLE sessions
  ADD CONSTRAINT sessions_audience_check
  CHECK (audience IN ('account', 'vault', 'extension', 'operator'));

-- The handoff table widens for the first time since M15 created it. It stays
-- as narrow as it can be: `account` is still not mintable through a handoff,
-- which is what stopped `mint()` being asked for an ordinary session while its
-- parameter was typed as the full union. Two members now, so Postgres will
-- store this one as `= ANY (ARRAY[…])` rather than as an equality.
ALTER TABLE auth_handoffs DROP CONSTRAINT auth_handoffs_audience_check;

ALTER TABLE auth_handoffs
  ADD CONSTRAINT auth_handoffs_audience_check
  CHECK (audience IN ('vault', 'operator'));
