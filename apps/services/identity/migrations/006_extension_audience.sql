-- ---------------------------------------------------------------------------
-- M16 — the third session audience: `extension`.
--
-- A browser extension is a SECOND CLIENT of the SRP/2SKD protocol living on an
-- artifact we do not control the delivery of (a vendor store auto-updates it,
-- with no CSP in the path). The compensating control that works whether or not
-- anyone is watching is blast radius: the extension's session is admitted PER
-- HANDLER to five vault routes and three identity ones, so it cannot reach
-- `reset`, either keyset route, `deleteItem`, any emergency-access route, or
-- `handoff`. AN EXTENSION SESSION CANNOT DESTROY A VAULT. See docs/03 §6j and
-- `AUDIENCE_ROUTE_ADMITTERS` in @estate/auth-guard, which is the authoritative
-- list and is checked against the real decorated handlers in both directions.
--
-- WHY A MIGRATION AT ALL: the vocabulary is closed in two hand-written places —
-- this CHECK and the `SESSION_AUDIENCES` union — and 004 said a spec pinned them
-- to each other. None existed until M16 wrote one
-- (`packages/auth-guard/test/session-audience.spec.ts`). It now reads this
-- directory, computes the EFFECTIVE constraint (the last statement to constrain
-- the column, which is why the widening below is a DROP and an ADD rather than
-- an edit to 004), and fails if the two lists differ in either direction. So
-- adding 'extension' to the union without this file is a red test rather than a
-- 23514 on the first extension session.
--
-- NOT WIDENED HERE, deliberately: `auth_handoffs.audience` keeps
-- `CHECK (audience IN ('vault'))`. M16 pairs an extension with a typed,
-- human-readable code and its own table, NOT through the handoff ceremony —
-- whose 60-second window is calibrated for a code no person ever reads. The
-- handoff's CHECK is also the only thing that stopped `mint()` from being asked
-- for an `account` session while its parameter was typed as the full union, so
-- it stays as narrow as it can be. M16 removed that parameter (see
-- handoff.service.ts) rather than relying on this constraint alone.
--
-- The `sessions.audience` DEFAULT is untouched and stays 'account'. It exists so
-- M15's ADD COLUMN could populate rows that predate it; every INSERT names the
-- value explicitly now that `SessionsRepo.create` requires it.
--
-- CONSTRAINT NAME: `sessions_audience_check` is what Postgres generated for
-- 004's inline `ADD COLUMN … CHECK (…)` — verified against the running auth
-- cluster rather than assumed, because a wrong guess here fails the DROP and
-- takes the whole migration with it.
-- ---------------------------------------------------------------------------

ALTER TABLE sessions DROP CONSTRAINT sessions_audience_check;

ALTER TABLE sessions
  ADD CONSTRAINT sessions_audience_check
  CHECK (audience IN ('account', 'vault', 'extension'));
