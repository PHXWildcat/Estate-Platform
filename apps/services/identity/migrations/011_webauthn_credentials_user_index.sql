-- M17 PR5 — the first index webauthn_credentials has ever had, and a debt
-- rather than a feature (the 005_auth_events_index shape): every read in the
-- repo resolves by user_id — the SecondFactorGate predicate, excludeCredentials
-- at registration, allowCredentials at every step-up assertion, and now the
-- management listing — and each has been a sequential scan since M2. PR5 makes
-- the routes reachable for the first time, which is what turns the debt due.
--
-- Partial on the live rows, matching every read's own predicate now that
-- revoked_at has its first writer.
--
-- The migrator runs every file inside BEGIN/COMMIT, so CREATE INDEX
-- CONCURRENTLY is structurally inexpressible here (the 005 note verbatim):
-- fine on the empty-to-small tables that exist, and whoever first runs this
-- against a populated production table must build the index out of band and
-- let IF NOT EXISTS make this a no-op.
CREATE INDEX IF NOT EXISTS ix_webauthn_credentials_user
  ON webauthn_credentials (user_id)
  WHERE revoked_at IS NULL;
