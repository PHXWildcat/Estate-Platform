-- M17 PR2 — the users version-capture image stops keeping password hashes.
--
-- WHY THIS SHIPS IN THE SAME CHANGE AS THE FIRST PASSWORD WRITE, not after it.
-- `CREATE OR REPLACE FUNCTION` only affects FUTURE captures. Every password
-- change that ran before this migration would have written its predecessor's
-- Argon2id verifier into `users_versions`, into a table this schema REVOKEs
-- UPDATE and DELETE on, and no later migration can retract it. Ordering is the
-- control here, not tidiness — which is why `POST /v1/auth/password` and this
-- file are the same commit.
--
-- WHY REDACT AT ALL, given the M6 vault precedent argues the opposite for most
-- columns. `vault_keysets` drops `wrapped_master_key` because a superseded
-- wrapping is a LIVE capability against the CURRENT secret. An old Argon2id
-- hash is not that: it verifies a RETIRED password, login reads only the live
-- row, and nothing in this repo reads `users_versions` at all. So the vault's
-- argument does NOT transfer, and the reason to redact is a different one that
-- the same comment supplies. Its justification for keeping full row images
-- everywhere else is that "the ciphertext in it is readable with the same key
-- as the live row" — i.e. crypto-shredding the DEK reaches the captured image
-- too. `password_hash` is the ONE column in `users` for which that is false:
-- it is a plain TEXT verifier, not a `*_ct` + `dek_id` pair, so it sits outside
-- the envelope and erasure does not reach it. A row image that survives
-- crypto-shredding must not contain a credential verifier.
--
-- WHAT IS DELIBERATELY KEPT. `email_ct` and `dek_id` stay: they ARE DEK-wrapped,
-- the shred does reach them, and they carry the audit value the trigger exists
-- for. Redacting them would make the capture useless without making it safer.
-- The rule this applies, rather than copies, is the vault comment's own:
-- record the event, never the secret.
--
-- AND THE CAPTURE NOW HAS A WHO. Identity was the only service that never set
-- `app.actor_id`, so every row this trigger has ever written came back with a
-- NULL actor — measured, not assumed. `Db.withTransaction` lands in the same
-- change, which is what makes the trade sound: what survives capture is who
-- changed the row and when, and only the verifier is dropped. Without that,
-- redaction would leave a row image with no evidential value at all.
--
-- NOT AN EDIT TO 001. `packages/db/src/migrator.ts` records a sha256 of every
-- applied file and raises MigrationDriftError on a mismatch, so editing the
-- original would fail every deployment that has already run it.
--
-- NOTE ON SCOPE: the trigger is per-ROW, not per-column, so it fires on ANY
-- `users` UPDATE — the M7 settlement-lock status CAS included. Redacting here
-- covers all of them, which is what we want: no path writes a hash into an
-- append-only table any more.

CREATE OR REPLACE FUNCTION users_capture_version() RETURNS trigger AS $$
BEGIN
  INSERT INTO users_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.id,
    TG_OP,
    to_jsonb(OLD) - 'password_hash',
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
