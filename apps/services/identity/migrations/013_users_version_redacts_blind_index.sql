-- M25 PR1 — the users version-capture image stops keeping the blind index.
--
-- WHY THIS SHIPS BEFORE ANY CALLER OF destroyDek, and not with it. This is
-- migration 008's argument applied to the column 008 said did not exist.
-- `CREATE OR REPLACE FUNCTION` only affects FUTURE captures, and erasure must
-- UPDATE `users` to set `status = 'closed'` — so if the destroy leg shipped
-- first, the erasure ceremony ITSELF would write the erased account's
-- `email_bidx` into `users_versions`, a table this schema REVOKEs UPDATE and
-- DELETE on, at the exact moment it claimed to erase them. No later migration
-- could retract it. Ordering is the control, again.
--
-- 008 SAID `password_hash` WAS "THE ONE COLUMN IN `users`" THE SHRED DOES NOT
-- REACH. There are two. Its reasoning is exactly right and stops one column
-- short: `email_bidx` is a plain BYTEA HMAC under a SERVICE-WIDE blind-index
-- key, not a `*_ct` + `dek_id` pair, so it sits outside the envelope and
-- destroying every DEK does not touch it. 008 is NOT edited to say so — it is
-- applied and checksummed, and editing it raises MigrationDriftError and
-- blocks the next migration. The correction lives in docs/03 §6kk and here.
--
-- WHAT THIS BUYS, stated narrowly so it is not over-read. `email_bidx` is not a
-- credential: it verifies nothing and grants nothing. What it is, is a stable
-- deterministic identifier — given the blind-index key and a candidate address,
-- an erased account can still be shown to have existed, and every historical
-- value would sit in an INSERT-only table forever. That is erasure
-- COMPLETENESS, and the threat model is an insider with the index key and
-- direct cluster read, not an external attacker. It is not a confidentiality
-- break and this migration should not be cited as fixing one.
--
-- `email_ct` and `dek_id` are still deliberately KEPT, for 008's own reason:
-- they ARE under the envelope, the shred does reach them, and they carry the
-- audit value the trigger exists for.
--
-- DERIVED FROM THE ROW, NOT A COLUMN LIST. The redaction reads the captured
-- image's own keys and drops every one ending in `_bidx`. A hand-listed column
-- name beside a table that grows is this repo's most repeated defect: a second
-- blind index added to `users` later is redacted by this function without
-- anyone remembering it is here. `password_hash` stays named because it is one
-- column with one reason, not a category.
--
-- NOT AN EDIT TO 001 OR 008, for the same checksum reason 008 states itself.

CREATE OR REPLACE FUNCTION users_capture_version() RETURNS trigger AS $$
DECLARE
  image jsonb := to_jsonb(OLD) - 'password_hash';
  blind text[];
BEGIN
  SELECT array_agg(k) INTO blind
  FROM jsonb_object_keys(image) AS k
  WHERE right(k, 5) = '_bidx';
  IF blind IS NOT NULL THEN
    image := image - blind;
  END IF;

  INSERT INTO users_versions (row_id, operation, row_data, actor_id, reason)
  VALUES (
    OLD.id,
    TG_OP,
    image,
    NULLIF(current_setting('app.actor_id', true), '')::uuid,
    NULLIF(current_setting('app.change_reason', true), '')
  );
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;
