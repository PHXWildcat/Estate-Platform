-- M25 PR1 — the contacts version-capture image stops keeping the blind index.
--
-- THE SAME DEFECT AS identity/013, AND THE CATEGORY IS WHY IT IS HERE. M25 PR0
-- recorded this as `users.email_bidx`, one column in one service. It is not:
-- three tables in three services carry a blind index AND a `_versions` shadow
-- that captures it, and a rule applied to one member of a category is a rule
-- half-applied. `contacts` is the second.
--
-- AND IT IS THE ONE THAT IS NOT ABOUT THE ACCOUNT HOLDER. `users.email_bidx`
-- indexes the owner's own address; `contacts.email_bidx` indexes a LIVING
-- THIRD PARTY's — the attorney, the beneficiary, the family member the owner
-- named. Erasing an account should not leave behind a searchable index of the
-- people that account knew, and those people never had a say in the account
-- existing. On the severity ordering this is the worse of the two, which is
-- the opposite of the order they were discovered in.
--
-- WHY NO COLUMN CHANGE. `contacts.email_bidx` is already NULLable and its
-- unique index is `WHERE deleted_at IS NULL AND email_bidx IS NOT NULL`, so
-- erasure nulling the live value needs no DDL here — unlike `users`, where the
-- column is NOT NULL. That asymmetry is real and belongs to PR3, which decides
-- what the erasure act writes; this migration only stops the CAPTURE.
--
-- Derived from the row rather than naming `email_bidx`: the function drops
-- every captured key ending in `_bidx`, so a second blind index on this table
-- is covered without a fourth migration.

CREATE OR REPLACE FUNCTION contacts_capture_version() RETURNS trigger AS $$
DECLARE
  image jsonb := to_jsonb(OLD);
  blind text[];
BEGIN
  SELECT array_agg(k) INTO blind
  FROM jsonb_object_keys(image) AS k
  WHERE right(k, 5) = '_bidx';
  IF blind IS NOT NULL THEN
    image := image - blind;
  END IF;

  INSERT INTO contacts_versions (row_id, operation, row_data, actor_id, reason)
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
