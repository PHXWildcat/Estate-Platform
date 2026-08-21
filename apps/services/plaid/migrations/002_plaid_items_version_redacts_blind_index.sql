-- M25 PR1 — the plaid_items version-capture image stops keeping the blind index.
--
-- THE THIRD AND LAST MEMBER of the category M25 PR0 recorded as one column:
-- tables carrying both a `*_bidx` and a `_versions` shadow that captures it.
-- Derived from the migrations rather than remembered — see
-- `packages/contracts/test/version-capture-redaction.spec.ts`, which finds the
-- set and fails if a fourth arrives uncovered.
--
-- THE WEAKEST OF THE THREE, AND SHIPPED ANYWAY. `item_bidx` is an HMAC of a
-- Plaid item id — an opaque provider identifier, not a personal one, so it does
-- not re-identify a human the way an email HMAC does. What it does do is
-- survive erasure as a durable link between an erased account and an item that
-- still exists at Plaid, which is enough to be worth not keeping. Recording the
-- weaker reason rather than implying all three are equally sharp: a category
-- fixed uniformly is easier to keep true than three columns each argued on its
-- own merits, and the cost here is one migration.
--
-- Derived from the row, not from the column name, for the reason the other two
-- state: a hand-listed column beside a table that grows is the defect.

CREATE OR REPLACE FUNCTION plaid_items_capture_version() RETURNS trigger AS $$
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

  INSERT INTO plaid_items_versions (row_id, operation, row_data, actor_id, reason)
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
