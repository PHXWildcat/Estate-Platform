-- ---------------------------------------------------------------------------
-- M27 PR3b: the owner-authored label a grantee sees instead of a raw user id.
--
-- WHY A NEW COLUMN AND NOT A LOOKUP. docs/03 §6yy carried "[OWNER: M27] the
-- grantee's row names the owner by raw account id", on the premise that a name
-- existed somewhere and only needed releasing. It does not. `profile` has no
-- display-name column at all: a person's name exists ONLY inside other users'
-- per-user-encrypted contact rows, and the grantee has no contact row for the
-- person who named them. Serving "the owner's name" would therefore mean
-- adding a Zone B identity field and a cross-user disclosure route, which is a
-- larger decision than the reading surface that needs it.
--
-- An owner-authored label sidesteps the disclosure question entirely: the
-- owner writes exactly the string their grantees will read, so there is no
-- name released that they did not choose to release, no second service in the
-- path, and nothing to get wrong at configure time except the wording.
--
-- NULLABLE, and the fallback stays the user id. A required label would make
-- ARMING emergency access harder than leaving it unarmed, which inverts the
-- rule that the protective action must never be the harder one.
--
-- TWO CHECKS, because this is the first string in Zone A's schema that one
-- user writes and a DIFFERENT user reads:
--
--   * a length cap, so the row a grantee reads cannot be used as a message
--     channel or a layout attack; and
--   * NO CONTROL CHARACTERS. Refused rather than stripped — the parser you
--     never added is the one that cannot be misconfigured — which also keeps a
--     NUL out of a value that is rendered, logged and versioned.
--
-- It is NOT redacted from the version trigger: that trigger subtracts named
-- key material (`to_jsonb(OLD) - 'platform_part' - ...`), and a label is
-- exactly the kind of owner-visible metadata whose history is worth keeping.
-- ---------------------------------------------------------------------------

ALTER TABLE emergency_access_configs
  ADD COLUMN label TEXT;

ALTER TABLE emergency_access_configs
  ADD CONSTRAINT emergency_access_configs_label_check
  CHECK (label IS NULL OR (char_length(label) BETWEEN 1 AND 80 AND label !~ '[[:cntrl:]]'));
