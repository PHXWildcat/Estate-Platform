-- ---------------------------------------------------------------------------
-- 003 — the contact link ceremony (M13 PR3).
--
-- WHAT THE LINK IS. `contacts.linked_user_id` says "this contact IS this
-- platform user". It is an AUTHORIZATION EDGE, not a convenience field: it is
-- what makes someone able to open a death case (docs/03 §6b credits the
-- linked-contact gate with the whole reason intake cannot enumerate and cannot
-- trigger), what makes an executor resolvable (M7's `isExecutorOf`), and what
-- makes a permission grant effective at all (profile's own
-- `effectiveContactReadGrants`). Until this migration the column had NO WRITE
-- PATH anywhere in the platform — four test files set it with raw SQL and said
-- so — which is why none of those capabilities could be reached by a real user.
--
-- THE CEREMONY, and why it is shaped this way. The owner mints a single-use
-- code under step-up; the server keeps only its sha256; the owner delivers it
-- OUT OF BAND (the M6 grantee-fingerprint precedent — they already have this
-- person's phone number); the contact redeems it while authenticated on THEIR
-- OWN existing account. That shape is forced by two shipped decisions and one
-- threat:
--   * M9's notification doctrine has no field for content and forbids links, so
--     an emailed invite would contradict it. Nothing here handles an address.
--   * docs/03 §6b's anti-enumeration property must survive: the code is the
--     ONLY selector on redemption, so there is no lookup by email or user id to
--     probe, and a wrong code cannot distinguish an account that exists.
--   * The redeemer must already have an account, so this is not an
--     invite-to-register flow and cannot be used to create one.
--
-- NO `deleted_at`, NO `_versions`, ON PURPOSE — the `permission_grants`
-- precedent (see 001). This is not a mutable business row: `redeemed_at` and
-- `revoked_at` ARE the history, and an invitation is EVIDENCE of who was
-- offered a way into an estate, which is exactly what an investigation of a
-- §5.1 fraudulent report would want. So nothing here is ever deletable.
-- ---------------------------------------------------------------------------
CREATE TABLE contact_link_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL,
  contact_id    UUID NOT NULL REFERENCES contacts(id),
  -- sha256 of the code. THE CODE ITSELF IS NEVER STORED: a database read (the
  -- docs/03 §5.3 insider, a leaked backup) must not yield a usable capability,
  -- and the owner is told once and only once.
  code_sha256   BYTEA NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  -- Per-invitation attempt cap. The code carries 128 bits, so this is not the
  -- control that makes guessing infeasible — it bounds an online attack against
  -- a code that really exists, and it is the counter an alert would watch.
  attempts      INT NOT NULL DEFAULT 0,
  redeemed_at   TIMESTAMPTZ,
  redeemed_by   UUID,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- `redeemed_by` accompanies exactly `redeemed_at` (the M4 executedAt shape).
  CONSTRAINT contact_link_redeemed_together
    CHECK ((redeemed_at IS NULL) = (redeemed_by IS NULL))
);

-- Redemption is ONE lookup by hash, and a hash can back only one invitation.
CREATE UNIQUE INDEX ux_contact_link_invitations_code
  ON contact_link_invitations (code_sha256);

-- At most one LIVE invitation per contact, so "the code I sent you" is never
-- ambiguous. Re-issuing revokes the previous one in the same transaction.
CREATE UNIQUE INDEX ux_contact_link_invitations_live
  ON contact_link_invitations (contact_id)
  WHERE redeemed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX ix_contact_link_invitations_owner
  ON contact_link_invitations (owner_user_id);
