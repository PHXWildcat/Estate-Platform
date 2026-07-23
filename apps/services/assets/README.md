# @estate/service-assets

Event-sourced manual-asset ledger for the financial cluster (docs/01 §2.3,
docs/02 §3). CQRS: `asset_events` is the append-only write model — the source
of truth; `assets_view` and `asset_beneficiaries` are projections applied in
the same transaction as the append via a pure reducer (`src/projection.ts`).
Asset history is the product: "what did the estate hold on date X" is served
by replaying the ledger (`?asOf=` on list/net-worth queries), and the
projection can be rebuilt and diffed at any time (`dist/rebuild-cli.js`) —
the docs/02 §8 disaster-recovery integrity check.

## Invariants

- **Never write to the projection directly.** Every `assets_view` /
  `asset_beneficiaries` write is the reducer applied to a just-appended
  ledger event, inside that event's transaction. The rebuild CLI proves
  replay equivalence.
- **Encrypted at rest.** Full event payloads (`payload_ct`) and the value
  fields of the projection (`est_value_ct`, `cost_basis_ct`, `location_ct`,
  `notes_ct`) are AEAD ciphertext under per-user KMS-wrapped DEKs. Payload
  AAD binds `user_id` + `event_id`, so ciphertext cannot be swapped between
  events. `category`/`title`/percentages are plaintext per docs/02 §3 DDL
  (dashboard/search drivers).
- **Every decryption is audited** (fail-closed via `@estate/crypto`), with a
  distinct purpose per endpoint; projection rebuild decrypts as
  `actorType: 'system'`, `purpose: 'projection_rebuild'` — rebuilds are loud
  by design.
- **Optimistic concurrency + idempotency.** Responses carry `version`
  (latest ledger `seq` for the asset); writes accept `If-Match`. Commands
  accept a client `eventId`; retries are no-ops (unique index on
  `event_id`).
- **One active DEK per user, DB-guaranteed** (`ux_deks_user_active`), with
  conflict adoption in `@estate/crypto` — this cluster closes the M2
  getOrCreateDek race from day one.

## Trust model: verified sessions (2026-07-23 — header trust retired)

- Caller identity comes from the caller's `Authorization: Bearer <token>`,
  VERIFIED by `@estate/auth-guard`'s `CallerGuard` against identity's
  `GET /v1/auth/session` (introspection via `HttpSessionVerifier`, fail-closed).
  This replaced the M2 `x-estate-user-id` header trust — no spoofable assertion.
  `IDENTITY_URL` configures identity's base URL (fail-fast in production).
- **Step-up MFA (docs/01 §5) for beneficiary changes** is enforced by
  `StepUpGuard` against the VERIFIED session: `mfa_level == 'stepup'` AND the
  ≤5-min freshness window (`isStepUpFresh`), 403 `stepup_required` otherwise.
  A boolean header can no longer stand in for a fresh step-up. The
  `SessionVerifier` interface leaves the OIDC/JWT local-verify end-state a
  drop-in.
- AuthZ is deny-by-default Cedar (`AssetsAuthz`); **owner-only in M3**.
  Beneficiary read access (`beneficiary.cedar`) requires resolving
  `contacts.linked_user_id`, which lives in the core cluster — deferred
  until a local contact-link projection consumes core domain events.

## Conventions notes

- `asset_events`: append-only (REVOKE UPDATE/DELETE), no soft-delete/versions
  — it IS the history.
- `assets_view`: rebuildable projection — exempt from the business-table
  conventions profile (no `id`/`created_at`/`_versions`); verified by custom
  assertions in `test/assets.int.spec.ts`.
- `asset_beneficiaries`: full business-table conventions; share sums per
  (asset, designation) are enforced ≤ 100 by app validation (422) and a DB
  constraint trigger. The API reports `designationComplete` (== 100).
- Category is immutable in M3 (recategorize = retire + recreate).

## Deferred (tracked in docs/04)

Plaid isolate + `plaid_items`/`accounts` DDL (next M3 PR) · `DocumentAttached`
event + photos/appraisals (M4) · beneficiary ABAC via contact-link projection ·
transactional outbox for post-commit audit/domain emits · as-of replay
snapshotting at scale.

## Runbook

- Migrate: `DATABASE_URL=... node dist/migrate-cli.js` (deploy step, not boot).
- Rebuild check: `DATABASE_URL=... node dist/rebuild-cli.js` (report + exit 1
  on divergence); `--repair` to restore the projection from the ledger.
- Env: see `src/config.ts` (`KMS_MASTER_KEY_HEX` dev/test; `AWS_KMS_KEY_ID` +
  `AWS_REGION` + `KAFKA_BROKERS` prod; KEK alias `financial/kek`).
