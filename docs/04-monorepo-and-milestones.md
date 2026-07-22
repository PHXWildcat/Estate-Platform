# Estate Planning Platform — Monorepo Structure & Milestone Plan

**Version:** 1.0 · Approved 2026-07-20. Companion to `00`–`03`. This records the agreed
repository layout, boundary rules, and the milestone sequence for implementation.

## Tooling

pnpm workspaces + Turborepo. Version policy via pnpm **catalogs** (`pnpm-workspace.yaml`);
dependency build scripts blocked by default (`onlyBuiltDependencies` allowlist, kept
near-empty). Strict TypeScript everywhere via `packages/config/tsconfig.base.json`.
Backend targets CommonJS; internal packages are consumed through their built `dist`
(Turborepo orders `^build`) — no TS path aliases.

## Layout

```
apps/
  web/                  Next.js (dashboard, auth, vault UI)
  bff/                  GraphQL BFF — persisted queries, depth/complexity limits
  services/             one NestJS app per bounded context (docs/01 §2)
    identity/ profile/ assets/ documents/ vault/ settlement/
    ai-assistant/ referral/ notifications/ search-indexer/ audit/
packages/
  config/               tsconfig base, jest preset
  contracts/            Kafka event schemas (zod), internal API types, GraphQL manifest
  crypto/               SERVER-side envelope encryption (KMS-wrapped DEKs), blind indexes
  vault-crypto/         CLIENT-side Zone A crypto (2SKD, SRP) — isolated, minimal deps
  db/                   migration runner + generators for docs/02 conventions
  audit-emitter/        typed audit producer — IDs/enums only, enforced at runtime
  auth-guard/           session verification, step-up freshness, Cedar PEP middleware
  kafka/                topic registry, producer/consumer wrappers, Zone B payload crypto
  ui/                   design system (Tailwind, WCAG AA+, dark mode)
  testing/              testcontainers harnesses, fixtures
infra/
  terraform/{modules,envs}/   helm/   argocd/
tools/                  codegen, release scripts
docs/                   00–04 + docs/adr/ going forward
```

## Boundary rules (enforced, not aspirational)

1. **Each service owns its migrations** (`apps/services/<svc>/migrations/`). No shared
   migrations, no cross-cluster joins; consistency via events (docs/02 §8).
2. **Local dev runs six separate Postgres containers** (`docker-compose.dev.yml`) so no
   code ever assumes cluster co-location. Ports 5433–5438.
3. **`vault-crypto` ≠ `crypto`.** Zone A client-side code is its own package with a
   near-zero dependency tree (TB6 audit surface). Server-side `crypto` (KMS) must never
   be importable from `apps/web` — lint-enforced.
4. **Services never import each other** — only `packages/*`. `web` may import `ui`,
   `contracts`, `vault-crypto` only.
5. **CI security gates are merge-blocking from commit one:** gitleaks, CodeQL,
   dependency review; tfsec/OPA once Terraform lands.

## Milestones

### M1 — Secure walking skeleton (shipped 2026-07-21; open items below)
Foundation packages (`config`, `contracts`, `crypto`, `db`, `audit-emitter`,
`auth-guard`) + **identity service** (auth-cluster DDL per docs/02 §1, registration with
encrypted email + blind index, Argon2id, passkeys, TOTP, sessions with refresh rotation,
step-up ≤5 min window, Cedar deny-by-default PEP) + **audit service** (Kafka consumer,
append-only hash-chained `audit_events`, chain verification) + thin BFF and Next.js auth
flows. **Acceptance:** E2E register → login → step-up → gated action → audit event
verified in chain; automated schema-convention checker passes (soft delete, `_versions`
tables, REVOKEs); no plaintext PII in logs under integration inspection; coverage gates
95/90.

**M1 status.** Shipped: foundation packages; identity service (WebAuthn schema in
place, endpoints deferred); audit service; GraphQL BFF (persisted operations enforced
in production, httpOnly-cookie sessions, CSRF header, masked errors); Next.js auth
flows (register/login/TOTP/step-up, design tokens, dark mode, AA+); walking-skeleton
E2E (`apps/e2e`, PG-gated) proving identity's exact produced bytes ingest into a
verified audit hash chain; schema-convention checker (`@estate/db checkConventions`)
run against both migrated schemas; CI guard failing the build if integration suites
would silently skip. **Open items rolling into M2:** Cedar PDP integration (guards
are deny-by-default but policy engine not wired), WebAuthn endpoints, Kafka
broker-hop E2E (needs Redpanda locally/in CI — current E2E bridges producer bytes to
the ingestor in-process), AWS KMS adapter (LocalKmsProvider is dev-only), coverage
thresholds (CI now prints coverage; gate at 95/90 once CI-measured numbers exist),
monthly audit partitions + S3 Object Lock anchoring, identity logout/revocation
endpoint, BFF depth/complexity limits.

**M1 security review (2026-07-21).** A focused review of the shipped code found no
exploitable vulnerability in the committed (dev) configuration. One production-conditions
finding is tracked here for M2:
- *Registration account-enumeration timing channel (Medium).* `register()` equalizes
  response body/status and the Argon2 cost, but the new-email path awaits extra KMS + DB
  + Kafka work; under production wiring an existing email returns measurably faster,
  giving a membership oracle. Not exploitable today (dev uses in-process KMS/audit
  doubles). Fix direction: an email-verification flow returning a fixed-shape, fixed-time
  response regardless of address existence. Decoy work (risks orphaned DEKs) and
  fire-and-forget publishing (breaks the audit-before-completion invariant) are both
  rejected as fixes. Docstring on `auth.service.ts register()` no longer overclaims.
Verified clean in review: AEAD/AAD binding, blind-index domain separation, opaque-token
handling, session/step-up guards, refresh rotation-reuse, all parameterized SQL and the
identifier-validating generators, the migrator, Kafka-message deserialization + PII
firewall, and the BFF cookie/CSRF/persisted-operations model.

### M2 — Security hardening + profile/contacts (in progress)
Shipped so far on `claude/m2-security-hardening`: `@estate/kms-aws` (production
AWS KMS provider, wired into identity — prod uses AWS KMS, dev LocalKmsProvider,
fail-fast); `@estate/authz` (Cedar PDP, deny-by-default, owner/beneficiary
policies); WebAuthn passkey register/authenticate in identity (passkey as a
step-up factor) with its audit actions added to `@estate/contracts` and emitted
to Kafka; per-package **coverage gates** (jest thresholds set just below current
coverage, ratcheting toward 95/90 — CI runs `pnpm test --coverage`). Profile &
contacts service (core cluster) — **shipped**: field-encrypted profiles/family/
contacts/role assignments/permission grants, the first Cedar PEP (`ProfileAuthz`,
deny-by-default) proving the §5.5 beneficiary ABAC (a grant-holder reads only the
named resource), caller identity via gateway-injected `x-estate-user-id`.

**M2 follow-ups noted while building:**
- **Cross-request DEK race (crypto package).** ~~`getOrCreateDek` is
  find-then-insert; two concurrent first-writes for the same brand-new user can
  each mint a DEK.~~ **Resolved.** The intra-request parallel race was fixed in
  M2 (pre-materialize the DEK before parallel field encryption); the
  cross-request DB guard shipped with M3 — `ux_deks_user_active` partial unique
  index on all three DEK-bearing clusters (financial from day one; auth+core
  backfilled by each service's `002_dek_unique_active.sql` with a pre-flight
  dedupe) plus 23505→`DekConflictError` adopt-the-winner in every
  `PgDekRepository`.
- Core-cluster **domain-event** contracts/topic (profile emits audit events only
  for now); real cross-service session verification to replace the trusted
  `x-estate-user-id` header; asset-scoped beneficiary ABAC when the asset service
  lands; a Cedar schema for `validateRequest`.

**M2 security review (2026-07-21).** Structured review (discovery + adversarial
filter) of the M2 diff: no authz bypass, injection, crypto, or data-exposure vuln
above the bar; the Cedar PEP, per-user field encryption, KMS context-binding, and
WebAuthn origin/challenge/clone controls all verified fail-closed. One confirmed
finding, **fixed in-branch**:
- *WebAuthn step-up accepted user-presence, not user-verification (Medium).* The
  passkey ceremony that elevates a session to step-up used `userVerification:
  'preferred'` and omitted `requireUserVerification` at verify, so a presence-only
  tap could satisfy step-up — the same gate as a TOTP code (docs/01 §5). In-scope
  for the docs/03 §2 device-access adversary. Fixed: `userVerification: 'required'`
  in both option generators, `requireUserVerification: true` at both verify calls,
  and the step-up elevation now gated on `authenticationInfo.userVerified`.

### M3 — Asset ledger (first half shipped 2026-07-21; Plaid isolate shipped 2026-07-22)
Scope agreed: manual-asset ledger first (backend only), Plaid isolating service as a
separate second PR — `plaid_items`/`accounts` DDL deliberately deferred with it so no
dormant schema gets frozen by migration drift detection.

**Shipped:** `apps/services/assets` (financial cluster) — event-sourced write model
per docs/02 §3: `asset_events` (append-only, encrypted payloads AAD-bound to
`user_id`+`event_id`) → `assets_view` + `asset_beneficiaries` projected in the SAME
transaction through a pure reducer (`projection.ts`); projection rebuild CLI
(`rebuild-cli.js`, report/`--repair`) as the docs/02 §8 DR integrity check, decrypting
as actorType `system`/purpose `projection_rebuild`; optimistic concurrency
(`version` = latest seq, `If-Match`) + per-command idempotency (client `eventId`,
unique index); as-of temporal queries (`?asOf=` on list/net-worth) by ledger replay;
beneficiary designations with share-sum ≤ 100 enforced app-side (422) AND by a DB
constraint trigger; step-up gating on beneficiary changes via `StepUpGuard`;
Cedar PEP (`AssetsAuthz`, owner-only, deny-by-default); audit actions `asset.*` +
domain topic `estate.asset.events.v1` (`asset.ledger.appended`, IDs/enums only);
`withTransaction` sets the `app.actor_id` GUC so `_versions` rows carry attribution
(first service to do so). Also landed: the M2 **cross-request DEK race fix** —
`@estate/crypto` `DekConflictError` + adopt-the-winner in `getOrCreateDek`, with a
partial unique index `ux_deks_user_active` on the financial cluster from day one.

**Explicit deviations (surfaced, not silent):** step-up asserted via
gateway-injected `x-estate-stepup-verified` at the same M2 trust level as
`x-estate-user-id` (real session/step-up verification remains the upgrade for
both); additive DDL vs docs/02 §3 (event-id unique index, `(user_id, occurred_at)`
index, beneficiary live-row unique index, deks unique index — propose folding into
docs/02 v1.1); share-sum trigger enforces ≤ 100 rather than the docs' "sum to 100"
(strict equality is unenforceable during incremental designation; the API reports
`designationComplete`); `assets_view` exempt from business-table conventions (no
`_versions` — its history IS the ledger; verified by custom int-test assertions);
domain topic carries IDs/enums only, so docs/01 §4 Zone B Kafka payload crypto is
not yet exercised (prerequisite for any value-bearing consumer).

**Shipped since (M3 continued):** deks unique-index backfill for auth+core —
`002_dek_unique_active.sql` in identity and profile. Design: pre-flight dedupe
retires a raced double ONLY when verified unreferenced (`destroyed_at` means
crypto-shredded, so retirement must be proven safe): explicit `dek_id` columns
on live AND soft-deleted rows plus `*_versions` row images; in the auth cluster
additionally the IMPLICIT binding of `mfa_methods.secret_ct` (no dek_id column
— encrypt/decrypt resolve the newest active DEK), so with MFA rows present the
newest active DEK counts as referenced. Keeper = the referenced DEK, else the
newest; if >1 active DEK of one user is referenced the migration RAISEs and
rolls back (SQL has no KMS access — runbook: re-encrypt onto one DEK, re-run).
Both `PgDekRepository.insert`s translate 23505→`DekConflictError` (adoption in
`@estate/crypto`). Int tests cover the race on both clusters plus staged-
migration dedupe cases (keeper selection, soft-delete/version references,
implicit MFA binding, abort-and-retire-nothing).

**Shipped (M3 second half): Plaid isolating service** — `apps/services/plaid`, a
SEPARATE app on the financial cluster (disjoint tables, own migrations dir; the
migrator tolerates co-owned clusters). TB5 isolation is cryptographic: DEKs under a
dedicated `plaid/kek` alias in the service's own `plaid_deks` table (unique-active
index from day one), so the asset service's KMS grant can never unwrap a token DEK.
`plaid_items`/`accounts` DDL per docs/02 §3 plus additive `item_id_ct` + UNIQUE
`item_bidx` blind index (webhook routing). Flows: link-token → public-token
exchange (token encrypted, per-item AAD) → sync (the ONLY token-decrypt site with
revoke, audited with explicit purposes) → verified webhooks (ES256 JWT on
node:crypto: pinned alg, kid via gateway, iat freshness, constant-time raw-body
hash; failures audited, no existence oracle) → step-up-gated per-item revocation
(provider remove best-effort, local soft-delete atomic). Anomalous-sync hook emits
`plaid.sync.anomalous` past a sliding-window threshold. Gateway is an interface:
deterministic stub (dev/test, signs real webhooks) + fetch-based live client
(mock-transport tested); production config REQUIRES live mode + credentials. Domain
topic `estate.plaid.events.v1` and all audit actions are IDs/enums/counts only,
asserted end-to-end (`plaid.int.spec.ts` token firewall; `plaid.e2e.spec.ts` audit
hash-chain proof).

**M3 follow-ups:** local contact-link projection from core domain events →
`namedBeneficiaries` beneficiary ABAC + contact existence validation; transactional
outbox for post-commit audit/domain emits; `DocumentAttached` event + photos (M4);
as-of replay snapshotting at scale; category is immutable in M3 (recategorize =
retire + recreate).

**M3 security review (2026-07-22).** Structured review (four parallel discovery
passes — webhook crypto, Plaid token-isolation/authz, DEK-dedupe migrations, asset
ledger — each finding adversarially re-verified against source) of the whole merged
M3 range. No critical or app-surface-exploitable vulnerability. Verified fail-closed:
object-level authz (ownership always loaded from the row → Cedar owner-only,
deny-by-default) across both new services; Plaid token isolation (decrypts only at
sync/revoke, never in responses/events/errors/logs); config fail-fast (prod cannot
run the stub gateway or local KMS; `plaid/kek` cannot collide with `financial/kek`);
ledger payload AAD binding to `user_id`+`event_id`; optimistic-concurrency/idempotency
cannot bypass authz; BigInt money math; all SQL parameterized; the dedupe
shred-safety theorem (no referenced DEK is ever retired); adopt-the-winner key
handling. Three bounded findings, all **fixed in-branch** (`claude/m3-security-review-fixes`):
- *`assets_view` column AAD not bound to `asset_id` (Low, insider/DB-tamper).* The
  four projection ciphertext columns were sealed with AAD `asset.<field>` — bound to
  `(user_id, field)` only — so a financial-cluster write adversary (docs/03 TB4) could
  relocate one of the owner's own blobs between their assets and it would decrypt under
  the API. Bounded: not reachable via the app surface; same-user only; the authoritative
  `asset_events` payload is correctly bound to `event_id`, so a projection rebuild
  re-derives truth. A deviation from the codebase's own convention (Plaid binds row id,
  the ledger binds `event_id`). Fixed: `viewField(assetId, field)` → `asset.<assetId>.<field>`;
  changing the AAD is a re-encryption handled by `rebuild --repair`.
- *Unauthenticated webhook forced a pre-signature outbound Plaid key-fetch (Low/Medium,
  DoS/amplification).* `keyFor(kid)` ran before the signature check and unknown kids were
  never cached, so a stream of JWTs with novel kids drove one outbound Plaid call each,
  burning the service's rate-limit budget. The ES256/JWT crypto itself was sound. Fixed:
  short-TTL negative cache for unresolved kids (legitimate rotation still refetches once
  it expires).
- *DEK-dedupe "newest MFA DEK" tiebreak disagreed with the runtime resolver (Low, latent
  crypto-shred).* `findActiveByUser` used `ORDER BY created_at DESC LIMIT 1` with no
  tiebreak, while the 002 migration's part C uses `created_at DESC, dek_id DESC`; since
  `created_at` is a client-side ms `Date`, a raced tie could make the two disagree and
  shred the live MFA DEK. Not reachable through identity's current paths (the DEK is
  pre-materialized once per registration with a fresh `userId`), but a real footgun in the
  safety-net migration. Fixed: added `, dek_id DESC` to `findActiveByUser` in all four DEK
  repositories so runtime and migration resolve identically. (The merged 002 migration is
  immutable and needed no edit — aligning the resolver closes it.)
Informational nits left as-is: Plaid `sync`/`revoke` 404-vs-403 item-existence oracle
(gated by unguessable UUIDs); webhook-driven sync audited as `actorType:'user'` not
`system` (audit fidelity); in-window webhook replay (inherent to Plaid's iat-only model);
`IsoDateSchema` accepts calendar rollovers (`2026-02-30`).

### Later milestones (rough order, one per bounded context)
M4 documents (template matrix, generation pipeline, S3 doc vault) ·
M5 Terraform/EKS to a real dev environment ·
M6 vault (Zone A) ·
M7 settlement (Temporal) ·
M8 AI assistant (privacy proxy) · then referral, notifications hardening, search.
Vault and settlement come late deliberately: highest-risk domains land on mature
primitives.
