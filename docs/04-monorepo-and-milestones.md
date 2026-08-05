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

### M10 — AI estate assistant (PR1 in progress)

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

### Later milestones (rough order, one per bounded context)
Referral · search · the M5 cloud half, reduced by what M8 took over.
Settlement came late deliberately: highest-risk domains land on mature
primitives. (Notifications moved up and shipped as M9; the AI assistant is M10,
both above.)
