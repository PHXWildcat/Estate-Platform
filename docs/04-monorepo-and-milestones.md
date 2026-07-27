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

### Later milestones (rough order, one per bounded context)
M7 settlement (Temporal) ·
M8 AI assistant (privacy proxy) · then referral, notifications hardening, search.
Settlement comes late deliberately: highest-risk domains land on mature
primitives.
