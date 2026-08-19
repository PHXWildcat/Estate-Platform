# Estate Planning Platform

Enterprise-grade estate planning platform targeting 10M users, 100K concurrent,
99.99% uptime, sub-250ms p95 for common reads. Engineering bar: Stripe/Plaid quality.
**Security is the single highest priority — above features, velocity, and convenience.**

## Source-of-truth documents — read the relevant ones before designing or coding
- `docs/00-requirements.md` — full product requirements and deliverables list
- `docs/01-system-architecture.md` — service decomposition, trust zones, AWS infrastructure
- `docs/02-database-schema.md` — six-cluster Postgres design, DDL, encryption conventions
- `docs/03-threat-model.md` — adversaries, attack scenarios, required controls

When a task touches a domain covered by these docs, follow them. If a task requires
deviating from them, stop and propose the change with rationale — do not silently diverge.

## Non-negotiable architecture rules
- **Three-zone trust model.** Zone A (password vault, sealed documents) is
  zero-knowledge: client-side encryption, server stores opaque ciphertext only,
  SRP-style auth. Zone B (PII, financial data, documents) uses per-user envelope
  encryption with KMS-wrapped DEKs; every decryption is a logged event. Never
  weaken a zone boundary to simplify a feature.
- **No hard deletes anywhere.** Soft delete (`deleted_at`) + trigger-maintained
  version tables. Legal erasure = crypto-shredding (destroy the DEK), never row deletion.
- **Append-only audit.** Every sensitive action emits an audit event (entity IDs and
  enums only — never plaintext PII in logs). Audit tables: REVOKE UPDATE/DELETE.
- **Event-sourced asset ledger.** `asset_events` is the write model; `assets_view`
  is a rebuildable projection. Never write to the projection directly.
- **Settlement is never fully automated.** Death signals open a case; mandatory
  human review + waiting period + staged access. No single source triggers anything.
- **Step-up MFA (fresh ≤5 min)** required for: vault open, document generation,
  data export, trustee/executor/beneficiary changes, deletion requests,
  emergency-access configuration.
- **AuthZ:** Cedar RBAC+ABAC, deny by default. Beneficiaries see only assets naming
  them unless the owner explicitly widens visibility.

## Stack (do not substitute without discussion)
- Backend: TypeScript (strict), NestJS, PostgreSQL 16 (six separate clusters:
  auth/core/financial/documents/vault/audit), Redis (cache only, never source of
  truth), Kafka (MSK), OpenSearch, Temporal for settlement workflows
- API: GraphQL at BFF only (persisted queries in prod); REST/gRPC internally
- Frontend: Next.js, React, TypeScript, Tailwind, Framer Motion; WCAG AA+; dark mode
- Infra: AWS multi-account org, EKS, Terraform (GitOps via ArgoCD), CloudFront +
  WAF + Shield Advanced, KMS + CloudHSM, everything in private subnets

## Coding conventions
- Strict TypeScript everywhere; no `any` without a justifying comment.
- Sensitive fields: `BYTEA` ciphertext + `dek_id`; blind indexes (`*_bidx`) only
  where an equality-search use case exists (never for SSN).
- All IDs are UUIDs; never expose sequential IDs.
- Secrets never in code or env files committed to git — Secrets Manager/Vault only.
- Tests accompany every PR: unit + integration. docs/00's stated target is 95%
  backend / 90% frontend; the ENFORCED rule is each package's own
  `coverageThreshold`, which ratchets UP and never down. Those two are not the
  same number and the difference is stated rather than implied: 17 of 24 backend
  packages sit below 95 on statements (`packages/db` 25, audit 57, assets 60,
  plaid 60, settlement 62), and `apps/e2e` and `packages/config` carry no floor
  at all. Treat 95/90 as the aspiration and the ratchet as the gate — a bar
  nothing measures is a bar nobody meets.
- Every external integration (Plaid, death-data providers, LLM providers) goes
  through an isolating service; third-party tokens decrypt only inside that service.
- Treat all user-uploaded content (documents, OCR text) as untrusted input,
  including for AI features — document text is data, never instructions.

## Workflow preferences
- Before large changes: propose a plan and the affected docs/services first.
- When a design decision gets settled in-session, append it to this file's
  "Decision log" so future sessions inherit it.

## Decision log
- (add entries as: date — decision — rationale)
- 2026-07-20 — Monorepo tooling: pnpm workspaces + Turborepo (over Nx) — less framework
  lock-in, remote-cacheable task graph, pnpm catalogs give one shared dependency-version
  surface, and pnpm 10 blocks dependency build scripts by default (supply-chain control).
- 2026-07-20 — Infrastructure (Terraform/Helm/ArgoCD) lives in the monorepo — one review
  surface and atomic app+infra changes; revisit extracting a deploy-config repo only if
  ArgoCD hygiene demands it.
- 2026-07-20 — Milestone 1 approved: "secure walking skeleton" — foundation packages plus
  identity + audit services end to end. Full structure and milestone plan:
  `docs/04-monorepo-and-milestones.md`.
- 2026-07-20 — Backend compiles to CommonJS; Jest + ts-jest; internal packages are consumed
  via their built `dist` with Turborepo ordering (no path aliases) — NestJS ecosystem
  alignment and deterministic type resolution over ESM friction.
- 2026-07-21 — M3 scope: manual-asset ledger first (backend only); Plaid isolate is a
  separate second PR, and `plaid_items`/`accounts` DDL ships with it — no dormant schema
  under migration drift detection.
- 2026-07-21 — Asset ledger mechanics: append + projection in ONE transaction via a pure
  reducer (only write path to `assets_view`/`asset_beneficiaries`; rebuild CLI proves
  replay equivalence); optimistic concurrency via `version` = latest per-asset seq +
  `If-Match`; idempotency via client `eventId` + unique index (retries are no-ops).
  Event payloads encrypted with AAD field `asset_event.payload.<event_id>` so ciphertext
  binds to user AND event and rebuild can re-derive the AAD from the row.
- 2026-07-21 — Step-up for beneficiary changes is asserted via the gateway-injected
  `x-estate-stepup-verified` header (StepUpGuard), the same M2 trust level as
  `x-estate-user-id`; both headers upgrade together when real cross-service session
  verification lands. Chosen over silently skipping the docs/01 §5 requirement.
- 2026-07-21 — Domain topic `estate.asset.events.v1` carries IDs/enums only
  (`asset.ledger.appended`), mirroring the audit PII firewall — Zone B Kafka payload
  crypto (`packages/kafka`) becomes a prerequisite only when a consumer needs values.
- 2026-07-21 — DEK-race fix: `deks(user_id) WHERE destroyed_at IS NULL` UNIQUE index on
  the financial cluster from day one + `DekConflictError` adopt-the-winner handling in
  `@estate/crypto` `getOrCreateDek`; auth/core clusters get backfill migrations (with
  pre-flight dedupe) as a follow-up.
- 2026-07-22 — DEK backfill dedupe (auth/core `002_dek_unique_active.sql`): a raced
  double is retired ONLY when verified unreferenced — explicit `dek_id` refs on live
  and soft-deleted rows plus `*_versions` row images, and in the auth cluster the
  implicit newest-active binding of `mfa_methods.secret_ct` (column has no dek_id).
  Keeper = referenced DEK, else newest. If >1 active DEK of one user is referenced,
  the migration RAISEs and rolls back — SQL has no KMS access, and `destroyed_at`
  means crypto-shredded, so the migration must never pick which ciphertexts die;
  runbook is re-encrypt onto one DEK, then re-run. Rejected: blind-destroy the loser
  (data loss) and an in-migration re-encryption tool (KMS creds in the migrator,
  built for a case with no observed instance and no production deployment).
- 2026-07-22 — Plaid isolate shape: SEPARATE NestJS app (`apps/services/plaid`), not a
  module in assets — TB5 wants token decryption in its own namespace/IAM/KMS-grant
  boundary. Isolation is cryptographic, not organizational: own KEK alias `plaid/kek`
  + own `plaid_deks` table, so the asset service's KMS grant can never unwrap a token
  DEK. Shares the financial cluster with disjoint tables + own migrations dir (the
  migrator's shared `schema_migrations` tolerates co-owners; names are disjoint).
- 2026-07-22 — Plaid DDL additions (docs/02 §3 additive): `item_id_ct` + UNIQUE
  `item_bidx` blind index (webhook routing = the equality-search case that justifies
  a blind index); no plaintext Plaid identifiers at rest or on the bus. Webhook JWT
  verification implemented on node:crypto (alg pinned ES256, kid via gateway, iat
  ≤5 min, constant-time raw-body hash check) — no new dependency on a
  security-critical path. Item revocation is step-up-gated (deletion-class action);
  provider-side remove is best-effort and cannot block local revocation.
- 2026-07-22 — Plaid gateway is an interface with a deterministic stub (dev/test,
  signs real ES256 webhooks) and a fetch-based live REST client (unit-tested against
  a mocked transport). No real credentials exist; production config REQUIRES
  PLAID_MODE=live + credentials so the stub can never run there.
- 2026-07-23 — Cross-service session verification (retires the `x-estate-user-id` /
  `x-estate-stepup-verified` header trust in profile/assets/plaid, both together).
  New `packages/auth-guard` (finally realizes the docs/04-reserved package): shared
  `CallerGuard`/`StepUpGuard` behind a `SessionVerifier` interface. `HttpSessionVerifier`
  introspects the caller's bearer token via identity's existing `GET /v1/auth/session`
  (fails CLOSED on 401/non-2xx/network/malformed; short-TTL positive cache keyed by
  sha256(token), negatives never cached so a transient outage can't lock out a valid
  token). StepUpGuard now checks the VERIFIED session's `isStepUpFresh` (one shared
  definition; identity re-exports it), not a boolean header. Chose introspection over
  identity-issued JWTs: it removes the real vuln (spoofable trust) with the endpoint
  that already exists, and the `SessionVerifier` seam makes the documented OIDC/JWT
  local-verify end-state (the "BFF milestone") a drop-in that touches no guard or
  service. Accepted trade-off: introspection forwards the caller's opaque access token
  downstream (wider blast radius than an assertion header), bounded by the 15-min token
  TTL + the mTLS mesh; the JWT end-state removes the forwarding. Each downstream service
  gains an `IDENTITY_URL` config, fail-fast in production. Cross-service e2e boots
  identity+assets and proves real introspection: a genuine session is admitted, a forged
  or missing credential is rejected with 401, and the step-up route stays 403 until a
  real TOTP step-up elevates the session. BFF unchanged (it has no profile/assets/plaid
  resolvers yet; when they land they forward the bearer credential downstream instead of
  injecting `x-estate-user-id`).
- 2026-07-23 — M4 scope: Document service in two PRs — PR1 template matrix +
  generation pipeline (including the ObjectStore/encryption substrate generation
  depends on: `document_versions.object_key` needs a store on day one); PR2 the
  upload-facing doc vault (malware-scan port, OCR port, encrypted search tokens,
  documents e2e). Full record in docs/04 M4.
- 2026-07-23 — Documents cluster uses PER-OBJECT DEKs (docs/01 §4's parenthetical,
  literal): `document_deks` keys wrapped DEKs by DOCUMENT id; `documents.dek_id` is
  the document's content DEK; crypto-shredding one document erases exactly its
  versions. Content AAD binds document id + owner + version + plaintext sha256.
  Sensitive DOCUMENT CONTENT exists only inside encrypted blobs, and intake
  variables are deliberately NOT persisted (the encrypted rendered artifact is
  the record). The one exception is `documents.title` — a user-supplied
  free-text display/label column kept plaintext so listing and the encrypted
  search index work without per-row decrypt, exactly as `assets_view.title` is
  plaintext in the financial cluster (docs/02 §3). Treat titles as
  low-sensitivity metadata (guide users to keep specifics in the content, not
  the title); an earlier phrasing here overclaimed "no plaintext-PII columns"
  and was corrected in the M4 security review.
- 2026-07-23 — Templates are "versioned like code" literally: in-repo JSON sources
  with schema-mandatory legalReview sign-off + per-state execution_requirements +
  typed variables declaration; `template-publish-cli.ts` is the only write path (no
  runtime template-mutation API — git review IS the sign-off gate); published
  versions immutable and content-pinned (`body_sha256`, verified on load,
  fail-closed). Renderer is a small in-repo deterministic engine (strict
  placeholder substitution + boolean conditionals, HTML-escaped, undeclared/absent
  values fail closed) — no Handlebars/eval on a security-critical path, same
  rationale as the node:crypto webhook verifier. Output is canonical HTML (not
  PDF — presentation deferred), so content_sha256 is reproducible.
- 2026-07-23 — ObjectStore port lives in-service (plaid-gateway precedent):
  LocalFsObjectStore (dev/test) + S3ObjectStore (If-None-Match:* immutability);
  prod REQUIRES s3 mode; blobs are ciphertext only (encryption happens in the
  service; S3 SSE is defense in depth). Objects immutable: re-put must be
  byte-identical or it errors. Extract to a package only when a second consumer
  lands.
- 2026-07-23 — Execution-status ladder is parameterized by the template's
  execution_requirements (required steps only, no skipping); regeneration is
  refused once signing starts (revoke/supersede first — a signed instrument's
  content is a legal record); executedAt accompanies exactly the `executed`
  attestation. Legal-hold ENFORCEMENT ships in M4 (blocks deletion); the setting
  surface belongs to settlement (M7). Generation, regeneration, and deletion are
  step-up gated per docs/01 §5.
- 2026-07-24 — M4 PR2 upload transport is strict-base64 JSON (10 MiB decoded cap,
  16 MiB body limit), NOT multipart: one parser (zod+JSON) on the untrusted-input
  path instead of adding busboy/multer to the fuzz surface. Declared mime is never
  trusted — magic-byte sniffing decides, allowlist pdf/png/jpeg/tiff only,
  mismatch rejects (polyglot mislabeling). Upload itself is CallerGuard-only
  (docs/01 §5's step-up list covers generation/export/deletion, not adding
  content).
- 2026-07-24 — Malware scan is FAIL-CLOSED and pre-storage: infected or
  scanner-error uploads are never written anywhere (422/503 + audited
  `document.scan.rejected` with resourceId null; scanner-produced signature names
  are sanitized into the audit-safe token grammar). Live scanner = clamd INSTREAM
  spoken directly on node:net (no dependency on a security-critical path — the
  webhook-verifier precedent); prod REQUIRES clamd mode. OCR is BEST-EFFORT and
  non-fatal (scan is the gate): stub in dev/test, AWS Textract sync
  DetectDocumentText in prod (async/multi-page Textract is a scale follow-up);
  OCR text is UNTRUSTED DATA — sealed as an encrypted artifact under the
  document's DEK + reduced to HMAC tokens, never parsed, logged, or treated as
  instructions.
- 2026-07-24 — Encrypted search (docs/01 §2.6) is per-user-keyed HMAC tokens in
  PG: userKey = HMAC(SEARCH_INDEX_KEY, userId), token = HMAC(userKey,
  normalized keyword); document_search_tokens is a DERIVED, rebuildable
  projection (assets_view precedent — exempt from soft-delete/_versions;
  replace-in-place on re-index; purged with the DEK by the retention job).
  Cross-user correlation is cryptographically out; the accepted leak is token
  counts per document. Generated documents index through the same pipeline
  (title + rendered text); search never decrypts anything (no decrypt audit
  event by design). OpenSearch stays a later milestone.
- 2026-07-24 — Uploaded documents widen `documents.doc_type` to DOCUMENT_KINDS =
  instrument types + vault categories (legal/tax/identity/insurance/property/
  military/medical/financial/other, per docs/00 §8); the unreleased
  `document.version.created` payload widened accordingly (no consumers existed).
  Binary content travels as base64 in ContentDto with an explicit `encoding`
  field; canonical HTML stays utf8.
- 2026-07-24 — M4 security review (structured discovery + adversarial verify, five
  parallel passes over the merged range): no critical/app-exploitable vuln. Seven
  findings fixed in-branch — the load-bearing one being that the execution-
  requirements ladder failed OPEN (a generated will/POA whose template was
  soft-deleted or whose requirements column was unparseable dropped to
  no-witness/no-notary); now a generated doc reads requirements from the
  sha256-verified template source and fails closed, extending the body_sha256
  pin to the formalities gate. Also: newVersion refuses to re-mint a DEK on a
  crypto-shredded document (Gone, not a fresh live key); scan gate admits only
  `clean` (fail-closed by construction); scanner signature re-clamped at the
  audit egress; clamd response bounded (8 KiB cap + hard deadline); publish CLI
  refuses placeholder-legalReview exemplars when NODE_ENV=production; and the
  "no plaintext-PII columns" claim corrected — `documents.title` is accepted
  plaintext label metadata like `assets_view.title`. Full record in docs/04 M4
  review; documented follow-ups (orphan-DEK sweep, 404-vs-403 oracle, post-commit
  outbox, async Textract) left as-is.
- 2026-07-24 — M5 SPLIT: containerization + supply chain ships now; the
  Terraform/EKS dev environment is deferred until an AWS org, billing (~$420–1,100/mo
  dev tier) and a CI OIDC role exist. Rationale: nothing was deployable anywhere
  (no Dockerfiles, empty `infra/`), and images are a hard prerequisite for the
  cloud half — so the free, blocking half goes first. ONE parameterized
  `node-service.Dockerfile` (ARG PKG) covers all seven Node apps instead of seven
  drifting copies; web is separate only because Next.js emits a `standalone`
  bundle. Distroless + non-root + glibc base matched to the runtime so
  `@node-rs/argon2`'s prebuilt binary matches its ABI. Images are built and
  verified in CI but NOT pushed and NOT cosign-signed (signatures need a registry;
  none chosen until ECR lands), and bases are tag-pinned not digest-pinned (an
  unrefreshable hand-written digest rots into an unpatchable base) — both recorded
  as deliberate gaps in docs/04 rather than silently skipped. CI smoke-tests that
  each service image still exits non-zero with its config error when run with no
  environment, so the fail-fast posture is proven in the shipped artifact.
- 2026-07-24 — Image vulnerability gate splits by OWNERSHIP, not severity alone:
  application (npm) high/critical BLOCK; base-image (deb/binary) findings are
  reported to the job summary. Rationale: the first scan found 21 high/critical,
  all in the distroless base (libssl3/libc6/bundled node, several "won't fix"),
  zero in our dependency tree — and a distroless image has no package manager, so
  there is nothing to patch from here. Blocking every PR on the base vendor's
  rebuild cadence yields a permanently red pipeline people learn to ignore. The
  compensating control is rebasing (floating patch tag every build; Renovate
  digest pinning + scheduled rebuild is the follow-up). Gate lives in
  `.github/scripts/gate-image-scan.mjs`.
- 2026-07-27 — M6 scope: vault (Zone A) in two PRs — PR1 the vault core
  (`packages/vault-crypto` + `apps/services/vault`), PR2 emergency access.
  Backend only; a vault UI needs the docs/03 TB6 isolated-origin/CSP work and
  gets its own milestone. Full record in docs/04 M6 + the docs/03 §6a delta.
- 2026-07-27 — Vault key hierarchy is 1Password-style 2SKD: keys derive from the
  vault password AND a 128-bit device-only Secret Key (`ES1-…`, checksummed).
  APPROVED DEVIATION from docs/00's "Passwords: Argon2id": the password KDF is
  PBKDF2-HMAC-SHA256 (650k) because WebCrypto has no Argon2 and a WASM Argon2
  would put a dependency tree on the highest-audit-surface code in the product
  (docs/04 boundary rule 3 / docs/03 TB6) to buy a defense the Secret Key's 128
  bits already provides. `kdfParams` is versioned so Argon2id is a later
  drop-in; account passwords keep Argon2id. One PBKDF2 pass feeds both the
  unlock key and the SRP private key through domain-separated HKDF expansions.
- 2026-07-27 — `packages/vault-crypto` has ZERO runtime dependencies, enforced
  by an ESLint `no-restricted-syntax` fence on the AST source value plus a
  source-scanning spec. `no-restricted-imports` was rejected for this: its
  `patterns` groups use gitignore-style matching where `*` never crosses a `/`,
  so `@noble/hashes/sha256`-style deep specifiers slip through (verified against
  a probe file). SRP-6a is hand-written on `bigint` for both roles in that one
  package — the node:crypto/webhook, template-renderer and node:net/clamd
  precedent — with `x` from 2SKD and identity = user UUID, never email.
- 2026-07-27 — The vault CLIENT pins the parameters the server serves it
  (`assertSupportedKdfParams`, before any modpow). Zone A's adversary includes a
  malicious server, which could otherwise substitute a degenerate SRP group and
  recover the private key by small-subgroup confinement. Every ciphertext also
  carries a domain-separated AAD, key wraps included, and item content AAD binds
  `blobVersion` (create = 1, update of N encrypts under N+1) — so item ids are
  client-generated, which also makes retried creates idempotent.
- 2026-07-27 — `vault_keysets` keeps version history (a no-history exemption was
  proposed and DECLINED) but the trigger's captured row image redacts
  `wrapped_master_key` and `srp_verifier`. The master key does not rotate on a
  password change, so a retained old wrapping plus a phished retired password
  would open the CURRENT vault: here the prior row is an attack asset, not an
  audit record. Everything with audit value survives. Versioned by `user_id` on
  the `profiles` precedent. Consequence: reset/erasure IS the crypto-shred —
  but only if EVERY wrapping of the master key goes, which the M6 security
  review found reset getting wrong (see the 2026-07-27 review entry below).
- 2026-07-27 — Keyset replacement requires an HMAC proof under a key both sides
  derive from the SRP session (`keyset_auth_key`), not just step-up + a vault
  session. Otherwise exfiltrated bearer tokens could overwrite the keyset and
  destroy every item — reading protected by cryptography, destroying protected
  by tokens. Reset is the deliberate exception (a lost password cannot be
  proven) and is therefore step-up-gated, distinctly audited, and notified.
- 2026-07-27 — M6 PR2 emergency access: TWO-LEVEL split,
  `RK = platform_part XOR contacts_part`, with `contacts_part` split Shamir
  M-of-N (GF(2^8), hand-rolled in vault-crypto) over the grantees. The XOR is a
  one-time pad, so every grantee colluding still cannot reconstruct RK without
  the platform half — that is what makes the ≥24h waiting period a real
  constraint rather than an honour system. Threshold 1 is the shipped default;
  arbitrary M-of-N works and needs no migration to adopt. Accepted residual: a
  server that releases its half early defeats the delay (inherent to docs/01's
  design); compensating controls are the audit trail and owner notification.
- 2026-07-27 — Emergency-access denial is STICKY with NO time-based cooldown: a
  denied policy refuses further requests until the owner re-arms (step-up). A
  cooldown would tell a patient grantee exactly how long to wait, and outlasting
  an owner who is hospitalised or offline is docs/03 §5.2's actual attack.
  Denial itself is the one owner action deliberately NOT step-up gated — it must
  be one tap from a notification. Release is one-shot (the escrow is spent).
  Every request, including refused ones, is audited and notified.
- 2026-07-27 — Emergency-access notifications are a PRECONDITION, not a
  side effect: in production the emergency-access routes refuse
  (503 `notifications_unavailable`) while only the stub notifier is wired,
  because a waiting period nobody can be told about is not a control. Scoped to
  those routes rather than a boot-time check, so the rest of the vault keeps
  serving. Grantee key authenticity is the owner's job by design: the client
  confirms a short fingerprint out of band before sealing a share, and
  `grantee_public_key_sha256` records what it sealed to so substitution is
  detectable. `emergency_access_policies` adds `grantee_user_id` to docs/02 §5
  because the vault cluster cannot dereference a core-cluster contact.
- 2026-07-27 — M7 scope (all four asked and approved): settlement ships WITHOUT
  Temporal — the docs/02 §7 Postgres state machine is authoritative and the only
  scheduled work (the owner-contact sweep) runs behind a deliberately POWERLESS
  in-process driver, so case state never advances on a timer and Temporal later
  replaces a setInterval, not a design (approved deviation from docs/01 §7's
  letter; no deployment exists for its durability to protect — the M5 cloud
  deferral). Separate `apps/services/settlement` co-tenant on the CORE cluster
  (Plaid precedent) EXTENDED with read-only use of profile's
  contacts/role_assignments (docs/02 §7's own DDL references contacts; prod
  grants SELECT-only). Human review by platform users on a CLI-managed
  `settlement_operators` allowlist — deliberately NO runtime grant API (stolen
  operator sessions must not mint operators); interim until the TB7 operator
  platform. The docs/03 §6a vault-release gate lands in M7 PR2.
- 2026-07-27 — M7 PR1 control decisions: intake only OPENS a case (reporters
  must be linked contacts — no email/id lookup = no enumeration oracle; provider
  matches are operator-filed; one open case per decedent; report locks NOTHING).
  Account lock at review-approve (never at raw report), INSIDE the case
  transaction via identity's new internal settlement-lock API — identity
  enforces its own closed transition table (active↔deceased_pending→settlement),
  revokes all sessions at verified, and the live-session SQL gains a status
  ALLOWLIST ('active','deceased_pending') because a status flip alone would
  have left 30-day refresh tokens working. deceased_pending deliberately keeps
  the owner's login alive (the §5.1 rescue path) while profile's role-holder
  grants freeze (to_regclass-guarded predicate — deploy-order independent);
  'settlement' logins get the generic 401 with a distinct recorded
  account_settled reason. Verification is twice-human: a lapsed waiting period
  only makes a case ELIGIBLE; the confirming operator (never the reporter, like
  the reviewer — DDL CHECK) triggers an owner-liveness re-check against
  identity's append-only step-up ledger, and a step-up newer than the case
  auto-voids it (409 owner_alive). The owner's void route is step-up-gated
  BECAUSE the step-up is the liveness proof. Settings are configurable UP only
  (5..60d) and frozen while a case is open. Cases have NO deleted_at — a case
  is evidence (§5.1 c6). Notifications are a precondition: intake +
  review-approve 503 in production on the stub notifier (M6 precedent).
- 2026-07-27 — M7 owner-liveness interlock (found by the pre-push adversarial
  review, fixed in-branch): the §5.1 "any owner step-up instantly voids the
  case" control is enforced TWICE — settlement reads liveness, AND identity
  restates it as a `NOT EXISTS` over `auth_events` inside the same CAS `UPDATE`
  that writes the status. One check was not enough: settlement's read and its
  commit are separated by a network hop, and because there is deliberately no
  un-verify ceremony, a step-up landing in that window would irreversibly
  entomb a LIVING owner in `settlement` — §5.1's Critical outcome reached by
  accident rather than by attack. Identity returns `409 owner_alive` (distinct
  from `invalid_transition`, which a caller would retry); settlement maps it to
  a typed `OwnerAliveError` and takes the void path, unwinding its own
  in-transaction `markVerified` (hence `markResolved` also clears `verified_at`,
  which the DDL CHECK requires). Residual — a step-up inside that one statement
  — accepted and recorded in docs/03 §6b: post-transition the sessions are
  revoked and the status allowlist blocks every lookup, so it buys nothing and
  stays visible in the ledger. Closing it fully needs the step-up path to take
  the users row lock, which belongs to the TB7 operator-platform milestone.
- 2026-07-27 — M7 new trust machinery: `ServiceCredentialGuard` in
  @estate/auth-guard (constant-time compare of a shared static credential;
  fails closed unwired; ≥32 chars required in prod) authenticates settlement on
  identity's internal routes — the one flow with no user bearer to forward by
  construction (chose over bearer-forwarding: identity cannot know settlement's
  allowlist, and deny-by-default forbids "any session may lock accounts").
  Interim until mesh mTLS/SPIFFE; the guard is the seam. Evidence reads flow
  the OTHER way on the operator's own forwarded bearer via
  `packages/settlement-client` (fail-closed; created as a package immediately —
  three consumers land in-milestone: documents PR1, assets+vault PR2), with the
  load-bearing cross-check that settlement's recorded evidence ATTACHER must
  equal the document's real owner (a reporter registering someone else's
  document id gets an operator a uniform 404, never a decryption).
  settlement.cedar permits are all scoped `resource is SettlementCase`, and the
  case resource carries decedent/reporter attrs, deliberately NOT `owner` —
  owner.cedar would otherwise grant the subject operator verbs on their own
  death case.
- 2026-07-28 — M7 PR2 (staged access, distributions, the §6a gate): the stage
  LADDER is the control — inventory→documents→vault, request only the next
  rung, each rung separately operator-approved, requester≠approver as a DDL
  CHECK — so Zone A is structurally the furthest grant from a fresh death
  report. Executor identity resolves from role_assignments' dormant
  `on_death_verified` half (settlement is its first consumer); designation
  alone grants nothing. docs/03 §6a is CLOSED: vault consults settlement at
  BOTH request and release (twice, because the waiting period is days long and
  an estate can enter settlement in between), inside the transaction after the
  row lock, authenticated by the SERVICE credential — a grantee's bearer must
  not mint an answer about the owner's estate. Any non-terminal case without an
  approved vault stage BLOCKS, and so does an unreachable settlement (fail
  closed everywhere); blocking only delays a legitimate recovery (the escrow is
  unspent) whereas allowing hands a fraudulent heir the platform half inside
  the §5.1 window. Dual control on distributions is a row-local CHECK rather
  than docs/02 §7's stated trigger — with `created_by` added, approver and
  recorder are columns of the same row, so a CHECK is strictly stronger
  (immediate, undeferrable, not disableable per session); the doc's intent is
  preserved, only the mechanism is simpler, and the repo's one CONSTRAINT
  TRIGGER (assets' share-sum) exists precisely because that invariant spans
  rows. Amounts are ciphertext under settlement's OWN `settlement/kek` +
  `settlement_deks`, keyed by the decedent so one shred retires the estate;
  profile shares the cluster and still cannot read them. Executor estate reads
  live on a SEPARATE assets route that forwards the caller's bearer to
  settlement — settlement holds no data-read power, so compromising it
  mis-answers rather than exfiltrates. Legal hold gained a writer ROUTE
  (service-credential internal route on documents) — but NOT a caller: the
  2026-07-28 credential-graph work found nothing in the repo calls it, so the
  M4 gap was NOT closed (corrected in docs/04 M7; closed in M9 PR2 — see the
  2026-08-04 legal-hold entry).
- 2026-07-27 — M6 security review (six parallel discovery lenses over the merged
  range + adversarial verify of each finding; 35 raw, 28 unique, 14 verified, 11
  refuted): no critical or app-exploitable vuln in the Zone A guarantee. Three
  findings fixed in-branch, the load-bearing one being that vault RESET did not
  tear down the emergency-access escrow — `emergency_access_configs` holds a
  SECOND live wrapping of the master key, so a grantee could still release and
  reconstruct the key the owner was told was destroyed, defeating the
  crypto-shred. Reset now destroys every wrapping (escrow config, policies, and
  the owner's own grantee keypair) in one transaction and audits the teardown.
  Also: the grantee-key fingerprint carried 50 bits where its own spec said 80
  (it is the only defense against server key substitution, so the width IS the
  security parameter) — widened to 16 symbols; and reset left a published
  grantee public key whose private half it had just destroyed, which would have
  let later escrows seal shares nobody can open. Full record in docs/04 M6.
- 2026-07-28 — M7 security review (six parallel discovery lenses over the merged
  range `a278635..4d24537` + adversarial verify of each finding, verifiers told
  to default to refuted; 23 raw, 23 unique, 12 verified, 6 confirmed / 6
  refuted): no single-source, single-actor or timer-driven path into settlement
  survived. The six confirmed collapse to TWO defects, both in machinery M7
  introduced, both contradicting docs written in the same milestone; fixed
  in-branch. (1) The service credential collapsed FOUR services onto one secret
  — `SETTLEMENT_INTERNAL_TOKEN` was both what settlement expected inbound and
  what it presented outbound, so any working deployment made vault's copy equal
  identity's expected value, letting whoever holds the Zone A service's secret
  call `PUT /internal/v1/settlement-lock/{victim}` twice and irreversibly entomb
  a living user with no case, no operator, no waiting period (§5.1's Critical
  outcome, whole control chain skipped). Rule adopted: ONE SECRET PER CALLEE,
  PER DIRECTION — each var named for the service whose routes it OPENS
  (`IDENTITY_INTERNAL_TOKEN`, `SETTLEMENT_INTERNAL_TOKEN`,
  `DOCUMENTS_INTERNAL_TOKEN`), and settlement's config REFUSES TO BOOT in
  production when its two credentials are equal, because splitting the field
  cannot stop one value being pasted into both slots. (2) Profile's grant-freeze
  `to_regclass` probe cached the NEGATIVE for the process lifetime, so a profile
  process older than settlement's migration had §5.1 control 4 compiled out of
  its SQL silently and forever — fail-open indistinguishable from a working
  freeze; only the positive is cached now (a table cannot un-exist). Also fixed:
  `revokeStage` lacked the requester≠decider pre-check, so the DDL CHECK
  surfaced as an unhandled 500 with the access still granted. Full record in
  docs/04 M7; the credential-scoping rule is in docs/03 §6b.
- 2026-07-28 — Service-to-service trust is DECLARED AND MACHINE-CHECKED:
  `packages/auth-guard/src/credential-graph.ts` states, as data, which service
  may hold which internal credential (the packages/authz shared-Cedar-bundle
  precedent). The M7 collapse survived two PR reviews because the trust graph
  existed only as prose and the prose was wrong, so the fix is a table that
  fails the build rather than a paragraph that fails silently. TWO layers,
  split by a hard constraint: every service depends on @estate/auth-guard, so a
  suite there can never import services back (workspace cycle). Source scanning
  therefore lives in `packages/auth-guard/test/credential-graph.spec.ts`
  (readFileSync only — the vault-crypto zero-dependency-fence precedent, which
  creates no package edge), and the RUNTIME half — load the service's real
  config with EVERY credential in the environment, assert it absorbs exactly
  the granted set — lives in each service's own `test/config.spec.ts`, where it
  compiles from src (no stale dist) and reuses the dev fixture already there.
  Deliberately NOT in apps/e2e: all seven specs there carry a copy-pasted
  `describeIfPg` line, so one tidy-up would silently skip the fence in every
  environment, and ci-guard only asserts PG_TEST_URL is set, never that a spec
  ran. Key design points, each from an adversarial critique lens: SERVICE_NAMES
  is asserted equal to the directories on disk (a hand-maintained list makes a
  ninth service invisible and silently narrows every other check); the guard
  check anchors on `provide: SERVICE_CREDENTIAL`, not on the `*_INTERNAL_TOKEN`
  suffix (a renamed secret evades a name-keyed fence); each credential's env
  var may be MENTIONED only in the graph module and the config.ts of its callee
  and holders (catches a process.env read in app.module, or a client default);
  `opens` is enforced against the real decorated routes; the sentinel value
  encodes its own variable name and `credentialsHeldIn` deep-walks nested
  objects and Buffers (a credential folded into a port config would otherwise
  escape). Mutation-tested, not just green: reintroducing the M7 aliasing, the
  vault-gains-identity's-key regression, a wrong inbound credential, an
  undeclared new route, a nested-object credential, and deletion or
  copy-paste of a service's runtime assertion are each confirmed to turn it
  red — which is how the anti-drop check was caught passing vacuously (the
  deleted assertion left its import behind). NOT enforced, recorded instead:
  which URL a credential is presented to, and cross-service provisioning drift
  (nothing verifies vault's copy equals settlement's inbound value — an
  operator pasting identity's secret into vault's slot re-creates M7 at deploy
  time with every service booting cleanly). Both close with the mesh.
- 2026-07-29 — M8 is the LOCAL STACK, not the AI assistant (flagged deviation
  from docs/04's ordering; approved). Rationale: nothing in the repo had ever
  run as a deployed system (M5 shipped images that CI builds and never runs);
  every production adapter was unit-tested against mocked transports only; two
  shipped milestones are deliberately inert in production pending
  notifications, whose SES adapter needs somewhere to run; and building the
  highest-prompt-injection-surface feature on a platform that cannot deploy is
  the wrong order. Five PRs: adapter seams, runtime seams, the stack, proof/CI,
  thin UI. Full record + runbook: docs/05-local-stack.md; milestone record in
  docs/04 M8.
- 2026-07-29 — M8 PR1 adapter seams: KMS gains the explicit mode enum every
  other adapter already had (KMS_MODE=local|aws; production pins 'aws'
  unchanged in strength — a BREAKING config change for deployments, none
  exist). AWS_ENDPOINT_URL is read/validated explicitly — the SAME name the
  SDK honours ambiently (verified in locked @smithy/core 3.29.6), so our value
  and the SDK's resolution cannot disagree; explicit buys the production
  https-only guard (SDK checks nothing) and S3 forcePathStyle (NO env selector
  exists in the SDK; s3ClientConfig is shared by service + publish CLI so they
  cannot address the bucket differently). OCR gains 'tesseract' (sidecar over
  HTTP — the clamd/node:net precedent: a large C++ parser of attacker bytes
  stays behind a process boundary); the production guard now names the STUB
  (!== 'stub'), which is what its message always meant. Both OCR selectors are
  exhaustive with a `never` — a ternary chain ending in the stub is the M4
  "fail-open in style" scan-gate lesson — and both were mutation-tested red.
- 2026-07-29 — M8 PR2 runtime seams: packages/kafka finally built (reserved
  since M1; in its absence seven byte-identical audit producers grew, all
  carrying the same bug: `connecting ??= connect()` cached the REJECTED
  promise, so one broker-not-ready moment at startup poisoned every later
  audited action for the process lifetime — now only rejection clears the
  shared in-flight connect). ensureTopics added for PR3 (Redpanda ships
  auto-create OFF, unlike Apache Kafka; nothing in-repo ever called admin()).
  Topic REGISTRY stays in @estate/contracts; the package owns transport only.
  Audit's fatal path now RELEASES ITS HANDLES and arms an unref'd forced exit:
  process.exitCode alone needs a drained event loop, and PG_CLIENT's open
  socket held it open forever — a container "up" with a dead audit trail,
  restart never firing, in the service whose silence is a paging signal.
  Migrator takes its advisory lock BEFORE `CREATE TABLE IF NOT EXISTS
  schema_migrations` (not race-safe; the co-tenant pairs profile+settlement
  and assets+plaid boot-race exactly that statement; ordering pin
  mutation-tested red). DROPPED from the PR2 plan: nine /healthz routes — a
  TCP probe on the port each service already listens on satisfies compose
  `service_healthy` and k8s `tcpSocket` without new unauthenticated surface
  on hardened services; audit (headless) is covered by exiting-on-failure +
  restart, which a health endpoint would have papered over.
- 2026-07-29 — M8 PR3 the stack: docker-compose.stack.yml runs all ten apps +
  clamd + tesseract + LocalStack (volume mounted at /var/lib/localstack —
  but see the 2026-07-30 correction: it does NOT preserve keys) + Redpanda.
  .env.stack is
  GENERATED (apps/stack), never committed: the three service credentials are
  minted per credential-graph EDGE and written to callee + every holder, so
  vault's copy equals settlement's inbound BY CONSTRUCTION — closing the
  recorded provisioning-drift residual FOR GENERATED ENVIRONMENTS (hand
  provisioning stays unverified; the mechanism is what generalizes to the
  secrets store). AWS credentials are deliberately fake ('test') as a control:
  env vars outrank ~/.aws/credentials, so a wrong/missing endpoint fails
  loudly at real AWS instead of silently minting real DEKs on a real account;
  the preflight doctor enforces endpoint-points-at-LocalStack + credentials-
  don't-look-real + the graph invariants + no-stub-adapters. Generator refuses
  to overwrite .env.stack without --force (new keys orphan every ciphertext in
  the volumes). apps/stack lives at apps/, NOT apps/services (the
  credential-graph fence derives SERVICE_NAMES from apps/services dirs).
  seed-templates runs the publish CLI as NODE_ENV=development EVEN in the
  production profile — the M4 guard refuses placeholder legalReview in
  production and the exemplars ARE placeholders; the guard is respected, and
  docs/05 states loudly that generation working there is not evidence of the
  legal gate. web's BFF_URL is a BUILD ARG (next serialises rewrites into the
  routes manifest at build; runtime env is ignored). Stack addressed as
  http://localhost:3000 (BFF Secure cookies + browser localhost exemption).
  Smoke-proven live: register/login over real HTTP; audit events crossed REAL
  Redpanda into the verified hash chain (count=2 — retires the M1 broker-hop
  open item); DEK minted via real KMS GenerateDataKey against LocalStack
  (116-byte KMS blob); upload 201 through real clamd INSTREAM (fail-closed
  gate ⇒ 201 proves the scan ran) + real S3 put; raw EICAR refused 422 by the
  sniff gate; blobs at rest are ciphertext (no PNG magic). NOT proven, stated
  in docs/05: KMS grant isolation (LocalStack Community has no IAM — six keys
  MODEL the boundary; EncryptionContext binding is the testable half, PR4
  asserts it), everything cloud-posture (IRSA/VPC/WAF/mesh/Kyverno/Aurora),
  and the M4 legal-hold gap (zero holders; the stack made it visible — closed
  in M9 PR2).
- 2026-07-29 — M8 PR4 proof + CI: `apps/e2e/test/stack.e2e.spec.ts` drives the
  platform as real processes over real HTTP (13 assertions in dev, 9 in the
  production rehearsal) and `aws-conformance.spec.ts` probes the three
  behaviours the adapters ASSUME. DETERMINISM CONTRACT, because a flaky
  blocking gate trains people to ignore it: no bare sleeps anywhere (poll +
  deadline), topics provisioned before any service starts, clamd readiness is
  `clamdscan --ping` (it accepts TCP long before signatures load and the scan
  gate is fail-closed), infra images tag-pinned, `timeout-minutes` on the job.
  CONFORMANCE RESULT — LocalStack DOES enforce the KMS EncryptionContext: a
  Decrypt with a foreign `estate:kek` (or none) is refused, so the local stack
  genuinely exercises the CRYPTOGRAPHIC half of the Plaid-isolation claim (a
  DEK wrapped for one domain cannot be unwrapped as another even with the right
  key id); the IAM half — which principal may call Decrypt at all — remains
  untested, and docs/05 now states that split precisely rather than hedging.
  S3 returns 412 for `IfNoneMatch:*` and surfaces not-found as
  S3ServiceException, so the immutability path and the `instanceof`-gated 404
  mapping both hold. The probes are parameterized (`CONFORMANCE_*`) so the same
  file can be pointed at a real AWS account.
- 2026-07-29 — M8 PR4 clamd FOUND path: EICAR structurally CANNOT exercise this
  platform's scan gate — it only matches at file start, and a file starting
  with plain text is refused by magic-byte sniffing before any scan, while
  prefixing a PNG/PDF header stops it being EICAR. So `infra/clamav/stack-test.ndb`
  declares one custom signature and the fixtures build a VALID PNG carrying the
  pattern in a tEXt chunk: sniffing admits it, clamd flags it
  (`Estate.Stack.TestProbe FOUND` over the real INSTREAM protocol), the upload
  is refused 422 and nothing is stored. Fixtures are generated with node:zlib
  only (no image library on the test tree); the clean fixture renders block
  glyphs that real tesseract reads back as "ESTATE STACK PROBE", which is what
  makes the OCR→HMAC-token→encrypted-search assertion meaningful.
- 2026-07-29 — M8 PR4 production TLS: the PR1 guard (`AWS_ENDPOINT_URL` must be
  https in production) correctly REFUSED the production profile against
  LocalStack's http endpoint. Resolved by giving the stack real TLS — an nginx
  terminator (`aws-tls`) with a generated cert the services verify through
  `NODE_EXTRA_CA_CERTS`, bind-mounted so host-mode runs trust the identical CA
  — NOT by relaxing the guard, and not via NODE_TLS_REJECT_UNAUTHORIZED, which
  the doctor now treats as an error in its own right (it would make the
  production TLS requirement decoration). Every service boots healthy under
  full production config with KMS over verified TLS.
- 2026-07-29 — M8 PR4 anti-drift: host addressing (`--addressing host`) lets CI
  run services from `dist` against containerised infra without image builds,
  and `run-services-cli` REFUSES a compose-addressed env file (container
  hostnames do not resolve from the host; every service would boot and fail per
  request). Because that creates a SECOND env mapping,
  `apps/stack/test/compose-parity.spec.ts` parses the compose YAML's
  environment blocks and asserts key-for-key/value-for-value agreement with
  `serviceProcessEnv` — it immediately caught the CA variable being added to
  the YAML and not the mapper. Supervisor children get a SCRUBBED parent env
  (AWS_*, *_INTERNAL_TOKEN, KMS_* removed) so an ambient developer profile
  cannot leak into a service the explicit mapping did not set. ci-guard gained
  the stack half (CI_REQUIRE_STACK ⇒ STACK_TEST must be set), and because jest
  exits 0 for an all-skipped suite, both workflows additionally assert
  `numPassedTests` against a floor from `--json` output.
- 2026-07-29 — M8 PR4 also recorded: an inbound credential edge with ZERO
  holders is deliberately NOT provisioned (documents' legal hold, holder-less
  until M9 PR2). The service absorbs the variable and its guard fails closed
  on the empty value; minting a secret nobody can present would be exactly the
  aspirational grant the credential graph exists to forbid. The generator, the
  doctor and the entitlement spec all agree on that subtraction, which stays
  in place for any future holder-less edge.
- 2026-07-29 — M8 PR5 thin UI: the BFF gained its FIRST non-identity resolvers
  (assets list/net-worth/create), realizing the 2026-07-23 decision's stated
  end-state — the BFF FORWARDS THE CALLER'S OWN BEARER downstream and injects
  no identity header, holds no assets credential, and so cannot mint authority
  it was not handed (a compromised BFF replays the sessions it is currently
  serving, never conjures new ones). Money is a decimal STRING through the
  whole path, GraphQL included. Logout landed end to end, retiring the M1 open
  item: identity revokes the PRESENTED session only (never revokeAllForUser —
  logging out one browser must not kill other devices; that verb stays for
  theft response and the settlement lock), then the BFF expires both cookies
  with the SAME attributes they were set with. Revocation happens FIRST and a
  failure does NOT clear cookies — a "signed out" message over a live session
  is the worst outcome, so the UI says so instead.
- 2026-07-29 — M8 PR5 found a LATENT PRODUCTION-ONLY BUG by driving the real
  web image in a browser: the GraphQL client omitted `persistedQuery.version`,
  which the BFF's APQ extractor requires, so EVERY persisted operation would
  have failed in production with "Operation not allowed". It was invisible
  because non-production builds also send `query`, so the document carried the
  request and the hash was never consulted — dev, tests and CI were all green.
  Fixed with a regression pin. Two more of the same class: the persisted-manifest
  BUILDER hashed raw CRLF bytes on Windows while ECMAScript normalizes template
  literals to LF, so every hash in the committed manifest was wrong (now
  normalized before hashing); and `turbo.json`'s build task declared no `env`,
  so Turbo 2's strict env mode stripped BFF_URL and the web image baked a
  rewrite to localhost:4000 — i.e. proxied /graphql to itself. All three were
  invisible to every existing test and only reachable by running the real
  artifact.
- 2026-07-29 — M8 PR5 also surfaced a DOMAIN rule the UI had to learn: a
  valuation is all-or-nothing (`CreateAssetSchema.refine` — estValue,
  valuationAsOf and valuationSource together or none). An amount with no date
  and no provenance is not a claim anyone could audit later, so the ledger
  refuses it. The BFF now rejects a partial valuation with INVALID_REQUEST
  rather than forwarding one and masking a downstream 400, the client type
  makes the triple indivisible, and the form reveals date+source as soon as an
  amount is typed. Coverage floors RAISED, not lowered, to absorb the new UI:
  web 62/55/58/65 → 70/62/64/73.
- 2026-07-30 — M8 security review (six parallel discovery lenses over the merged
  range `b95bb5f..8bec8af` + adversarial verify of each finding, verifiers told
  to default to refuted): no zone boundary weakened, no production fail-fast
  relaxed to make the stack run, no credential reaching a service the graph
  forbids. THREE confirmed defects, all in machinery M8 introduced, TWO of them
  contradicting a claim in the same milestone's own commit messages — the
  recurring M6/M7 pattern, now expected rather than surprising. (1) LOGOUT read
  identity's 401 as success: the guarded route needs a live 15-minute ACCESS
  token, so a tab older than that cleared both cookies while the session and its
  30-DAY REFRESH TOKEN stayed live — a browser that looks signed out over a
  session that is not, which is precisely what the PR5 message claimed to avoid.
  Identity gained `POST /v1/auth/logout/refresh`, deliberately NOT behind
  SessionGuard (a live access token is the thing that is missing), resolving by
  refresh-token hash and always answering 200 so it is not a liveness oracle;
  the BFF falls through to it and still clears no cookie unless something was
  revoked. (2) The BLOCKING stack gate had never run: `stack.yml` handed the
  HOST-addressed env file to compose, where `localhost` is each bootstrap
  container's own loopback, so every migration failed and the job died before
  the stack test — the production rehearsal never executed while docs/05
  credited it as proven. Now two files, the host one DERIVED from the compose
  one (`--from`, same secrets — two addressings are two views of ONE set of
  volumes, and independent generation would give the host processes a different
  KMS master key and search-index key than the bootstrap jobs wrote under), and
  `diagnose --for compose|host` refuses a mismatch, mirroring
  run-services-cli's refusal of the opposite direction — the ASYMMETRY was the
  hole. Same finding: the `numPassedTests` floors sat two tests below the real
  counts, slack exactly wide enough to `.skip` the clamd FOUND path and the
  OCR→search path and stay green; both workflows now assert EXACT passed and
  pending counts. (3) A dead audit CONSUMER left the process running: PR2 fixed
  startup and left steady state open — `consumer.run()` resolves once the loop
  is running, and kafkajs restarts only RETRIABLE errors (`shouldRestart =
  isErrorRetriable && restartOnFailure(e)`, read in the locked 2.2.4 source), so
  anything else disconnects and returns, leaving a live process holding its PG
  socket and answering the TCP probe while ingesting nothing. `start()` now
  takes the fatal handler. Full record in docs/04 M8 review.
- 2026-07-30 — MEASURED, correcting the PR3 claim: LocalStack Community does NOT
  persist state and the volume at /var/lib/localstack holds the state DIRECTORY,
  not the state. A plain `docker restart localstack` leaves 0 of 6 KMS aliases,
  an empty bucket, and a previously wrapped DEK failing Decrypt with
  NotFoundException — while the Postgres volumes persist, so that one restart
  strands every DEK and dangles every object_key with no error at the time.
  `/tmp/stack-init-complete` also SURVIVES a restart (container filesystem, not
  container state), so the healthcheck reported a healthy keyless LocalStack.
  The init hook now clears the marker FIRST and refuses to re-provision when its
  volume-resident epoch file exists with no keys behind it: re-minting under the
  same aliases would hand the services a stack that boots cleanly and cannot
  read its own data, so it exits non-zero with instructions
  (`STACK_ALLOW_KEY_LOSS=1` to override). Consequence for the runbook: the data
  volumes are ONE UNIT — `stack:reset` (down -v), never `stack:down`, is how you
  come back from a stopped stack.
- 2026-07-30 — Frontend visual direction: "Evergreen rail" app shell, chosen by the
  user from three mocked candidates (fintech-polish lane per docs/00's
  Wealthfront/Apple influences; mockup artifact in the 2026-07-29 session). Two
  surface worlds in `globals.css`: the content palette (near-neutral, green-biased,
  flips with the scheme) and `--rail-*` (deep evergreen, deliberately CONSTANT
  across schemes — theme switching changes the light in the room, not the
  building). Typeface: Instrument Sans (SIL OFL), VENDORED into
  `apps/web/public/fonts` with manual `@font-face` + unicode-range — no
  next/font/google because builds must not depend on a third-party fetch, and no
  runtime CDN by CSP posture. Routes split into `(app)` (AppShell: rail +
  mobile brand bar + bottom tab bar) and `(auth)` (login/register render without
  app navigation). Nav shows Documents/People/Vault as inert "Soon" previews —
  backends shipped M4–M7 without UIs; Vault's future entry is an OUTBOUND link
  (isolated origin, docs/03 TB6). Money display: `formatMoney` groups digits by
  string manipulation only (proven against >MAX_SAFE_INTEGER values) — the
  never-parse-money-to-float rule now has a formatter, not just a renderer.
  Sign-out moved from page content into the rail account section. Deliberately
  OUT of this pass (layer on next): Framer Motion, dashboard modules/charts,
  richer loading/empty states.
- 2026-08-04 — M9 is NOTIFICATIONS, sequenced ahead of docs/04's "AI assistant ·
  referral · notifications" ordering (user-approved reorder, the M8 precedent):
  it is the smallest milestone that un-gates two shipped ones — M6 emergency
  access and M7 settlement intake/review-approve deliberately answered 503
  `notifications_unavailable` in production, and "a waiting period nobody can
  be told about is not a control" stops being rhetoric only when something can
  actually tell them. Bundled: the settlement→documents legal-hold caller
  (closing the M4 zero-callers gap) shipped as PR2 of the same milestone
  (2026-08-04 entry below).
- 2026-08-04 — M9 architecture, TWO approved deviations from docs/01. (1) The
  notification service is called SYNCHRONOUSLY over HTTP (new
  `apps/services/notifications`, ninth service, core-cluster co-tenant), not
  docs/01 §2's Kafka-consumer placement: the M6/M7 fail-closed capability
  gates are request/response by nature — a producer cannot know whether anyone
  can deliver — and the per-send outcome feeds vault's `delivered_at`
  bookkeeping. Kafka fan-in can arrive later for non-gating kinds. (2)
  Recipient resolution is EVENT-CARRIED, not cross-cluster decryption: the
  service keeps its own `notification_recipients` store (AEAD under its own
  `notifications/kek` + `notification_deks`; NO blind index — lookup is by
  user id only), fed by identity at REGISTRATION and LOGIN, the two moments
  the user themselves supplies the plaintext address. Consequence: no service
  anywhere needs an email-ciphertext read path (identity's `users.email_ct`
  still has none), the docs/03 §5.3 bulk-decrypt chokepoint never forms in
  the lowest-trust service, and the feed is fire-and-forget (an awaited call
  on register would widen the documented enumeration timing channel;
  self-heals at next login; gaps surface as recorded `no_recipient` outcomes).
- 2026-08-04 — M9 content doctrine is enforced BY CONSTRUCTION, not by review:
  the wire schema (`packages/notifications-client`, consumed by vault +
  settlement + identity) carries userId, a CLOSED namespaced kind enum, a
  requested channel, and an optional deadline — there is no field for text, so
  no caller can leak estate content into a carrier message. The template
  registry is the only source of carrier-visible words: no user data beyond
  the deadline DATE, ONE uniform subject for every kind (a mailbox observer
  learns that Estate wants attention, never which control fired — the M6
  review's delivery-channel-leakage item), and NO LINKS AT ALL ("we will never
  link you" is strongest as "we never link"). Delivery is email-only (SES v1 —
  the API LocalStack Community also serves, so the stack proves real sends via
  `/_aws/ses`); SMS/push/in-app and one-tap deny capability tokens are
  recorded follow-ups (deny links need the vault UI's origin to exist).
- 2026-08-04 — M9 trust machinery: fourth credential-graph edge
  (`NOTIFICATIONS_INTERNAL_TOKEN`, callee notifications, holders identity +
  settlement + vault — every route it opens is notification-domain; no
  lock-class power leaks to holders). Production PINS the real adapters
  (vault/settlement `NOTIFY_MODE=http`, notifications `EMAIL_MODE=ses` — the
  KMS/clamd/OCR rule; the old "not a boot-time requirement" comments predated
  a real adapter existing), pairwise credential-aliasing refusals extend to
  the new secret in every holder, the per-route 503 gates REMAIN as defense
  in depth and now AUDIT their refusal (`*.notifications_refused` — a control
  firing must not read as an outage), and the M6 review's two recorded
  follow-ups ship: owners are notified on vault RESET (nullable `policy_id`
  via migration 003, kind-anchored CHECK) and when a reconfiguration retires
  the previous grantees. Send failures never roll back state; every send is
  an append-only `notification_sends` row + ids/enums-only audit event, and
  every address decrypt is a logged `crypto.field.decrypted`.
- 2026-08-04 — M9 PR2 closes the M4 legal-hold zero-callers gap: settlement's
  `documents-hold.ts` (the identity-lock pattern verbatim — fail closed,
  idempotent callee, 503 `documents_unavailable` + rollback on any failure)
  drives documents' `PUT /internal/v1/legal-hold` PAIRED with the account
  lock at every case transition: set with `deceased_pending` at
  review-approve, cleared with every restore to `active` (reject-from-wait,
  owner void, liveness void), and RE-ASSERTED with the terminal lock at
  verification because the owner's login survives `deceased_pending` (the
  §5.1 rescue path) and the estate can grow during the wait — the invariant
  is "every live document of a verified estate is held". Graph edge flipped
  `holders: [] → ['settlement']` in the same change as the client (the rule
  the graph comment mandated); `DOCUMENTS_INTERNAL_TOKEN` became
  production-required on BOTH sides; settlement's aliasing refusal is now a
  full pairwise loop over all FOUR credentials it touches. Deliberate scope
  note: the hold OUTLIVES case close — no lift surface exists
  post-settlement; that ceremony belongs to the TB7 operator platform. A hold
  stranded by a commit failure blocks only deletion (deny-safe) and heals on
  re-drive. Proven at three levels: first-ever route tests (real guard, real
  Postgres, 401/400/sweep/idempotent/audited/409→200), eight transition tests
  over a fake port, and a dev-journey stack e2e driving the generator-minted
  credential live (approve freezes the estate against a step-up-authorized
  deletion; reject releases it); `document.legal_hold.set` joined the
  verified-hash-chain assertion and the workflow exact counts moved
  13/4→14/4 (dev) and 9/8→9/9 (production). Running the gates locally also
  found WHY PR1's CI was red, both fixes cherry-picked onto PR1's branch so
  #20 merges green on its own: stack.yml's hand-copied migrate list never
  learned about migrate-notifications (now DERIVED from the compose file —
  the copy-pasted-line drift class again), and the notifications coverage
  floor was set from a number CI never produced — closed by the
  controller/error-filter's first specs and the floor RATCHETED UP to the
  newly measured numbers, never down.
- 2026-07-30 — Also from the M8 review: the doctor's endpoint check was a PREFIX
  match, so `https://localhost:x@kms.us-east-1.amazonaws.com/` passed the one
  guard between a misconfigured stack and real AWS — it parses the URL now.
  Related and NOT closed: the SDK resolves `AWS_ENDPOINT_URL_KMS`/`_S3`/
  `_TEXTRACT` BEFORE `AWS_ENDPOINT_URL` and each service's https-in-production
  guard only reads the plain name; the stack's preflight refuses those variables
  outright, production does not, and six config comments that overclaimed "can
  never disagree" now scope themselves precisely. The supervisor also scrubs
  `NODE_TLS_*`/`NODE_OPTIONS`/`NODE_EXTRA_CA_CERTS` from the parent env — the
  doctor reads the FILE, and these reach a child from the developer's shell
  without ever appearing in it. And plaid's compose profile name is now
  GENERATED (`PLAID_PROFILE`), so the production profile omits the container
  instead of crash-looping one that cannot boot without live credentials —
  matching what `plannedServices` already did for host mode.
- 2026-08-05 — M9 security review (seven parallel discovery lenses over the
  merged range `8aba7c7..03126c9` + TWO adversarial verifiers per candidate on
  different angles — reachability in a real production config, and
  is-it-a-documented-decision — both told to default to refuted; 24 raw, 24
  unique, 26 verified, 8 confirmed collapsing to SIX distinct defects). No zone
  boundary weakened, no production fail-fast relaxed (M9 only ADDED pins), no
  credential reaching a service the graph forbids. The M6/M7/M8 pattern held a
  fourth time and is now the expectation, not a surprise: five of six sit in
  machinery M9 introduced, four falsify a claim M9 made about itself. Two are
  load-bearing. (1) ONE CREDENTIAL, TWO CAPABILITIES:
  `NOTIFICATIONS_INTERNAL_TOKEN` opened send AND recipient-upsert with holders
  identity+settlement+vault, though identity only upserts and the other two only
  send — so vault's copy could repoint any owner's address and silence
  SETTLEMENT's §5.1 death-case alerts, and settlement's could silence VAULT's
  §5.2 emergency alerts. Cross-domain, and docs/03 §6c claimed in the same
  milestone that this "requires identity-level compromise". Split into two edges
  / two guards / two DI tokens (send: settlement+vault; recipients: identity
  ALONE), config refuses equal values in production, and the credential-graph
  fence moved from "one credential per callee" to "one per EDGE with distinct
  guards per callee" — routes now attribute per guard CLASS, plus a new
  cross-check that every guarded route in the repo is declared exactly once.
  (2) ORDER WITHIN A TRANSITION IS A CONTROL: confirmVerification ran the
  IRREVERSIBLE `setState('settlement')` (no path back to active; revokes every
  session) BEFORE the fallible `setHold(true)`, so a documents blip rolled the
  case back to waiting_period while the account stayed terminally locked — and
  every restore path then 503s on an invalid transition, permanently entombing a
  LIVING owner with only "finish settling the estate" unblocked. Fixed by
  swapping two calls; the rule is now written down as THE STEP THAT CANNOT BE
  UNDONE RUNS LAST, which is why the ordering deliberately DIFFERS at the
  approve site (reversible identity state ⇒ lock first, or a failed hold strands
  a hold whose reject path never clears it). Also fixed: the legal hold
  attributed itself to the DECEDENT in `documents_versions` while its own audit
  event said `service` (evidence integrity in exactly the §5.1 investigation
  cases are kept for); the stack doctor's aliasing check never compared two
  CALLEES, so one secret reused across two of them passed while docs/04 and the
  compose file claimed a "full n² loop"; and templates' "an observer never
  learns WHICH control fired" was true of the SUBJECT only — the bodies name
  their control deliberately, so the claim was narrowed rather than the bodies
  gutted (an unactionable notification is not a control). RECORDED NOT FIXED,
  in docs/03 §6c: registration feeds an UNVERIFIED address into the delivery
  store (`users.email_verified_at` is dead schema — identity's word means the
  address was TYPED, not OWNED; a confirm-token flow is its own change), and
  `notification.recipient.updated` cannot ATTRIBUTE a change (null actor, and
  identity emits it on every login), so it is evidence for recovery, never a
  detection control — closing that needs the mesh's peer identity. The M6
  delivery-channel identifier-leakage item is ANSWERED as PARTIALLY CLOSED:
  identifiers are closed by construction, the EVENT CLASS reaching the carrier
  is an accepted residual, and fully closing it is the isolated-origin push
  channel. Full record in docs/04 M9 review.
- 2026-08-04 — M10 is the AI ESTATE ASSISTANT (docs/04's stated next milestone;
  both reasons M8 displaced it are gone — the platform deploys and can notify).
  Four PRs: PR1 the spine with no model call, PR2 the live Anthropic adapter +
  privacy proxy + stack wiring, PR3 the deterministic analysers, PR4 the thin
  UI. The load-bearing scoping decision is RETRIEVAL: **no embeddings, no vector
  store, no semantic index.** Feature 6 reads like RAG and mostly is not —
  funding recommendations, missing-document detection, beneficiary-conflict
  detection and estate-tax estimation are STRUCTURED-data problems over facts
  the platform already computes (`assets_view.in_trust`, `funding_status`,
  `ownership_pct`, the `designationComplete` flag `GET /v1/assets/:id/
  beneficiaries` already returns). The assistant reads them through read-only
  tool calls. M4's per-user HMAC index is not a poor substitute for embeddings
  here — it does a job embeddings cannot, LOCATING a document without
  decrypting anything. Document explanation splits: generated instruments are
  explained from the in-repo, sha256-pinned TEMPLATE (product content, not user
  data), and where the user's own rendered instrument is needed they point at
  ONE document, fetched through the existing audited content route on their own
  bearer. Uploaded-document OCR text has NO read path in M10 at all (M4's
  sealed artifact has `encryptOcr` and deliberately no counterpart). REJECTED:
  an embedding index — it is a plaintext-derived projection living outside the
  DEK envelope with no KMS chokepoint, it needs a SECOND third-party egress
  (Anthropic has no embeddings API) with its own retention profile, and
  OpenSearch is deferred so there is nowhere to host it. Accepted cost, stated
  rather than hidden: there is no semantic search — "the lake house" will not
  match unless "lake" is an indexed token.
- 2026-08-04 — The assistant holds ZERO internal service credentials, in either
  direction, and it is the first service of which that is true by design. It
  authenticates callers with CallerGuard on their own bearer and reaches
  assets/documents/profile by FORWARDING that same bearer (the M8 PR5 BFF
  pattern), so it can only ever see what the calling user could already see and
  a compromised assistant replays the sessions it is currently serving rather
  than minting new authority. This matters more here than anywhere: it is the
  one process an attacker can address in natural language. The claim is
  machine-checked, not asserted — `ai-assistant` is in `SERVICE_NAMES` but in no
  edge, and its `test/config.spec.ts` follows the AUDIT precedent of asserting
  the granted set is explicitly `[]` as well as equal to what it absorbs
  (without the second assertion the test passes vacuously if the graph ever
  loses the service). Consequence found while wiring: `ai-assistant` is the
  first service name containing a HYPHEN, and both `envVarPrefixFor` and the
  stack's generators built env-var prefixes with a bare `toUpperCase()`,
  minting the illegal `AI-ASSISTANT_DATABASE_URL`. Fixed with one
  `envPrefixFor` helper mapping `-`→`_`, routed through all eleven prefix sites;
  a no-op for the nine single-word services and verified as such.
- 2026-08-04 — Consent is DENY BY DEFAULT STRUCTURALLY: there is no `granted`
  boolean anywhere. `assistant_consents` follows profile's `permission_grants`
  (append + revoke, no soft delete, no `_versions` — the rows are the history),
  so consent is the PRESENCE of an unrevoked row and a user who never answered
  is indistinguishable from one who revoked. `permits()` additionally requires
  the `assistant.enabled` master switch alongside the specific scope, so
  revoking one row turns the assistant off without the user revoking five
  things. GRANTING is step-up gated (widening third-party egress is
  export-class, docs/01 §5); REVOKING is not — the M6 emergency-access-denial
  rule that the protective action must never be harder than the permissive one.
  The scope vocabulary is closed in BOTH a TypeScript union and a SQL CHECK, and
  a spec reads the migration file to pin them to each other rather than to a
  comment.
- 2026-08-04 — THE SUBJECT IS NEVER A TOOL PARAMETER. A tool is handed its
  authority (a verified session subject plus that caller's bearer) and declares
  only WHAT to fetch, never WHOSE data. Injected text can persuade the model to
  CALL a tool; it has no field in which to say whose estate it wants. Enforced
  at registry construction, so a violation is a process that will not start.
  The first implementation used an anchored regex and had a real hole —
  `ownerUserId` passed, because the subject word was neither at the start nor
  after an underscore — so it now splits identifiers into words across
  camelCase and snake_case and matches whole words; `account` is deliberately
  ALLOWED because in this product it names a financial resource rather than a
  person. This is layer 1 of three: (2) every tool is read-only with no send,
  write or fetch sink, so a successful injection has no egress; (3) framing
  retrieved text as data, which is ADVISORY and documented as the weakest of
  the three. Layers 1 and 2 cannot be argued with by a payload; layer 3 can.
- 2026-08-04 — `assistant.cedar` names its resource attribute `subject`, NOT
  `owner`, and the policy's own spec is what found the bug. `owner.cedar`
  permits a principal ANY action on a resource carrying `owner` equal to them,
  so the first draft — which claimed to grant exactly read/converse/delete —
  silently granted every verb in the product, including ones no milestone has
  written yet (an export or share added later would be INHERITED rather than
  step-up gated as docs/01 §5 requires). settlement.cedar avoids `owner` for the
  identical mechanical reason. The accompanying scope test also had to be
  rewritten: asserting against the shared bundle measured `owner.cedar`, so it
  now builds a PDP from `assistant.cedar` alone, with a positive control so a
  parse failure cannot masquerade as a pass. The PEP raises 404, never 403 — a
  403 on a conversation id confirms the conversation EXISTS, turning id guessing
  into an oracle for whether someone uses the assistant and how much.
- 2026-08-05 — M10 PR2 live adapter: `anthropic-gateway.ts` is the ONLY file
  that may import `@anthropic-ai/sdk` and `config.ts`/`app.module.ts` the only
  files that may name the API key, both enforced by a source scan
  (`test/sdk-fence.spec.ts`, the vault-crypto fence precedent) — anything that
  can import the SDK can construct a client, and anything that can construct a
  client can bypass the tokenizer, the egress assertion, the consent check and
  the audit trail in one line. The adapter is a TRANSLATOR, not a policy layer:
  it re-implements no upstream control and re-frames nothing. It owns two
  properties. FAIL CLOSED — a refusal, a rate limit, a dead connection, an
  unparseable response and a truncated turn all collapse to ONE fixed
  platform-authored sentence, because distinguishing them hands whoever composed
  the prompt (possibly via an uploaded PDF, docs/03 risk #6) a probe for which
  control fired; same reasoning as the PEP's uniform 404 and M9's one subject
  line. DO NOT LEAK — no provider error body, `stop_details.explanation` or
  request id is returned or logged, and the class holds no logger to be tempted
  by. Three specifics: `stop_reason` is read BEFORE `content` (a refusal is a
  200 whose content may be empty, so `content[0]`-first code breaks on exactly
  the responses that matter); `max_tokens`/`model_context_window_exceeded` are
  NON-ANSWERS, not answers, because a truncated estate reply reads as complete
  ("names three beneficiaries" without "…but it is unsigned"); and 401/403 is
  RETHROWN as a typed reason token rather than absorbed, since a polite apology
  on every turn would hide a wrong key forever (the M8 dead-audit-trail lesson).
  Also decided: model id is a pinned CONSTANT not config (which model sees
  estate content is a threat-model decision, so it changes by reviewed commit);
  the loop is NON-STREAMING because the port's single-step shape is what lets
  the egress gate see a complete payload before every call; the prompt-cache
  breakpoint sits on the system block alone, so the cached prefix is
  declarations + standing instruction — platform constants, no user id, no
  timestamp — and THE CACHED PREFIX CONTAINS NO ESTATE CONTENT; tool results
  travel as a quoted user turn rather than native `tool_result` blocks, because
  the port carries no `tool_use` ids and both alternatives are worse (per-
  instance state in a singleton serving concurrent users is a Zone B leak;
  synthesising ids means fabricating the assistant blocks that requested them,
  in the one product where the transcript is evidence); server-side refusal
  fallbacks default ON but are a CONFIG SWITCH because a refusal re-runs THE
  SAME ESTATE PAYLOAD ON A DIFFERENT MODEL, so zero-retention/no-training must
  hold for the fallback too. `LlmToolParameter` gained a scalar `type` DERIVED
  from the tool's zod field (`parameterTypeOf` throws rather than defaulting on
  an unmappable shape) — a typeless property makes the model guess and the
  executor refuse the guess as `invalid_input`, two layers from the cause.
- 2026-08-05 — The privacy proxy tokenizes BY DECLARED FIELD, never by regex
  over prose: a name detector without NER mangles estate vocabulary that is also
  names ("Will", "Trust", "Grant", "Rose"), misses what it was built for, and
  leaves everyone believing a control exists. Tool results are structured JSON
  with schemas this repo owns, so `TOOL_FIELD_RULES` names exact paths and has
  no false positives — and because coverage is then a LIST that goes stale,
  `assertTokenizerCoversTools` runs at registry construction and refuses a tool
  with no decision in EITHER direction (missing rules, or rules naming a tool
  that no longer exists), so a new retrieval arrives with a tokenization
  decision or the process does not start (the `assertSubjectFree` precedent); an
  empty rule list is a recorded decision. THE EGRESS INTERLOCK IS LOAD-BEARING:
  tokenizing an asset title of "dad's account 123-45-6789" to ⟦ASSET_1⟧ would
  let `assertEgressClean` pass and silently convert a fail-closed control into
  a green turn, so the tokenizer REFUSES to map a value that trips the egress
  detectors and returns it unchanged — the property holds whatever order the two
  run in, because the tokenizer cannot be the thing that handles an SSN and so
  cannot be the thing that hides one. The mapping is per-turn and in memory
  only, in `#private` fields rather than TypeScript `private` ones (which is
  erased at compile time, leaving the maps own enumerable properties that
  `Object.values` — or a structured logger — hands back in plaintext; caught by
  the module's own spec). The STORED TRANSCRIPT KEEPS REAL TEXT: tokenization is
  a property of the provider hop, not of the record, so history is tokenized
  outbound (a title typed in turn 1 keeps its placeholder in turn 5) and the
  reply is detokenized before it is persisted or returned, with an invented
  ⟦ASSET_9⟧ left as a harmless literal — no index arithmetic, no nearest match.
  Recorded gaps, not oversights: `get_document_text` is NOT tokenized (document
  prose has nothing to key on; accepted only because it is the user's own
  content, behind its own larger-disclosure consent scope, framed as untrusted —
  closing it needs NER over legal prose); most PERSON rules are DORMANT but kept,
  because the failure this codebase keeps finding is a client schema widened
  while the privacy layer, being elsewhere, silently does not follow; opaque
  UUIDs are not tokenized (tokenizing them would force an inbound detokenization
  path on tool arguments), residual being that a log-retaining provider could
  correlate one opaque id across conversations.
- 2026-08-05 — M10 PR2 stack wiring: the assistant is the tenth compose service
  (port 3009, fourth core co-tenant, eighth KEK alias, appended to the core
  migration chain) and the ONLY service block with no `*_INTERNAL_TOKEN` in
  either direction — asserted by scanning its mapped keys, not by trusting the
  mapping. Production OMITS the container on the Plaid pattern (generated
  profile name + `plannedServices` skip, so compose and host mode agree),
  because production pins `LLM_MODE=anthropic` and no Anthropic credential
  exists here. NOTHING MINTS AN `ANTHROPIC_API_KEY` at any layer, each refusing
  it differently: the generator writes none (a placeholder is a credential
  nobody can present — the M8 zero-holder-edge subtraction — and a real one
  would both put a third-party secret in a generated file and make a LOCAL stack
  able to ship retrieved estate content off the machine), `serviceProcessEnv`
  maps `LLM_MODE` alone, the supervisor scrubs `ANTHROPIC_*` from the ambient
  shell (without which a developer's own key reaches the largest
  prompt-injection surface in the product with no explicit mapping ever deciding
  it should), and the doctor warns on any `ANTHROPIC_*` in the generated file.
  The doctor deliberately does NOT flag `LLM_MODE=stub`: the stack can host KMS,
  S3, a scanner and OCR but cannot host a model provider, so the stub is the
  only possible dev value (PLAID_MODE's position), and a warning on every dev
  run is the permanently-red-pipeline mistake. Config completes PR1's
  NOTIFY_MODE timeline — production pins the real adapter by NAMING THE STUB so
  a third mode is not silently admitted, the key is required in EVERY
  environment whenever the mode selects it, and a spec pins that `ConfigError`
  never echoes it. `LLM_REQUEST_TIMEOUT_MS` bounds the turn's open transaction
  and row lock, and since the SDK retries twice by default the worst case is
  roughly deadline × attempts — sized against the transaction, not one hop.
  Stated rather than implied: no credentials exist, so the live adapter has
  never made a real call (its whole spec runs on a fake transport, the Plaid
  live-client precedent) — the first genuine provider call is a deployment
  event, not a test result.
- 2026-08-05 — M10 PR3 analyser doctrine: THE ANALYSER COMPUTES, THE MODEL
  EXPLAINS. Funding, missing-document, beneficiary-conflict and estate-tax
  findings are deterministic code over facts the platform already holds
  (`inTrust`, `fundingStatus`, `ownershipPct`, `designationComplete`, execution
  status, household structure), emitted as enum CODES with structured detail —
  never prose. Three consequences, each a reason: a number on an
  estate-readiness panel is arithmetic rather than a sampled token; two users
  with the same estate get the same findings, so the feature is testable; and an
  injected instruction in an uploaded deed cannot invent a finding, only
  describe a real one badly. Results carry `disclaimer` as a REQUIRED field
  (docs/01 §2.8's non-legal-advice watermark — one a caller may forget to render
  is not a warning), and `status` keeps three things apart that a single empty
  list would merge: `ok` with no findings ("nothing found" is a real answer),
  `unavailable` (an input read failed — never an empty estate), and `refused` (a
  control fired). Product judgements recorded with the code: funding analysis is
  conditional on a trust EXISTING and respects `na` as the owner's own decision;
  missing-document detection separates ABSENT from PRESENT-BUT-NOT-IN-FORCE
  because a generated unsigned will looks like a plan and directs nothing; the
  beneficiary analyser's headline finding is an in-trust asset that ALSO names
  beneficiaries directly (the designation passes it outside the instrument, and
  it is invisible in either place alone); estate tax reports a GROSS upper bound
  and names its exclusions, and in an inheritance-tax state reports that
  exposure exists rather than a rate, because the rate turns on a recipient
  relationship the platform deliberately does not hold.
- 2026-08-05 — Legal/tax REFERENCE DATA carries the M4 template gate: a
  `review: {reviewedBy, reviewedAt, source, effectiveYear}` block, and an
  analyser built on unreviewed data REFUSES in production
  (`reference_unreviewed`) while running everywhere else — an exemplar that
  never executes is one nobody tests. The estate-tax table states the law on the
  platform's authority, so it is gated; the missing-document matrix is NOT,
  because it conditions only on structure the platform can see and phrases every
  finding as a fact about the user's own account. The line: a rule that needs a
  statute to justify it (a state execution formality, a filing deadline,
  community-property characterization) belongs in reviewed data with the tax
  table, and M4's sha256-pinned `execution_requirements` is where the first one
  goes. Refusal is audited under its own reason token, distinct from a peer
  outage — the M9 rule that a control firing must not read as an outage.
- 2026-08-05 — The analysers ship on TWO surfaces over one core, with
  deliberately DIFFERENT consent gates. Tools require EVERY scope the analysis
  touches (`AssistantTool.scope` became `scopes`; `missingScopes` requires all,
  never any) because findings rendered into a prompt disclose every domain they
  drew on, and a partial run would answer "no conflicts" from data nobody agreed
  to share. The `GET /v1/analysis/*` routes require only `assistant.enabled`,
  because consent scopes gate EGRESS to a third-party provider and that path
  sends nothing anywhere: it fetches on the caller's own forwarded bearer,
  computes in-process, and returns the result to the same caller who could
  already read every input. Treating the scopes as a second authorization layer
  over the user's own data would protect nobody while teaching users to grant
  provider egress to see their own document checklist. Route surface: 403 (not
  the conversation surface's 404 — there is nothing to enumerate, every route is
  about the caller themselves), `unavailable`/`refused` become 503 rather than a
  200 carrying an empty answer, and the audit event carries a finding COUNT,
  never the findings. Supporting shapes: `assistant_tool_calls.scope` stores the
  sorted set joined with ':' (one TEXT column; SAFE_TOKEN_PATTERN admits ':' and
  rejects ',', and an array column would mean backfilling an append-only table
  whose UPDATE is revoked); denials name the missing scopes, which are
  closed-vocabulary constants, so a refusal is actionable; `assertScoped`
  refuses an empty scope set at boot, because "every declared scope is granted"
  is vacuously true over one.
- 2026-08-05 — `packages/money` extracted from the assets service (M10 PR3) when
  the analysers became the second consumer of exact BigInt decimal arithmetic —
  a second copy is the M8 PR2 shape where seven byte-identical audit producers
  shared one bug. Zero runtime dependencies. The extraction FIXED a latent sign
  bug it inherited: `moneyToCents('-12.34')` split on '.' and added the fraction
  unsigned, returning −1166n. Unreachable through `MoneySchema` (which forbids
  the sign) but reachable through a subtraction, which is exactly what an
  analyser does — so the function now validates its input and throws rather than
  answering confidently for input it cannot handle.
- 2026-08-05 — M10 PR4 (the thin UI) ships READINESS + CONSENT, not chat: the
  analysis routes work in both stack profiles today, while a conversation UI
  could only ever be demonstrated against the deterministic stub (production
  omits the assistant container for want of a provider credential). It also
  closes the zero-callers gap PR3 opened by design — the `GET /v1/analysis/*`
  routes existed for a UI that did not yet exist, which is the M4 legal-hold
  shape. The BFF gains its SECOND non-identity downstream on the assets-client
  terms (forwards the caller's own bearer, holds no credential), and because
  the assistant holds none either, the whole chain from browser to analyser
  runs on one session's authority. AN ANALYSIS CROSSES GRAPHQL AS A PAYLOAD
  WITH A STATUS, never as a thrown error: the page requests all four at once,
  so one 503 costs its own card instead of blanking the set — and there are
  FOUR statuses where the service has three, because `DISABLED` (the master
  consent switch is off) is the only one the user can act on and collapsing it
  into `UNAVAILABLE` would make the page lie about which happened. What never
  happens at any layer is a failure rendering as an empty finding list.
- 2026-08-05 — `apps/web/src/lib/findings.ts` is where an analyser CODE becomes
  a sentence, and on this surface the writer is reviewed code rather than a
  model — identical for every user, incapable of inventing a finding. Two rules
  keep it honest: every sentence is a fact about the user's own account and
  never a legal claim (the same line `reference/required-documents.ts` holds,
  and what lets the readiness surface ship while the estate-tax table cannot),
  and every number comes from the finding's `detail` through `formatMoney`, so
  money is never parsed. The map is TOTAL over the code union, so a new finding
  without wording is a compile error; an unknown code still renders a safe
  fallback, because a service deployed ahead of the app must not blank the page.
  The consent UI makes the M6 asymmetry visible: granting reveals an inline
  step-up prompt and retries the same grant, revoking is one click, and every
  mutation renders the SERVER's returned grant set rather than a local boolean
  (absence is denial, so an optimistic toggle could show a grant that was
  refused).
- 2026-08-05 — Driving the real browser found what jsdom could not, the M8 PR5
  lesson repeating: findings keyed on code + subject ref COLLIDED, because the
  commonest analysis in the product emits several `instrument_missing` findings
  with no subject row ("no guardian designation on file" and "no HIPAA
  authorization on file" are both that shape). React's remedy for a duplicate
  key is to drop or duplicate a child, so a real finding about someone's estate
  would have silently disappeared from the page — with every unit test green.
  Fixed by including the index, pinned by a test that renders exactly that pair.
  The same pass caught a layout inconsistency no assertion would have.
- 2026-08-05 — M10 security review (six parallel discovery lenses over the
  merged range `26a4813..51bc81e` + TWO adversarial verifiers per candidate on
  different angles — reachability in a real production config, and
  is-it-already-a-documented-decision — both defaulting to refuted; 11 raw, 11
  unique, 4 confirmed, 7 refuted). No zone boundary weakened, no production
  fail-fast relaxed, no credential reaching a service the graph forbids. The
  M6–M9 pattern held a FIFTH time: every confirmed finding sits in machinery M10
  introduced and three of four falsify a claim the milestone made about itself.
  TWO LENSES DISAGREED ABOUT ONE DEFECT and the disagreement was the useful
  part — one confirmed "the turn path consults no consent", the other refuted it
  because NOTHING CALLS THE TURN ROUTE (no chat UI, no BFF resolver). Both were
  right; reachability is "when chat ships", not "today". (1) HISTORY REACHED THE
  PROVIDER UNTOKENIZED on the first call of every turn: the placeholder map is
  filled only by the turn's own tool results, which arrive after the first
  `complete()`, so the history pass ran against an empty map — and because
  replies are stored detokenized BY DESIGN, turn 1 protected a title inside a
  structured result and turn 2 shipped it in prose; a turn calling no tool
  shipped the whole transcript raw. Every existing tokenizer test seeded an
  EMPTY conversation, so all of them passed while the documented cross-turn
  property was false. Fixed by re-deriving the map from the conversation's own
  recorded retrievals before the first provider call (same AAD, same rules, no
  second copy of the rule table); an unopenable row is skipped, because a
  crypto-shredded result must not lock a user out of their own conversation.
  (2) The `assistant.enabled` MASTER SWITCH DID NOT GATE THE TURN — the only
  consent read was per-tool, so a user with no consent row still drove a
  provider call with their text and the replayed transcript; the gate now sits
  in `takeTurn` AFTER the ownership check, so consent state cannot become an
  oracle about someone else's account. (3) "Designations look consistent" was
  shown to an estate where NOTHING carries a designation — affirmative
  reassurance from a check that examined nothing, on the one card a user acts on
  by doing nothing; split into `designations_consistent` and
  `no_designations_on_file` because they are two different facts. (4) docs/03
  §6d credited PR4 with a restricted-markdown rendering constraint THAT DOES NOT
  EXIST (the M4 zero-callers shape, in prose): the risk is now stated OPEN and
  the constraint named as a requirement owed by whoever ships chat.
- 2026-08-05 — Two non-vulnerabilities worth the same fix discipline, both from
  the M10 sweep. A test that "proved" ConfigError never echoes the provider key
  forced its failure by setting that key to '' — overwriting the sentinel it
  then asserted was absent, so the assertion was VACUOUS; it now triggers the
  error with a different missing variable and leaves a real key in the
  environment. And `analysis/beneficiary-conflicts.ts` used a LITERAL NUL BYTE
  as a composite-key separator, which makes git classify the file as BINARY —
  so that analyser shipped through PR #26 with no reviewable diff at all, only
  "binary file not shown". Keyed by nested maps now, so no separator exists to
  choose badly. The lesson generalizes: a control character in source silently
  disables human review of that file, and nothing in the pipeline complains.
- 2026-08-05 — M11 (the conversation surface) discharges docs/03 §6d's open
  rendering constraint IN THE SAME PR as the first model-authored pixel, which
  is what the M10 review said it owed. Model output renders as PLAIN TEXT, and
  the control is an ABSENCE rather than a filter: `MessageText` builds text
  nodes, with no parser to misconfigure, no allowlist to widen, no dependency,
  and no `dangerouslySetInnerHTML` anywhere in the app (a source scan enforces
  that, with `app/layout.tsx`'s theme script as the one DECLARED exemption —
  the credential-graph habit of stating exceptions as data). Markdown was
  declined for the third time on the same reasoning as the template renderer,
  the webhook verifier and the clamd client: a parser on an untrusted-input path
  is the thing we do not add. Both roles render through the one component,
  because a later edit giving the assistant's half a richer path is exactly how
  this regresses. Behind it a CSP (`img-src 'self' data:`, `connect-src 'self'`)
  refuses a remote image load even if the renderer regresses — and it says
  plainly that `script-src` is NOT locked down, since Next's inline bootstrap
  needs nonces; a stricter directive that gets relaxed under deploy pressure is
  worse than an honest partial one. Cost, stated where it lands: no lists, no
  emphasis, and whoever adds formatting inherits the requirement.
- 2026-08-05 — M11 BFF and UI decisions. The assistant's UNIFORM 404 stays
  uniform through the BFF (it is the anti-enumeration control — "no such
  conversation" and "someone else's" must stay indistinguishable), while
  `assistant_disabled` gets its own code because it is the one refusal a user
  can act on; the discriminator is the peer's TOKEN, not the status, so a future
  403 cannot inherit "turn the assistant on". A turn carries its own deadline
  ABOVE the assistant's per-provider-call bound: a BFF that gave up first would
  abandon a turn the service is still committing — row lock held — and report a
  failure for an answer that lands in the transcript unread. CONSENT IS A UI
  STATE, not an error path: with the master switch off the composer is replaced
  by an explanation and a link, because the turn route now refuses outright
  (M10 review) and a box that takes what you type and throws it away is worse.
  And running the real app found the third browser-only defect in three
  milestones: `gqlRequest` answers ok for any `data` object, so a version skew
  arrives as `{"data":{}}` and white-screened the page — the panel now reads a
  response missing its fields as NO DATA rather than as data, which is the peer
  clients' own rule applied in the browser.
- 2026-08-05 — M11 security review (three focused lenses over the merged range
  `dee0cff..557cef2` + two adversarial verifiers per candidate, both defaulting
  to refuted; 8 raw, 8 unique, 2 confirmed — the same defect found by two lenses
  — and 6 refuted). Sized to a single-PR range rather than repeating M10's
  six-lens sweep over code M11 did not touch. THE EDGE TIMEOUT WAS BACKWARDS AND
  ITS COMMENT SAID THE OPPOSITE: `TURN_TIMEOUT_MS = 150_000` claimed to sit
  above the assistant's deadline, but the SDK's `maxRetries` defaults to 2 with
  the timeout applied PER ATTEMPT (~180s for one call) and a turn makes up to
  six calls (~18 minutes). A verifier corrected the framing precisely — the
  literal sentence was true (150s > the 60s per-call bound); the RATIONALE both
  the code and CLAUDE.md restated was false. The harm was not slowness: nothing
  cancels the server side, so the turn COMMITTED while the user was told it
  failed — transcript sealed, audit emitted, payload already across TB5 — and
  the invited retry blocked on the row lock and re-sent a longer transcript to
  the provider, a second unauthorized egress and a duplicate of an exchange the
  user was told never happened. THE FIX IS A SHARED NUMBER, NOT A BETTER
  COMMENT: `packages/contracts/src/assistant-timing.ts` owns
  `ASSISTANT_TURN_BUDGET_MS`; the service enforces it as a WALL CLOCK across the
  loop (its own distinct message, so "too long" is not confused with the
  iteration cap), the SDK's retries are pinned rather than inherited, and the
  BFF waits `assistantTurnTimeoutMs()` derived from the same constant. Prose
  could not hold an invariant that spans two services; one constant plus a spec
  on each side can.
- 2026-08-05 — Two M11 findings were REFUTED as security findings and fixed
  anyway, because both contradicted a claim the milestone made about itself —
  the failure mode this codebase keeps rediscovering. `startConversation`
  dereferenced its response without the shape guard M11 said it applied
  everywhere (it held in two call sites out of three), and the CSP shipped
  `'unsafe-eval'` in every environment while its rationale justified only inline
  hydration. A directive nobody explained is how a relaxation outlives its
  reason, so it is development-only now (React Refresh needs it; a production
  build does not) and `csp.test.ts` pins the policy — including the sentence
  admitting what it does not do, because an honest partial CSP only stays honest
  while the honesty is written next to it.
- 2026-08-06 — M12 is THE DOCUMENTS SURFACE, in two PRs: PR1 read + generate,
  PR2 upload + search + the execution ladder + deletion. It closes the biggest
  remaining zero-callers gap in the repo — apps/services/documents has exposed
  eleven owner-facing routes since M4 with no consumer anywhere — and the
  incoherence M10/M11 created, where the readiness page says "your will has not
  been executed" and the product offers no way to act on it. The BFF gains its
  THIRD non-identity downstream on the assets/assistant terms (forwards the
  caller's own bearer, holds no credential), and still cannot reach documents'
  two service-credential-guarded internal routes.
- 2026-08-06 — The document viewer is CONTAINMENT, not absence, and that is the
  one place M12 knowingly departs from M11's renderer rule. `MessageText` can
  build text nodes because model output is prose; a will rendered that way is
  not a will. So `DocumentViewer` hands the stored bytes to a `srcdoc` iframe
  with `sandbox=""` — the EMPTY value, granting no scripts, no same-origin, no
  forms, no navigation — and three layers hold it: the sandbox, the page CSP
  (a srcdoc frame INHERITS it, so `img-src 'self' data:` applies inside the
  frame), and the Chromium-only `csp` attribute, explicitly named as defence in
  depth rather than as the control. The component still reads and parses
  nothing, and `dangerouslySetInnerHTML` remains absent app-wide. Because the
  sandbox VALUE is the security parameter, its spec asserts the exact string:
  `allow-scripts allow-same-origin` also contains "allow-scripts" and is the
  combination that undoes everything. A SECOND FENCE ships with it — a source
  scan asserting `DocumentViewer.tsx` is the only file in the app rendering an
  `<iframe>` — because the realistic regression is a second frame added
  elsewhere for a preview, not an edit to the viewer. Only `text/html` + utf8
  is framed (an upload can never be text/html; the component checks anyway).
  Proven in a real browser against a hostile document substituted into the
  content response: zero requests to the payload's host, the script probe never
  fired, nothing entered the parent DOM, `contentDocument` unreachable.
- 2026-08-06 — AUDITED-DECRYPT VOLUME IS A UI CONSTRAINT. Each content read
  emits `crypto.field.decrypted` + `document.content.viewed` and spends a KMS
  operation, so a list that previewed content would turn one page load into N
  events on the user's own trail — and blunt the per-principal decrypt-rate
  baseline docs/03 §4 TB4 calls the single most important insider control.
  Hence metadata-only lists, NO content field on the GraphQL `Document` type
  (so no query can ask for it incidentally), no prefetch, and no cache that
  would make a repeat read invisible. Asserted in the panel specs and proven
  live: two Read presses produced exactly two decrypt pairs; loading the list
  and the detail page produced none.
- 2026-08-06 — Intake crosses GraphQL as a TYPED input
  (`[DocumentVariableInput!]!`), not the `JSON` scalar the readiness surface
  uses — that scalar is an OUTPUT of data the service already validated, and
  putting an untyped shape on the one mutation reaching a legal instrument's
  renderer is the opposite trade. The BFF refuses a variable carrying neither
  value or both (a silently-chosen answer is the one thing that must never
  happen to a will) and refuses a DUPLICATE name rather than letting
  last-write-wins decide, which would let the value on screen differ from the
  value rendered. What a variable may CONTAIN is deliberately not re-checked
  there: that is the template's declaration to enforce, and a second copy of a
  legal gate is a copy that drifts. Three error mappings likewise stay
  separate because their remedies differ: `template_not_found` vs a missing
  document (both 404s, opposite facts), `content_erased` (permanent — never
  offer a retry against a key destroyed on purpose), and the two 409s. A plain
  403 is narrowed to the uniform not-found AT THE EDGE ONLY; the service's
  404-vs-403 oracle stays open as M4's review recorded it.
- 2026-08-06 — Driving the real app found a defect for the fourth milestone
  running, and this one was PRE-EXISTING: identity answers
  `invalid_credentials` for a rejected TOTP code exactly as for a rejected
  password, so every inline step-up prompt — the M10 consent controls, and M12's
  generator — told the user "that email and password combination didn't work"
  about a form with neither on it, implying a remedy that is not the problem
  while the real cause (codes last 30 seconds) went unsaid. Fixed with
  `stepUpMessageFor`, used by both surfaces; only that one code changes meaning
  with the surface. Every unit test passed over it because the copy table was
  correct in isolation — the defect lived in which entry a surface chose.
- 2026-08-06 — M12 PR2 makes ONE service change, and it is the only honest
  option: `GET /v1/documents/:id` gains `allowedTransitions`, computed by the
  document service's own `allowedTransitions()` over its own
  `requirementsFor()`. The ladder is parameterized by the template's
  `execution_requirements`, which live in the sha256-VERIFIED template source,
  so only that service can compute it — and a UI that hardcoded the ladder
  would be a second copy of docs/03 risk #8's per-state engine, drifting toward
  offering a will a no-witness path. It FAILS CLOSED AS AN EMPTY LIST rather
  than an error: `requirementsFor` refuses to guess for an unverifiable
  template and that refusal must not be softened, but failing the whole READ
  would make an intact document unopenable because of its template's state.
  The list is advisory anyway — `transitionStatus` re-resolves the requirements
  inside its own transaction. Deliberately NOT on the list DTO (a template load
  per document, and a list is not where anyone attests anything), and the
  transition's own response carries the NEW ladder so no client renders a stale
  one for a round trip.
- 2026-08-06 — The upload client is built NOT TO HAVE AN OPINION about file
  types. Magic-byte sniffing against the declared mime is the server's control
  against polyglot mislabeling; a client-side check is a second opinion that
  can disagree with the one that matters, refusing what the platform would
  accept or promising what it will not. So `accept` is a picker hint,
  `file.type` is forwarded as a DECLARATION, and the only local check is the
  size cap, which mirrors the server's own number rather than adding a rule.
  The three refusals stay apart to the last layer — all three mean "nothing was
  stored" (the pipeline is pre-storage and fail-closed) and three different
  things to the person holding the file; softening `malware_detected` into
  "unsupported file type" would withhold the one thing they need to know about
  a file somebody sent them.
- 2026-08-06 — Driving the real app found the fourth and fifth browser-only
  defects of the milestone. (1) documents' StepUpGuard sits at the CONTROLLER
  and the legal-hold check inside the handler, so a stale session is answered
  `stepup_required` FIRST and `legal_hold` only after — the page walked someone
  through finding their authenticator to be told, correctly, that the document
  could not be deleted anyway. The server ordering is kept (moving the hold
  check ahead of the guard would put a read of estate state before the gate);
  the UI stopped OFFERING deletion for a held document, on the same rule the
  revise link follows: never offer what the server would refuse. (2) The detail
  panel dereferenced `allowedTransitions` before checking it, so a BFF
  predating the field white-screened the page — the M11 shape a third time. It
  now reads a missing ladder as NO DATA rather than as an empty one, because
  an empty ladder is a REAL answer (fail-closed) and a version skew must not be
  indistinguishable from it.
- 2026-08-06 — M12 security review (five discovery lenses over `f06a157..HEAD`
  + TWO adversarial verifiers per candidate on different angles, both
  defaulting to refuted; 17 raw, 10 verified under the fan-out cap with the 7
  dropped LOGGED BY NAME, 4 confirmed — and the capped 7 were each verified by
  hand and fixed too). No zone boundary weakened, no production fail-fast
  relaxed, no credential reaching a service the graph forbids. Sixth milestone
  running where every finding sits in machinery the milestone introduced, and
  four falsify a claim it made about itself.
- 2026-08-06 — FAILING CLOSED IS NOT "REFUSE EVERYTHING": the line is ADVANCE
  vs DE-ESCALATE. M12 PR2's unverifiable-template fallback withdrew the whole
  transition set, but `allowedTransitions` computes `revoked` and `superseded`
  without ever reading the requirements — so a soft-deleted or integrity-failed
  template permanently stripped the owner's only way out of an attested status,
  in the read AND the write, with regeneration already barred past `generated`.
  That inverts the M6 rule that the protective action must never be harder than
  the permissive one. `deEscalationTransitions` is the fallback now, and
  `signed` stays withheld even though it is technically requirement-independent:
  advancing asserts something about the world on a template nobody can vouch
  for, which is what the M4 review closed. Asserted as a strict subset of the
  real ladder under every profile, not argued for in a comment.
- 2026-08-06 — A TAMPER DETECTOR THAT PRODUCES NOTHING IS NOT A CONTROL. The
  same bare `catch` swallowed `TemplateIntegrityError` — the signal
  `body_sha256` exists to raise (docs/03 TB4) — identically to a transient DB
  error, on read paths that answer 200 and log nothing by design. New audit
  action `document.template.integrity_failed`, emitted where the failure is
  CAUGHT because that is the only place it exists. And the TEMPLATE CATALOG now
  serves `TemplateEngine.load`'s sha256-verified parse rather than the
  `templates.variables` / `execution_requirements` COLUMNS: two lenses
  independently found that the generator's docstring claimed the questionnaire
  was "content-pinned by sha256" while the route read the row, so a tampered
  column could put different questions and a different statement of what a will
  requires in front of an owner. M4 made the verified source authoritative for
  the formalities GATE; the DISPLAY had been left behind. A template that fails
  verification is omitted from the catalog, never degraded.
- 2026-08-06 — The search term moved OFF THE URL. `GET
  /v1/documents/search?q=` was M4's shape and M12 was its first caller, so M12
  is what made the exposure real: the term is by construction a word out of the
  user's estate, and a query string is the one part of a request intermediaries
  log by default (CloudFront + WAF, docs/01 §2). Now a POST with the term in
  the body; nothing else about the design changes, since the term is still
  reduced to per-user HMAC tokens and no decrypt serves a search. Also from the
  review: uploaded binaries finally get the presentation PR1 promised and PR2
  forgot (images inline from a `data:` URI whose mime is checked against a
  closed set; PDFs and TIFFs download, because a framed PDF is the browser's
  PDF parser on attacker bytes inside our frame tree; filenames from ids, never
  from the user-authored title) — without which `Read` was spending an audited
  decrypt to display nothing.
- 2026-08-06 — `TemplateEngine`'s cache EXPIRES, and the reason is detection
  rather than correctness. The key `(row id, sha)` COMMITS TO THE CONTENT — an
  entry can only be a parse whose bytes hashed to the sha in its own key, and a
  published version is immutable — so a warm cache never could serve a tampered
  parse; swap the object-store body and a warm process kept serving the
  legitimate one. What it cost was that the process STOPPED LOOKING, so a swap
  went unremarked for the process's lifetime. That was tolerable while nothing
  acted on the signal and stopped being so the moment M12 gave the check an
  audit event: an alarm wired to a check that only runs on cold starts is an
  alarm that mostly does not run. `TEMPLATE_CACHE_TTL_MS` (5 min) is a reviewed
  CONSTANT, not config, because it is a detection-latency parameter — the
  longest a swapped body can sit in front of a replica unreported;
  `TEMPLATE_CACHE_MAX_ENTRIES` bounds a key space that grows with every
  republication (a new version is a new ROW) for the life of the process.
  Consequence is MORE fail-closed: past the TTL a tampered body makes `load`
  throw where it used to serve the cached parse, and all three callers were
  already built for that throw (generation refuses, the ladder degrades to
  de-escalation and audits, the catalog omits the template). Accepted residual,
  stated rather than implied: within one TTL a warm process neither serves nor
  notices a swap, and closing that means verifying on every load — N
  object-store reads per catalog request on a user-facing route — for a
  detector whose job is to raise an alarm, not to gate each read.

- 2026-08-06 — M13 is THE PEOPLE SURFACE, in three PRs: PR1 hardens the shipped
  profile service (no new surface), PR2 is the UI, PR3 is the contact-link
  ceremony alone. It closes the LARGEST remaining zero-callers gap in the repo —
  apps/services/profile has exposed fifteen owner-facing routes across three
  controllers since M2 with no consumer anywhere — and the M12-shaped
  incoherence where the readiness page emits `state_of_residence_unknown` and
  `minor_status_unknown` at a user who has no way to tell us, while M12's
  generator asks for a state by hand *because* the BFF has no profile
  downstream. ORDER IS THE POINT: three defects were verified in shipped code
  before any UI was designed, and reading for more found three additional ones,
  two of the same destroy-what-you-were-not-given shape.
- 2026-08-06 — M13 PR1, the two load-bearing fixes. (1) NO STEP-UP EXISTED
  ANYWHERE IN PROFILE: `POST /v1/role-assignments` granted trustee/executor/
  beneficiary under CallerGuard alone, though docs/01 §5 names exactly those
  changes and assets' sibling route already complied — M2 predates
  @estate/auth-guard and nothing revisited it. The gate now covers grant,
  revoke AND permission-attach, uniform across all twelve roles rather than a
  "which role is sensitive" table that drifts (`agent_financial` is a power of
  attorney; `viewer` still reads an estate), and gating REVOKE is not an M6
  violation because the rule forbids the protective action being HARDER, not
  equal — revoking here destroys the executor-resolution path (M7) and can
  strip the last linked contact able to report a death, so a stolen bearer that
  revokes is running an isolation attack. Withdrawing a PERMISSION GRANT is
  ungated, and that asymmetry IS the M6 rule. (2) EDITING A CONTACT CLEARED ITS
  PLATFORM LINK: one `encryptRow` hardcoded `linked_user_id: null` and fed both
  the insert and the update, whose SQL wrote the column — so changing a phone
  number revoked a docs/03 §6b control (the linked-contact gate is the whole
  reason intake "cannot enumerate and cannot trigger") with no audit event and
  no owner decision. Fixed BY TYPE, not by review note: `ContactFields`, the
  shape both statements are built from, has no such key, so the ordinary write
  path has no field in which to say anything about the link — PR3's ceremony
  gets its own statement.
- 2026-08-06 — Reading the shipped service for more defects found THREE, two
  being the same shape as the link bug — a write path destroying data it was
  never handed. (1) `PUT /v1/profile` SILENTLY DESTROYED THE SSN on any edit:
  the upsert was a full replace, `ssn` was optional, and `GET /v1/profile`
  returns `ssnLast4` and never `ssn`, so NO CLIENT COULD ROUND-TRIP THE ROW —
  read it, change a field, PUT it back, and `ssn_ct` + `ssn_last4_ct` went NULL.
  dob/address/phone/occupation share the semantics but are returned, so they
  survive; the SSN structurally cannot. Absent now means unchanged, explicit
  `null` means clear, and THE CARRY MOVES CIPHERTEXT: decrypting untouched
  fields to re-encrypt them would put the full SSN through the process on every
  unrelated edit and emit a `crypto.field.decrypted` on `profile.ssn` each time,
  turning a change of address into a logged read of the most sensitive value we
  hold. Sound only while carried and new bytes share one key (one `dek_id`
  column + the partial unique index), so a row under a RETIRED DEK is refused
  `409 profile_key_retired` rather than stamped with a live key id — the M4 rule
  that a shredded record is Gone, not a fresh live key. Contacts and family
  KEEP replace semantics: their reads return every field they store, so they can
  be round-tripped, and the profile is the one row with a field it will never
  hand back. (2) DELETING A CONTACT SILENTLY RETIRED ITS DESIGNATIONS: every
  role-holder query joins `contacts ... AND c.deleted_at IS NULL` (profile's
  grant resolution, settlement's isLinkedContact/isExecutorOf/reportableEstates)
  while `role_assignments` rows were untouched, so one delete un-resolved an
  executor on the §5.1 chain and disabled every grant, with the assignment still
  listed and no `role.revoked` anywhere — now `409 contact_in_use`. (3) Recorded
  rather than fixed: contact/family reads decrypt every field and FieldCipher
  emits one audit event per field, so a 20-contact list is ~100 events on the
  owner's own trail — the TB4 decrypt-rate baseline, and PR2's design
  constraint.
- 2026-08-06 — A MUTATION EXPOSED A VACUOUS TEST, and the lesson generalizes:
  the service-level unit test for the contact-link fix PASSED with
  `linked_user_id = NULL` put back into the repo's UPDATE, because it fakes the
  repo and a fake repo cannot see SQL — the defect lived in a statement no unit
  test observes. The assertion moved to the Postgres-backed int spec, where
  reintroducing the column turns two tests red. All six PR1 fixes were then
  mutated against a real database and each confirmed to fail. Corollary for this
  repo: a fix whose defect lived in SQL must be pinned by a test that runs SQL,
  and "the unit test is green" is not evidence about a repo layer.
- 2026-08-06 — Adding the step-up gate BROKE THE SETTLEMENT E2E, which is the
  gate working. `seedEstate` named an executor and a viewer on the owner's
  ordinary session; rather than weaken the seed to raw SQL, it seeds through a
  SECOND step-up-elevated session — step-up freshness is a property of a SESSION
  (identity's `grantStepUp` takes a `sessionId`), so the owner's primary session
  stays un-elevated and the owner-void test still observes `stepup_required` on
  it, while the seeding step-up stays strictly OLDER than any case reported
  afterwards and so cannot trip the M7 owner-liveness interlock. TOTP enrollment
  is cached per user because `enrollTotp` only revokes UNVERIFIED methods, so
  enrolling twice would leave two verified secrets and make `findActiveTotp`'s
  choice decide whether a later step-up works.
- 2026-08-06 — M13 PR2 (the people surface): the BFF's FOURTH non-identity
  downstream on the established terms, and /people stops being a "Soon" preview.
  THE DECRYPT BUDGET IS THE DESIGN: contact PII is under the owner's DEK and
  every field read is one audited `crypto.field.decrypted`, so the list route was
  NARROWED to a summary — one decrypt per row (the name) plus two plaintext
  columns, with `has*` flags from column nullity so a row says WHAT is on file
  without reading it, and NO email/phone/address/notes field on the GraphQL
  summary type so no query can ask incidentally. Narrowing the SHARED route also
  tightens §5.5 for a grant-holder (details now cost them one audited read each),
  which is why there is ONE projection rather than two branched by audience.
  Verified against the live stack's audit chain: `contact_list` decrypted only
  `contact.name` across five page loads. THE SSN IS DISPLAYED AND NEVER
  COLLECTED — no `ssn` argument on the mutation, no field in the BFF client, no
  input in the app, only read-only `ssnLast4` so an owner can see whether we hold
  one; with PR1's merge semantics a real browser edit (CA→AZ) left ssn_ct,
  ssn_last4_ct and dob_ct intact AND `profile.ssn` never appeared in the decrypt
  trail, because the carry moves ciphertext. A DESIGNATION IS NOT ACCESS is said
  out loud per condition, and `linked` is THREE-VALUED (a failed read passes
  null, never false — "no account yet" is a claim about someone's estate).
  Three-way step-up asymmetry: name a role → prompt + retry; REMOVE a role →
  prompt too (equal, never harder); withdraw a permission → one click.
  `StepUpPrompt` extracted at its third caller; the two earlier callers stay as
  they are and the reason is recorded in the component (DocumentGenerator's
  prompt is INSIDE a form and this renders one, and an "actually a div" mode
  would put the branch back inside the shared thing).
- 2026-08-06 — M13 PR3, THE CONTACT LINK CEREMONY. `contacts.linked_user_id` had
  no write path anywhere: four test files set it in raw SQL and said so, which is
  why §6b's linked-contact gate was a real control guarding an unreachable
  capability. Owner mints a 160-bit single-use code under STEP-UP; the server
  stores only sha256(code); the owner is shown it ONCE and delivers it OUT OF
  BAND (the M6 grantee-fingerprint precedent); the contact redeems it while
  authenticated on THEIR OWN existing account. The shape is forced, not chosen:
  M9's notification doctrine has no content field and forbids links, so an
  emailed invite would contradict a decision one milestone old; §6b's
  anti-enumeration property survives only if the CODE IS THE ONLY SELECTOR, so
  the redeem route takes no owner id and no contact id and there is nowhere in it
  to name an account; and requiring an existing account keeps this from becoming
  an invite-to-register flow. EVERY REDEMPTION FAILURE IS ONE ANSWER
  (`invalid_code`) — unknown, expired, spent, revoked, self-directed, raced —
  because distinguishing them tells whoever holds a guess that it named something
  real; the cost is a vaguer message for an honest user, paid down by free
  re-issue (which retires the previous code and audits the retirement).
  ASYMMETRIC IN BOTH DIRECTIONS: minting is step-up gated (it hands out a
  capability on the §5.1 chain), while withdrawing a code and removing a live
  link are CallerGuard only (M6 — the protective action must never be harder).
  Self-redemption is refused because linking yourself to your own contact would
  make you eligible to report your own death.
- 2026-08-06 — Two pieces of M13 PR3 machinery worth their own entries. (1)
  ATOMICITY IS THE CONTROL: spending the invitation and writing the link share
  ONE transaction, each statement restating its own preconditions, because a
  spend with no link locks that contact out of ever being linked and a link from
  a still-live invitation is replayable. A data-modifying CTE cannot express
  that — its UPDATE commits even when the outer statement matches nothing — so
  profile adopted the assets service's `withTransaction` chokepoint, and the
  version-capture trigger records the REDEEMER as actor, which is what the trail
  should say. Two concurrent redemptions produce exactly one link and the loser
  rolls back (the M7 owner-liveness CAS shape). (2) REDEMPTION TAKES NO CEDAR
  DECISION, and it is flagged in docs/03 §6g rather than disguised: every other
  route in the service passes a PEP, but the redeemer has no relationship to the
  estate until redemption succeeds, so every attribute a policy could match on is
  exactly what the code stands in for — the authority is a bearer capability.
  Also: profile becomes the THIRD holder of the notifications SEND credential and
  deliberately NOT of the RECIPIENTS one (the M9 review's split applied to a new
  holder — profile has no business repointing where anyone's alerts go), and
  redemption REFUSES in production behind a stub notifier, because a claim the
  owner never hears about is how a mis-delivered code becomes an invisible
  authorization edge.
- 2026-08-06 — M13 security review (five discovery lenses over the three-PR range
  + TWO adversarial verifiers per candidate on different angles, both defaulting
  to refuted; 21 raw, 21 unique, 6 confirmed, 10 refuted, 7 dropped under the
  cap and hand-verified). The first fan-out LOST FOUR LENSES to stalled agents —
  a whole-range `git diff` is 9.5k lines and the agents hung on it — so they were
  re-run with FILE-SCOPED prompts; the loss is recorded in docs/04 rather than
  papered over, and the lesson is that a review prompt must name files, not
  ranges. SEVENTH milestone running where every confirmed finding sits in
  machinery the milestone introduced, and most falsify a claim it made about
  itself. Two were load-bearing. (1) THE STEP-UP RETRY RAN THE WRONG ACTION: a
  refused permission widen folded into the role-grant variant, so after a genuine
  TOTP challenge the app called `grantRole()` from the picker's current state —
  minting an `executor`/`on_death_verified` designation the owner never chose onto
  the §5.1 executor-resolution chain, audited as theirs, while silently dropping
  the permission they clicked. THREE claims said otherwise (the in-code "Elevate,
  then retry", StepUpPrompt's "re-run the action that was refused", the M13 PR2
  log entry) and the one existing test asserted only that the prompt OPENED, so
  the suite was green over it. Fixed with a discriminated union that CARRIES every
  argument the retry needs, plus per-action wording — the consent ceremony was
  also mis-stating what it authorized. (2) THE OWNER NOTIFICATION OF A CLAIMED
  LINK COULD VANISH: the audit emit ran before the notify and propagates broker
  failures by design (M8), so a blip after the commit left the link standing, the
  owner untold, and no retry able to tell them; and the notify's empty catch
  cited "the claim event above" when that event carried no delivery fact, while
  notifications.ts claimed "the caller records the failure" and no caller did.
  Fixed: notify FIRST (an audit hiccup must not cancel the control that makes the
  ceremony's out-of-band trust anchor auditable by the owner), and the outcome
  rides the claim event as `ownerNotified: delivered|failed` — the vault
  delivered_at-NULL precedent.
- 2026-08-06 — Also from the M13 review, three fixes whose shape generalizes.
  (1) PROMPT-AND-RETRY WAS A CLAIM THE PLATFORM COULD NOT KEEP: every service
  builds `HttpSessionVerifier` with the 30s default positive cache, so after a
  genuine elevation the peer still answers from the cached un-elevated session and
  a single-shot retry leaves the prompt doing nothing — exactly what happened the
  first time this surface was driven in a browser. The TTL is a recorded
  trade-off (2026-07-23); what M13 got wrong was promising a retry that always
  works. Made true rather than narrowed: `onElevated` now reports
  `applied | stale` and the prompt POLLS to a documented deadline, the contract
  the stack e2e already treats as a contract rather than a flake. The window is
  pinned to auth-guard's own constant by a spec that READS that file — the
  compose-parity mechanism, because the web app cannot import a Nest package and
  a duplicated number drifts. (2) `contact_in_use` WAS CHECK-THEN-ACT: a
  `grantRole` committing between the service's check and the soft delete would
  delete a contact that had just acquired a designation — the fail-open §6f
  declares Closed. The predicate moved into the UPDATE's own WHERE with a
  discriminated outcome, and the now-callerless helper was deleted rather than
  left as dead code. (3) `grantRole` accepted ANY contact id (the FK proves
  existence, not ownership): refuted as an escalation because every resolver
  scopes by owner, fixed anyway because a cross-owner designation resurrects the
  silent-retirement shape PR1 closed — the other owner's `contact_in_use` check is
  owner-scoped and would never see it.
- 2026-08-06 — `role_assignments` HAD NO UNIQUENESS OF ANY KIND — hardening, and
  the entry is worth keeping mostly for how it was nearly mis-recorded. Nothing in
  the schema, the repo or the service stopped a double-submit or a retry from
  minting two identical live designations, and revoking "the" designation would
  leave the duplicate conferring everything it conferred before; on the docs/03
  §5.1 executor chain "revoked" has to mean revoked. Closed with a partial unique
  index over (owner, contact, role, scope_type, COALESCE(scope_id, nil-uuid),
  effective_condition) WHERE deleted_at IS NULL — the COALESCE because SQL
  uniqueness treats NULLs as distinct and `scope_id IS NULL` (the whole estate) is
  the commonest case, so without it the constraint would permit unlimited
  duplicates of exactly the broadest designation — plus a `409
  role_already_granted` so a double click is an ordinary refusal rather than a 500
  or a silent second write.
  CORRECTED IN THE SAME SESSION: this was first written up as a defect the live
  stack had EXHIBITED ("two clicks minted two identical designations"). It had
  not. Two `executor`/`on_death_verified` rows were read as a duplicate pair off a
  two-line `SELECT role, effective_condition` listing — while a
  `GROUP BY owner_user_id, contact_id, role` run minutes earlier had already
  returned nothing, which was the right answer; the rows belonged to two different
  owners and two different contacts. The migration's own pre-flight then settled
  it independently: run against that database it APPLIED instead of refusing,
  which is only possible with no duplicate group present. THE LESSON IS THE
  GENERAL ONE THIS REPO KEEPS RESTATING, turned on myself: a listing that LOOKS
  like duplicates is not a grouping query, and a doc that claims evidence it does
  not have is a defect even when the fix it justifies is sound.
- 2026-08-06 — The link code's ALPHABET WAS HALF-IMPLEMENTED, and the fix is worth
  the entry because the reasoning recurs: the mint avoids I, L, O and U so a code
  can be read down a phone line, but redemption hashed the RAW submission — so
  lowercase, dropped grouping dashes, or a typed O-for-zero all failed with the
  uniform `invalid_code` and the owner's only remedy was minting a fresh code. A
  security property (uniform refusals) was hiding a usability defect the design
  had already promised to handle. `canonicalCode` folds onto the minted alphabet
  before hashing on BOTH sides; because the fold only maps characters the
  generator never emits, it cannot make two mintable codes collide, and
  case-folding costs no entropy since the mint is uppercase-only.
- 2026-08-06 — MIGRATIONS ARE APPEND-ONLY, and the enforcement is real rather
  than conventional. The M13 duplicate-designation index was first appended to
  `003_contact_link_invitations.sql`, a file the migrator had already recorded.
  CORRECTED as to why that is wrong: `packages/db/src/migrator.ts` records a
  sha256 CHECKSUM alongside every applied name and raises `MigrationDriftError`
  on a mismatch, so appending to 003 fails LOUDLY on the next run — even editing
  a comment in an applied file blocks the next migration until it is restored.
  The original claim here ("keys on FILENAME, so the edit silently never runs")
  was drawn from a container still running the pre-edit 003, the second time in
  that session a stale image was mistaken for evidence about the code. The
  conclusion survives; the mechanism is stricter than the doc credited. It is
  `004_role_assignments_unique.sql` now, with a pre-flight that RAISES over
  pre-existing duplicates and retires NOTHING — the `002_dek_unique_active` rule
  restated for a new case, because duplicates are identical as DESIGNATIONS but
  not as ROWS: `permission_grants.role_assignment_id` references the row, so
  retiring the spare would silently revoke every grant hanging off it, and a
  migration must never choose which access dies. The runbook is in the file:
  consolidate the grants, revoke the other assignment through the API (which
  audits it), re-run. `role-unique-migration.int.spec.ts` pins both properties,
  and one case exists purely to catch the appended-to-003 mistake — it asserts
  the file appears in `applied` AND that the index actually exists, which is the
  pair of facts an edited-in-place migration separates.
- 2026-08-06 — STALE ARTIFACTS ARE NOT EVIDENCE ABOUT SOURCE. Twice in the M13
  session a conclusion about the code was drawn from something built earlier: a
  stale `@estate/contracts` `dist` produced nine phantom test failures, and a
  container still running a pre-edit migration produced a false claim about how
  the migrator behaves (recorded above). Both times the artifact was the bug.
  The rule: before believing an observation that contradicts the source, rebuild
  or recreate the thing that produced it — `pnpm build --filter=…` for a package
  under test, `stack:reset` for the compose stack (never `stack:down`, per the
  2026-07-30 LocalStack entry).
- 2026-08-06 — A TEST OF MINE WAS NAMED FOR A PROPERTY IT NEVER TOUCHED, and
  only mutation testing found it. The case "the COALESCE matters" seeded two
  whole-estate duplicates and asserted the migration refused — which passes with
  or without the COALESCE, because the pre-flight's `GROUP BY` treats NULLs as
  equal while a `UNIQUE INDEX` does not. Two mechanisms, one test, wrong one
  exercised. Rewritten to migrate a CLEAN database and then ask Postgres to
  accept the duplicate, which is the only path through the index's own
  predicate. The general rule this repo keeps relearning: when a guard exists at
  two layers, a test must say WHICH layer it is proving, and mutating that layer
  alone is how you find out whether it does.
- 2026-08-06 — M13 review ROUND 3 ran over round 2's OWN FIXES, on the repo's
  five-for-five expectation that new trust machinery is defective — and found
  TWO HIGH defects, both in code written to close a finding. (1) CANCEL DID NOT
  CANCEL: round 2 made the step-up prompt POLL (peers learn of an elevation
  through a 30s positive session cache, so a single-shot retry left the prompt
  idle after an accepted code), but the loop had no abort and `Cancel` only asked
  the parent to hide it — so for up to the whole propagation budget after the
  owner declined, the loop kept retrying and could still APPLY the action.
  Measured, not theorised: a third `GrantRole` landed after Cancel and put an
  `executor`/`on_death_verified` designation on the §5.1 executor-resolution
  chain with no UI signal, because React 19 makes the post-unmount `setState` a
  silent no-op. A step-up prompt is a CONSENT ceremony; proceeding after consent
  is withdrawn is the one thing it must never do. Fixed with an `abandoned` ref
  set by Cancel AND by unmount, checked in the loop condition, after the sleep,
  and around the identity round trip, re-armed on a fresh submit. (2) THE
  DELETE/GRANT RACE WAS STILL A RACE: round 2's single `UPDATE … WHERE NOT
  EXISTS (…role_assignments)` reads atomically but locks the CONTACTS row, not
  the assignments it consulted, and `grantRole` was itself check-then-act — so
  two statements could delete a contact and name it to a role, defeating the
  in-use refusal PR1 added. The contact row is the serialization point for both
  paths now (`softDelete` takes `FOR UPDATE`; `RolesRepo.insertForLockedContact`
  takes the same lock and the unlocked `insert` is deleted so nothing can skip
  it), proven by a 5-iteration concurrent race test that fails 3/3 runs without
  the lock. Round 3's smaller items: `permission_grants` had no uniqueness and
  `grantPermission` was the one retried action with no in-flight guard (two
  clicks wrote two grants, and withdrawing the visible one left the other
  conferring the read) — closed by migration `005` plus a `busy` guard; neither
  new 409 had a BFF mapping, so the "ordinary refusal" the migrations promised
  surfaced as a masked server error; `FakeContactsRepo.softDelete` dropped its
  `ownerUserId`, leaving the delete path's ONLY access control unmodelled (the
  PEP models the resource owner as the caller there, so the repo predicate is
  the whole check — and it must answer a uniform not-found, never a 403 that
  would confirm the id names something); `RedeemLinkSchema`'s `min(8)` measured
  the RAW submission, so separators alone satisfied it and folded to empty —
  redemption measures the CANONICAL form against a length DERIVED from the mint
  now, refusing before any lookup and with the same uniform `invalid_code`; and
  `004`'s `RAISE` carried two bugs reachable only by making the branch fire
  (plpgsql's placeholder is a bare `%`, so `%s%s` wedged stray "s" characters
  into the duplicate list, and the first correction to `%%` — zero placeholders
  — turned the branch into a hard error). AN EXCEPTION NOBODY TRIGGERS IN A
  TEST IS AN EXCEPTION NOBODY HAS READ.
- 2026-08-06 — A COMMENT ASSERTING AN ABSENCE OUTLIVED THE ABSENCE, and the
  shipped web image lost the vendored typeface for several milestones.
  `web.Dockerfile` copied `.next/standalone` + `.next/static` and stated "There
  is no `public/` directory in this app" — true when M5 wrote it, false the
  moment the Evergreen-rail redesign vendored Instrument Sans into
  `apps/web/public/fonts`. `output: 'standalone'` excludes `public/` from the
  traced bundle exactly as it excludes `.next/static`, so the omission was not a
  build error but a RUNTIME 404: measured against the live stack, the face
  status was `error` with 0 bytes transferred and every page fell back to a
  system font — defeating the whole reason the font is vendored (2026-07-30: no
  build or page load may depend on a third-party fetch). Invisible to every gate
  because the image's only frontend check was LIVENESS, and a missing asset
  still boots, still renders, still answers 200 at `/`. Fixed with the COPY;
  `images.yml` now asserts each file under `apps/web/public` returns 200 from
  the built image, DERIVED FROM THE REPO TREE rather than hardcoded so the next
  asset is covered without anyone remembering — and so a `.dockerignore` rule
  that starts excluding something under `public/` turns red instead of shipping
  quietly. Mutation-tested both ways (exit 1 against the shipped image, 0 with
  the COPY). Service images are NOT exposed to this class: `node-service.
  Dockerfile` ships `pnpm deploy --prod`'s whole package tree, so `.cedar`
  policies and the template JSON travel without an explicit copy — verified
  present in the running documents image. The general rule: a comment that
  justifies an omission by asserting a fact about the tree is a test nobody
  runs, and the fix is to make the tree the input.
- 2026-08-07 — A DIAGNOSTICS STEP MUST DERIVE ITS CONTAINER SET, which is the
  THIRD instance of one drift class and the reason it is now written down. CI
  went red on main with `service "migrate-documents" didn't complete
  successfully: exit 1` and nothing else — although `images.yml` HAD an
  `if: failure()` Diagnostics step, and it ran. That step named nine
  long-running services by hand, `migrate-documents` was not among them, and
  neither was any other one-shot job: it printed sixty lines each from healthy
  containers, an EMPTY block for `documents` (whose `depends_on` chain runs
  through the job that died, so it never started and never logged), and nothing
  from the container holding the answer. The whole root cause then had to be
  chased off-box against a scratch database. Same shape as stack.yml's
  hand-copied migrate list (M9) and web.Dockerfile's asserted-absent `public/`
  (2026-08-06): a list maintained by memory beside a thing that grows. Fixed by
  deriving from the project — `compose ps -a --status exited --services`, each
  exited container framed and UNTRUNCATED (a migrator's entire output is one
  `err.message` with no stack, so it is the one place a `--tail` removes the
  answer), then a bounded whole-project dump for ordering context. Four
  properties were measured rather than assumed: `logs` does cover EXITED
  containers, but only because `Stop` (`down -v`) runs after Diagnostics — the
  two steps must not be reordered; the `--profile` flags are REQUIRED for the
  bare service-less form (without them, ten of thirty-five containers, exit 0,
  no warning) and so live in one shell function that `ps` and `logs` share,
  since the old step passed them to `ps` only; the bare dump INTERLEAVES
  containers, so it is context and not the answer; and the step needs an
  env-file guard, because the failures most in need of it happen before
  `.env.stack` exists and `bash -e` would make the entire output one
  `couldn't find env file` line. stack.yml gets the same fix for a
  non-obvious reason: its migrate loop runs each job ATTACHED, so a job NAMED
  on the command line streams its own failure, but an unattached DEPENDENCY
  does not — and the sorted list starts at `migrate-ai-assistant`, which pulls
  notifications → settlement → profile in as prerequisites. Do NOT "improve"
  either step with `docker inspect` or `compose config`: those print the
  resolved environment, where the generated service credentials and KMS keys
  live. Container logs do not, and that was verified rather than assumed —
  every `ConfigError` carries zod issue paths and messages only, no service
  dumps `process.env`, audit's logger is closed to scalars behind `no-console`,
  a migrator prints `err.message` and never its connection string, and
  localstack runs `DEBUG=0`.
- 2026-08-07 — THE SCHEDULED SECRET SCAN HAD NEVER PASSED, and the fix is a
  fingerprint rather than an exclusion. `gitleaks-action` scans only the pushed
  commits on `push` but the WHOLE HISTORY on `schedule`, so both scheduled runs
  that have ever executed (2026-08-06, 2026-08-07) failed on
  `generic-api-key` in the M1 walking-skeleton commit `b21e514` — an xkcd
  passphrase used as a test password, already remediated in the tree (the line
  generates it with `randomBytes` and says why) but immortal in that commit. A
  remediated tree does not make a history scan pass. `.gitleaksignore` now
  carries the 4-field commit form `commit:file:rule-id:start-line`, and three
  details are load-bearing: the line number is the line AT THAT COMMIT (93),
  not in the tree (95), which would never match; the 3-field GLOBAL form is
  checked FIRST and matches in EVERY commit, so it would silently suppress a
  genuine secret re-introduced at the same path and rule and is banned in the
  file's own header; and a wrong entry can only leave the scan RED, never turn
  it green, which is what makes the file reviewable. A `.gitleaks.toml`
  allowlist was rejected — it has no concept of a line, and expressing it there
  means writing the literal string back into a tracked file at HEAD, inside a
  file gitleaks itself scans and whose allowlist cannot cover its own path.
  The point of the entry is that the gate goes GREEN: a permanently red scan is
  one where the NEXT finding is invisible, which is the M5 base-image-gate
  lesson arrived at from the other direction.
- 2026-08-07 — M14 is ADDRESS OWNERSHIP, and the defect it closes is that three
  shipped fail-closed controls rested on an assumption docs/03 §6c itself
  recorded as unverified. M6 emergency access (§5.2), M7 settlement
  intake/review-approve (§5.1) and M13's link ceremony (§6g) all refuse in
  production rather than proceed silently — but all three test
  `deliversToRealChannels`, which is A PROPERTY OF THE ADAPTER, NOT OF THE
  RECIPIENT: a hardcoded literal on whichever adapter class that service's own
  `NOTIFY_MODE` selected, declared independently three times, `false` on the
  stub and `true` on the HTTP one. It asks whether SES is wired. It never asks
  whether the stored address belongs to the owner, and could not, because the
  bit never leaves the process and never names a recipient. Meanwhile identity
  fed the delivery store whatever was typed, at registration and at EVERY login,
  and `users.email_verified_at` had sat unread and unwritten since M1. So the
  gate was satisfied, the escrow armed or the five-day clock started, and the
  owner's ability to INTERRUPT — the entire content of §5.2 and of §5.1's
  control 3 — was unenforced. The sharp part is an anti-correlation: the only
  self-heal was the login-time re-feed, so the address is freshest for active
  users and STALEST for the dormant owner a fraudulent death report actually
  targets — and once status is `settlement`, login is blocked, so it can never
  heal at all.
- 2026-08-07 — M14 PR0, found while scoping and split out because a live defect
  must not hide inside a feature branch: `notification_sends`'s kind CHECK had
  fallen behind the wire enum since M13. `contact.link_claimed` was on the wire,
  in the template registry and in profile's adapter, and NOT in the DDL — and
  `PROFILE_NOTIFY_MODE=http` in BOTH stack profiles, so the path was live. The
  row is recorded AFTER the carrier hand-off and OUTSIDE the try/catch, so every
  real link claim mailed the owner, threw on the INSERT, emitted no
  `notification.sent`, and made profile record `contact.link.claimed
  {"ownerNotified":"failed"}` ABOUT AN OWNER WHO HAD BEEN WARNED. That inverts
  an audit claim rather than losing a row: `ownerNotified: 'failed'` exists so
  an operator can re-drive a notification the owner never got (§6g), and here it
  would duplicate one they already had while the real signal — this kind cannot
  be logged at all — read as an ordinary carrier failure. MEASURED on the
  running stack, not reasoned about: LocalStack's SES inbox held the body,
  `notification_sends` held no row of that kind, and both claim events said
  "failed"; after the fix a fresh ceremony records `sent` / "delivered".
  Nothing caught it because the unit suite fakes the repo (no CHECK to violate),
  the int suite exercised three kinds by hand and none was the new one, and the
  stack e2e polls for an audit event whose shape is identical either way. The
  int suite now drives EVERY kind DERIVED FROM the enum, and the stack e2e
  asserts the send LOG rather than only the event.
- 2026-08-07 — M14 gate classification: A VERIFIED ADDRESS GATES
  CAPABILITY-ARMING ACTIONS, NOT CASE-OPENING ONES. Arms (require verified):
  vault escrow `configure`, vault `rearm`, profile link-code `invite`. Proceeds
  and RECORDS `unverified_recipient`: vault `request`/`release`, profile
  `redeem`, settlement `report`/`reportProviderSignal`/review-approve. The
  discriminator is that in the second group THE ACTOR AND THE NOTIFICATION
  RECIPIENT ARE DIFFERENT PEOPLE, so blocking on the OWNER's unverified address
  would let an owner's own typo permanently deny a legitimate grantee, redeemer
  or reporter — the M6 rule that the protective action must never be harder,
  pointed the other way — and applied to §5.1 intake it would become a denial of
  service for exactly the unverified dormant owner (M12's "fail closed without
  trapping the owner"). `rearm` lands in the first group though the brief did not
  enumerate it: it restores a grantee's ability to start the §5.2 clock and
  actor == recipient, so refusing costs the owner an action they can unblock
  themselves. Corrections to the brief's own table, both verified in code:
  `release` had NO gate to reclassify (it notifies after the fact), and profile's
  `invite` had none either — so M14 ADDS a precondition there rather than
  tightening one.
- 2026-08-07 — M14 decision 2, an APPROVED DEVIATION from M9's content doctrine,
  taken one notch narrower than proposed. The platform now mails a variable that
  is not a date. It is a typed `code` and never a `text` field, it is
  PLATFORM-AUTHORED (`randomBytes`, never derived from anything a user or caller
  wrote), opaque, single-use and short-lived; the subject is unchanged and there
  is still NO LINK, so "we never link you" stays literally true. Implemented as
  a SEPARATE port method and route (`POST /internal/v1/notifications/verification`)
  rather than a widened `send`: `NotificationSendInput` keeps zero variable
  content beyond the deadline, and — the reason that matters — `SendSchema` is
  built from a new `ESTATE_NOTIFICATION_KINDS` that EXCLUDES the verification
  kind, because a send-credential holder naming it on the shared wire would mail
  "enter this code: undefined", authored by a secret vault, settlement and
  profile all hold. `NOTIFICATION_KINDS` stays the union and is the send LOG's
  vocabulary, so every kind is still logged; the three sending services' adapters
  are typed over the narrower union so they structurally cannot name it either.
- 2026-08-07 — M14 credentials: TWO new edges on the notifications callee, not
  one. `NOTIFICATIONS_VERIFY_INTERNAL_TOKEN` (identity alone) mails the code;
  `NOTIFICATIONS_STATUS_INTERNAL_TOKEN` reads the verified bit (identity in PR1;
  vault + profile join in PR2, in the SAME change as the clients, the
  DOCUMENTS_INTERNAL_TOKEN rule). Identity deliberately does NOT join the SEND
  holders — the service that mints sessions must not be able to ring "a death
  report was filed on your account" — and the graph's `identity is deliberately
  NOT here` comment was REWRITTEN to say exactly that rather than deleted. VERIFY
  is separate from RECIPIENTS despite an identical holder because RECIPIENTS can
  REPOINT an address and VERIFY can only mail to what is already on file, so the
  first future holder of a resend capability does not inherit the power the M9
  review split out. STATUS is separate from SEND because settlement holds SEND and
  never asks (its gates proceed and record), so folding the read in would violate
  `holders` minimality AND make the send edge's promise that it "exposes no
  delivery state" untrue — the sentence was kept true verbatim rather than
  hedged. Vouching for an address rides the RECIPIENTS credential: setting one and
  declaring it proved are the same capability class. Both service configs now run
  a FULL PAIRWISE aliasing loop derived from a list rather than a hand-written
  `if` per pair — the M9 split left one `if`, correct only while there were two.
  The fence was made RED FIRST (10 failing assertions) and green after.
- 2026-08-07 — M14 decision 4: the ceremony fires at FIRST AUTHENTICATED LOGIN,
  never at registration, so docs/03 §6c's mitigation ("no notification kind fires
  at registration") stays literally true — an unauthenticated route would be a
  mail-bomb and sender-reputation primitive and this repo has no rate-limiting
  machinery. Two consequences, each easy to get wrong. It is CHAINED onto the
  existing recipient upsert rather than fired beside it: the verification send
  resolves the address from the recipient store, so on a first login the two
  racing would leave the send with nothing to mail, every time. And the whole
  chain stays fire-and-forget, so login latency is never coupled to SES.
  Idempotence is the point — mint only when unverified AND no live code exists
  AND the last mint is older than a five-minute floor — enforced by a PARTIAL
  UNIQUE INDEX (`WHERE revoked_at IS NULL AND verified_at IS NULL`) rather than
  check-then-act, so two concurrent logins produce one code and the loser adopts
  it. A send that does not land RETIRES its code, or the idempotence guard turns
  into a TTL-long lockout over a mail nobody received. CORRECTED 2026-08-14 —
  that last clause was true when written and was invalidated by M14's OWN
  review, which made the retire UNCONDITIONAL at the top of every mint: with
  that in place, neither guard can wedge (the live-code condition is cleared by
  the next call's own retire, and the re-issue floor keys on `lastMintedAt`,
  which orders over revoked rows and so cannot be shortened by retiring at all).
  The send-failure retire survives for a different and better reason — a live
  code that reached no mailbox should not exist, and a carrier failure is
  precisely the case where the carrier may have taken the message before
  failing. The same false justification was found copied into the reset and
  address-change ceremonies and corrected there in the same pass; a milestone
  that invalidates a sentence owns it, and the review that changed the mechanic
  did not come back for this one. Deliberately still open and stated in docs/03
  rather than dropped: the fixed-shape/fixed-time register response for the M1
  enumeration timing channel.
- 2026-08-07 — M14 decision 5: the verified bit lives on
  `notification_recipients`, NOT on `users`, so the delivery store structurally
  cannot hold an unproven address without saying so and the question "can we
  actually reach this owner?" is answered by the store that would have to do the
  reaching. `users.email_verified_at` stays dead rather than becoming a second
  source of truth. FOUR consequences, each asserted rather than assumed. (a) The
  port shape had to change and THAT IS THE FIX: `deliversToRealChannels` was not
  on the shared wire at all, so a per-recipient answer needed a new route, a new
  client method, and a per-service port method — making this the FIRST NETWORK
  ROUND TRIP these gates have ever performed, which is why `recipientStatus`
  returns `null` for UNANSWERABLE rather than flattening to `false`: before M14
  the check could not fail, so no call site had an error path, and each must now
  state what an outage means for its own gate instead of inheriting it. (b) The
  login re-feed CANNOT clobber the bit, because login resolves the user by
  `email_bidx` first, so the address a login carries is by construction the one
  on file — that reasoning lives in a comment next to the upsert, with the
  forward commitment that THE DAY AN ADDRESS-CHANGE ROUTE EXISTS IT INHERITS THE
  OBLIGATION TO CLEAR THE BIT. No blind index; M9's decision intact. (c) The
  versions trigger captures the new column with no trigger change (whole-row
  `to_jsonb(OLD)`) and (d) the bit dies with the row, so a shredded or
  soft-deleted recipient loses verification with its address and the arming gates
  refuse by construction — both proved against real Postgres, because a "free"
  consequence is exactly the kind of claim that turns out to be wrong.
- 2026-08-07 — M14 PR1 was driven live before being called done, and the whole
  ceremony was observed against the running stack: registration mailed NOTHING,
  login produced a real SES message carrying a 160-bit `EV1-…` code, a wrong code
  of the right shape got the uniform `invalid_code`, the code RETYPED THE WAY A
  HUMAN RETYPES IT (lowercase, dashes dropped) was accepted — which is the M13
  canonical-fold lesson applied at the point of use — the status flipped to
  verified, a replay was refused, a resend answered `already_verified`, and a
  second login mailed nothing. `email_verifications` holds a 32-byte digest and
  no code; the wrong guess did NOT count against the attempt cap (an unknown code
  has no row) while the replay did; and both services' audit events landed with
  EMPTY details, because a trail that named which refusal fired would re-create
  through the audit stream exactly the oracle the uniform answer removes from the
  wire.
- 2026-08-07 — M14 PR2 applies the gate table, and the load-bearing change is
  that `deliversToRealChannels` GAINED A NEIGHBOUR rather than being replaced:
  it is a true statement about the adapter and stays, and
  `recipientVerified(userId)` is the question about the RECIPIENT that three
  shipped controls had been answering with it. That makes this the FIRST
  NETWORK ROUND TRIP those gates have ever performed, so every port declares
  what an outage means instead of inheriting it from a thrown exception:
  `recipientStatus` returns `null` for UNANSWERABLE on the shared client, and
  each service's own adapter collapses it to `false` at the boundary that knows
  what the question was for. Stubs answer `false`, never `true` — a dev default
  must not be the permissive answer to a security question (the M8
  fail-open-in-style rule). ARMS ⇒ refuse with its OWN token
  (`recipient_unverified`, distinct from `notifications_unavailable`, because
  "SES is not wired" and "this owner never confirmed their address" call for
  completely different operator responses, and the refusal audit now carries a
  `reason`). OPENS ⇒ proceed, and record.
- 2026-08-07 — WHERE THE PROCEED-AND-RECORD FACT LANDS, and why it is two
  places. `notification_sends.outcome` gains `sent_unverified` (migration 004),
  so the delivery store — the one that KNOWS — carries it in its own
  append-only log rather than in a parallel table nobody would join against;
  `delivered` stays TRUE for it, because the carrier accepted the message and a
  caller must not retry an unproved address as though it were a transport
  failure. And `recipientVerified` rides the SEND RESPONSE, which is what lets
  settlement record the fact on the case's own trail WITHOUT holding the status
  credential. That is the classification made structural: settlement sends and
  never asks, so it is deliberately absent from the STATUS edge's holders while
  vault and profile joined it in the same change as their clients. A service
  that never asks the question must not hold the key to it. Not backfilled:
  every pre-M14 `sent` row went to an unproved address, but rewriting an
  append-only log to say so would be a worse lie than the one it corrects, and
  `REVOKE UPDATE` forbids it anyway — the absence of `sent_unverified` before
  migration 004 IS the marker.
- 2026-08-07 — M14 PR2 was proven live under FULL PRODUCTION CONFIG, and the
  whole table is visible in one audit trail: escrow `configure` refused with
  `vault.emergency.notifications_refused {"reason":"recipient_unverified"}`;
  the ceremony then ran against a real SES message
  (`auth.email_verification.verified` + `notification.recipient.verified`); the
  same request was admitted and its own notification recorded `sent`, the only
  `sent` row in the stack. Meanwhile settlement intake PROCEEDED for an
  unverified decedent and recorded both `settlement.unverified_recipient` and a
  `sent_unverified` row — the two halves of the classification, from one run.
  The verification mail itself is `sent_unverified` BY CONSTRUCTION (it goes to
  an address that is by definition not yet proved), which is what makes the
  dev journey's `sent` assertion on the later link-claim mail meaningful rather
  than a constant.
- 2026-08-07 — M14 PR3 (the verification surface) is the only place a user can
  answer the question PR2 started asking, and its design problem is that the
  REFUSAL and the CAUSE happen in different places: an owner with an unverified
  address is turned away at escrow configure and link-code mint, and nothing at
  that moment explains why. So the surface is TWO components. An app-wide
  one-line banner states the cause before anyone meets the effect, and the
  Security page carries the ceremony. The banner renders NOTHING on
  `UNAVAILABLE` or on an error — telling somebody to go and confirm an address
  during a notifications outage sends them to a ceremony that cannot run, so
  this is the one place in the milestone where failing safe means saying LESS;
  the settings page says it properly when they arrive. Neither is a modal and
  neither is dismissible: a dismiss button on a real capability gap is a way to
  hide it.
- 2026-08-07 — M14 PR3 wire decisions, each an existing rule applied rather than
  a new one. THREE STATES CROSS GRAPHQL, not a boolean, because `UNAVAILABLE` is
  a fact about the platform and collapsing it into `UNVERIFIED` would make the
  page lie about which happened (the M10 PR4 readiness rule). The status is its
  OWN query and deliberately not a field on `session`: that resolver backs every
  authenticated request and identity's own session route is the cross-service
  introspection hot path, so a settings-page question must not cost a
  notifications round trip on every call in the product. The resend OUTCOME is
  returned rather than flattened — `TOO_SOON` is the re-issue floor, the only
  rate limit on this path, and a user told "sent" who receives nothing keeps
  pressing. And the code is passed through the edge EXACTLY as typed: identity
  measures and hashes the canonical form, so a fold in the BFF or the browser
  would be a second copy of a matching rule, free to disagree with the one that
  decides (the M12 upload-client rule: never a client-side second opinion on a
  server-side gate).
- 2026-08-07 — M14 PR3 gave a refused verification code its OWN error code
  rather than reusing `INVALID_CREDENTIALS`, which is the M12 finding applied
  before it could recur: that token already means "email and password" on the
  login surface, and one code changing meaning with the surface is exactly what
  produced copy telling a user to check a password on a form that has none.
  `VERIFICATION_UNAVAILABLE` is separate again — the code was fine and there is
  nothing to re-check. The copy for the uniform refusal has to carry what the
  server refuses to say: identity answers one `invalid_code` for unknown,
  expired, spent, revoked and attempt-exhausted, so the message lists the
  possibilities instead of asking the user to guess which applied.
- 2026-08-07 — M14 PR3 also closed a coverage gap it would otherwise have
  opened: `identity-client.ts` sat at 58% because every BFF spec exercises the
  FAKE, and adding three methods dropped the package under its floor. The fix
  was the first `identity-client.spec.ts` — the real client against a stubbed
  transport, the peer-client pattern — which took that file to 77% and the
  package to 90.5/88.05/91.01/91.08, ratcheted up. Lowering the floor was never
  the option; the floor doing its job is what surfaced the gap.
- 2026-08-07 — M14 security review (five discovery lenses over NAMED FILE LISTS
  — never a diff range, the M13 lesson — then TWO adversarial verifiers per
  candidate on different angles, production reachability and
  is-it-already-a-decision, both defaulting to refuted). The verifiers refuted
  or downgraded five of the candidates put to them, which is what they are for.
  EIGHTH milestone running where every confirmed finding sits in machinery the
  milestone introduced, and most falsify a claim it made about itself.
  THE WORST ONE INVERTED THE MILESTONE: a partial unique index cannot reference
  `now()`, so `ux_email_verifications_live` counted a LAPSED row as occupying
  the live slot, while `findLive` — which decided whether to retire the previous
  code — carried the clock. Retirement ran only inside `if (live)`, so once a
  code passed its TTL nothing ever cleared it: the next insert took the unique
  violation, the ceremony answered `too_soon` FOREVER, and the account could
  never be verified again, which meant every M14 arming gate refused it
  permanently. The trigger was the most common user behaviour there is —
  ignoring the first email. M14 had replaced "the gate is satisfied without
  proof" with "the gate can never be satisfied". THREE claims contradicted it,
  and the third is the lesson: an int-spec comment said "findLive agrees, so the
  service re-mints rather than waiting" and the test never asserted the re-mint
  — the M13 "a test named for a property it never touched" shape, reproduced by
  me in the milestone that cites it. Fixed by retiring UNCONDITIONALLY (the
  retirement predicate matches the INDEX, deliberately, not `findLive`), and
  `findLive` now also matches `verify()` on `attempts` so all three notions of
  liveness agree. Reproduced on the live stack before the fix and mutation-
  tested after.
- 2026-08-07 — THE SECOND M14 REVIEW FINDING IS THE SAME SHAPE AS THE FIRST, one
  layer over: the re-issue floor — documented in its own class docstring as
  "the ONLY rate limit on this path" — was checked only when a live code
  existed. A send that fails RETIRES its code, so in exactly the state where
  sends are failing (no recipient row, SES refusing, the verification route
  down) there was no live code, the floor was skipped entirely, and the resend
  route had no rate limit of any kind, at whatever rate a caller could sustain;
  each iteration cost a real SES call and two append-only `auth_events` rows.
  The floor keys on the LAST MINT now (`lastMintedAt`), which is the question it
  was always trying to ask: how recently did we mail this address. Both findings
  came from one predicate being written twice with different clauses — the
  general rule being that when a rule exists at two layers, a test must say
  WHICH layer it proves, and the layers must be made to agree rather than
  assumed to.
- 2026-08-07 — M14 review, the other confirmed defects. (a) VAULT RESET recorded
  every notification as DELIVERED: PR2 changed the port from throw-based to
  outcome-based and updated every call site except `vault.service.ts`, so the
  `catch` was unreachable and `deliveredAt` was stamped unconditionally — on the
  one route where a bearer token destroys a Zone A vault, and where that record
  is the only compensating control the route's own docstring names. Reset also
  discarded `recipientVerified`, so it was the single path that could never emit
  the M14 evidence event. (b) A CRYPTO-SHREDDED RECIPIENT still answered
  `verified: true`, because shredding destroys the DEK and not the row, so the
  arming gates would ARM while every subsequent alert recorded
  `carrier_failure`; migration 003 claimed the opposite as "fail-closed by
  construction" AND claimed the specs asserted it, while only the soft-delete
  half was tested. Latent — no in-repo caller destroys a DEK — and fixed anyway,
  because it arms itself the day an erasure route lands and the comment is
  exactly what would stop someone looking. (c) THE VERIFICATION CODE FIELD
  accepted 64 characters of readable English (`/^[0-9A-Z-]+$/` against a minting
  alphabet that excludes I, L, O and U) and interpolated it verbatim into a real
  message from the platform's verified sender. The fix puts the pattern in the
  WIRE CONTRACT both services import, with an identity spec asserting every
  minted code satisfies it — one declaration rather than two free to drift,
  which is why the obvious local tightening was rejected. (d) An outage was
  recorded as a FAILED VERIFICATION: `verification_unavailable` reached
  `recordFailure`, putting "this user failed a verification" in the one trail an
  investigator reads to decide whether somebody is guessing at a user's codes.
  It has its own action now — the M9 rule that a control firing must not read as
  an outage, applied in the other direction.
- 2026-08-07 — I SILENTLY DISABLED A FENCE, and the shape generalizes past this
  repo. `credential-graph.spec.ts` matched outbound credential wiring with
  `/(?:serviceCredential|credential)\s*:\s*config\.(\w+)/`; M14 PR1 changed every
  notifications client to the per-capability object `credentials: { send:
  config.X }`, which that regex does not match (an `s` sits between `credential`
  and `:`). Measured: identity, profile and notifications were checked on ZERO
  credentials, so rule 2's outbound half — the exact line the M7 collapse
  crossed — covered none of the seven notifications presentations, while the
  decision log went on citing the fence as enforcing it. A FENCE THAT STOPS
  MATCHING IS WORSE THAN ONE THAT NEVER EXISTED. Two fixes, both structural:
  the scan is keyed on the CONFIG FIELD rather than the property name (a
  property name is a caller's choice and can be renamed into invisibility, which
  is what happened; the set of credential-bearing config fields is derived from
  the graph), and the loop gained the ANTI-VACUITY floor the file header already
  claimed every scan carried. Mutation-tested with the exact mis-wiring it had
  become blind to — settlement handing its own inbound §6a gate secret to the
  notifications client — which now turns it red.
- 2026-08-07 — THE ROOT CAUSE OF FOUR OF THE TEN M14 FINDINGS, named by a
  verifier rather than by me: M14 shipped 84 files of code and ZERO lines of
  documentation, so every sentence it invalidated was still standing. Including
  a citation IN SHIPPED CODE pointing at docs/03 §6c "recording the deviation"
  for mailing a code — a passage that recorded the opposite, since §6c still
  described unverified addresses as an open residual with "a confirm-token flow
  is the fix and needs its own change". The credential graph's SEND edge still
  promised it "exposes no delivery state" after PR2 put `recipientVerified` on
  the send response, in three more restatements. docs/03 §6h now exists, §6c is
  marked closed by it, and the citation points somewhere true. The rule this
  yields: A MILESTONE THAT INVALIDATES A SENTENCE OWNS THAT SENTENCE, and
  deferring the docs to after the review means shipping code that cites
  documentation contradicting it.
- 2026-08-07 — M14's ARMING-GATE JUSTIFICATION IS TRUE ONLY FOR THE CONTRAST IT
  WAS WRITTEN FOR, recorded in docs/03 §6h rather than softened. "Refusing costs
  them an action they can unblock themselves by verifying" is right about actor
  == recipient, and FALSE unconditionally: there is no address-change route
  anywhere in the platform, so a user who mistypes their address at registration
  — precisely the failure M14 exists to catch — can never verify, and is
  permanently refused escrow configure, rearm and link-code mint in production,
  with no operator remedy until the TB7 platform. It fails in the safe
  direction. The address-change route that closes it already carries a written
  obligation to clear the verified bit, and now also to invalidate any
  outstanding code.
- 2026-08-07 — M14 REVIEW ROUND 2, over the fixes themselves, and it earned its
  place for the second milestone running. Two agents against the fix commit's
  files only. The headline: THE COMMIT MESSAGE SAID "EVERY FIX MUTATION-TESTED"
  AND THREE OF THEM SHIPPED CHANGES NO TEST COULD DISTINGUISH FROM A REVERT —
  vault's new `unverified_recipient` emit (no test anywhere, and the int case
  added beside it builds the one state where it cannot fire), settlement's
  emit-outside-the-catch restructure (whose only observable difference is a
  broker failure propagating, which nothing provoked), and profile's ordering
  swap (both emits pushed to separate arrays, so relative order was never
  asserted). All three have tests that go red on revert now. The lesson is not
  "write more tests": it is that MUTATION-TESTING A FIX MEANS REVERTING THE FIX,
  not re-running the suite — three of these were "verified" by watching a green
  suite that would have been green either way.
- 2026-08-07 — Round 2 also found MY WEDGE TEST PROVING THE WRONG LAYER, which
  is the M13 lesson committed inside the fix that cites it. The int case was
  named for "the M14 review's worst finding, pinned against a real database"
  and called `repo.revokeLive` EXPLICITLY — whose SQL the fix never touched. It
  proved the primitive that was always correct and asserted nothing about the
  service decision that was wrong. It drives the SERVICE against the real index
  now, which is the pair (decision + partial unique index) that no test
  combined before.
- 2026-08-07 — Round 2's substantive finds, both in the crypto-shred fix. (a)
  THE DEK PREDICATE WENT ON THE READ AND NOT THE WRITE: `findStatus` refused a
  shredded recipient while `markVerified` still stamped one, so the platform
  would tell a user their address was verified in the same breath as telling
  every gate it was not — and two docstrings asserted the opposite. (b) THE
  SHRED WAS FAIL-CLOSED ONLY UNTIL THE NEXT LOGIN: `encryptField` mints a fresh
  DEK once the old one is destroyed and the upsert preserved `verified_at`, so
  the row came back with an active key and an untouched proof and every arming
  gate re-armed with nothing re-proved. The upsert clears the bit when
  `dek_id` CHANGES now — which happens exactly when the key underneath changed
  (a shred, or a rotation when one lands) and never on an ordinary login
  re-feed, so it costs the common path nothing.
- 2026-08-07 — AND THE ATTEMPT CAP WAS DECORATIVE, which round 2 proved from
  the code rather than from a test. `countAttempt` took a resolved row id and
  `verify()` only ever called it inside the branch that had ALREADY decided the
  row was dead — so `attempts` could only increment on a code that was revoked,
  spent or expired. Worse, a wrong guess produces a DIFFERENT DIGEST, so the
  lookup returned nothing and no counter moved at all: the cap could not see
  the only kind of failure a guesser actually produces. Three comments claimed
  it "bounds guessing against a LIVE code"; it bounded replay of a dead one,
  which nothing needed. Keyed on the USER now, so a failed redemption costs the
  caller's own live code one attempt whatever they submitted — which is what
  makes `findLive`'s attempts predicate reachable and gives the redeem route
  its only bound (every failure there writes an append-only `auth_events` row
  and an audit event). Self-inflicted only: it moves a counter on the caller's
  own code, from their own session, and the response stays the same uniform
  refusal.
- 2026-08-07 — RECORDED, NOT CLOSED: the credential-graph fence still only sees
  a literal `config.<identifier>`. `config['field']`, `config?.field`, a
  destructured factory parameter and an intermediate `const` all evade it, as
  does a config.ts written with `||` instead of `??` (which is what the
  field→env mapping parses), and the anti-vacuity floor is per SERVICE rather
  than per edge. None is a regression — the old pattern had every one — but the
  fix's own rationale about renaming into invisibility applies to the ACCESS
  SHAPE too, so the remaining holes are written next to the scan rather than
  left for a reader to assume closed. Closing them properly wants the
  TypeScript AST rather than a regex, which is a bigger change than a review
  should make.
- 2026-08-08 — M15 is THE VAULT SURFACE: Zone A in the browser, on an isolated
  origin (docs/03 §4 TB6, risk #4). It closes the LARGEST remaining zero-callers
  gap in the repo — apps/services/vault has exposed 22 owner-facing routes since
  M6 with no consumer anywhere — and it is the first consumer of the 16-symbol
  grantee fingerprint the M6 review widened for a client that did not exist.
  M6 deferred the UI explicitly because a vault surface needs the TB6
  isolated-origin and CSP/Trusted-Types work; M14 removed the last blocker in
  front of the emergency-access half. Four PRs: PR1 the origin, the handoff and
  the fences (no vault crypto behind it yet — prove the boundary first), PR2 the
  vault core, PR3 emergency access both sides, PR4 the security review.
- 2026-08-08 — THE ISOLATED ORIGIN IS A DIFFERENT HOST, and the reason was
  MEASURED IN A BROWSER rather than reasoned about: cookie scope IGNORES THE
  PORT. A probe served on an unrelated port was handed a real
  `estate_access`/`estate_refresh` pair left over from a previous stack run, so
  a vault surface at `localhost:3010` would have received the app's full session
  on every request — the cheapest candidate design, failing live. `vault.localhost`
  receives NONE of them (the app's cookies are host-only), and `*.localhost` is a
  potentially-trustworthy origin, so the vault's `__Host-` prefixed `Secure`
  cookie is accepted there over plain http exactly as the BFF's is on
  `localhost`. No TLS terminator is needed for the dev stack and the prefix is
  UNCONDITIONAL in every environment — unlike the BFF's `Secure`, which is
  production-only, because a conditional prefix would mean the dev profile
  exercising a different cookie from the production one. Production addressing is
  `vault.<domain>`; the residual is stated rather than hidden — a subdomain
  shares a registrable domain with the app, which is exactly why `__Host-` is
  used, since it makes host-only a property the BROWSER enforces rather than a
  convention someone has to keep. A separate registrable domain is strictly
  better and is a deployment choice, not a code one.
- 2026-08-08 — THE VAULT CLIENT IS FRAMEWORK-FREE, and that is a security
  decision rather than a taste one. M6's own stated TB6 control is that "the code
  holding the only keys that open a vault has no transitive tree to compromise";
  putting Next and React on that origin would place a large tree there and then
  ask a CSP to compensate. Hand-written DOM (`createElement`/`textContent`, no
  parser anywhere) is what makes the origin's policy REAL instead of declared:
  `default-src 'none'`, `script-src 'self'` with NO `unsafe-inline` and NO
  `unsafe-eval` IN ANY ENVIRONMENT (nothing here needs React Refresh, so the M11
  development-only carve-out has no counterpart), plus
  `require-trusted-types-for 'script'` with `trusted-types 'none'` — enforceable
  only because no policy is ever created. MEASURED in a real browser on the
  running stack: `trustedTypes.createPolicy` refused, `innerHTML` threw a
  TypeError producing ZERO child nodes, and `new Function`/`eval` both threw
  EvalError. That last one initially reported ALLOWED and the discrepancy was
  worth chasing — the browser tool evaluates in an isolated world whose CSP is
  not the page's, so a temporary in-page probe was served to get the real
  answer. There is no `'sha256-…'` and there is not meant to be: the client will
  reach @estate/vault-crypto by ABSOLUTE PATH (`/lib/vault-crypto/index.js`,
  served by this edge) rather than through an inline import map, precisely so
  `script-src` can stay `'self'` and nothing else for the life of the app. Cost,
  stated: no React, no Tailwind, and a visual seam with the rest of the product
  — narrowed by copying the Evergreen palette rather than importing it, because
  an unfamiliar-looking page asking for the most valuable secret in the product
  is what a phishing page looks like. The `Vault · Zone A` rail marker says it is
  a different place.
- 2026-08-08 — AUTHORITY CROSSES BY A SINGLE-USE HANDOFF, AUDIENCE-SCOPED. The
  app mints a 160-bit code (`POST /v1/auth/handoff`, SessionGuard + StepUpGuard),
  puts it in a HIDDEN FIELD, and the browser submits a TOP-LEVEL FORM POST to the
  vault origin — not a redirect with the code in the query string and not a
  fragment, because a form body is the only shape that keeps it out of browser
  history, out of the `Referer` and out of every intermediary's access log (the
  M12 document-search reasoning). The edge redeems it server-side and sets its
  own `__Host-` cookie; nothing the app can read ever holds a vault credential.
  WHAT A STOLEN CODE BUYS, which is the only reason any parameter is what it is:
  60 seconds to redeem (pure exposure, not a usability number — no human ever
  sees this code, unlike M13's link code and M14's verification code); burned on
  the ATTEMPT, so a race with the legitimate redemption is winner-takes-all; and
  on success ONE access token, 15 minutes, WITH NO REFRESH TOKEN — `refresh_token_h`
  is NOT NULL, so it holds the digest of a value generated and discarded in the
  same expression, meaning no refresh token for that session exists anywhere to
  be presented. And it still decrypts nothing: reaching the vault API is not
  opening a vault. Every failure — unknown, expired, spent, raced — is one
  `invalid_code`, on the wire AND in the audit trail, where `auth.handoff.failed`
  carries no actor and an empty detail (the M14 PR1 rule: a trail that named
  which refusal fired would re-create the oracle the uniform answer removes).
- 2026-08-08 — `SessionContext` GAINED AN AUDIENCE, enforced DENY BY DEFAULT in
  `CallerGuard`: a service admits `account` alone unless it binds
  `ALLOWED_SESSION_AUDIENCES`, and only vault does. The eight other services
  reject a leaked vault session without changing a line. Two parse directions,
  deliberately different: an ABSENT `audience` on the introspection response
  defaults to `account` (version-skew tolerance that is sound, because only
  identity mints a non-account audience and an identity old enough to omit the
  field has no handoff route), while an UNRECOGNISED one fails the whole parse.
  Identity itself cannot take one service-wide decision — introspection MUST
  admit every audience or the origin cannot exist — so its gate is PER ROUTE
  (`@AllowSessionAudiences`), and exactly three routes widen: `session`,
  `stepup` (a vault session must re-prove a factor without a round trip back
  across the origin boundary; step-up strengthens the session presenting it and
  confers nothing else) and `logout` (revoking your own credential can only
  reduce authority — the M6 rule). `handoff` is deliberately NOT among them, so a
  vault session cannot mint another and a leaked one cannot chain itself forward;
  a test names that fact by itself. Vault admits `account` TOO, and the asymmetry
  is the point: an account session is strictly MORE powerful, so refusing it
  there would protect nothing while making the service reachable only through the
  handoff. The property bought runs one way. Both halves are declared as DATA —
  `AUDIENCE_ADMITTERS` in @estate/auth-guard and `VAULT_AUDIENCE_ROUTES` in
  identity — and checked against source in both directions, the credential-graph
  precedent. Every refusal is the SAME generic 401 as an invalid token: a
  distinct "wrong audience" would tell whoever presented a stolen session that it
  is real and merely pointed at the wrong door.
- 2026-08-08 — The vault edge HOLDS NO CREDENTIAL, in either direction, making it
  the second component in the product of which that is true by design (the
  assistant service is the first). It forwards the caller's own bearer from a
  cookie scoped to its own origin, so it can only reach what the calling user
  could already reach. Asserted three ways rather than claimed: a source fence
  (no `_INTERNAL_TOKEN` may appear), a runtime one (`credentialsHeldIn(config)`
  is asserted BOTH equal to the granted set and explicitly empty — without the
  second assertion the test passes vacuously if the graph changes shape, the
  ai-assistant precedent), and a deployment one (its compose block carries
  nothing credential-shaped). It lives at `apps/` rather than `apps/services/`
  ON PURPOSE: `SERVICE_NAMES` is derived from that directory, and keeping the
  vault origin out of it keeps it out of the credential graph, where a service is
  presumed to hold a secret. Its proxy is an ALLOWLIST of exact routes, not a
  prefix rewrite — a proxy that forwards whatever path it is given is an SSRF
  primitive carrying a live bearer, and the identity entries are EXACT matches
  because `startsWith('/api/auth/logout')` also matches
  `/api/auth/logout/refresh`, identity's unauthenticated refresh-token
  revocation route.
- 2026-08-08 — M15 PR1 fences, each MUTATION-TESTED RED before green, because a
  fence that has never failed has never been tested. Zero dependency tree in the
  browser client (only relative `.js` specifiers and the one absolute
  vault-crypto path); no HTML/script sink anywhere on the origin with ZERO
  declared exemptions (the main app has one for its theme script; this one has
  none and must never acquire one); `api.ts` is the ONLY module that may reach
  the network, which is what makes "nothing derived from the vault password or
  Secret Key leaves the device" checkable rather than re-argued per screen; no
  `console.*` in the client, because a log is an exfiltration channel that
  survives review far more easily than a fetch; the served shell has no inline
  script or style; the audience table matches source in both directions; and
  identity's per-route widening matches its declaration. Confirmed red by
  reintroducing each: an `innerHTML`, a second network call site, a
  `console.log`, a bare specifier, an inline script, a runtime dependency, an
  undeclared service binding the audience token, vault dropping or widening its
  own, and `handoff` quietly admitting `vault`.
- 2026-08-08 — A TEST THAT PASSED FOR THE WRONG REASON, twice over, in M15 PR1's
  own suite — the M13 lesson about a test named for a property it never touched.
  The static server's traversal test used `fetch`, which NORMALISES `/../../x` to
  `/x` before the request is sent (measured: the request line the server saw was
  `/package.json`), so the 404 came from the extension allowlist and no traversal
  was ever attempted. Rewritten to use a RAW SOCKET — and then a mutation showed
  the `startsWith(publicDir)` guard is UNREACHABLE anyway, because the WHATWG
  `URL` parse upstream of it collapses `..` and decodes `%2e%2e` to `..` first.
  The guard stays as defence in depth against a refactor that stops routing
  through `new URL`, but it is documented as unreachable rather than credited as
  the control, and the test now asserts the PROPERTY (nothing outside `public/`
  is ever served, targeting a real `.css` file in another app so the extension
  allowlist cannot mask an escape). Mutation-tested by rooting the server at
  `apps/` and watching it go red.
- 2026-08-08 — M15 PR1 was DRIVEN LIVE against a freshly reset stack in both
  profiles, and the audience boundary was measured rather than asserted from
  unit tests: presenting a redeemed vault session gets 200 at vault, 401 at
  assets, documents, profile and the assistant, 200 at identity's introspection
  route, and 401 at identity's TOTP-enrollment and handoff routes. Replay of a
  spent code and an unknown code return byte-identical `{"error":"invalid_code"}`;
  the redeem response carries no `refreshToken`; the audit stream shows
  minted/redeemed with the audience and `failed` with no actor and empty detail.
  On the origin itself: Trusted Types enforced, `innerHTML` blocked,
  cross-origin `fetch` to the app's BFF refused by `connect-src 'self'`, no
  JS-visible cookies, and the app's cookie names buy nothing (401). The whole
  ceremony also ran through the real UI — register, login, TOTP, `/vault`
  interstitial, step-up prompt, form POST, landing on
  `http://vault.localhost:3010` showing `Session type: vault`.
- 2026-08-08 — Driving the real app found the fifth browser-only-class defect in
  as many milestones, and this one was caught by its own new test rather than in
  production: `VaultLaunch` destructured `result.data.startVaultHandoff` with no
  shape guard, so a BFF predating the mutation (`{"data":{}}`) would have thrown
  mid-click. Worse than the M11/M12 instances, because the alternative failure is
  a form posting `code=undefined` at the vault origin. A missing field is NO
  DATA, never data. Related and deliberate: the vault origin is returned by the
  BFF at REQUEST time rather than baked into the web bundle — the M8 PR5 lesson,
  where `BFF_URL` had to be a build arg because Next serialises rewrites into
  the routes manifest and the image duly baked a rewrite to localhost:4000. The
  app's CSP still needs the origin at BUILD time for one directive
  (`form-action`), so that value IS a build arg, and a parity spec asserts it
  equals the one the BFF hands the browser — a disagreement is a refused form
  post rather than a silent downgrade.
  CORRECTED 2026-08-19, and BOTH halves of that last sentence were false when
  written. Compose PASSED a build arg; `web.Dockerfile` declared no `ARG` to
  receive it and `turbo.json`'s strict `env` stripped it, so the value never
  reached `next build` and the config fell through to its localhost default.
  And the parity spec asserts that compose's literal equals `topology.ts`'s
  constant — two DECLARATIONS agreeing — never that the value the build
  received equals the one the BFF serves, which it could not, there being no
  received value. See the 2026-08-19 entry below.
- 2026-08-08 — M15 PR1 stack counts MEASURED IN BOTH PROFILES, not derived, and
  the reason is instructive: run the production assertions against a DEVELOPMENT
  stack and the M14 arming gate legitimately answers 201 instead of 503, because
  `assertOwnerReachable` is production-scoped — a derived number would have
  encoded that as a pass. The six vault-origin tests sit OUTSIDE the profile
  split, unlike plaid's and the assistant's, because nothing about this origin
  needs a third-party credential and it runs in both: 18/4 → 24/4 in
  development, 9/13 → 15/13 in the production rehearsal. `vault-web` joined the
  image matrix with an explicit `smokeProduction` flag rather than by
  overloading `kind` (which also drives the web/liveness branch), and its
  fail-fast message was verified against the workflow's own grep. The e2e also
  fetches `/app/main.js` from the SHIPPED image, closing the class the
  2026-08-06 `web.Dockerfile` defect belonged to: this origin's client is build
  output under `public/` too, so its absence would look identical — a shell that
  loads and a page that never renders.
- 2026-08-08 — ROADMAP: M16 is the VAULT BROWSER EXTENSION, M17 the SUBSCRIPTION
  MANAGER. Both recorded in docs/04 with the decisions each will have to take.
  The extension is sequenced after M15 because it is a SECOND CLIENT of the same
  SRP/2SKD protocol and building it before the first client settles would fork
  the protocol; it is a milestone rather than a PR because of three things that
  are not incidental. MV3 service workers are TERMINATED, and a non-extractable
  `CryptoKey` cannot be serialized — so keeping keys warm across browsing means
  either frequent re-unlock, a kept-alive offscreen document, a native-messaging
  host, or storing raw key bytes and surrendering the docs/03 TB6
  non-extractable-keys property. That must be an explicit decision with a
  recorded residual, not whichever option happens to work. Origin matching IS
  the security property (eTLD+1 via the Public Suffix List, never a substring; no
  cross-origin iframe fill without opt-in; no https→http downgrade; no
  auto-submit), and the content script must be structurally unable to REQUEST a
  credential. And the extension INVERTS M15's central argument: a signed artifact
  auto-updated through a vendor store with no CSP in the path, so a compromised
  update is silent full Zone A compromise — reproducible builds and a published
  attestation are the compensating controls to design for. Stated up front:
  autofill does NOT resist phishing (it fills a lookalike domain the user saved),
  so a lookalike warning is the minimum owed and passkey provisioning is a
  legitimate competing priority. `@estate/vault-crypto` gains a SECOND declared
  importer, as fence data rather than as a remembered exception — and the fence
  asserting who may import it does not exist yet (M15 PR1 shipped seven fences,
  and that was not among them).
- 2026-08-08 — M17's subscription manager exists because THE ESTATE KEEPS PAYING
  UNTIL SOMEBODY STOPS IT: recurring charges continue debiting after death and
  every month before cancellation is money out. It is NOT an asset and must not
  be modelled as one — `asset_events` is an event-sourced ledger of what the
  estate OWNS, and a subscription is a recurring OUTFLOW — so separate tables in
  the financial cluster. Five decisions worth pre-recording. (1) A subscription
  list is a BEHAVIOURAL PROFILE — therapy, medication delivery, religion,
  politics, sexuality, recovery — and arguably more sensitive than the asset
  list, so the merchant name is CIPHERTEXT, deliberately unlike
  `assets_view.title`'s accepted plaintext. (2) Manual entry first, Plaid-assisted
  detection second (the M3 decision verbatim, no dormant schema), and detection
  must respect the isolate: IDs and enums on the bus, never a widened KMS grant.
  (3) THE PLATFORM NEVER CANCELS ANYTHING — it produces a worklist and records
  what the executor did; automated cancellation would make the platform an agent
  on someone's accounts and is a fraud vector against a LIVING owner, squarely
  against "settlement is never fully automated". (4) Credentials stay in the
  vault: a record may REFERENCE a vault item id and must never hold a password,
  or the feature becomes a second credential store outside Zone A. (5) The naive
  version is HARMFUL — life insurance is an asset, a storage unit may hold estate
  property, a domain may carry a business — so records carry a cancel /
  review-carefully / DO-NOT-CANCEL classification and the surface leads with the
  last rather than with "cancel all". Executor access rides M7 PR2's staged
  ladder at the FIRST rung, which is a happy alignment: the thing that saves
  money is available earliest while documents and Zone A stay further along.
  Beneficiaries get nothing (docs/03 §5.5 scopes them to assets naming them; a
  subscription names nobody). No blockers — financial cluster, Plaid isolate,
  staged access and the analysers all ship — so it could swap ahead of M16.
- 2026-08-08 — M15 PR2 ships the VAULT CORE: setup, unlock, item CRUD, password
  change and reset, with every key operation client-side. Vault routes 1–12 of
  the 22 now have a caller. TWO BUILDS OF ONE SOURCE — vault-crypto has always
  shipped CommonJS because the vault SERVICE imports its server-side SRP half,
  and the browser needs native ES modules with no bundler, so `tsconfig.esm.json`
  emits the same sources a second way and every relative import gained an
  explicit `.js` (a no-op for CJS, mandatory for a browser). The client loads it
  by ABSOLUTE PATH from this origin (`/lib/vault-crypto/index.js`, copied into
  the served tree at build time) rather than through an inline import map, which
  is what lets the CSP stay `script-src 'self'` with no hash for the life of the
  app. A copy rather than a second static root: the static handler is the one
  piece of the edge that turns a URL into a file path, and its safety argument
  rests on there being exactly one root.
- 2026-08-08 — `VaultSession` IS THE ONLY MODULE THAT TOUCHES A KEY, and the
  screens pass user input in and get rendered values out. It holds the master
  key as a non-extractable CryptoKey, the SRP-derived keyset-auth key, the
  vault-session token, and — solely for the password change — the AUK and the
  wrapped master key, because re-wrapping needs master-key BYTES that a
  non-extractable CryptoKey cannot provide (`exportMasterKeyBytes` exists for
  exactly this) and the alternative is a second full SRP unlock minting a server
  session to immediately revoke. All in `#private` fields: TypeScript's
  `private` is erased and leaves ordinary enumerable properties reachable
  through `Object.values` or a structured logger, which the M10 privacy-proxy
  review found the hard way and which matters more here because these are the
  keys. Dropped by `lock()`, by a 5-minute idle timer (shorter than the server's
  15, because it bounds what an unattended SCREEN is worth rather than what a
  stolen token is), and by `pagehide` so a bfcache restore comes back locked.
- 2026-08-08 — THE MILESTONE'S CENTRAL CLAIM IS NOW DRIVEN RATHER THAN ARGUED.
  `no-key-material-egress.spec.ts` runs enrollment, a REAL SRP-6a unlock (the
  stand-in service speaks the server half, which vault-crypto also ships), a
  create and a list against a recording transport, then searches every recorded
  byte for the password, the Secret Key, its ungrouped parts and the item
  plaintext — and separately round-trips an item back through decryption, so the
  blob is proven BOTH opaque on the wire and openable by this device's key. A
  version that stubbed the crypto could not tell "the plaintext is absent" from
  "the encryption never ran". Mutation-tested: sending the content alongside the
  blob, or the Secret Key alongside the keyset, each turns it red.
- 2026-08-08 — THE SECRET KEY'S LIFE, stated rather than implied. Generated on
  the device, shown ONCE behind an explicit acknowledgement (there is no "show
  it again", because the server does not have it), downloadable as an Emergency
  Kit carrying the key and deliberately NOT the password — a kit with both would
  turn a filing cabinet into the single point of failure 2SKD exists to remove.
  Remembered in IndexedDB by DEFAULT with an opt-out, and the screen says why
  that is not as safe as it sounds: under XSS on this origin any persisted key is
  readable, localStorage and IndexedDB alike, and the control is the empty
  dependency tree and the CSP rather than the storage API. The alternative —
  retyping 26 characters every unlock — reliably pushes people to a text file on
  the desktop, which is worse. IndexedDB over localStorage for two smaller real
  reasons: raw bytes rather than a base64 STRING in the string table, and not in
  the flat key list extensions walk. Reset forgets it, because the old key opens
  nothing afterwards.
- 2026-08-08 — ONE MESSAGE FOR BOTH HALVES OF 2SKD. A wrong vault password and a
  wrong Secret Key produce the same "did not open this vault", because the
  server answers one `srp_failed` for both by design and naming which half was
  wrong would tell someone holding a stolen Secret Key that it is the right one
  — halving the work of the attack 2SKD exists to make hard. A mistyped Secret
  Key throws in `parseSecretKey` BEFORE any network call, and lands on the same
  message rather than a distinguishable client-side one.
- 2026-08-08 — TWO REAL DEFECTS, both found by tests refusing to pass rather than
  by review. (1) A malformed Secret Key makes vault-crypto THROW rather than
  return a result, so the password-change screen sat on "Changing…" forever —
  the worst possible answer on the screen that changes key material. Every async
  handler now catches and reports. (2) The settings screen had TWO fields both
  labelled "New vault password" (the change-password one and the reset one),
  which is ambiguous to a person and genuinely broken for a screen reader; the
  test that could not tell them apart is the same confusion a user would have.
- 2026-08-08 — A STALE `dist` NEARLY BECAME THE THING UNDER TEST. Giving
  vault-crypto's relative imports an explicit `.js` made jest's resolution of
  `./bigint.js` depend on the built output: moving `dist/` aside made every
  import fail with "Cannot find module './bigint.js' from 'src/srp.ts'", and a
  run against a stale `dist` was observed reporting 10.68% coverage with only
  the two files that have no relative imports instrumented. BOTH SYMPTOMS PROVED
  CACHE-SENSITIVE and neither reproduces once `dist` is current, so the
  mechanism is recorded as observed rather than explained — the M13 rule that a
  doc claiming evidence it does not have is itself a defect, applied to my own
  first write-up of this, which asserted a confident mechanism and a test-count
  drop I could not reproduce. The fix is not in doubt: a `moduleNameMapper`
  makes the suite read `src` regardless of whether a build artifact exists or
  how old it is (the 2026-08-06 rule, enforced rather than hoped for).
- 2026-08-08 — M15 PR3 (emergency access, both sides) opened by finding that the
  DESIGN COULD NOT COMPLETE: M6 wrote `vault_keysets.wrapped_private_key` and
  cleared it on reset, and no route ever served it back — so a grantee could
  never open a share sealed to them and no release could finish. Invisible
  because nothing consumed it (the M4 legal-hold shape). `GET
  /v1/vault/recovery-key` closes it behind an OPEN VAULT rather than a session,
  which is also the property that makes emergency access safe to expose: a
  stolen bearer reaches the release route and comes away with ciphertext it
  cannot open.
- 2026-08-08 — THE OBVIOUS WAY TO CROSS ZONE B COULD NEVER HAVE WORKED, and
  driving the live stack is what said so. Choosing a grantee needs contact NAMES,
  which live in profile; profile admits `account` sessions only, so the vault
  origin's read of `/v1/contacts` returned 401 on the first real run. The
  shortcut that makes it work is widening profile SERVICE-WIDE, which hands a
  leaked vault handoff the owner's PII, every contact's decrypted detail, the
  family tree and the role assignments. Instead `CallerGuard` gained PER-ROUTE
  audiences (union with the service-wide list, never a narrowing — a route-level
  table that could take authority away is a second place to look when something
  is unexpectedly 401), and profile gained ONE dedicated route whose whole
  response is a contact id, an account id and a name. The `linkedUserId` field
  first added to `ContactSummary` was REVERTED: with a dedicated projection it is
  unnecessary, and not adding it leaves every existing profile client's
  disclosure surface exactly where M13 left it. Narrowed TWICE on purpose —
  profile projects because it owns the data, and the vault edge re-projects
  because it is the only upstream response this origin parses and a later
  widening of profile's shape must not reach Zone A because nobody remembered the
  edge exists.
- 2026-08-08 — ONE VOCABULARY, TWO GUARDS: `AllowSessionAudiences` and
  `SESSION_AUDIENCE_METADATA` moved into @estate/auth-guard, so identity's own
  `SessionGuard` and every downstream `CallerGuard` read the same key and ONE
  fence sees every widening in the repo. `AUDIENCE_ROUTE_ADMITTERS` is the single
  declaration and identity's `VAULT_AUDIENCE_ROUTES` DERIVES from it rather than
  restating it (a second hand-written list is a second place for one fact, free
  to disagree with the one the fence checks). The fence checks the table against
  the real decorated handlers in both directions, refuses an entry whose service
  already holds the audience service-wide, and asserts every decorator is
  ATTRIBUTED to a handler — its first version used a `[\s\S]{0,400}` bridge that
  backtracked past `async` and reported `identity:constructor`, which is the
  2026-08-07 lesson restated: a fence that matches the wrong thing is worse than
  one that matches nothing, because it still goes green. Mutation-tested three
  ways.
- 2026-08-08 — THREE DEFECTS THE LIVE DRIVE FOUND AND EVERY UNIT TEST PASSED
  OVER, all from ONE cause: the arranged row printed a raw UUID (an owner could
  not recognise who they had named, which is the only reason to read an
  arrangement back), the status rendered the DDL's own word `configured` at a
  person, and "Request access" was gated on `armed` — A STATUS THE SCHEMA DOES
  NOT HAVE — so a grantee could never have started a waiting period. Every
  fixture used a vocabulary a test author invented rather than the one Postgres
  stores. Fixtures are pinned to `002_emergency_access.sql` now, with a case
  walking all six statuses against what the service's own `blockReason` accepts.
  The general rule: A FIXTURE THAT INVENTS AN ENUM TESTS THE FIXTURE.
- 2026-08-08 — Two more M15 PR3 defects, both caught by tests refusing to pass.
  A malformed public key made `offerFor` THROW, leaving the candidate row on "not
  confirmed" with nothing said — Zone A's threat model treats the server as
  hostile, so an unparseable key is a refusal (`INVALID_REQUEST`), not an
  exception, and refusing to fingerprint it is also the right security answer
  since there is nothing there to seal a share to. And a success message written
  before the screen re-read itself was DESTROYED by that re-read, so a grantee
  who started a 48-hour waiting period was told nothing at all; what an action
  wants to say is carried INTO the render now rather than left behind it.
- 2026-08-08 — M15 PR3 copy decisions: M14's arming gate
  (`recipient_unverified`) and a notifications outage
  (`notifications_unavailable`) are separate `ApiFailure` codes with separate
  sentences, because "we cannot reach anyone" and "you never confirmed your
  address" have completely different remedies (the M9 rule that a control firing
  must not read as an outage). `emergencyMessage` was briefly a SECOND message
  table and was collapsed back into `messageFor` — two copies of two sentences is
  the drift shape this repo keeps finding. Denial is one ungated tap and re-arming
  is step-up gated, which is the M6 asymmetry made visible on screen.
- 2026-08-10 — M15 PR4 security review (six discovery lenses over NAMED FILE LISTS
  — the M13 rule, and this range is 128 files / 12,263 insertions, exactly the
  size that stalled agents before — then TWO adversarial verifiers per candidate
  on different angles, production reachability and is-it-already-a-decision, both
  defaulting to refuted; 26 raw, 25 unique, 18 verified under the cap with the 7
  dropped LOGGED BY NAME and hand-verified, 10 survivors, 8 refuted). NINTH
  milestone running where every confirmed finding sits in machinery the milestone
  introduced, and most falsify a claim it made about itself.
  THE WORST ONE CROSSED THE BOUNDARY THE MILESTONE EXISTS TO CREATE, in the
  destructive direction. `POST /v1/auth/handoff/redeem` is unauthenticated by
  construction (the code IS the authority) and redemption GRANTED STEP-UP, while
  `POST /v1/vault/reset` is gated on step-up ALONE — deliberately, because a lost
  vault password cannot be proven. So a stolen 60-second handoff code
  crypto-shredded every item, the emergency escrow and the recovery keypair, with
  no vault password and no Secret Key. The sharp part is an escalation: script on
  the app origin CANNOT mint a handoff (minting is step-up gated) but can read one
  out of the hidden field it is posted in, so stealing a code converted
  no-step-up into step-up authority over Zone A — and the app origin is the weaker
  one, since M11 recorded that its `script-src` is not locked down because Next's
  inline bootstrap needs nonces. Isolation held for CONFIDENTIALITY (reaching the
  vault API is still not opening a vault) and not for DESTRUCTION.
  Fixed by granting no step-up on redemption and wiring the vault origin to prove
  its own factor through `POST /v1/auth/stepup` — the route PR1 widened for the
  `vault` audience with exactly this rationale and then left unwired, because the
  free step-up made it look unnecessary. Measured live after the fix: the redeemed
  session reports `mfaLevel: none`, `stepupExpiresAt: null`, and reset answers 403
  `stepup_required`.
- 2026-08-10 — REMOVING THE FREE STEP-UP BROKE VAULT SETUP, and only the live
  drive found it. `POST /v1/vault/keyset` is step-up gated too, so enrollment
  became the FIRST place a factor must be proved on this origin — and I had wired
  the prompt into reset, delete and publish but not setup, so a brand-new user was
  told "that action needs a fresh identity check" with no way to give one. Every
  gated action is wrapped now (setup, change-password, reset, item delete,
  recovery-key publish, escrow configure, rearm, revoke), and the old copy —
  "Open the vault again from Estate" — is gone from all of them, because
  re-opening MINTS A FRESH HANDOFF, which is the credential the change exists to
  devalue. The general shape: removing a capability that was silently satisfying
  several gates breaks every gate at once, and the unit suite stayed green because
  its fakes never returned `stepup_required` for those routes.
- 2026-08-10 — THE FINGERPRINT CEREMONY HAD ONLY ONE SIDE, which both verifiers
  rated high. The owner's screen shows the fingerprint of the key it is about to
  seal a share to and says "check this with them by phone or in person" — and the
  person on the other end of that call had NOWHERE to read their own, so the
  comparison could not be performed and the sole defence against a malicious
  server substituting its own key was a ceremony nobody could complete.
  `grantee_public_key_sha256` cannot help: it is derived client-side from whatever
  key the client was handed, so it binds to a substituted key just as happily. The
  grantee's own fingerprint is displayed now, computed from the key the SERVER
  serves back (the value an owner would see, so agreement rules out substitution
  on either leg) — verified live: the screen showed `BEM1-A582-HS7E-0JBJ` and the
  same digest computed from `vault_keysets.public_key` matched exactly.
- 2026-08-10 — AN M-of-N ESCROW ABOVE 1 COULD NEVER BE OPENED. `createEscrow`
  splits Shamir over the grantees exactly as M6 designed and the service stores
  it, but `releaseAndRecover` hands `recoverMasterKey` a SINGLE share, and release
  is one-shot per policy with no way for one grantee to collect another's. Arming
  2-of-3 therefore stored an arrangement nobody could open, and the first grantee
  to try would spend their own policy finding out. Refused at BOTH layers now —
  the screen and `configureEscrow` — because failing closed here means refusing to
  ARM, not arming something unusable. The capability stays in the protocol and the
  service; the field says plainly that this client cannot complete it yet.
- 2026-08-10 — PASSWORD CHANGE ACCEPTED ANY WELL-FORMED SECRET KEY, and my own
  first severity call on it was WRONG — recorded because the correction is the
  useful part. I called it critical and unrecoverable; a verifier refuted that and
  was right on both counts. The master key is unchanged and merely RE-WRAPPED, so
  the vault still opens with (new password + the key that was typed); and reaching
  the screen at all needs an OPEN vault, i.e. the correct password AND Secret Key,
  so an attacker there gains nothing they did not have. Real severity medium: a
  lockout only via a typo that survives the ONE-BYTE checksum (~1 in 256), plus
  three false claims — the field hint ("Unchanged by this"), the error copy ("That
  Secret Key does not match this vault", when nothing checked matching) and the
  success message. Fixed by asking for the CURRENT password too and verifying
  locally: re-derive this vault's AUK from the typed pair and use it to unwrap the
  master key already held. `open()` is an AEAD decrypt, so either wrong half fails
  authentication rather than returning garbage — and one message covers both, the
  2SKD rule the unlock screen already follows.
- 2026-08-10 — TWO OF MY OWN TESTS PROVED NOTHING, both found by this review.
  `fences.spec.ts`'s proxy-allowlist scan sliced on a COMMENT anchor while its
  input is `code()`, which strips comments — so `indexOf` returned -1,
  `slice(start, -1)` ran to the end of the file, and the fence scanned everything
  rather than the route table it is named for. It still went red under my
  mutation, which is why it survived: a scan that is too WIDE catches the planted
  defect and hides that it is not testing the stated layer. It anchors on the
  array's own closing bracket now, with a case asserting the slice EXCLUDES the
  handler below it, and mutation-tested in both directions. And
  `emergency-crypto.spec.ts` asserted the fingerprint equalled
  `publicKeyFingerprint(offer.data.publicKey)` — both sides computing over the
  same served key, i.e. f(x) === f(x), which holds just as well for a substituted
  key and so could not fail in the one case the ceremony exists for. It compares
  against the key the grantee's device published now, and a separate case
  substitutes an impostor key and asserts the displayed value CHANGES.
- 2026-08-10 — Also fixed in the round: `digestOf` in the emergency client was
  dead (no caller anywhere) and is deleted rather than tested — untested dead code
  in a Zone A module is worse than either alone; and the release path, which
  reconstructs the owner's key and immediately wipes it because no screen reads
  their items yet, now SAYS SO BEFORE the button is pressed rather than after,
  since release is one-shot and spending it for a message is worse than not
  offering it. The reader screen is deliberately a separate PR: holding a second
  owner's master key in memory needs its own retention decision, and appending it
  to a fix round is how that decision gets skipped.

- 2026-08-10 — M16 is THE VAULT BROWSER EXTENSION, and it is a milestone rather
  than a PR because three things in it are decisions rather than
  implementations. Autofill is a docs/00 §7 deliverable that M15 deferred with a
  reason; the extension is the SECOND client of the SRP/2SKD protocol, which is
  why it waited for M15 to settle the first. Five PRs: PR1 the boundary, the
  credential and the debts that credential makes acute; PR2 unlock + read; PR3
  matching + fill; PR4 writes + the release pipeline; PR5 the security review.
  Each PR carries its OWN docs delta — the M14 rule that a milestone which
  invalidates a sentence owns that sentence, and that deferring docs to the
  review means shipping code citing documentation that contradicts it. Full
  record in docs/04 M16.
- 2026-08-10 — M16 problem 1 (MV3 terminates service workers): KEYS LIVE AS
  NON-EXTRACTABLE `CryptoKey`s IN AN OFFSCREEN DOCUMENT, which is the only
  extension context that loads @estate/vault-crypto; the service worker holds
  nothing, `chrome.storage.session` holds no key material, and an offscreen
  teardown is a LOCK (fail closed). The brief's premise — "a non-extractable
  CryptoKey cannot be serialized" — is false in the direction that matters: it
  cannot go into `chrome.storage.session` (JSON) but it CAN be structured-cloned
  into IndexedDB and stay non-extractable across browser restarts. That fifth
  option is the one that "happens to work" and is REJECTED — not on
  serializability grounds but because it yields a vault permanently open with no
  password, no Secret Key and no TOTP, defeating 2SKD and docs/01 §5's
  re-auth-on-vault-open. Recorded as a claim to MEASURE in PR1, not as a fact.
  Raw bytes in `chrome.storage.session` rejected because docs/03 §4 TB6 says
  "where the platform allows" and here it does; a native-messaging host rejected
  as a second distribution artifact with keys outside the browser sandbox.
  Residual: while unlocked, code in the offscreen document decrypts everything —
  non-extractability stops EXFILTRATION, not USE. Chromium only, and the
  key-holder is one module so a second host is a port rather than a redesign.
- 2026-08-10 — M16 problem 1, second half: THE EXTENSION IS SERVER-ANCHORED, NOT
  A LOCAL VAULT. It caches item CIPHERTEXT and caches nothing that enables an
  offline unlock — no `wrapped_master_key`, no `srp_salt`, no `kdf_params` — so
  unlock is a real SRP-6a run with the step-up `srp/start` and `srp/verify`
  already require. MEASURED, and it confirms the shape rather than merely
  allowing it: `VAULT_SESSION_TTL_MS` is 15 minutes and vault's `sessions.repo.ts`
  has NO renewal path, so the ceremony is necessarily step-up → SRP → full sync
  (one `listItems` call returns full ciphertext blobs) → the vault session
  expires and stops mattering, after which the extension fills from the mirror
  until the client idle lock. REJECTED: caching the wrapped master key, which
  puts an offline brute-force target on disk and bypasses docs/01 §5 — a
  legitimate product choice, but one needing an approved deviation and a
  reversal of M15's persist-the-Secret-Key default, not a default. Residuals,
  stated rather than hidden: no unlock without connectivity, and picking up a
  credential saved on another device costs a full re-unlock. The client idle
  lock is 15 MINUTES, configurable 1–60 and never "never" — deliberately unlike
  the vault origin's 5, because a page you visit and an ambient extension are
  different things and a 5-minute extension lock trains people to raise it to
  the maximum.
- 2026-08-10 — M16 problem 2, ORIGIN MATCHING IS THE SECURITY PROPERTY, because
  filling the wrong origin IS credential exfiltration. Registrable domain via a
  VENDORED Public Suffix List snapshot — never a substring, never label
  stripping — carrying source/fetchedAt/sha256 with the digest pinned by a test
  and a staleness check, vendored because the extension has no runtime
  dependencies and must not fetch a security parameter at runtime. Scheme
  binding: an `https`-saved credential is never offered on `http`. Cross-origin
  iframes refused by default with a per-item opt-in. NEVER auto-submit, and
  never fill without a gesture in extension-owned UI: the content script is
  structurally unable to REQUEST a credential (its message union has no such
  variant and it cannot import the key-holder), and the fill is a one-shot
  `chrome.scripting.executeScript` into a specific frame at the moment of the
  gesture, so there is no standing channel a page can address. Page access is
  `activeTab` + `scripting` with NO declared content scripts — which also makes
  any later broadening a required-permission increase the browser surfaces as
  re-consent, the one supply-chain control the browser itself gives us.
  CONSEQUENCE, and it narrows a CLAIM rather than a control: with `activeTab`
  the extension has no view of a page until the user clicks it, so the
  lookalike check fires AT CLICK TIME. The extension REFUSES to fill on a
  confusable domain (UTS #39 skeletons, punycode, edit-distance-1 against the
  user's own saved domains) — refusing beats warning, the M12 rule — but it
  cannot warn someone sitting on a phishing page who never opens it. docs/03
  §6j must therefore say "refuses to fill on a confusable domain" and never
  "warns the user about phishing sites". Unchanged and stated on screen:
  AUTOFILL DOES NOT RESIST PHISHING, and filling a credential into a page gives
  that page the credential — the isolated world protects the extension's
  variables, not the DOM value.
- 2026-08-10 — M16 problem 3, THE SUPPLY CHAIN INVERTS M15's CENTRAL ARGUMENT:
  the vault origin's case is "what ships is what a reviewer reads", and an
  extension is a signed artifact auto-updated through a vendor store with no CSP
  in the path. The only control that works UNATTENDED is blast-radius reduction,
  so it comes first — a new `extension` audience admitted PER HANDLER to a
  strict subset, so AN EXTENSION SESSION CANNOT DESTROY A VAULT. Then minimum
  permissions held constant (the manifest's set declared as data and pinned by a
  test), reproducible builds (CI builds twice and compares digests), SLSA
  provenance via GitHub OIDC, and a verification procedure a third party can
  actually run, published in-repo and at a `/.well-known/` path. (CORRECTED in
  PR4b: the `/.well-known/` half was not a thing anyone may do — RFC 8615
  requires a well-known URI to be IANA-REGISTERED, so a path we invent is not
  one; the registered mechanism is `security.txt`'s `Policy:` field, and the
  vault edge's static handler additionally serves only four extensions, none of
  them `.txt`. Published in-repo, and the served path deferred with both
  obstacles named rather than the commitment quietly dropped.) Residual,
  unsoftened: a compromised update keeping the same permissions exfiltrates
  everything the user unlocks and THE PLATFORM CANNOT DETECT IT — a self-check
  is written by the same artifact and a reported version is one it controls.
  Reproducible builds make it discoverable by a third party, not prevented.
- 2026-08-10 — M16's `extension` route-admitter table, and why guard shape
  cannot be the discriminator. The vault service has 23 owner-facing routes —
  NOT the 22 this log has cited since M15, `GET /v1/vault/recovery-key` having
  arrived in PR3 — and the step-up-alone set contains BOTH the destructive
  routes (`reset`, `createKeyset`, `configure`, `rearm`, `revoke`,
  `publishRecoveryKey`) AND the two SRP legs an extension cannot function
  without. ADMITTED: vault's `keysetStatus`, `startUnlock`, `finishUnlock`,
  `listItems`, `lock`, plus identity's `session`, `stepUp` and `logout`; PR4
  adds `createItem` and `updateItem` in the same change as the callers.
  `refresh` WAS LISTED HERE AS A FOURTH IDENTITY ADMISSION AND IS NOT ONE —
  `AUDIENCE_ROUTE_ADMITTERS.extension` names three identity routes, and
  `POST /v1/auth/refresh` carries no guard at all, being unauthenticated by
  construction (the refresh token in the body IS the credential). The
  extension reaches it, and the reason is a different security argument
  entirely: there is no audience to admit, and a refreshed credential cannot
  become something more powerful only because `rotateTokens` is an in-place
  `UPDATE` whose SET list omits `audience` — an implementation accident this
  log records separately and M16 PR1 pinned with a test. Conflating "the
  extension may call it" with "an audience decision admits it" hides exactly
  that distinction. `getItem` is deliberately OUT — `listItems` already returns full
  ciphertext blobs, so it buys nothing an autofill client needs and every
  handler left out is authority not granted. The extension must NOT be added to
  vault's `ALLOWED_SESSION_AUDIENCES`: `CallerGuard.audiencesFor` returns
  `[...new Set([...serviceWide, ...perRoute])]`, a union that widens and can
  never narrow, so a service-wide grant would hand it all 23 routes including
  `release` (the one moment the platform half of a recovery key leaves the
  service) and `request` (which starts a §5.2 waiting period). EVERY OTHER
  VAULT ROUTE IS REFUSED, and this sentence deliberately no longer says how
  many: `apps/services/vault/test/session-audience.spec.ts` DERIVES the refused
  set from the controller prototypes and asserts the count, with the worst of
  them also named individually in `MUST_REFUSE` on the `mintHandoff`
  precedent — so the numbers live where they are measured. Both figures this
  entry used to carry were wrong by M21: it said EIGHTEEN refused, true when
  written and made false two PRs later by its own next sentence (PR4a moved
  `createItem` and `updateItem` into the admitted set, so the spec asserts
  sixteen), and it said the worst FOURTEEN were named when `MUST_REFUSE` holds
  twelve. A count in prose beside a fence that derives one is a second copy
  free to drift, and this one drifted in both directions at once.
- 2026-08-10 — M16 credential model, TAKEN AGAINST THE RECOMMENDATION AND
  RECORDED AS SUCH: pairing yields a refresh-capable `extension`-audience
  session rather than a device credential exchanged per unlock. Verified in
  shipped code before building, and the verification changed what has to ship.
  (1) The escalation question is CLOSED but only accidentally: `AuthService.refresh`
  never creates a session — `rotateTokens` is an in-place `UPDATE … WHERE id = $1`
  whose SET list omits `audience` — so the audience survives because there is no
  new row to carry it to. Nothing checks it and no test mentions it
  (`IssuedTokens` carries no audience field, so no caller of refresh can observe
  what it refreshed), and the standard hardening for a long-lived refresh token —
  rotating the session id, not just the tokens — would replace that UPDATE with
  an INSERT and silently mint an `account` session. PR1 pins the property with a
  test rather than leaving it an implementation accident. (2) `rotateTokens`
  does not write `expires_at`, so a session's absolute lifetime is fixed at
  creation: "long-lived" means choosing that number deliberately, and a paired
  extension HARD-EXPIRES and must be re-paired. (3) ROTATION-REUSE DETECTION IS
  A SELF-REVOCATION HAZARD UNDER MV3 — a service worker killed between receiving
  a rotated pair and persisting it presents the old token on next wake and
  revokes its own session. The security behaviour is right and is not weakened;
  the extension persists before use and treats revocation as "re-pair required",
  never as something to retry. That hazard does not exist in the per-unlock
  exchange model and is a direct cost of the choice.
- 2026-08-10 — M16 pairing is A TYPED HUMAN-READABLE CODE, MINTED ON THE APP
  ORIGIN — and the second half of that is a correction to the plan I proposed.
  The MECHANISM is M13's link-code shape (Crockford alphabet + canonical fold,
  already built) rather than `externally_connectable`, because for a
  once-per-browser ceremony the control is an ABSENCE: no permanent
  page→extension channel any script on the origin can address, and no extension
  id in the vault origin's config. The LOCATION was going to be the vault origin
  behind an open vault, and reading the shipped code showed it cannot be and
  should not be: the vault edge allowlists three EXACT identity routes and
  deliberately excludes `/v1/auth/handoff` because a vault session must not mint
  another credential — "a leaked one cannot chain itself forward". Minting there
  needs a fourth proxy entry plus a new identity route widened to the `vault`
  audience, and it would make that sentence false, chaining a leaked 15-minute
  no-refresh session into a 30-day refreshing one — the M15 PR4 shape
  re-committed. So pairing is an APP-ORIGIN ceremony on the `VaultLaunch`
  pattern (mint → shape-guard → step-up prompt with retry), account-audience +
  step-up, and the vault origin is untouched. Residual: app-origin script can
  read the code out of the DOM, which buys a paired extension that reaches
  CIPHERTEXT and still needs the vault password, the Secret Key and a TOTP —
  and which appears in the owner's device list.
- 2026-08-10 — M16: THE VAULT ORIGIN'S EDGE IS THE EXTENSION'S SINGLE FRONT
  DOOR, gaining an `Authorization: Bearer` path alongside its `__Host-` cookie
  path. Forced rather than chosen — the extension cannot use the BFF (it
  authenticates from cookies, so a bearer-bearing request arrives cookie-less
  and throws UNAUTHENTICATED), and identity and vault are private-subnet
  services with no other public front door. The edge already holds no
  credential, forwards the caller's own bearer and matches an exact allowlist,
  so this reuses the reviewed thing instead of opening a second door into Zone
  A, and it means the extension needs `host_permissions` for exactly ONE origin.
  The safety argument is that a hostile PAGE cannot set an `Authorization`
  header cross-origin without a CORS opt-in this edge must never give, while an
  extension with host permission bypasses CORS by design. `/api/auth/refresh`
  joins the allowlist: it is a rotation of an existing credential rather than a
  mint, so it confers nothing on a vault session, which has no refresh token by
  construction.
- 2026-08-10 — M16 adds STEP-UP ATTEMPT COUNTING, closing the half of docs/03
  §6a's rate-limiting residual that a long-lived extension credential makes
  reachable. Capping step-up bounds the SRP path TRANSITIVELY, because vault's
  `srp/start` and `srp/verify` are themselves step-up gated — one chokepoint for
  both. DERIVED from the append-only `auth_events` ledger (`stepup.denied` newer
  than the latest `stepup.granted`, in a rolling window) rather than a new
  counter: no new table, no new write path, and a count an attacker cannot
  reset. Keyed on the USER, never the session or a resolved row — the M14
  round-2 lesson, where the email-verification cap was decorative because a
  wrong guess produced a different digest and no counter moved. A cap-refusal
  emits its OWN kind (`stepup.rate_limited`) and NOT `stepup.denied`, or the
  counter feeds itself and a retrying client locks its own user out
  permanently. A rolling cooldown, NEVER a sticky lock: a sticky step-up lock
  would be a denial-of-service primitive against the OWNER, reachable by anyone
  holding a stolen credential, blocking vault open, document generation, export,
  beneficiary changes and deletion at once — the M6 rule pointed the wrong way.
  5 denials / 15 minutes as reviewed CONSTANTS, not config (the
  `TEMPLATE_CACHE_TTL_MS` precedent). WebAuthn writes the same `stepup.granted`
  kind so both factors clear the window; failed WebAuthn assertions are
  deliberately NOT counted (not brute-forceable, and they emit their own kind).
  NO owner notification, deliberately: identity is not a holder of the
  notifications SEND credential (M14 — "the service that mints sessions must not
  be able to ring 'a death report was filed on your account'"), and adding it
  for a nice-to-have would contradict a decision one milestone old. The failure
  mode is moot by construction — the count is an indexed read on the connection
  the step-up already needs.
- 2026-08-10 — FIVE DEFECTS IN SHIPPED CODE, found by verifying M16's plan
  before writing any of it, all fixed in PR1 because every one sits in machinery
  M16's credential model leans on. (1) A FENCE THAT WAS DOCUMENTED AND NEVER
  WRITTEN: `004_session_audience_and_handoffs.sql` states the audience
  vocabulary is closed in three places and that "a spec reads this file to pin
  the first to the second" — no such spec exists anywhere;
  `session-audience.spec.ts` imports `SESSION_AUDIENCES` and scans SERVICE
  SOURCE, never a `.sql` file. Latent only because the two lists agree today,
  and M16 is exactly the change that diverges them. The 2026-08-07 lesson one
  degree worse: not a fence that stopped matching, but one that never existed
  while a migration cited it. (2) `SessionsRepo.create` takes
  `audience?: SessionAudience` and binds `input.audience ?? 'account'` — a
  FAIL-OPEN DEFAULT in the one function that decides what a session may be spent
  on, in a repo whose rule is deny by default. Made required; two call sites.
  (3) THERE IS NO USER-REACHABLE WAY TO REVOKE ANY SESSION BUT YOUR OWN:
  `revokeAllForUser` has exactly one caller, behind `ServiceCredentialGuard` on
  the settlement lock, and identity exposes no session listing, no revoke-by-id,
  and no password-change or password-reset route at all — so the classic
  implicit mass-revoke does not exist either. Tolerable while every session is
  one cookie-bound browser; acute the moment a 30-day rotating credential sits
  on a device, invisible on every screen and killable only by presenting its own
  token, i.e. not killable at all in the stolen-laptop and compromised-update
  cases the M16 roadmap entry itself names. (4) `HandoffService.mint`'s
  `audience` parameter is typed as the FULL union, so `mint(u, s, 'account')`
  type-checks and only `auth_handoffs`' `CHECK (audience IN ('vault'))` stops
  it — the one constraint an audience-widening milestone is tempted to touch.
  (5) NO INDEX ON `auth_events` EXISTS in identity's migrations at all, so M7's
  owner-liveness interlock scans that table today on the docs/03 §5.1 path; the
  index the step-up counter needs pays a debt it did not create.
- 2026-08-10 — M16 PR1 therefore SHIPS THE PRODUCT'S FIRST SESSION-MANAGEMENT
  VERTICAL, as a precondition rather than a feature: a paired-devices list with
  per-row revoke, which needs a live-sessions read in `sessions.repo.ts` (which
  does not exist), a new identity route with its own audience decision,
  `audience` added to `IdentitySession`, `SessionSchema`, the `Session` GraphQL
  type and its persisted operation, and a REGENERATED APQ manifest — the M8 PR5
  defect class, where an operation added to `operations.ts` but not regenerated
  is green in dev, tests and CI and dead in production. It is also the first
  place the product surfaces "revoke someone else's session", a verb identity
  has reserved for the settlement lock. The M6 asymmetry applies verbatim:
  pairing is step-up gated, revoking is one ungated click.
- 2026-08-10 — M16 says NO to displacing autofill with passkey provisioning, and
  corrects the premise that made the swap look cheap. docs/00 §7 lists autofill
  as a deliverable and passkeys appear nowhere in docs/00. More to the point,
  identity's WebAuthn machinery is a RELYING PARTY (`@simplewebauthn/server`,
  `verifyRegistrationResponse`, credentials for Estate's own login);
  provisioning passkeys for third-party sites means implementing an
  AUTHENTICATOR — conditional-mediation interception, per-RP keypair generation,
  a sync format, and an RP-id matching rule at least as strict as M16's origin
  rule — and essentially none of identity's code is reused. It is a LARGER
  milestone, not a cheaper swap, and it gets its own. The estate's institutions
  (banks, brokerages, insurers, transfer agents, county recorders)
  overwhelmingly do not offer passkeys, and a vault that cannot fill them is a
  vault nobody uses — which means the estate's credentials never get recorded,
  which is the whole reason feature 7 exists in an estate product. Running both
  in one milestone was rejected too: two authenticator surfaces in one milestone
  is how both get half-reviewed.
- 2026-08-10 — M16 adds a TRUST BOUNDARY the model does not have: TB9, the
  extension against arbitrary web pages, in docs/03 §3 with its own §4 STRIDE
  block and a §6j delta. §3 enumerates TB1–TB8 and none of them is this — TB6 is
  the client DEVICE, and the adversary here is an arbitrary PAGE reached over a
  channel that did not previously exist. Writes from the extension are
  `createItem` + `updateItem` and never `deleteItem`, deferred to PR4 so PR3 can
  prove the page boundary read-only first: `vault_items_versions` captures
  `UPDATE OR DELETE`, so an overwrite is recoverable and deletion is the
  step-up-gated destructive verb. And `@estate/vault-crypto` gains its SECOND
  declared importer, so the fence asserting WHO MAY IMPORT IT — the one M15 PR1
  did not ship among its seven — lands as data in PR1, BEFORE the second
  importer exists.
- 2026-08-10 — THE IMPORTER FENCE WAS PROMISED IN TWO PLACES AND WRITTEN IN
  NEITHER, until the end of PR1. The entry directly above and docs/04 M16 both
  said it "lands as data BEFORE that importer exists"; a repo-wide grep found
  nothing. That is the SAME defect PR1 opens by fixing — migration 004 citing a
  spec that pinned its CHECK to the TypeScript union, where no such spec existed
  — committed by me one entry later, in the sentence describing this fence.
  Recorded rather than quietly corrected, because the citation is the harm: a
  fence a document claims and nobody wrote is worse than one nobody claimed,
  since the claim is what stops the next person looking. Now shipped as
  `packages/vault-crypto/test/declared-importers.spec.ts`: a
  `VAULT_CRYPTO_IMPORTERS` table carrying a REASON per entry (which packages is
  answerable from the lockfile; why each is allowed is not), scanned in both
  directions over manifests AND comment-stripped source, with an anti-vacuity
  floor. It counts the browser consumer by the path it ACTUALLY loads
  (`/lib/vault-crypto/`, served from the vault origin's own tree) rather than by
  the bare specifier — a fence looking only for `@estate/vault-crypto` would
  miss the one consumer that ships this code to a user's device, which is the
  opposite of the point. Mutation-tested five ways: an undeclared importer, a
  real importer dropped from the table, a phantom entry, a vacuous scan, and
  blindness to the served path each turn it red on the assertion that names the
  property.
- 2026-08-10 — M16 PR1 slice A: the SESSION-AUDIENCE VOCABULARY MOVED to
  @estate/contracts and the ENFORCEMENT stayed in @estate/auth-guard, because a
  consumer exists that cannot follow it — the BFF labels sessions with the
  audience and deliberately does not depend on auth-guard, a NestJS guard
  package having no business inside the edge. `MfaLevelSchema` travelled the
  same way for the same reason and sits on the adjacent line. auth-guard
  re-exports, so every existing importer is unchanged and there is still exactly
  one definition. `DEFAULT_SESSION_AUDIENCE` is typed as the LITERAL rather than
  widened to the union, so `audience === DEFAULT_SESSION_AUDIENCE` narrows the
  other branch — the fence that walks the audience tables needs that narrowing,
  and the annotation was throwing away which member it is.
  Also in slice A: `SessionsRepo.create`'s `audience` is REQUIRED (the compile
  error immediately found a THIRD mint path, in an int spec, that had been
  silently receiving `account`); `HandoffService.mint`'s audience parameter was
  DELETED rather than narrowed, since nothing passed it and M16 pairs extensions
  through their own ceremony — a future audience adds it back in the same change
  as its DDL widening, which is strictly better than finding the knob already
  there and assuming the database agrees; and `005_auth_events_index.sql` adds
  the first index `auth_events` has ever had, which is a debt rather than a
  feature (M7's owner-liveness read has been a sequential scan on the docs/03
  §5.1 chain since it shipped). Recorded in that migration: the migrator runs
  every file inside BEGIN/COMMIT, so `CREATE INDEX CONCURRENTLY` is structurally
  inexpressible — fine on an empty table, and whoever first runs it against a
  populated one must build the index out of band and let `IF NOT EXISTS` make
  the migration a no-op.
- 2026-08-10 — TWO WAYS TO FAKE A MUTATION TEST, both committed by me in one
  session and both worth the entry because neither is visible in a green run.
  (1) `git checkout --` IS NOT A MUTATION-REVERT FOR UNCOMMITTED WORK. Mutating
  a fence and reverting with git works only while the file is clean; used on the
  fence I was in the middle of writing, it silently restored HEAD and deleted
  the fence, and the "baseline" that followed was green because it was testing
  the OLD file — the count dropping from 15 to 10 was the only tell. Revert from
  a saved copy when the file under test is itself the work. (2) A MUTATION THAT
  DOES NOT MUTATE READS EXACTLY LIKE A TEST THAT CANNOT FAIL. A column-order
  mutation of `005` appeared to prove the ordering assertion toothless; in fact
  `String.replace` with a string argument replaces the FIRST occurrence, which
  was the same tuple written in the comment above the DDL. The statement was
  never touched. Both cases produce the same symptom — a mutation that stays
  green — and the response has to be to verify the artifact actually changed
  before concluding anything about the test.
- 2026-08-10 — M16 PR1 slice C, the step-up cap AS BUILT. `deniedSinceLastGrant`
  counts `stepup.denied` newer than the latest `stepup.granted` within a rolling
  window, both branches served by the index `005` added; the refusal is 429
  `too_many_attempts` with its own ledger kind and its own audit action
  (`auth.stepup.rate_limited`, the FIRST step-up outcome audited — individual
  denials are deliberately not, being ordinary noise, while hitting the cap is
  at most one event per window and is the burst signal docs/03 §4 TB1 asks for).
  The gate runs BEFORE the code is checked, so an exhausted caller never causes
  the TOTP secret to be read and the refusal's timing cannot vary with whether
  the guess was right. Proven at BOTH layers and said out loud in both files:
  the unit suite fakes the repo and therefore proves only the DECISION, and
  `stepup-cap.int.spec.ts` drives the real `AuthService` over the real repo
  against Postgres — the M14 round-2 lesson applied before it could bite, since
  a test that called the repo directly would prove the primitive that was
  already right and say nothing about the decision that could be wrong.
- 2026-08-10 — M16 PR1 slice C, THE PAIRING CEREMONY. A readable `EP1-…` code
  minted on the APP origin under step-up (account audience only, undecorated =
  deny by default, named by its own test for the same reason `mintHandoff` is),
  displayed for the user to type into the extension, redeemed UNAUTHENTICATED —
  the extension has no session yet, so the code is the only selector and there
  is nowhere in the request to name an account (§6g). Redemption yields an
  `extension`-audience session with a REAL refresh token, which is the whole
  difference from M15's handoff and the reason the audience is admitted per
  handler to a set that yields ciphertext and cannot destroy. NO STEP-UP is
  granted, per the M15 PR4 rule that an unauthenticated redeem route must not
  produce a step-up-fresh session while `POST /v1/vault/reset` is gated on
  step-up alone. Session lifetime is a HARD 30 days — `rotateTokens` does not
  write `expires_at`, so refresh cannot extend it and a paired extension must be
  re-paired, which costs a fresh step-up. TTL is 10 MINUTES, taken from the
  journey (screen → popup, one sitting) rather than from M14's mailbox or M13's
  phone call or M15's sixty seconds for a code no human ever sees. NO ATTEMPT
  CAP COLUMN, deliberately: a cap can only count attempts it can ATTRIBUTE, and
  a wrong guess against an unauthenticated route resolves no row — the exact
  shape that made M14's cap decorative until it was re-keyed onto the user, and
  there is no user here until redemption succeeds. The bound is 160 bits plus
  the short TTL, which is `auth_handoffs`' argument unchanged.
- 2026-08-10 — M16 PR1 slice C, THE PRODUCT'S FIRST SESSION-MANAGEMENT VERTICAL:
  `GET /v1/auth/sessions` and `DELETE /v1/auth/sessions/:id`. It is a
  precondition rather than a feature — before M16 a session was a cookie in one
  browser and the only thing anyone could do to it was present it, so there was
  nothing to list; a 30-day extension credential that outlives the browser and
  appears on no screen is what makes the absence intolerable. THE LOAD-BEARING
  PIECE IS `revokeOwned`: the existing `revoke(sessionId, …)` takes an id and NO
  owner, which is right for its callers (logout already holds a verified
  session, the settlement lock is a service credential acting on a whole
  account) and catastrophic for a route where the id arrives in the URL — any
  authenticated caller could have killed any session in the product. The owner
  predicate rides the UPDATE rather than sitting in a check above it (the M13
  `contact_in_use` race), and the boolean it returns is what lets the route
  answer a UNIFORM 404 for "no such session" and "not yours" alike, so the reply
  is no oracle for whether an id names something real. Revocation is NOT
  step-up gated while minting a pairing is — the M6 asymmetry, and the reason is
  concrete here: a user who thinks their extension is compromised must not be
  sent to find an authenticator first. Both routes are account-audience only; an
  extension enumerating the owner's other devices is reconnaissance, not
  function. The list deliberately returns ids, audience and timestamps and NOT
  `ip_ct`/`device_id`, which exist as columns and are written by nothing —
  returning them would be a promise the data cannot keep.
- 2026-08-10 — M16 PR1: `audience` FINALLY CROSSES THE BFF, and the defect was
  an absence rather than a mistake. Identity has RETURNED the field on its
  introspection response since M15 and the BFF silently discarded it — `z.object`
  strips unknown keys, so there was no parse error, no log and no failing test,
  and "the BFF has no audience" read like a missing identity field when it was a
  missing line in one schema. It matters now because a paired-devices list has
  to say "browser extension" rather than "a session". Threaded through
  `IdentitySession`, `SessionSchema` (tolerant `.default()` for an identity that
  predates the field, on the verifier's reasoning — only identity mints a
  non-account audience, so an identity old enough to omit it has none to
  describe; an UNRECOGNISED value still fails the parse), a `SessionAudience`
  GraphQL enum, `SessionPayload`, and an exhaustive `AUDIENCE_GQL` Record so a
  fourth audience is a COMPILE error rather than an unmapped value reaching a
  client. THE APQ MANIFEST WAS REGENERATED, which is the M8 PR5 trap paid rather
  than re-sprung: a field added to the document without it is green in dev,
  tests and CI and dead in production with "Operation not allowed". And
  `apps/bff/test/helpers.ts` held a HAND-COPY of the same document, which
  `persisted.spec.ts` hashes — so the suite would have stayed green while
  executing a document no client sends. Updated, with the hazard written next to
  it, because the BFF does not depend on the web app and the copy cannot be
  derived away without a package neither wants.
- 2026-08-10 — `readable-code.ts` EXTRACTED, because M16 would have been the
  THIRD byte-identical copy of the same base32 derivation and fold (M13's
  `ESL1-`, M14's `EV1-`, now `EP1-`) — the M8 PR2 shape where seven audit
  producers shared one bug because there was one behaviour and several places to
  fix it. Identity's two ceremonies now share it and `email-verification.service`
  re-exports the old symbols so every importer is unchanged. PROFILE'S COPY
  REMAINS, and that is stated in the module rather than left to be discovered:
  it is a different service, sharing would need a package, and unifying a
  shipped M13 ceremony is a change to M13 rather than a part of M16. Two copies
  is worse than one and better than three.
- 2026-08-10 — MY MUTATION HARNESS LIED TO ME TWICE MORE, in the two remaining
  ways it can, and both made RED LOOK GREEN — the dangerous direction. (1) THE
  OBSERVATION was broken: passing two spec files to jest drops it out of verbose
  mode, so no `✕` lines are printed, and a grep for `✕` reported nothing while
  four tests were failing. Six mutations in a row read as "no test catches
  this". (2) THE MUTATION was broken, again — a `node -e` inside shell quotes
  lost `$1` to expansion, so the SQL predicate was never changed and its green
  read as a coverage gap. The fix for both is the same shape and it is now the
  rule: a mutation harness is a FILE, not a `node -e` string; it VERIFIES the
  bytes changed and throws if they did not; and the observation asserts on the
  summary line, not on a decoration that depends on jest's output mode. With
  that in place all six mutations turn red on the assertions that name the
  property. A corollary worth keeping: the guard caught a third case honestly —
  an anchor of `const ok = await this.checkTotp` also matches the TOTP-ENROLMENT
  path earlier in the file, so `end < start` and the harness refused rather than
  silently mutating nothing.
- 2026-08-10 — AND A TEST OF M15's THAT WAS ALREADY NAMED FOR A PROPERTY IT
  NEVER TOUCHED, found by slice A rather than by the review. `handoffs.int.spec`
  asserted "a session created without an audience IS an account session" and
  commented that it proved "the migration's DEFAULT" — but its row was seeded
  through `SessionsRepo.create`, which bound `input.audience ?? 'account'`, so
  the INSERT always named the column and the DDL default was never once
  exercised. It measured the TypeScript fallback while claiming to measure the
  DDL. Deleting that fallback left it asserting that a value written two lines
  earlier comes back. It inserts in RAW SQL with the column omitted now, which
  is the only path that reaches the default, and a mutation of the DDL default
  turns it red — a mutation the previous version was blind to.

- 2026-08-10 — M16 PR1's SECURITY SURFACE ships in the same PR as the routes it
  calls, so the milestone closing the repo's zero-callers gaps does not open one
  of its own. THE PAGE HOLDS ONE STEP-UP PROMPT AND THAT IS STRUCTURAL: it can
  now be refused for three reasons (the demo export, the standalone elevation,
  minting a pairing code), and `StepUpPrompt` labels its field "Confirm it's
  you" for EVERY caller — so two open at once are two identical inputs neither a
  person nor a query can tell apart, which is the M15 PR3 defect verbatim. One
  `StepUpTarget` admits one at a time and every other opener is disabled while
  it is up (asserted live: all three buttons `disabled=true`). The retried
  action is bound WHERE IT IS RENDERED rather than selected from state
  afterwards, so the M13 review's worse defect — a shared handler running a
  different action than the one refused — has no shape to reoccur in.
- 2026-08-10 — REPLACING THE PAGE'S PRE-M13 STEP-UP FORM FIXED TWO LIVE DEFECTS
  IT WAS HIDING. That form labelled its input "6-digit code", the same label as
  the enrollment field two sections up, so the collision the M15 lesson warns
  about was ALREADY on this page. And it reported a rejected TOTP code through
  `messageFor`, so identity's `invalid_credentials` — which it answers for a
  wrong code exactly as for a wrong password — became "that email and password
  combination didn't work" on a form with neither field on it. That is the M12
  finding, whose fix landed on the consent controls and the document generator
  in 2026-08-06 and never came back here; the ENROLLMENT form had it too, and
  both use `stepUpMessageFor` now. The rule the two cases share is narrower than
  "step-up": a form whose only field is an authenticator code must never explain
  a refusal in the vocabulary of a password. The standalone "Verify your
  identity" control STAYS despite every action now prompting inline — it is the
  §5.1 rescue path the people surface links to by name, and a step-up is what
  writes `stepup.granted` and voids a death case.
- 2026-08-10 — REVOKING THE CREDENTIAL YOU ARE HOLDING GOES THROUGH LOGOUT.
  Both kill the same row; only logout also expires the two cookies carrying it,
  and revoking without clearing them leaves a browser that still looks signed in
  over a dead session — what the M8 logout entry calls the worst outcome. Every
  other row is one ungated click (the M6 rule: minting the pairing code is the
  gated half, and someone who believes their extension is compromised must not
  be sent to find an authenticator first). A row says what a credential can
  REACH rather than where it is, because identity deliberately returns no IP and
  no device name — those columns exist and nothing writes them — which makes the
  device list the one place a user reads the boundary M16 exists to create.
- 2026-08-10 — `PAIRING_UNAVAILABLE` exists because `startExtensionPairing`
  reused `VAULT_UNAVAILABLE` for a malformed identity response, and that code's
  copy reassures the reader "nothing about your vault has changed" on a screen
  where nothing was opening a vault — the M12 collision one surface over, in
  machinery M16 wrote three commits earlier. `VaultHandoffSchema` became
  `MintedCodeSchema` in the same change: a schema named for the first ceremony
  that used it is how a reader concludes two ceremonies are the same thing.
- 2026-08-10 — `GQL_ERROR_CODES` WAS A SECOND COPY NOTHING CHECKED, and the
  failure it permits is the M9 rule inverted: `extractErrorCode` narrows against
  that list and anything unrecognised becomes `UNKNOWN`, so a code the BFF adds
  and the app misses renders A CONTROL FIRING AS AN OUTAGE, silently, with both
  sides' suites green because each list is internally consistent.
  `error-codes.test.ts` reads `identity-client.ts` and asserts EQUALITY in both
  directions (a code the app keeps after the BFF drops it is dead copy, and the
  next reader cannot tell which of the two happened) — the compose-parity
  mechanism, because apps/web cannot import a Nest package. Its ANTI-VACUITY
  FLOOR earned its place immediately: the first version ended the union at the
  next `;`, one member's doc comment has a semicolon in its prose, and the scan
  silently saw nine codes of twenty-eight. A fence that stops matching goes
  green, which is the 2026-08-07 lesson; the floor is what turns that red.
- 2026-08-10 — M16 PR1 driven live against a stack rebuilt so EVERY service runs
  M16 code — otherwise the refusals are the unknown-audience parse rather than
  the deny-by-default table, and the claim being measured is not the one being
  made. A code minted through a real TOTP step-up, redeemed at identity, giving
  an `extension` session that answers 200 on `GET /v1/vault/keyset`, 403
  `stepup_required` on both SRP legs and 403 `vault_locked` on `items`/`lock` —
  admitted by audience and stopped by the NEXT control, so reaching the API is
  still not opening a vault — and 401 on `vault/reset`, both keyset writes,
  `recovery-key`, every emergency-access route, `POST /v1/auth/handoff` (it
  cannot chain itself forward), `POST /v1/auth/extension/pairing` (it cannot
  mint another), `GET /v1/auth/sessions` (it cannot enumerate the owner's
  devices), and on assets, profile, documents, the assistant, plaid and
  settlement. It then appeared in the owner's own list as "Browser extension",
  was revoked in one click with no prompt, and answered 401 on every route
  probed afterwards. The trail carried `stepup.granted` →
  `pairing_minted {retired:false}` → `paired {audience:extension}` → four
  `pairing_failed` with NO actor and EMPTY detail — the uniform refusal
  preserved in the audit stream as well as on the wire.
  NARROWED, because the first version of this sentence said the credential was
  "dead everywhere a second later" and that does not generalize.
  `HttpSessionVerifier` caches POSITIVE introspections for
  `DEFAULT_CACHE_TTL_MS` (30s), so a peer that introspected the token inside
  that window keeps accepting it for the remainder of the TTL; my probe missed
  the window only because minutes of image rebuilding sat between the boundary
  probes and the revoke. What was measured is what is now claimed. The general
  rule this repo keeps restating, turned on myself in the same session I applied
  it to somebody else's diagnosis: a run that happened to observe a property is
  not evidence that the property holds. The downstream half — that a user
  pressing Revoke is told "immediately" while a peer may honour the credential
  for up to 30 more seconds — is a docs/03 §6j residual whose fix is COPY rather
  than a shorter TTL, since shortening it would put an introspection on every
  request in the product.
- 2026-08-10 — The live drive found two things no unit test had, the pattern
  holding for the ninth milestone running. THE SESSION CARD LIED ABOUT ITSELF:
  it kept reading "Step-up not fresh" immediately after a pairing code had been
  minted through a genuine step-up, because only the standalone verify path
  re-read the session — a security page stating the opposite of its own current
  state, about exactly the thing the page exists to report. Fixed with a
  `withSessionRefresh` wrapper that re-reads once an action SETTLES, not on
  every poll (a `stale` outcome means the peer has not caught up, and re-asking
  identity would change nothing). And the row with the longest description
  wrapped its button onto the next line while its neighbours kept theirs on the
  right, so the button moved with the prose — the M10 PR4 shape, a layout
  inconsistency no assertion would have caught.
- 2026-08-10 — RECORDED, NOT FIXED: events emitted while the AUDIT CONSUMER was
  still running pre-M16 code never reached `audit_events`. An action the
  consumer does not know is a `schema_violation` to it, indistinguishable from
  malformed input — so a rolling deploy with identity ahead of audit loses the
  events for the window, in the one log whose completeness is the point.
  Observed as ABSENCE and no more than that: the old container's logs did not
  survive its restart, so the rejection was read out of `ingestor.ts` rather
  than seen, and this entry says so rather than claiming evidence it does not
  have (the 2026-08-06 rule turned on myself again). Deploy contracts consumers
  first; nothing enforces it.
- 2026-08-10 — A FLAKY TEST WAS THE DEFECT SHOWING ITSELF FOR A FEW MICROTASKS.
  CI went red on `StepUpPrompt`'s "a fresh submission re-arms after an earlier
  cancel" while it passed locally 5/5, and the obvious reading — a scheduling
  artifact, since the button's label is `waiting ? 'Applying…' : busy ?
  'Checking…' : submitLabel` and the test re-submits by a `/Confirm/` query — was
  incomplete. Reproduced deterministically by removing the test's microtask
  drain, and the diagnostic printed the answer: after Cancel the submit button
  was DISABLED and reading "Checking…". `abandon()` set the abort flag and called
  `onCancel()`, leaving an interactive form to be restored by the continuation of
  the request being cancelled — which happens whenever that request settles, and
  NEITHER AWAIT IN `submit` HAS A TIMEOUT. A stalled identity call therefore left
  a consent form the owner had declined permanently disabled, with a page reload
  as the only remedy. The M6 rule stated for a new case: THE PROTECTIVE ACTION
  MUST NOT BE CONTINGENT ON THE PERMISSIVE ONE FINISHING. `abandon` clears
  `busy` and `waiting` itself now.
- 2026-08-10 — CLEARING `busy` ON CANCEL OPENS A HAZARD, WHICH IS WHY THE ABORT
  BOOLEAN BECAME AN OWNERSHIP COUNTER. With the form interactive again the owner
  can start a SECOND attempt while the first is still in flight, and `submit()`
  re-arms consent on the way in (deliberately — cancelling one attempt must not
  veto the next). A boolean cannot tell "nobody owns this any more" from
  "somebody else does", so the abandoned request would see consent restored BY A
  DIFFERENT SUBMISSION and run the action a second time — the M13 round-3 defect
  reachable again through its own fix. `activeAttempt` is bumped by every submit
  and every abandon, and a continuation proceeds only while the number it
  captured is still live. Two consequences worth stating: the abandoned path no
  longer clears `busy` (either `abandon` did, or a newer attempt owns it and
  clearing it would re-enable a form mid-flight), and the counter SUBSUMES the
  boolean rather than sitting beside it — one mechanism, because two that must
  agree are two that can drift.
- 2026-08-10 — Measured rather than assumed, and it corrected my own framing:
  the component fix and the test fix are NOT independently sufficient. With the
  component fix present the test passes under the exact adverse scheduling that
  reproduced CI EVEN WITH ITS WAIT REMOVED; with the component fix reverted it
  fails even WITH the wait. So the component change is what makes the gate
  deterministic, and the added `waitFor` is a stated precondition rather than the
  repair — worth keeping for saying out loud what the test depends on, worth not
  crediting with more than it does. The `/Confirm/` matcher was left alone: the
  busy labels are signal, and loosening the query would have deleted the only
  thing that made the wedge visible at all.
- 2026-08-10 — M16 PR2 SPLIT IN TWO (approved), making the milestone six PRs
  rather than five. docs/04 lists PR2 as "unlock + read", a reading that assumed
  the extension already existed — PR1 shipped the BOUNDARY (the audience, the
  pairing ceremony, the paired-devices surface) and no extension at all. PR2a is
  therefore the M15 PR1→PR2 precedent verbatim: the artifact, its transport and
  its fences, with NO key material behind them, so PR2b lands SRP unlock and item
  read on a path that already works. What PR2a visibly does is one sentence —
  type a pairing code, and the popup reports whether the account has a vault —
  and that sentence exercises pairing → token storage → refresh → the vault
  edge's new bearer path → the vault service's per-handler audience admission,
  end to end, with nothing cryptographic in the way.
- 2026-08-10 — THE MV3 OFFSCREEN `reason` ENUM HAS NO VALUE THAT DESCRIBES
  HOLDING VAULT KEYS, which the M16 brief did not know when it chose an offscreen
  document. The enum is closed (TESTING, AUDIO_PLAYBACK, IFRAME_SCRIPTING,
  DOM_SCRAPING, BLOBS, DOM_PARSER, USER_MEDIA, DISPLAY_MEDIA, WEB_RTC, CLIPBOARD,
  LOCAL_STORAGE, WORKERS, BATTERY_STATUS, MATCH_MEDIA, GEOLOCATION) and the
  honest options were: declare something untrue, drop the offscreen document and
  re-unlock on every popup open (TOTP + vault password + Secret Key each time —
  unusable), or move the UI to a side panel. DECIDED: keep the offscreen
  document, declare `WORKERS`, and MAKE THAT TRUE by running the blocking
  2048-bit SRP `modPow` in a real `Worker` — synchronous bigint math that wants
  off-thread anyway. The residual is stated rather than hidden: a Worker that
  exists partly to make a manifest declaration accurate. Applies to PR2b; PR2a
  declares no `offscreen` permission because it holds nothing. Measured while
  deciding: an offscreen document with a non-`AUDIO_PLAYBACK` reason has NO
  lifetime limit, and only one may exist per extension.
- 2026-08-10 — THE EXTENSION BYPASSES CORS, AND THAT IS WHY THE EDGE NEEDS NO
  PREFLIGHT. Verified against chromium.org rather than assumed: extension PAGES
  and service workers bypass CORS for hosts in `host_permissions`, while CONTENT
  SCRIPTS do not and are subject to the page's own origin policy. Two
  consequences. The vault edge answers no preflight and sets no
  `Access-Control-Allow-Origin` — the property its CSRF defence rests on stays
  exactly as M15 left it. And the asymmetry aligns with docs/03 TB9, where the
  content script must be structurally unable to reach the vault: the platform
  enforces half of that before we write a line.
- 2026-08-10 — THE EDGE'S CREDENTIAL PRECEDENCE IS ONE RULE, NOT A FALLBACK
  CHAIN: `Authorization: Bearer` wins when present, the `__Host-` cookie is read
  only in its absence, and a request carrying both never looks at the cookie.
  Cookie-first-with-bearer-fallback was rejected because it would let a paired
  device's request silently travel on whatever browser session happened to be in
  the jar, and "which credential did that actually use" is not a question this
  edge should ever be ambiguous about. `GET /api/grantee-candidates` stays
  COOKIE-ONLY — the one Zone B read on this origin belongs to the interactive
  vault session someone is sitting in front of choosing grantees, not to a
  credential stored on a device — and that is defence in depth rather than the
  control, since profile admits only the `vault` audience there anyway. THE EDGE
  DOES NOT RE-IMPLEMENT THE AUDIENCE TABLE: the services decide what an
  `extension` session may reach, PR1 measured it end to end, and a second copy
  here is a second copy that drifts.
- 2026-08-10 — TWO CREDENTIAL-FREE ROUTES ON THE EDGE, AND A METHOD THAT CANNOT
  CARRY A CREDENTIAL. Pairing redemption and refresh are unauthenticated BY
  CONSTRUCTION at identity — the code is the authority for one, the refresh token
  in the body for the other — so neither fits `PROXY_ROUTES`, whose handler
  requires one. They are a separate exact-match table reaching a new
  `Upstream.passThrough` that HAS NO BEARER PARAMETER AT ALL: an optional
  credential on `proxy` would be a fail-open shape where the next caller forgets
  the argument and the request silently goes out anonymous, so anonymity is
  expressed in the type instead. Both keep the CSRF header — free for the
  extension, one rule for every `/api/` route — with a comment saying plainly
  that for these two it is noise reduction and not the control. Refresh through
  the edge is what keeps docs/04's "one `host_permission`, one origin"; the
  residual is one more unauthenticated identity route reachable from the vault
  origin, unreadable cross-site because the edge sets no CORS headers.
- 2026-08-10 — THE EXTENSION'S ORIGIN IS READ BACK OUT OF ITS OWN MANIFEST.
  A `host_permissions` entry is a literal the browser reads before any code
  runs, so it cannot come from runtime configuration — and M8 PR5's lesson is
  that a baked value must then be ASSERTED rather than assumed, because the web
  image once shipped a rewrite pointing at itself and every test passed over it.
  So there is no second constant: `config.ts` reads the manifest, refuses
  anything but exactly one exact origin, and the code physically cannot address
  a host the manifest does not permit. Tokens live in `chrome.storage.local` and
  not `session`, because pairing is deliberately once per browser and needs a
  step-up on the APP origin to repeat — a device that forgot its pairing on every
  restart would send people through that ceremony daily, and the predictable
  result is an unpaired extension. THE REFRESH TOKEN IS THEREFORE ON DISK, and
  what bounds it is the AUDIENCE rather than the storage (docs/03 §6j).
- 2026-08-10 — AN OUTAGE MUST NOT WEAR THE FACE OF A REVOCATION, which is the M9
  rule pointed the other way and the sharpest decision in PR2a's client. The
  popup FORGETS the credential on `UNAUTHENTICATED`, because after a refresh
  attempt that code means the session is genuinely gone — revoked from the
  owner's paired-devices list, or expired. So `withSession` distinguishes a
  REFUSED refresh from an UNREACHABLE one and reports the transport failure as
  itself: without that, a wifi blip would un-pair a perfectly good device and
  send someone back through a step-up ceremony because their connection dropped
  for a second. Disconnect follows the M8 PR5 logout rule in the same shape —
  revoke first, clear storage only if something was actually revoked — and
  refreshes a stale access token BEFORE spending it, because identity's logout
  needs a live one and the unauthenticated `logout/refresh` route M8 added for
  exactly this case is one the vault edge deliberately refuses to proxy.
- 2026-08-10 — TURBO WAS NOT CACHING HALF OF TWO PACKAGES' BUILDS, found by
  building the repo in a fresh git worktree. `outputs` listed `dist/**` only, so
  `@estate/vault-crypto`'s `dist-esm` (the BROWSER build) and `vault-web`'s
  `public/app` + `public/lib` were undeclared — and an undeclared output is not
  merely uncached, it is ABSENT after a cache hit, because turbo skips the build
  and restores nothing. Turbo then reports a package successfully built that is
  missing half of itself: the failure is silent in the direction that matters,
  and it surfaced as `vault-web`'s copy step failing ENOENT against a dependency
  turbo considered done. A restored cache would also have served the Zone A
  origin with no browser client at all. Declared per package rather than
  globally, so `public/app`/`public/lib` cannot start meaning something in
  `apps/web`, which has a `public/` of checked-in assets. Proven by deleting all
  three directories and watching a `FULL TURBO` hit restore them.
- 2026-08-10 — M16 PR2a driven live against the running stack, with the edge run
  as a HOST process from the worktree so the shared containers were not
  disturbed. A real pairing code minted through a real TOTP step-up, then every
  assertion made THROUGH THE NEW EDGE: redemption returned a token pair; a
  replay of the same code returned the uniform `{"error":"invalid_code"}`;
  `GET /api/vault/keyset` answered 200 while `items` and `lock` answered 403
  `vault_locked` (admitted by audience, stopped by the next control — reaching
  the API is still not opening a vault); `vault/reset` and `grantee-candidates`
  answered 401; `handoff` and `logout/refresh` answered 404 without leaving the
  process. Refresh rotated the pair IN PLACE (same session id, new access token)
  and `/v1/auth/session` still reported `audience: extension`, so a refreshed
  credential cannot become something more powerful. Precedence held: bearer +
  junk cookie 200, junk bearer + junk cookie 401, malformed Authorization 401,
  no CSRF header 403. Logout returned 200 and sent NO Set-Cookie to a caller
  that has no cookie.
- 2026-08-10 — AND THE LIVE DRIVE REPRODUCED THE REVOCATION RESIDUAL, WITH
  NUMBERS. After logout, identity refused the token IMMEDIATELY (401 at t+0)
  while the VAULT kept honouring it through the edge at t+0 and t+10 and refused
  it from t+20 — the tail of `HttpSessionVerifier`'s 30-second positive
  introspection cache, which had an entry because the boundary probes moments
  earlier had populated it. This is the same residual the other M16 session
  recorded in docs/03 §6j from the paired-devices surface, and the same one that
  made my own PR1 sentence ("dead everywhere a second later") an
  over-generalisation of a run that happened to miss the window. Now measured
  rather than reasoned about, from both ends.
- 2026-08-11 — M16 PR2b: THE KEY LIVES IN A WORKER, WHICH MAKES THE OFFSCREEN
  `reason` SIMPLY TRUE. PR2a found the MV3 offscreen `reason` enum closed with
  no value describing "hold vault keys", and the approved answer was to declare
  `WORKERS` and MAKE it true by moving the blocking SRP maths off-thread.
  Building it, a better shape appeared: if the WORKER HOLDS THE KEY rather than
  merely computing for it, the declaration stops being one made true and becomes
  structurally true — the offscreen document's entire job is to spawn and host
  the worker, which is exactly what the reason says. It is also stronger. The
  master key is a non-extractable `CryptoKey` created inside the worker that
  never crosses a boundary; the compute-here-hold-there split would have had to
  move either a `CryptoKey` (serializable, but relying on that) or the raw master
  key BYTES across `chrome.runtime`, a channel every extension context receives.
- 2026-08-11 — THE OFFSCREEN DOCUMENT IS NOT A TRUST BOUNDARY, and the code says
  so rather than letting the architecture imply it. `chrome.runtime.sendMessage`
  delivers to EVERY extension context with a listener, so the vault password and
  Secret Key in an `unlock` message transit a broadcast the service worker also
  receives and ignores by `target` — a filter, not isolation. All extension
  contexts are one signed artifact and one trust domain. What the offscreen
  document buys is LIFETIME (an MV3 service worker is terminated in seconds; a
  non-audio offscreen document has no limit) and NON-EXTRACTABILITY, not secrecy
  from the popup. Anyone who can read that channel has already compromised the
  artifact and could simply ask the worker to decrypt. docs/04's "the service
  worker holds nothing" is therefore a STORAGE rule, not an isolation claim.
  What the split does buy is auditability: the key holder cannot fetch (`api.ts`
  is the one call site) and the host cannot decrypt (only the holder may import
  the crypto), so "can anything derived from the password leave the device" has
  one file to read.
- 2026-08-11 — A WRONG VAULT PASSWORD WOULD HAVE DISCONNECTED THE DEVICE, caught
  before it shipped. The vault service answers `401 srp_failed` for a failed
  handshake, and the extension's `failureFor` mapped every unlabelled 401 to
  `UNAUTHENTICATED` — which on this surface means the DEVICE's pairing is gone
  and makes the popup forget the credential. A mistyped vault password would have
  un-paired the extension: a per-attempt mistake with an account-level
  consequence, costing a step-up on the app origin to undo. `SRP_FAILED` is its
  own code now, and still ONE code for a wrong password, a wrong Secret Key and a
  locally malformed one, because the server answers one `srp_failed` and naming
  the half would tell someone holding a stolen Secret Key that it is the right
  one. The general shape is the M9 rule again: two failures that need different
  remedies must not share a token.
- 2026-08-11 — THE SECRET KEY IS REMEMBERED ON DISK WITH AN OPT-OUT (approved),
  mirroring `vault-web` — and the differences are named rather than inherited.
  The alternative is retyping 26 characters at every unlock, and with a
  15-minute vault session that cannot be renewed that is many times a day; the
  reliable result is the Secret Key in a text file, which is worse. It is written
  ONLY after a key has actually opened the vault, so a typo is never persisted as
  the device's key, and disconnecting forgets it — a device that is no longer
  paired has no business holding half the key material for an account it cannot
  reach. IndexedDB over `chrome.storage.local` for `vault-web`'s reasons (raw
  bytes rather than a base64 string; not in the flat key list sweeps walk),
  neither of which hides anything from code running in this extension. RESIDUAL,
  recorded in docs/03 §6j: this artifact already keeps a 30-day refresh token on
  disk, so two of three factors now sit on one disk missing only the password —
  and unlike the vault origin, this is a signed artifact auto-updated through a
  vendor store with no CSP in its path. What it still does not buy is an OFFLINE
  unlock: the wrapped master key, the SRP salt and the KDF parameters arrive per
  unlock and are never stored.
- 2026-08-11 — "A RECORD WITH NO TITLE" AND "CONTENT THIS BUILD CANNOT READ" ARE
  DIFFERENT FACTS. A JSON array passed the item envelope's bare
  `typeof === 'object'` check and listed as an item with an empty title, which
  claims the first when the truth is the second — and a user acts on them
  differently. Arrays are refused now and the row lists as unreadable, which is
  the same rule M15 PR2 applied to a blob the AEAD rejects: shown as present
  rather than hidden, because somebody must be able to see that something is
  there.
- 2026-08-11 — ENTRY FILES ARE EXCLUDED FROM COVERAGE, AND THE EXCLUSION IS
  BOUNDED BY A FENCE. `background.ts`, `offscreen.ts`, `vault-worker.ts` and
  `main.ts` are the wiring the PLATFORM calls — a service-worker registration, a
  `new Worker`, a `self.onmessage` — around modules the suite drives directly,
  and a test that stubbed the platform to reach them would only prove the stub.
  Excluding them is honest; leaving the exclusion unbounded would not be, because
  logic could then accumulate where nothing measures it. `fences.spec.ts` asserts
  each stays under twenty lines and contains no loop, switch or error path. The
  fence's FIRST version also refused a single `if` guard and was simply wrong
  about what it protected: a one-line guard IS wiring, and the line cap is the
  real bound.
- 2026-08-11 — A COVERAGE FLOOR WENT DOWN, AND IT IS WRITTEN IN THE CONFIG RATHER
  THAN QUIETLY APPLIED. PR2b measured 97.94/91.41/96.70/99.38 — statements,
  branches and lines up; FUNCTIONS DOWN 97 → 96, a floor set two commits earlier
  in the same PR. The package roughly tripled in size after that number was
  measured, and the two functions still uncovered are the IndexedDB `onerror`
  callbacks in `secret-key-store.ts`, which `fake-indexeddb` will not provoke and
  which the store's own fails-soft case already covers from the outside.
  Contriving a test to reach them would have measured the contrivance. The rule
  stays "ratchet up, never down"; this is the exception, and an exception that is
  stated is the only kind worth having.
- 2026-08-11 — TWO OF MY OWN TESTS WERE WEAKER THAN THEIR NAMES, both found by
  mutation rather than by review. The verify-response shape case omitted ONE
  field and survived a mutation deleting two of the five guards, because the
  remaining three still caught that payload — table-driven now, one case per
  field. And the list-ORDERING claim could not be proved by a fixture holding one
  item, so the stand-in service seals a row per title and hands them back
  reversed. Same lesson as the M13 entry this repo keeps citing: a test named for
  a property must exercise the layer that property lives in.
- 2026-08-11 — A FLAKE OF MY OWN, fixed the way I had told the other M16 session
  to fix theirs that morning. The unlock path grew an IndexedDB write between the
  reply and the redraw, so a fixed `setTimeout(0)` in the screen test was
  intermittently one macrotask short. It polls to a deadline now — wait for the
  condition, do not race it — which is the same correction, applied to my own
  code within hours of writing it down.
- 2026-08-11 — THE IndexedDB PREMISE IS MEASURED AT LAST, and the brief was
  wrong about it. The M16 roadmap rejects persisting a non-extractable
  `CryptoKey` in extension IndexedDB on CEREMONY grounds (it would yield a vault
  permanently open with no password, Secret Key or TOTP), and explicitly NOT on
  the brief's serializability grounds — which this file recorded as "a claim to
  MEASURE in PR1, not as a fact". PR1 did not measure it. Measured now, in a
  real Chromium: `structuredClone` of a non-extractable `CryptoKey` SUCCEEDS and
  the clone is still `extractable: false`; IndexedDB accepts it; and after a page
  navigation it reads back as a `CryptoKey`, still non-extractable, with
  `exportKey` still refusing and an AES-GCM round trip still working. The
  premise is false in the direction that matters. THE REJECTION IS UNCHANGED and
  is stronger for it: it never rested on serializability, and a key that
  persists this well is exactly what makes the ceremony argument bite. Two parts
  remain unmeasured and are handed over rather than claimed — survival across a
  full BROWSER RESTART, and the same sequence on a real `chrome-extension://`
  origin. The probe for both is a SCRATCH unpacked extension, deliberately never
  committed: a key-persistence harness living inside the artifact that must not
  persist keys is the wrong thing to be right about, and the measurement is
  evidence rather than a feature.
- 2026-08-11 — A CI FAILURE ON `main` WAS A TEST SELECTOR MATCHING AN ANCESTOR,
  and the previous diagnosis was wrong in a way worth keeping. `vault-web`'s
  step-up specs advanced the prompt with `querySelectorAll('form')` filtered by
  `querySelector('#stepup-code')` — but the prompt renders into a `<div>` INSIDE
  the form of the action it guards, so the step-up form is NESTED and the
  ancestor's `querySelector` finds the field too. The filter matched BOTH and
  dispatched submit on the guarded form as well, silently starting a THIRD
  enrollment: a full PBKDF2 at 650k that nothing awaits, whose `renderSecretKey`
  continuation repaints "Save your Secret Key" over whatever screen is showing
  whenever it lands. On a fast machine it landed inside its own test and merely
  repainted a screen already there; on a loaded CI runner it OUTLIVED the test
  and repainted the NEXT one's unlock screen, so the following test waited out
  its full 30s deadline looking at a screen it had already clicked past — going
  BACKWARD through the flow, which is the detail that ruled out slowness. MEASURED
  rather than reasoned about: three `POST /api/vault/keyset` where two are
  legitimate, dropping to two under the fix. Fixed with `input.form` — the HTML
  form owner, i.e. the nearest ancestor form, which is the prompt's own — hoisted
  into a `submitStepUp` helper so the pattern cannot be copied again.
  THE PIN IS A COUNT, not a wait: a stray async action is invisible on a fast
  machine and intermittent on a slow one, and only the number never varies. The
  file header had blamed contention and credited a file split with curing it;
  splitting reduced the RATE and removed nothing, and the header now says so —
  a comment claiming an unproved cause is what stops the next person looking.
  Also measured and reported as a NON-finding: the identical loop in
  `screens-emergency.spec.ts` fired no duplicate (2 calls either way, the arming
  action being a button rather than a submit), so that change is the pattern
  removed, not a second defect fixed.
- 2026-08-11 — M16 PR3 SPLIT IN TWO (approved), making the milestone seven PRs.
  Origin matching is the boundary's DEFINING control — docs/03 §4 TB9 puts it
  first because *a filled credential belongs to the page that received it*, and
  the isolated world protects the extension's variables rather than the DOM
  value, so the origin decision IS the disclosure decision. PR3a therefore lands
  the decision logic and proves it with NO code running in any page; PR3b lands
  the content script, the one-shot injection and the gesture requirement. Same
  reasoning as the PR2a/PR2b split: the review of the matcher is not tangled up
  with the review of the page boundary.
- 2026-08-11 — MY OWN SCOPE CLAIM WAS WRONG, and the test caught it before the
  code shipped. The confusables decision was taken on the stated basis that
  "punycode + edit-distance-1" catches the realistic cases, `rn`/`m` named among
  them. It does not: `exarnple.com` is TWO edits from `example.com` (substitute
  `m`→`r`, insert `n`), so a distance-1 check calls it `no-match` — refused for
  filling, but never FLAGGED, and `rn`/`m` is the most-cited homograph there is.
  Rather than weaken the test to match the code, the code gained a POOR MAN'S
  SKELETON: fold the short list of ASCII sequences that actually get used
  (`rn`→`m`, `vv`→`w`, `cl`→`d`, `1`→`l`, `0`→`o`) on BOTH sides and compare.
  Deliberately not UTS #39 — the full skeleton algorithm needs a vendored
  Unicode confusables table and is a named follow-up (docs/03 §6j) — and every
  miss remains a REFUSAL, so the failure is a missing explanation and never a
  wrongful fill.
- 2026-08-11 — MATCHING HAPPENS IN THE KEY HOLDER, because the item's `url`
  lives inside the encrypted blob. The alternative — return each item's domain
  to the popup and match there — would disclose a list of every site the user
  has an account with in order to answer a question about ONE origin. So the
  worker protocol gains a single `matches(rows, pageUrl)` variant returning only
  what relates to the page: a `match`, or a refusal worth explaining. `no-match`
  and `unusable` are dropped, so the caller learns nothing about unrelated
  items, and NO variant returns a secret — that stays PR3b's deliberate act.
- 2026-08-11 — A VERDICT, NOT A BOOLEAN. `no-match` and `confusable` are
  different facts: one means nothing is saved here, the other means something is
  saved somewhere that LOOKS like here, which is the moment worth telling
  someone about. `scheme-downgrade` is a third. Collapsing them would make a
  refusal indistinguishable from an absence — the shape this repo keeps finding
  (M10 PR4's readiness statuses, M9's "a control firing must not read as an
  outage"). §4 TB9 commits to REFUSING a confusable rather than warning, so the
  popup SHOWS the refusal and offers nothing on it; `isFillable` is true for
  exactly one verdict.
- 2026-08-11 — THE PUBLIC SUFFIX LIST IS VENDORED, DIGEST-PINNED, AND COMPILED
  TO A MODULE — the last part forced by a fence rather than chosen. `api.ts` is
  the extension's only network call site, so reading the packaged `.dat` at
  runtime would mean `fetch(chrome.runtime.getURL(...))` and either a breach of
  that fence or a widening of it to admit "local" fetches. The fence is worth
  more, so `scripts/build-psl.mjs` emits `src/psl-data.ts` and the transformation
  is deliberately trivial (drop comments and blanks, exactly what the PSL spec
  says a parser does). `vendor/public-suffix-list.dat` stays byte-for-byte as
  published, licence header included, and is the pinned artifact; the test
  regenerates from it in a subprocess and compares, so a committed generated file
  cannot drift from the bytes the digest covers. Staleness is reported with a
  DELIBERATELY GENEROUS one-year bound: a stale list fails in one narrow
  direction (an unknown new suffix yields a shorter registrable domain), and a
  check that fails weekly is one people learn to bump.
- 2026-08-11 — `activeTab` IS THE NARROWEST THING THAT COULD WORK, verified
  before it was relied on: it grants the active tab's URL at INVOCATION and is
  revoked on navigation, and no `tabs` permission is needed to read `url` that
  way. Script injection additionally requires `scripting` — which is exactly the
  PR3a/PR3b line, so PR3a adds `activeTab` alone and the manifest fence still
  refuses `scripting`, `content_scripts` and `web_accessible_resources` with
  PR3b named against each. Reading a URL is not running code in a page.
- 2026-08-11 — A STEP-UP PROMPT MAY NOT BE HOSTED INSIDE THE FORM IT GUARDS.
  `promptForStepUp` renders a `<form>`, and `renderSetup` and `renderItem` both
  hosted it in a `note` that sat INSIDE their own form. A form nested in a form
  is invalid HTML no parser would build — but this origin builds its DOM
  imperatively (`createElement`/`append`, the Trusted-Types posture), so the DOM
  API accepts what the parser forbids and the tree was real. Nothing about it
  was visual: it made `document.querySelectorAll('form')` ambiguous about which
  form holds the code field, and PR #67 is what that ambiguity cost — a spec
  helper selecting "every form CONTAINING `#stepup-code`" matched the ancestor
  too, submitted the guarded action a second time, and started an enrollment
  nothing awaited whose `renderSecretKey` repainted a later test's screen. #67
  fixed the helper (`input.form`, the form OWNER); this removes the shape the
  helper walked into, so the trap is gone rather than merely unvisited — the
  repo's own rule that a fence protecting an invariant is weaker than not having
  the invariant to protect. Both hosts moved out; DOM order is unchanged.
  SETUP ALSO ENROLLS ONCE PER SUBMIT, behind an in-flight guard released in a
  `finally`. The submit button is disabled while an enrollment runs, so a second
  CLICK never got through and this is DEFENCE IN DEPTH rather than a reachable
  bug — stated plainly rather than dressed up. What it bounds if reached is not
  small: a second enrollment mints a second master key and overwrites the first
  keyset, so whichever `renderSecretKey` continuation lands LAST is what the
  user is told to save — a Secret Key for a keyset the server no longer holds,
  on the one screen shown exactly once and never again. `renderItem`'s delete
  prompt is deliberately NOT guarded the same way: `screens-actions.spec.ts`
  re-clicks Delete to retry a refusal, so re-entry there is the intended
  behaviour, and changing it silently would be a different decision wearing this
  one's clothes.
  Each of the three changes was mutation-tested by reverting it from a saved
  copy and confirming the pin goes red. That harness caught one of my own
  mutations that changed BYTES BUT NOT BEHAVIOUR — putting `note` back into the
  form's children is a no-op while `replaceChildren(main(), …, note)` still
  re-parents it straight out, so a faithful revert needs both halves. The
  2026-08-10 rule restated: a mutation that does not mutate reads exactly like a
  test that cannot fail.
- 2026-08-11 — THE PSL SHIPPED U-LABELS AND EVERY HOST ARRIVES AS AN A-LABEL, so
  459 of the vendored list's 10,239 rules could NEVER MATCH — found while
  scoping M16 PR3b, fixed as its own PR before it. `URL.hostname` applies IDNA
  (`a.公司.cn` → `a.xn--55qx5d.cn`) while the published list writes
  internationalised suffixes in Unicode, and `labelsMatch` compares raw strings.
  So for every IDN registry the longest match fell back to the bare TLD, every
  registrant under it collapsed onto ONE registrable domain, and `matchOrigin`
  answered `match` for two different registrants: `bank.公司.cn` and
  `shop.公司.cn` both resolved to `xn--55qx5d.cn` and compared EQUAL — a
  credential offered on somebody else's site, which docs/03 §4 TB9 calls the
  boundary's defining failure and which `registrable-domain.ts` names in its own
  docstring as the reason it uses the list at all. The ASCII path was always
  correct, which is exactly why 300 tests passed over it, and why the milestone
  doc's own sentence ("never from a substring and never from label stripping")
  was false in the paragraph asserting it. MEASURED BEFORE BELIEVED: an agent
  found it by reading and said plainly it had not executed the module; running
  it is what turned a plausible reading into a defect, and the same run supplied
  the numbers. Converted at GENERATION time — the vendored `.dat` stays
  byte-for-byte as published (it is what the digest pins), the runtime stays a
  plain string compare with no IDNA in the hot path, and no IDN implementation
  enters a package whose whole posture is zero dependencies; `!` and `*.` are
  stripped before conversion, and a rule with no A-label form is REFUSED rather
  than emitted, because a rule that matches nothing is the failure being fixed.
  The regenerated diff is exactly 459 lines, which is the measured count and not
  a target: conversion is a verified no-op on all 9,780 ASCII rules.
  THE MUTATION HARNESS EARNED ITS PLACE TWICE. It caught that two of the three
  branches — marker stripping and the refusal — were untestable by the shipped
  list (no rule combines a marker with a non-ASCII label, and none fails
  conversion), so both went green under mutation and would have rotted unread:
  the M13 round-3 rule that an exception nobody triggers in a test is an
  exception nobody has read, arriving in the same session that cites it. Pinned
  now by a subprocess probe (ts-jest cannot import a `.mjs` — the drift check's
  own precedent), after which all three mutations turn red.
  Latent while PR3a had no fill. PR3b is what would have made it exploitable,
  which is the whole argument for fixing it first rather than alongside.
- 2026-08-11 — M16 PR3b BEGAN BY MEASURING THE PLATFORM IN A REAL CHROME 151,
  and the measurement corrected shipped code, two documents and one of my own
  research agents. A scratch unpacked extension (never committed — the PR2b
  precedent) against a page carrying all three frame shapes on
  resolver-mapped fake hosts, with `host_permissions` deliberately ABSENT so
  `activeTab` was the only grant in play. FOUR ANSWERS, none of them assumed.
  (1) THE GRANT IS HOST-EXACT AND DOES COVER SAME-ORIGIN SUBFRAMES: top and a
  same-origin child injected; `pay.example.test` under `example.test` and
  `other.test` were both refused with "Cannot access contents of the page".
  So PR3a's `frameIsAllowed` — same registrable domain plus same scheme, on the
  reasoning that "a same-site iframe is the page" — was MORE PERMISSIVE THAN THE
  PLATFORM, computing "allowed" for a frame the fill could only ever fail on,
  which puts the refusal at the bottom of the stack as an opaque platform error
  instead of at the top as a decision. Narrowed to same-ORIGIN via `URL.origin`,
  which asks the platform's own question rather than a proxy for it. The
  per-item cross-origin OPT-IN IS DELETED, not deferred: honouring it needs
  `optional_host_permissions` + a runtime `chrome.permissions.request()`, a
  manifest key and consent surface this milestone does not have, so the flag
  could never be honoured — the M4 zero-callers shape with an extra step.
  docs/03 §6j described it as a live control and is corrected.
  (2) `allFrames: true` RETURNS PARTIAL RESULTS SILENTLY — two of four frames
  came back, `ok: true`, no error. MDN states the opposite for Chrome ("any
  missing permission prevents any execution"); that is false on 151. The shape
  is the dangerous one, because a caller cannot tell "no such frame" from "not
  permitted", so the fill targets ONE named frame and infers nothing from a
  count.
  (3) THE ISOLATED WORLD SOLVES THE REACT-TRACKER PROBLEM FOR FREE, which
  contradicts the recommendation I was given. Both a naive `el.value =` and the
  prototype-setter dance fired the change event, because the page's
  own-property `value` setter lives in the page's world and is INVISIBLE from
  the isolated world — so a naive assignment already reaches the native setter
  and leaves the tracker stale. The "you must use
  `HTMLInputElement.prototype`'s setter" advice is correct for page-context
  scripts and unnecessary for an extension. Scoped honestly: measured against a
  faithful mimic of React's tracker mechanism, not against React itself.
  (4) AN INJECTION OUTLIVES THE POPUP: issued and not awaited, with the popup
  closing in the same turn, it was still delivered and executed. Only the
  popup's own promise continuation dies with its context — so a popup may issue
  a fill and close, and may not observe the outcome.
  AND A FIFTH, UNPLANNED: Chrome 151 has DISABLED `--load-extension` (removed
  ~137 after malware abuse) and the `DisableLoadExtensionCommandLineSwitch`
  override is gone. Three rig attempts produced nothing until that was
  diagnosed rather than guessed at — no extension in the profile, none among
  the CDP targets. It is not a rig annoyance: docs/04 commits PR4 to a
  "third-party-runnable verification procedure", and any recipe phrased as
  "load it unpacked with `--load-extension`" is no longer runnable by anyone.
  Both docs/04 passages are corrected.
  TWO OF THE THREE FAILED ATTEMPTS WERE MY OWN ERRORS, recorded because the
  second is the more instructive: a leftover `--disable-extensions-except`
  whitelisting one path refused the manual load I had just asked for, and my
  results endpoint omitted `Access-Control-Allow-Methods`, so the JSON POST
  would have failed its CORS preflight and the findings would have vanished in
  transit even had the probes run. A measurement rig needs the same "did this
  actually report, or merely not fail" discipline as a fence — which is why the
  extension now announces its own load.
- 2026-08-11 — M16 PR3b WAS DRIVEN IN A REAL CHROME AND FOUND THE DEFECT THAT
  MADE PR2b INERT: AN OFFSCREEN DOCUMENT CANNOT READ ITS OWN MANIFEST. Measured,
  with the popup as the control — the popup's `chrome` carries
  `action, dom, extension, i18n, management, offscreen, permissions, runtime`
  while the offscreen document's carries `loadTimes, csi, runtime` and nothing
  else: no `getManifest`, no `chrome.storage`. `config.ts`'s `vaultOrigin()` read
  the origin back out of `chrome.runtime.getManifest()` — deliberately, so there
  was ONE copy of the value and nothing to drift against — and the key holder
  lives in an offscreen document, so every vault request threw there. `api.ts`
  caught it and returned `NETWORK`, so the product told the user to CHECK THEIR
  CONNECTION. M16 PR2b shipped an extension that could never unlock a vault.
  Nothing in jsdom could have caught it: `test/chrome-double.ts` supplies
  `getManifest` unconditionally, so THE DOUBLE WAS MORE GENEROUS THAN THE
  PLATFORM — the fixture lesson this repo keeps relearning, one layer beneath
  the fixtures, and the reason a double must be faithful about absences and not
  only about values.
  A SECOND, MASKING DEFECT sat on top: `vaultOrigin()` was called INSIDE the
  `try` whose `catch` returns `NETWORK`, so a CONFIGURATION error wore a
  CONNECTION error's words. That is what hid it for a whole PR — the message
  named the one thing that was not wrong. It is resolved before the `try` now.
  FIXED BY GENERATING THE ORIGIN AT BUILD TIME (approved): `src/origin.ts` holds
  the dev default and `build-package.mjs` substitutes the same `VAULT_ORIGIN` it
  writes into the manifest, after the same validation. That is a SECOND PLACE
  the value appears, which is exactly what the old design existed to avoid, so
  it is a second place that is CHECKED rather than trusted: `manifest.spec.ts`
  builds a real package and asserts the two agree — derived from each other, not
  both compared to a literal — plus a case proving the build REFUSES when the
  substitution would be a no-op. A wrong constant cannot widen reach, because
  `host_permissions` is what the browser enforces; it would produce refused
  requests, which is how this presented in the first place.
  The obsolete describe was REWRITTEN, not deleted (the third time this PR),
  and it now includes a case that calls `vaultOrigin()` with NO `chrome` at all
  — stricter than the offscreen document, where it exists but is nearly empty.
  THE END-TO-END DRIVE, against the running stack with a real account, a real
  TOTP step-up, a real SRP unlock and an item sealed by the same
  `@estate/vault-crypto` the worker opens: pairing 200, step-up 200, unlock
  `{status: unlocked}`, PR3a matching `{kind: match, domain: example.test}`, and
  PR3b's fill returning the credential for its own page while refusing BOTH
  `other.test` and the lookalike `exarnple.test` with an indistinguishable
  `null` — even though the caller named the item explicitly, which is the whole
  shape of the variant. Then the injection itself, verified IN THE PAGE rather
  than from the popup's own message: the password and username filled, the
  page's React-style value tracker FIRED (`data-change-count` 1 — so a naive
  `el.value =` from the isolated world really is enough, and the prototype-setter
  dance really is unnecessary), `document.activeElement` still `BODY` (nothing
  focused, therefore no `blur`), the URL unchanged with nothing submitted, and
  the SAME-ORIGIN SUBFRAME LEFT EMPTY — the top-frame-only decision holding in
  reality rather than in a comment.
  THREE FALSE STARTS, all mine, all worth the entry because each was a wrong
  thing to believe rather than a wrong thing to type. (1) The stack's `vault-web`
  container predated PR2a's pass-through table, so pairing 404'd — a STALE
  ARTIFACT, diagnosed by comparing the edge (404) against identity directly
  (401) rather than by reading code. (2) I stored the paired session under a key
  I INVENTED (`estate.vault.session`); the real one is `estate.session`, so the
  popup kept showing "Connect to Estate" while I insisted it was paired. (3) The
  rig's own `run.mjs` exits after its wait window and took the page server with
  it, so the tab became a Chrome error page and the fill correctly reported "no
  password field was found" — the extension behaving WELL under a condition I
  had broken, and the distinction `inject.ts` draws between "the injection ran"
  and "it filled something" earning its place.
- 2026-08-11 — M16 PR4a (extension writes) TOOK TWO DECISIONS THAT NARROWED IT,
  and an adversarial pass caught a defect in my own first commit before either.
  THE GRANT SHIPPED AHEAD OF ITS CALLERS: the audience widening for
  `vault:createItem`/`vault:updateItem` landed while `sealItem` was reachable
  from nothing — the M8 zero-holder-edge shape, against the rule that same
  commit quoted ("in the same change as the callers"). It resolves at PR
  granularity because the repo squash-merges, but the observation was right and
  the callers followed immediately rather than next week. The same pass found
  FIVE SENTENCES I had falsified and not fixed (the controller docstring plus
  four counts in docs/03), and two claims that were overclaiming: docs/03 §4's
  "cannot destroy a vault" survives only for the KEYSET — an unlocked extension
  can overwrite every item — and migration `006_extension_audience.sql` also
  says "five vault routes" and must NOT be corrected, because the migrator
  checksums applied files and would raise `MigrationDriftError` on every
  deployment that has run it. A migration records what was true when it ran; the
  live count lives in the spec that derives it.
  DECISION 1 — AUTHORING IS TYPED IN THE POPUP, never captured from a page.
  Capture needs a page observing form submissions, i.e. a standing content
  script, which PR3b refused and the manifest fence forbids. So the write
  surface adds NO page surface. The cost is a missing "save this login?" prompt,
  which is what people expect from a password manager, and it is stated rather
  than quietly absent.
  DECISION 2 — AN EDIT NEEDS NO READ, and this is the one I would defend
  hardest. Editing normally means reading the item back and rewriting it whole,
  which would have made the popup a GENERAL VAULT READER — today it cannot open
  an item at all (`summarise` gives titles, `fillFor` gives one credential and
  only for a matching page). Instead the key holder MERGES: the caller sends
  only the fields it is changing, decryption and re-sealing happen inside, and
  the plaintext it did not send is never sent back. Absent means unchanged,
  because a blank field must not erase a password the user cannot see; an
  explicit empty string is a real value (the profile-SSN distinction). The cost,
  on screen: clearing a field is not expressible in the extension.
  THE VERSION IS THE SUBTLE PART. The service writes `locked.blob_version + 1`
  after comparing `If-Match` to the row it locks, and the version is inside the
  AEAD's AAD — so an update must seal for the SUCCESSOR of what it read while
  sending what it read in the header. Reversed, the row lands unopenable and
  NOTHING IN THE RESPONSE SAYS SO. The item summary therefore carries the
  version it was read at: re-reading it at write time would make `If-Match` pass
  every time and defeat the whole check.
  SHARPEST CONSEQUENCE, named by the critique rather than by me: the item's
  `url` lives INSIDE the blob and `fillFor` re-decides the origin from it, so
  ANYTHING THAT CAN WRITE AN ITEM CAN REPOINT WHERE ITS CREDENTIAL FILLS. The
  origin control is not bypassed, it is FED. It buys persistence rather than
  access — writing already needs an unlocked vault — but it outlives the session
  in which it was done. Write and fill are one trust level.
  Three closed-set fences fired, once per widening (`seal`, `reseal`,
  `create`/`update`), each a compile error naming the new variant; the popup
  union had NO exhaustive test before this PR and now has one. And the refusing
  test double refuses each new variant — last time I gave one a double that
  quietly SUCCEEDED, which made a locked-vault assertion pass for the wrong
  reason.
  TWO SHELL MISTAKES WORTH THE ENTRY, both the same class as the mutation
  harness lying: I committed once with an eslint error present because
  `cmd && echo ok` does not gate the NEXT line, and I read `eslint | tail` as
  passing when `$?` was `tail`'s exit and eslint had reported six errors. Check
  the exit of the thing under test, not of what you piped it into.
- 2026-08-11 — M16 PR4a DRIVEN IN A REAL BROWSER, and the drive proved the
  milestone's residual by accidentally causing it. The audience change went
  first, over HTTP against a vault image REBUILT from the branch, with a genuine
  extension-audience session: pair 200, step-up 200, both SRP legs, `listItems`
  200, `createItem` 201 and `updateItem` 200 — while `deleteItem` and `reset`
  answered 401 to the same session. The two writes are admitted, the destructive
  verb and the crypto-shred are not, and the writes only worked AFTER a
  completed SRP unlock, which is the whole shape of the claim: the capability
  belongs to an unlocked vault, not to the credential.
  THEN THE UI, and the merge is correct where it counts. An item sealed with all
  four fields, edited in the popup by typing ONLY a new password: decrypting the
  row afterwards shows `secret` changed and `username`, `url` and `title`
  UNTOUCHED, at version 2, still opening — so blank fields were omitted rather
  than sent as empty strings, and the blob was sealed for the successor the
  service actually wrote. The edited item still matches its page and fills with
  the new password and the preserved username, which closes the loop: authored
  in the popup, edited by merge, still fillable.
  I CORRUPTED AN ITEM AND IT WAS THE MOST USEFUL THING THAT HAPPENED. My HTTP
  probe re-sent a row's EXISTING blob with `If-Match: 1`; the service stored it
  at version 2 and answered 200, and because the version is inside the AEAD's
  AAD a blob sealed for v1 does not open at v2. The item is permanently
  unreadable. That is exactly the failure the code comment describes — "reversed,
  the row lands unopenable and nothing in the response says so" — and exactly
  the docs/03 §6j residual written hours earlier: an unlocked session can
  overwrite items with bytes that do not decrypt and the platform cannot tell.
  Two of four rows ended unreadable, recoverable only by an operator reading
  `vault_items_versions`, which no production code does. Evidence for the
  restore-surface follow-up, obtained by doing the thing rather than arguing it.
  THE UI WAS RIGHT ABOUT THE BIT THAT LOOKED WRONG: the corrupted item showed no
  Edit control, which is deliberate — there is nothing to merge into, and
  offering an edit would turn a display problem into data loss.
  STALE ARTIFACTS, TWICE MORE. The stack's vault container was 18 hours old and
  predated the audience change, so writes would have 401'd and proved nothing —
  rebuilt from the branch with `--no-deps` so nothing else moved. And the FIRST
  rebuild silently failed: `docker-credential-desktop` is not on PATH from this
  shell (it lives in the Docker.app bundle), and after the failed build compose
  still printed `Container Running`, which reads like success. The tell was the
  container's uptime still saying 18 hours. Check what you built, not what the
  orchestrator says about it.
- 2026-08-11 — M16 PR4b (the release pipeline) rests on one claim — WHAT SHIPS IS
  WHAT A REVIEWER READS — and that claim is only worth stating if somebody with
  no relationship to this project can check it. So the artifact is packed by
  `scripts/pack-extension.mjs` rather than by `zip`. Not a preference: a ZIP is
  non-deterministic in FIVE independent ways, each MEASURED against `zip 3.0` by
  producing two differing archives — per-entry MS-DOS mtime, filesystem walk
  order, the Unix mode (which `-X` does NOT strip), Info-ZIP's default UID/GID
  and extended-timestamp extra fields, and deflate. With all five pinned the CLI
  is reproducible on ONE machine, so it was not disqualified for being a CLI;
  it was disqualified because three of the five then depend on whichever
  Info-ZIP and zlib the runner ships, which is precisely the variable a
  reproducibility claim must not rest on. Writing the archive ourselves is the
  node:crypto webhook verifier and node:net clamd precedent, applied to a path
  whose entire job is to be checkable. The COMPILE was measured as already
  reproducible (no `incremental`/`composite`, so no `.tsbuildinfo` state;
  TypeScript emits LF regardless of platform); the ZIP was the only step that
  was not.
  CORRECTED LATER THE SAME DAY: this first shipped deflating at level 9, on the
  reasoning that `node:zlib` "pins deflate to the Node the repo already pins".
  It does not — see the STORED entry below, where the first CI run measured that
  claim false and the fifth factor was removed rather than pinned.
- 2026-08-11 — "TWO RUNS MATCHED" IS THE WEAKEST POSSIBLE REPRODUCIBILITY TEST,
  and it is what almost shipped. Two runs on one machine seconds apart match for
  reasons that have nothing to do with the writer: the mtimes did not change,
  the walk order did not change, the umask did not change — and a third party on
  another machine on another day hits all three. So `pack.spec.ts` CHANGES each
  variable and asserts the digest does not move (clock forward eleven years,
  `chmod`, creation order), reads the entry names and the extra-length fields
  out of the archive BYTES rather than inferring them, and carries an
  anti-vacuity case proving a content change DOES move the digest. (The fifth
  factor was described here as untestable from inside one Node and handled by
  pinning; it is now an assertion, because the factor was removed — below.)
  MY OWN ORDER TEST MEASURED THE FILESYSTEM: it built one tree in two creation
  orders and compared digests, which PASSES with the writer's `.sort()` removed,
  because APFS returns directory entries in codepoint order anyway. Rewritten to
  assert the CONTRACT over the bytes — and then honestly recorded as a branch
  this machine cannot exercise at all, rather than credited with coverage it
  does not have (the M16 PR3a shape).
- 2026-08-11 — TURBO WAS SILENTLY DISCARDING THE EXTENSION'S ORIGIN, found while
  writing the CI job and fixed as part of it. Turbo 2 runs tasks in STRICT env
  mode, `VAULT_ORIGIN` was undeclared, and `build-package.mjs` bakes it into
  both `manifest.json` and `origin.js`. MEASURED:
  `VAULT_ORIGIN=https://vault.example.test pnpm build --filter=@estate/vault-extension
  --force` produced a package saying `http://vault.localhost:3010`. The script
  VALIDATES the value it reads and throws on a malformed one, so its own guard
  could not help — it never received the variable and fell through to its dev
  default. Exit 0, green everywhere, wrong artifact. This is the M8 PR5 `BFF_URL`
  defect verbatim, one milestone later, in the same `turbo.json` whose own
  comment describes it — which is why the fix is not "declare VAULT_ORIGIN".
  `test/turbo-env.spec.ts` reads the build COMMAND out of `package.json`,
  follows it to the scripts it actually runs, scans those for `process.env`
  reads and requires each to be declared, with an anti-vacuity floor; a new
  build-time input arrives declared or the build goes red. Mutation-tested four
  ways (drop the variable, drop the task entry, add an undeclared input, break
  the command so the scan sees nothing) — each red on the assertion that names
  the property. Declaring it also puts it in the task HASH, without which a
  build for one origin would be served from the cache of a build for another.
- 2026-08-11 — THE CI JOB IS ITS OWN WORKFLOW, and the reason is the permission:
  `.github/workflows/extension.yml` is the only place in the repo asking for
  `id-token: write`, and an escalation like that belongs in a file whose subject
  is the thing being signed rather than folded into one about container images.
  It builds TWICE with `--force` on both (a cache hit restores outputs without
  running the compile, which would compare a build against a copy of itself),
  deletes `dist` between them (repacking the same tree only re-proves the packer
  is a pure function of its input, which its own spec covers), and fails on a
  digest mismatch. WHAT THAT PROVES IS BOUNDED AND SAID SO: two builds on one
  runner show the pipeline is deterministic given one toolchain; cross-machine
  reproducibility is what a third party's own rebuild tests, which is why the
  published procedure asks them to do it rather than to trust this job. The
  attestation is skipped on `pull_request` — a signed statement that an unmerged
  branch built something is a statement nobody should act on — and the
  notify-on-failure wiring was deliberately NOT copied over: its gate can only
  fire on `workflow_dispatch`, which by definition has a human watching, and the
  reusable workflow's own header says those must not open issues. Dead machinery
  is the zero-callers shape this repo keeps closing, not a spare tyre.
- 2026-08-11 — NODE IS NOT PINNED TO A PATCH, and after the STORED change it no
  longer needs to be. The original reasoning here was that deflate stability
  across Node patches is unverified, so a purist claim wants the patch frozen —
  and freezing it means building a SECURITY artifact on a runtime that cannot
  take security patches, so the digest was LABELLED instead and `VERIFYING.md`
  named a version mismatch as the first thing to check. That trade-off is now
  moot for the digest and the instruction was WRONG: nothing compressed means
  no zlib, so Node's version and build do not reach the archive at all. The
  version still travels in the `.sha256` beside the commit and the origin, as
  provenance rather than as something a verifier must match. Keeping the entry
  because the reasoning is right for the next artifact that does have a
  toolchain-sensitive step; only its premise was removed.
- 2026-08-11 — `apps/vault-extension/VERIFYING.md` states up front what it CANNOT
  establish, because a verification procedure that oversells itself is worse than
  none. It can show the archive came from this repo's `Extension` workflow at a
  named commit (`gh attestation verify --signer-workflow …`, and the flag is the
  part that carries weight — without it you learn only that SOME workflow in the
  repo built it), and that the archive is byte-for-byte what that source
  produces. It cannot show the source is safe, and — the one most likely to be
  assumed — IT CANNOT SHOW THE COPY YOUR BROWSER IS RUNNING IS THAT ARCHIVE:
  stores repackage, Chrome converts the upload to a CRX3 with its own signature
  and adds `_metadata/verified_contents.json`, so a store install is compared
  file-by-file against an extracted rebuild, never by zip digest. Also carried
  over from the PR3b measurement rather than left to be rediscovered: the load
  step is MANUAL, because Chrome 151 has disabled `--load-extension` and the
  feature override is gone with it, so any recipe built on that flag is not
  runnable — docs/04 recorded that this PR owed the difference, and this is it.
  Every command was run: `shasum -a 256 -c` tolerates the `#` comment lines the
  digest file carries, and the job's whole sequence reproduces locally
  (two clean builds, 42 entries, identical digests).
- 2026-08-11 — THE FIRST CI RUN FALSIFIED THE MILESTONE'S CENTRAL CLAIM WITHIN
  MINUTES OF MY MAKING IT, and the fix was to delete a variable rather than
  document it. The job went green — and its archive was 118,147 bytes where the
  same commit on this laptop produced 118,875. Compared entry by entry rather
  than guessed at: all 42 CRCs and uncompressed sizes IDENTICAL, 40 of 42
  compressing differently, one of them LARGER on CI. So the COMPILE is
  reproducible across platforms (a stronger result than I had evidence for
  before) and DEFLATE is not.
  The cause is neither the Node version nor the CPU. It is HOW NODE WAS BUILT:
  Homebrew's is `node_shared_zlib: true` against system zlib 1.2.12, official
  builds vendor Chromium's 1.3.1-e00f703. Isolated by running the packer under
  official `node:22` in Docker on ARM64, which reproduced the x86-64 runner's
  digest EXACTLY — so architecture is irrelevant and the zlib build is
  everything. Two people on the same OS running the same `node -v` get different
  digests depending on whether they installed Node from Homebrew or nodejs.org,
  and `VERIFYING.md` was at that moment telling both of them that a mismatch is
  "a finding worth reporting".
  FIXED BY STORING EVERY ENTRY (method 0). The archive is then a pure function
  of the compiled bytes plus four constants — no zlib, no Node, no platform —
  and the factor that could never be tested from inside one Node became an
  assertion over the local AND central headers. Both Node builds now produce
  `bc8b2467…`, 333,789 bytes, `unzip -t` clean (the digest later moved to
  `807eb87c…` when the review round fixed the UTF-8 name flag and
  version-made-by; the property is what matters, not the constant). The cost is ~3x size on a 118 KB
  artifact, invisible to a store that repackages into CRX3 anyway, and worth
  nothing against being checkable by a stranger. The general rule: when a
  reproducibility input cannot be pinned from inside the artifact, REMOVE it
  rather than label it, because a procedure whose failure mode is "your digest
  differs, and the remedy is a paragraph about your package manager" teaches
  people to shrug at the signal it exists to raise.
- 2026-08-11 — AND MY OWN FIXTURES MADE THAT NEW ASSERTION UNOBSERVABLE, caught
  by mutation and not by review — the third way this session's harness has found
  a test weaker than its name. Reintroducing deflate VERBATIM left "STORES every
  entry" GREEN, because every fixture was an 18-byte line and 18 bytes deflate
  LARGER than they store, so the writer's `deflated.length < raw.length` branch
  was never taken: the test could not see the exact regression it was written
  for. A compressible fixture (`big.js`, one line 400 times) fixes it, and the
  case now ALSO asserts that fixture really does compress — because an edit that
  shrinks it would silently disarm the check instead of failing it. The general
  shape, restated for fixtures rather than for selectors: a test of a
  conditional needs an input that reaches the condition, and "the mutation
  stayed green" means either the test is weak or the fixture never got there.
- 2026-08-11 — A FENCE NAMED FOR AN ABSENCE READ ONLY HALF THE ARCHIVE, found by
  an adversarial agent and confirmed by both CI checks going GREEN over it. A ZIP
  records every entry TWICE — a local header and a central-directory record, and
  an extractor may believe either — and `pack.spec.ts`'s "carries NO extra
  fields" case scanned only the local ones (`0x04034b50`). The agent added an
  Info-ZIP `ux` field carrying `process.getuid()`/`getgid()` to the CENTRAL
  records alone: 11 bytes per entry, 462 bytes of the builder's identity in every
  archive, and the case named for their absence stayed green. Nor could the
  `package` job see it — two builds on ONE runner share a uid, so the digests
  agreed, which is exactly the bound that job's header claims for itself. The
  fence now asserts extra AND comment lengths in BOTH records (the field next
  door is just as good a place to put a hostname), and every case WALKS THE
  ARCHIVE from the end-of-central-directory record instead of scanning for
  signature bytes — which was wrong a second way once entries became STORED,
  since raw file content can contain `PK\x03\x04` and be counted as an entry that
  does not exist. Mutation-tested with the agent's exact payload plus the
  local-only and comment variants; the packer's own output is unchanged
  (`bc8b2467…` at that point), so this is purely the observer getting better.
- 2026-08-11 — I COMMITTED A REVIEW AGENT'S MUTATION AND PUSHED IT, which is a
  process defect with a general lesson: BACKGROUND AGENTS AND `git add -A` DO NOT
  MIX. The adversarial review was running against this same working tree with
  instructions to mutate production files and restore them — the only way to
  prove a fence catches something — and my `git add -A && git commit` ran while
  one mutation was in flight, so `c3bc6aa` shipped the uid/gid extra field above.
  The agent restored the file afterwards, which is why the revert commit's diff
  reads as a REMOVAL and why nothing looked wrong locally. The pre-commit suite
  had passed BEFORE the mutation landed. Contained (the previous commit was clean,
  no scratch directory was committed, and the restored file reproduces the digest
  measured beforehand), and it would have shipped an archive carrying the
  builder's uid — the precise non-determinism the packer exists to prevent.
  THREE RULES ADOPTED: stage explicit paths, never `git add -A`, while anything
  runs in the background against the tree; verify `git status` immediately before
  every commit rather than trusting an earlier green suite; and give review agents
  `isolation: 'worktree'` so they physically cannot reach the tree being edited.
  The last is the real fix — the other two are discipline, and discipline is what
  failed here.
- 2026-08-11 — THE PR4b REVIEW'S BEST FINDING WAS ABOUT WHAT A FENCE DOES NOT
  LOOK AT, and three independent lenses reached it separately. `pack.spec.ts`
  varied three inputs (mtime, mode, content) and asserted the digest held, then
  asserted that certain LENGTHS and METHODS were zero — and never asserted the
  VALUE of a single pinned field. So the builder's identity could still reach
  every archive through the external attributes, the internal attributes,
  version-made-by, the DOS date/time words, or the archive comment at the END of
  the file, which is not per-entry and which no entry-level assertion could ever
  see. CI could not help: two builds in one job share a uid and a hostname, so
  they agree on the wrong answer twice. THE FIX IS A GOLDEN DIGEST — a fixed
  fixture tree and one exact expected sha256 — because it is the whole artifact
  rather than a list of fields somebody thought of, so a byte in a field nobody
  has thought of YET turns it red, which is the only kind that matters. It is
  deliberately brittle: changing the format must edit the constant, and that
  edit is the review. The per-field value assertions stay beside it so that when
  it fails it says which field moved. Mutation-tested with uid in the external
  attributes, uid in the internal attributes, the clock in the DOS time word,
  and the hostname in the EOCD comment — all four now red, and the third proves
  the point, because the mtime-perturbation case could never see a clock (an
  unchanged file mtime is not an unchanged clock).
- 2026-08-11 — Three real defects in the packer, all found by the same review and
  all latent rather than active. (1) Names are written as UTF-8 while general
  purpose BIT 11 was clear, which per APPNOTE declares them CP437 — every name
  in `dist` is ASCII, where the two agree, which is exactly why it was easy to
  miss. (2) `version-made-by` said host 0 (MS-DOS/FAT) while the external
  attributes carry a Unix mode; under FAT those bytes mean DOS attribute flags,
  so the carefully fixed 0644 was a field an extractor was entitled to read as
  something else. (3) The main-module guard compared `import.meta.url` against a
  RAW `process.argv[1]`, so from any path containing a space — or on Windows,
  always — the packer exited 0 and wrote nothing at all, silently, while
  VERIFYING.md promised OS independence. Fixed with `pathToFileURL`, and
  verified by running the packer from `/tmp/has space/probe`, which now produces
  the archive instead of nothing. The first two move the digest, which is the
  right time for it to move: before anything is published.
- 2026-08-11 — THE SIGNING CAPABILITY MOVED OUT OF THE JOB THAT RUNS THE CODE.
  `permissions` is static per job, so a single job held `id-token: write` and
  `attestations: write` on every event — including `pull_request` runs that
  never use them — in the same job that executes the branch's own build scripts.
  Splitting is the only way to scope it: `package` builds with `contents: read`
  and nothing else, `attest` runs no repository code and re-derives the digest
  before signing rather than trusting what `package` reported. It is also gated
  on `github.ref == 'refs/heads/main'` and not merely on "not a pull request",
  because `workflow_dispatch` accepts any ref, so a side-branch build could
  otherwise mint an attestation that a verifier cannot distinguish from a main
  one. AND THE VERIFICATION COMMAND WAS WEAKER THAN ITS OWN PROSE:
  `--signer-workflow` is matched as an anchored PREFIX against a certificate
  subject that ends `@refs/heads/<branch>`, so it pins repo and path at ANY ref
  — while VERIFYING.md said it proved "the one whose text you can read". It now
  passes `--source-ref` and `--source-digest` too, with a table saying what each
  flag binds. The adjacent sentence was worse: "the output names the commit the
  build ran from" is simply FALSE — the default output is four rows and no
  commit — so the doc was instructing a comparison the tool does not offer.
- 2026-08-11 — Smaller PR4b review fixes, each the same shape as something this
  log already records. `turbo-env.spec.ts` hardcoded the package NAME while
  turbo keys its per-package task on it, so a rename would silently fall back to
  the base `build` task — no `VAULT_ORIGIN`, wrong artifact, fence green because
  it would still be reading the orphaned key; it derives the name from
  `package.json` now, and a rename turns it red. The digest-comparison step took
  its exit status from `cut`, so two unreadable archives yielded two empty
  strings that compared EQUAL and reported success — `set -euo pipefail` plus a
  64-character length check on every digest. VERIFYING.md's rebuild omitted the
  `rm -rf dist` the workflow itself performs, so a second verification in the
  same clone could produce a mismatch the document tells the reader to escalate;
  its triage recipe claimed `unzip -v` "names the files that actually differ"
  when it shows content only, so it now says what an identical listing with
  differing digests means; and step 1's snippet returned an empty run id with no
  explanation, which is the state the repository is in until this very workflow
  first runs on main.
- 2026-08-12 — RUNNING THE PUBLISHED PROCEDURE AGAINST THE REAL ARTIFACT found
  the last defect, and it is the one a reader is most likely to be defeated by:
  `gh attestation verify` prints a summary on a TTY and NOTHING AT ALL when
  piped or scripted, so a successful verification is byte-for-byte
  indistinguishable from a command that did nothing. VERIFYING.md said what to
  look for in the output and never said to check the exit status. Confirmed to
  be a real pass rather than a no-op by the anti-vacuity discipline this repo
  applies to its own fences, pointed at somebody else's tool: a wrong
  `--source-digest` exits 1 naming the true commit, a wrong `--source-ref` exits
  1 naming the true ref, and one appended byte exits 1 with HTTP 404 — which
  reads oddly and is correct, since attestations are looked up BY the artifact's
  digest, so altered bytes have none. All three are now in the doc, because a
  procedure whose success and whose no-op look the same is a procedure nobody
  can rely on. The first `attest` job also ran for the first time here: it had
  skipped on every pull-request run by design, so its first real execution was
  on main after the merge, which is exactly the shape of thing this repo keeps
  finding — machinery that has never once executed.
- 2026-08-12 — HOW TO RUN AN ADVERSARIAL REVIEW IN THIS REPO, written down
  because PR4b's review taught three things that cost real time and none of
  which is discoverable from the tooling. (1) GIVE EVERY AGENT
  `isolation: 'worktree'`. A review is told to mutate production files to prove
  a fence catches something, and a shared tree means one of those mutations can
  be swept into a commit — which happened, and shipped a uid/gid field to a
  pushed branch. (2) AND THEN PIN THE AGENTS TO THE COMMIT UNDER REVIEW: an
  isolated worktree is created at MAIN, not at the branch, so four agents
  spent their first run reading code that contained none of the change. They
  cannot `git checkout <branch>` either — it is checked out in the session's own
  worktree and git refuses — so the first instruction in the prompt must be
  `git checkout --detach <sha>`, with a "confirm with git log before you read
  anything" beside it. Verified in a scratch worktree before relying on it.
  (3) SIZE THE FAN-OUT FOR PARTIAL LOSS. PR4b's review lost 22 of 50 agents to a
  session limit mid-run, all in the verify phase, so the discovery findings
  arrived unverified. That is survivable only if the findings are confirmed by
  hand afterwards — which is what happened, by mutation and execution rather
  than by reading a verdict. Plan for it: fewer, better-scoped lenses beat a
  wide fan-out that dies half way, and the journal (`journal.jsonl`, one result
  row per completed agent) is what survives a stop, so read it rather than
  assuming a killed run produced nothing.
  Two cleanup consequences worth knowing: isolated worktrees are LEFT BEHIND
  (44 of them, 9.9G, cleared with `git worktree remove --force` + a branch
  sweep), and the agents are told not to restore what they change, so the
  scratch branches `worktree-wf_*` accumulate too.
- 2026-08-12 — M16 PR5 security review (seven file-scoped discovery lenses over
  the M16 range, each in its own detached worktree at the reviewed commit; 21
  candidates, no agents lost; EVERY finding confirmed by mutation or execution
  before it was acted on — against real Postgres, a real jsdom page, or the
  modules run directly). Tenth milestone running where every confirmed finding
  sits in machinery the milestone introduced — WITH ONE EXCEPTION, and it is the
  worst thing in the review.
  THE EXCEPTION IS OLDER THAN M16 AND M16 IS WHAT MADE IT MATTER: a stolen
  session could ENROL ITS OWN SECOND FACTOR. `POST /v1/auth/totp/enroll` has been
  `SessionGuard`-only since M2; `revokeUnverifiedTotp` spares a VERIFIED method
  while `findActiveTotp` takes the NEWEST — so enrol a secret you control,
  confirm it with a code you compute yourself, step up. Three ordinary requests,
  no guessing, and step-up stops being a second factor for anyone holding a
  session: vault reset, document generation, export, beneficiary changes,
  deletion. Measured end to end, including the half that makes it a lockout as
  well as a takeover — the owner's own authenticator answers 401 afterwards,
  which is docs/03 §5.1's liveness proof gone. THE REPO HAD ALREADY SEEN THE
  MECHANISM and filed it as a test-seeding nuisance (the 2026-08-06 entry on why
  the settlement e2e caches TOTP enrolment says, in as many words, that enrolling
  twice leaves two verified secrets and lets `findActiveTotp`'s choice decide
  whether a later step-up works). That is the general lesson: A FACT RECORDED AS
  A TEST INCONVENIENCE IS STILL A FACT ABOUT THE PRODUCTION CODE PATH. Fixed by
  gating enrolment on a fresh step-up WHEN A VERIFIED FACTOR EXISTS — conditional
  because the first enrolment cannot be gated (no factor to prove with, and
  `checkTotp` refuses a user with no method, so an unconditional gate makes a
  second factor unreachable forever). Residuals stated: the bootstrap case stays
  open and identity cannot even warn, being deliberately not a notifications SEND
  holder (M14); and a legitimate re-enrolment silently retires the previous
  authenticator, which is now owner-only but still one behaviour for two
  intentions.
- 2026-08-12 — THE M16 STEP-UP CAP WAS BYPASSABLE AND WAS ALSO A LOCKOUT, two
  independent defects in machinery M16 introduced, both measured. (1) AN UNCAPPED
  ORACLE ONE ROUTE OVER: `POST /v1/auth/totp/verify` resolves the same
  `mfa_methods` row and calls the same `verifyTotpCode`, had no cap at all, and
  wrote `totp.verify_failed` — a kind `deniedSinceLastGrant` did not count. Forty
  guesses, forty 401s, never a 429, counter still zero; the code the guessing
  found then elevated at `stepup` on the first try, spending none of the five.
  `stepup.ts`'s "one chokepoint covers both" was wrong by exactly one route. The
  chokepoint is the SET of routes that read the factor, so failures and successes
  are both sets now, one gate serves both callers, and
  `test/second-factor-kinds.spec.ts` scans the service for every kind it writes
  so a third checker arrives declared or turns it red. (2) THE ROLLING WINDOW DID
  NOT ESCAPE THE OWNER-DoS ITS OWN DOCSTRING REJECTED A STICKY LOCK FOR: the
  count was keyed on the USER and every live session wrote into it, so five wrong
  codes from ONE credential — the 30-day extension token on disk being the
  cheapest — refused every OTHER session, measured as the owner's untouched
  session getting 429 where it should have got 401. The only thing that clears
  the window is a success, which the 429 prevents, so five denials a quarter-hour
  hold it there indefinitely. Fixed with TWO SCOPES rather than a different
  number: a per-session cap a stolen credential exhausts on itself (its refusals
  are `stepup.rate_limited`, which is not counted, so the account total rests
  where it was), under an account ceiling that stays keyed on the user for M14's
  reason and remains the real bound. Residual: an attacker who can MINT sessions
  still walks the account total to its ceiling — a strictly higher bar, and the
  one that cap exists for.
- 2026-08-12 — ONE INTERNATIONALISED PAGE RETURNED THE WHOLE VAULT, and the fix
  was to DELETE a rule rather than improve it. `isConfusable` began "any punycode
  on either side, against a domain that is not identical, is refused as
  confusable" — which is not a comparison at all, because it never looks at the
  other domain. Since `matchesFor` keeps `confusable` and drops only `no-match`,
  every saved item's title and registrable domain came back from the key holder
  on any IDN page: precisely the disclosure that function's own docstring says
  the design exists to prevent ("would disclose a list of every site the user has
  an account with in order to answer a question about ONE origin"). It also fired
  the lookalike refusal — the one phishing bound §4 TB9 commits to — on every
  item at once, on ordinary pages, which is how an alarm stops being read.
  Deleting it gave up NOTHING the boundary needed: filling requires
  `savedDomain === pageDomain`, so a punycode host that is not the saved domain
  was already unfillable and the clause only decided the LABEL on the refusal.
  The general case (a real punycode homograph) needs decoding plus UTS #39 and
  stays a named follow-up, which §6j already declares the accepted failure
  direction. What replaces it is a fact about the PAGE said once, not a claim
  about each credential. THE GENERAL SHAPE: a rule that takes one argument
  cannot be a verdict about a pair, however cautious it looks.
- 2026-08-12 — A FUNCTION CALLED TWICE MUST AGREE WITH ITSELF. `normaliseHost`
  stripped ONE trailing dot, and `registrableDomain` normalises and then calls
  `publicSuffix`, which normalises AGAIN — so the two ran on DIFFERENT strings.
  `publicSuffix` saw `bank.com` and its empty-label guard never fired, while
  `registrableDomain` counted labels on `['bank','com','']` and returned the last
  two: `bank.com..` and `evil.com..` both became `com.` and `matchOrigin`
  answered `match`. A bare public suffix, which that file's own docstring
  promises never to return, shared by two different registrants. `URL.hostname`
  preserves the doubled dot, so the input is reachable (both sides must carry it,
  which is what keeps it medium rather than high). One `+` in a regex.
- 2026-08-12 — "NOTHING IS EVER AUTO-SUBMITTED" WAS NEVER THE EXTENSION'S TO
  PROMISE. `fill-into-page.ts` withholds `blur` because "a page is free to submit
  on blur, so dispatching one would be auto-submission by proxy" — and that
  reasoning is true verbatim of `input` and `change`, which a fill MUST dispatch
  or no field notices the value. Measured under jsdom against the real module: a
  page's `change` listener held the real secret. There is no fix, because the
  events ARE the fill, so the CLAIM was narrowed in §4 TB9 and on screen ("Estate
  didn't submit anything" rather than "Nothing was submitted"). What WAS fixable
  is ORDER: the password was written FIRST, so a page committing on its `change`
  posted the real secret with the username field still empty — measured as
  `username at submit: ""`. Username first now, so whichever field an eager page
  acts on, the pair is complete. The lesson is the one about absolutes: a control
  that must produce an observable effect cannot also promise the effect is
  unobservable.
- 2026-08-12 — THE FILL'S ORIGIN DECISION RAN ON A STALE URL, and the docstring
  claiming otherwise named the exact scenario it could not see. `fillFor` says it
  re-decides "because the page can navigate between the two calls" — but
  `vault-screens.ts` reads the tab ONCE in `refresh()` and the Fill button closes
  over that string, so `matchesFor` and `fillFor` were handed the SAME value and
  the second decision was f(x) === f(x) over the page URL. What actually stood
  between a navigated tab and a misfill was Chromium revoking `activeTab` on a
  cross-origin navigation — real, plausibly sufficient, and UNMEASURED in this
  repository with no test asserting it. The tab is re-read at the gesture now, so
  the claim is true independently of the platform; a tab that changed is a
  REFUSAL rather than a fallback to the captured value, because the grant is
  revoked exactly when the thing you would fall back on has become wrong.
  Recorded rather than closed: whether that revocation happens is still owed by
  whoever next drives this in a browser.
- 2026-08-12 — Three smaller M16 findings that share one shape — THE PROTECTIVE
  PATH WAS THE WEAKER ONE. (1) Key material survived a failed unlock: `prepare()`
  runs before the second SRP leg, so a refused or malformed `srp/verify` returned
  with the AUK and the SRP private key resident, and because the idle clock is
  armed only on SUCCESS nothing was scheduled to collect them — only an offscreen
  teardown ever would have. (2) A REVOKED pairing forgot the session and kept the
  Secret Key on disk: `forgetSecretKey` had two callers, the explicit opt-out and
  the VOLUNTARY disconnect, so the path an owner takes when they believe a device
  is compromised did less than the one they take when they do not. (3) A refused
  injection rendered as "No password field was found on this page" — `doFill`
  never read `outcome.ok`, so the platform REFUSING and the page having no login
  form said the identical sentence, on the one signal that would tell anyone the
  grant had lapsed. All three closed.
- 2026-08-12 — THE ROUTE-AUDIENCE FENCE WAS NAME-KEYED, which is the shape the
  credential graph was fixed for twice (2026-07-28, 2026-08-07) arriving in a
  third place. It scanned source for the literal `@AllowSessionAudiences`, while
  `CallerGuard.audiencesFor` and identity's `SessionGuard` both resolve
  `SESSION_AUDIENCE_METADATA` through `Reflector.getAllAndOverride` — so a route
  is widened by CARRYING THE KEY, however it got it: an aliased import, or a raw
  `SetMetadata`, is honoured at runtime and matched by nothing. Only `vault` and
  `identity` have a second-layer spec reading real handler metadata; for the
  other seven services that regex is the whole enforcement. Closed by also
  asserting the metadata key has exactly ONE route into it, mutation-tested by
  aliasing the decorator for real. The rule generalises past this repo: anchor a
  fence on what the RUNTIME reads, never on the identifier a caller chose.
- 2026-08-12 — MY OWN MUTATION GUARD LIED TO ME, in a new way, and the fix is one
  word. The harness asserted `len(mutated) != len(original)` — so a mutation that
  SWAPS TWO LINES (exactly the fill-order revert) reported "MUTATION IS A NO-OP"
  and I nearly concluded the test was toothless. Length is not identity. It
  compares CONTENT now. This is the third distinct way this repo has caught a
  mutation harness misreporting (2026-08-10: `git checkout --` on uncommitted
  work; a `node -e` losing `$1` to shell expansion; a grep for `✕` in a
  non-verbose jest run) and they all produce the same symptom — a conclusion
  about a test drawn from a measurement that never happened.
- 2026-08-12 — A GREEN JEST RUN IS NOT A TYPECHECK. `totp-enrollment-gate.int.spec.ts`
  passed under ts-jest with `mfaLevel: 'password'` — a value not in `MfaLevel`
  (`'none' | 'mfa' | 'stepup'`) — and only `pnpm -r run typecheck` caught it. Worth
  the line because the repo's habit is to trust a green suite: for a spec that
  constructs a domain type by hand, the suite and the compiler are different
  gates and the compiler is the one that knows the vocabulary.
- 2026-08-12 — A COVERAGE FLOOR CALIBRATED AGAINST THE ONE CONFIGURATION NOTHING
  RUNS. `apps/services/identity/jest.config.js` says its threshold is "set near
  the LOCAL number (the full-flow integration suites only run with
  PG_TEST_URL)" — and `ci.yml` sets `PG_TEST_URL`, so CI measured the HIGH
  number and the number the floor exists for was evaluated by no gate at all.
  It had rotted to 62.24/66.60/28.43/60.24 against a 65/66/30/63 floor, under on
  statements, lines AND functions, failing for anyone who ran the suite without
  a database. THE FENCE-THAT-NEVER-RUNS SHAPE FROM THE OTHER DIRECTION: not a
  scan that stopped matching (2026-08-07) but a threshold nothing evaluates.
  Closed by giving `auth.controller.ts` its FIRST unit spec — 23 route handlers
  at 0% functions without Postgres, because only the int suites reached them,
  which is M9 PR2's remedy for the identical thing in notifications where the
  floor "was set from a number CI never produced". Local 67.91/67.55/39.25/66.23,
  CI 89.96/79.31/83.64/89.57, floor ratcheted UP to 67/67/39/66. The spec is not
  coverage-shaped: it pins the controller's whole contribution to authorization
  — every authenticated handler takes its subject from the context SessionGuard
  attached, never from the body, which the guard itself does not check — and
  each case drives a body that TRIES to name somebody else. Mutation-tested:
  making `verifyTotp` prefer a body-supplied userId turns one case red,
  defeating `requireAuth` turns six red.
- 2026-08-12 — AND THEN THE FLOOR WAS GIVEN SOMETHING THAT RUNS IT, which is the
  half that stops it rotting again: a `ci.yml` step running identity with NO
  database. Two things about it are the lesson rather than the feature.
  (1) THE OBVIOUS SPELLING WOULD HAVE BEEN VACUOUS. `pnpm --filter
  @estate/identity test -- --coverage` DOES NOT FORWARD THOSE FLAGS — measured:
  no coverage collected, no output file written, exit 0. Since thresholds only
  arm when coverage is collected, the step would have been a gate that could
  never fail, in a commit whose whole subject is a gate that never ran. Caught by
  refusing to ship it until it had been seen RED: raising the statements floor to
  99 makes the real command exit 1. It runs the package's own jest from
  `working-directory` instead. (2) IT MUST PROVE IT RAN THE CONFIGURATION IT
  NAMES, or it is the same class of thing — a step that quietly acquired a
  database would go green while measuring what the step above already covers. So
  `PG_TEST_URL` is asserted empty, the `describeIfPg` suites are asserted to have
  SKIPPED (pending > 0), and a passed-count floor catches a run that executed
  almost nothing; all three were confirmed to exit 1.
- 2026-08-12 — THE NEW STEP FAILED ITS FIRST CI RUN, AND THAT WAS THE STEP
  WORKING. `test/ci-guard.spec.ts` asserts that in CI `PG_TEST_URL` must be set,
  so integration suites cannot skip silently — and the new step deliberately
  runs without one. Two correct gates wanting opposite things from the same
  environment, which no amount of local running would have shown, because the
  guard keys on `CI`. Reconciled with a DECLARED exemption that asserts its own
  precondition: `IDENTITY_NO_DB_RUN` exempts the guard's first case and arms a
  second requiring that such a run really has no database — so the flag cannot be
  pasted into the ordinary Test step as a mute button, since it would then fail
  the other case. All four configurations proven rather than argued: CI without a
  database and without the flag still fails, CI with a database AND the flag
  fails, and the two legitimate combinations pass. Only identity's copy is
  exempted; the other ten refuse outright. (Eleven near-identical copies of that
  guard is this repo's own copy-pasted-line drift class, noted in the spec rather
  than fixed there — unifying them touches ten packages for reasons unrelated to
  why this one was edited.)
- 2026-08-12 — ELEVEN COPIES OF THE `ci-guard` SPEC UNIFIED, and the interesting
  part is what the drift turned out to be. MEASURED before touching anything:
  the ASSERTION was byte-identical in all ten service copies, so nothing
  behavioural had broken. What had drifted was TEXT — three docstring wordings,
  and vault's copy had lost its docstring entirely, so the one file explaining
  WHY the guard exists was the one that no longer said it. Two had also grown
  real clauses (identity's database-free run, e2e's stack gate), so eleven files
  under one name were becoming three different things. This is the point BEFORE
  a copy-pasted line costs something, which is the only cheap time to fix it.
  THE TRADE-OFF IS THE ENTRY. Eleven copies have one virtue — an edit breaks one
  of them — and unifying trades that for the drift. Demonstrated rather than
  asserted: making `evaluate` return `satisfied: true` silences the gate in ALL
  ELEVEN at once (audit goes from exit 1 to exit 0 in CI with no database). So
  the shared thing gets the tests THE COPIES NEVER HAD, which is the only way
  that trade is worth taking: `evaluate` is a PURE function of an environment,
  driven over fabricated environments in `packages/config/test/ci-guard.spec.ts`
  — fourteen cases, most of them a configuration that MUST FAIL — and both
  weakening mutations are caught by it. The rule generalizes: UNIFYING N COPIES
  OF A GUARD IS ONLY SAFE IF THE UNIFIED ONE IS TESTED HARDER THAN THE COPIES
  WERE, because the blast radius is now N. Each package keeps a thin spec (jest
  projects are per-package, so a spec in `@estate/config` would run nowhere) and
  the two parameterised cases read as parameters rather than as forks. Verified
  PER PACKAGE rather than centrally, because a central green would prove the
  helper and not the wiring.
- 2026-08-12 — THE SAME ESCALATION WAS STILL OPEN THROUGH WEBAUTHN, and
  verifying the fix is what found it. #75 gated `POST /v1/auth/totp/enroll` on a
  fresh step-up when a verified factor exists, against
  `MfaRepo.hasVerifiedTotp`. `POST /v1/auth/webauthn/register/verify` was
  `SessionGuard`-only and `WebAuthnService` grants step-up on a successful
  assertion, so a caller holding nothing but a session could bind an
  authenticator OF THEIR OWN and elevate with it — MEASURED against real
  Postgres, the attacker's session row coming back `mfa_level=stepup` with a
  live `stepup_expires_at`. `excludeCredentials` looks protective and is not: it
  stops re-registering the SAME authenticator, never a different one. QUIETER
  than the TOTP version, too — that one locked the owner out (`findActiveTotp`
  takes the newest, so their codes started failing, which is a signal), whereas
  here the victim's factors keep working and nothing they can observe changes.
  It also cleared the M16 step-up attempt cap, since WebAuthn writes
  `stepup.granted`.
  A PER-TYPE PREDICATE LEFT A HOLE IN BOTH DIRECTIONS: `hasVerifiedTotp` is
  FALSE for an account holding only a passkey, so the TOTP-only fix would still
  have admitted a stolen session enrolling TOTP on a passkey-protected account.
  The question has to be "does this account hold ANY factor it could be made to
  prove", so `SecondFactorGate` asks it over both stores and either one arms the
  gate. Called from `enrollTotp` and from BOTH ends of the WebAuthn ceremony —
  the options end so a refusal comes before the hardware ceremony, the verify
  end because that is the write. THE GENERAL LESSON: a rule applied to one
  instance of a category is a rule half-applied, and the way to tell is to ask
  what ELSE is in the category before calling the fix done.
- 2026-08-12 — A GATE THAT LIVES IN A SERVICE IS INVISIBLE TO EVERY FENCE THAT
  SCANS FOR A DECORATOR, so it needed one of its own. The enrolment rule is
  conditional on ACCOUNT STATE, which a route decorator cannot see — that is why
  the gate is in `SecondFactorGate` rather than `StepUpGuard`, and it is exactly
  how the WebAuthn route sat ungated while its TOTP twin was fixed one file
  away. `apps/services/identity/test/factor-routes.spec.ts` closes it and
  DISCOVERS BY WHAT THE CODE DOES: it scans for calls to the repo methods that
  WRITE factor state, so a new enrolment path is found by the write it has to
  make, whatever it and its route are called. Two things it taught while being
  written, both kept: it caught a genuine error in its own declaration table on
  the first run (`startRegistration` is gated but writes no factor — it issues a
  challenge, so `writes` had to become an explicit field rather than an
  assumption), and on the second it reported `email-verification.service.ts` as
  an undeclared factor writer because `EmailVerificationRepo` ALSO has a
  `markVerified`. A bare method-name scan was not good enough; the receiver is
  resolved from its TYPE ANNOTATION now, which is both precise and un-evadable
  by renaming — the 2026-07-28/2026-08-07 rule applied ahead of the bite rather
  than after it. Mutation-tested four ways: a deleted gate (red), a brand-new
  undeclared method binding a credential (discovered and named in the failure),
  a renamed repo field (correctly still GREEN — the positive control that proves
  the anchor is the type), and a revert to the TOTP-only predicate (red in the
  behavioural specs).
- 2026-08-12 — AND THE DATABASE-FREE CI STEP EARNED ITS KEEP WITHIN A DAY. Adding
  `SecondFactorGate` dropped identity's no-Postgres coverage under its floor on
  functions (38.53% against 39%), because the gate's methods are exercised by
  the Postgres-backed specs and nothing else. That is precisely the drift the
  step was added to catch, caught on the first change after it landed. Closed
  with `second-factor-gate.spec.ts`, which is owed on its own terms rather than
  for the number: the int suites prove the SQL PREDICATE, and this one proves
  the DECISION the three inputs combine into — including that a LAPSED step-up
  is refused, not merely an absent one, which no int case isolates. Floor
  re-measured at 68.59/68.19/39.90/66.89 and ratcheted UP.
- 2026-08-12 — `activeTab` REVOCATION MEASURED AT LAST, closing the residual the
  M16 PR5 review recorded as owed. Chrome 151.0.7922.110 on macOS, a scratch
  probe extension holding `activeTab` and `scripting` and NO host permissions so
  the grant was the only thing in play. Result: the grant is ORIGIN-scoped and
  ANY cross-origin navigation revokes it — same-origin survives, a different
  host is revoked, a different PORT on the same host is revoked, and a SUBDOMAIN
  of the same registrable domain is revoked. Two consequences. The pre-fix
  TOCTOU really was being held shut by the platform rather than by the
  extension's own logic, which is why re-reading the tab at the gesture was the
  right fix regardless: it makes the code's stated claim true instead of resting
  on undocumented behaviour nobody had checked. And THE PLATFORM IS STRICTER
  THAN OUR OWN MATCHER — `matchOrigin` treats a subdomain as the same
  registrable domain and would fill there, while the grant does not survive
  navigating to it.
  THE CONTROL IS WHY THIS IS BELIEVABLE, and the first run failed it. Calling
  `chrome.action.openPopup()` programmatically from the service worker OPENS THE
  POPUP AND DOES NOT GRANT — measured, `tab.url` stayed null and the popup
  target was present. Every scenario in that run said "refused", and reported
  without the control it would have read as a clean confirmation of revocation
  from a rig that never granted anything. The grant needed a real OS-level
  invocation (an `osascript` keystroke bound to `_execute_action`), after which
  `tab.url` populated and injection succeeded. A second confound was caught the
  same way: the first cross-PORT case navigated to a port with no server, so its
  refusal could have been an error page rather than a port rule — re-run against
  a real second server, it still revokes.
- 2026-08-12 — AND A DOCUMENTED CONCLUSION WAS WRONG: extension loading IS
  scriptable on Chrome 151. PR3b measured that `--load-extension` is refused —
  true, and re-confirmed by launching with it and watching no extension appear
  among the CDP targets — and concluded from that that loading "cannot be
  scripted" and "no CI job can ever stand in for it". The CDP command
  `Extensions.loadUnpacked` works, returns the extension id, and the probe was
  driven end to end through it: service worker attached, action invoked,
  `executeScript` run against a live page. THE FLAG IS GONE AND THE CAPABILITY
  IS NOT. The lesson is narrow and worth keeping: a removed ENTRY POINT is not a
  removed CAPABILITY, and "cannot be done" deserves the same standard of
  evidence as "can" — PR3b measured one route and generalised to all of them.
  `VERIFYING.md` still tells a human to use developer mode, deliberately: asking
  a third-party verifier to attach a debugging protocol would be a worse
  instruction, not a better one.
- 2026-08-12 — A CI STEP THAT DOWNLOADS ITS OWN TOOL IS A DEPENDENCY ON A THIRD
  PARTY'S UPTIME, and `main` went red on one. `anchore/sbom-action` fetches the
  syft BINARY from GitHub releases on every matrix job; that endpoint answered
  503 and took down three of fourteen jobs on one run and a DIFFERENT three on
  the next, none of them for any reason to do with the images being built.
  RE-RUNNING IS A COIN FLIP, WHICH IS WORSE THAN A REMEDY THAT PLAINLY FAILS:
  of the two re-runs measured, main's failed the same way and the PR's passed —
  so the honest reading is not "retrying does not work" but that green depends
  on somebody else's CDN at the moment it is asked, which is the
  permanently-flaky shape the M5 base-image-gate entry warns about arrived from
  a new direction. THE FIX WAS ALREADY IN THE FILE, one step down: the
  vulnerability scan has never had this problem because it runs a PINNED
  CONTAINER (`anchore/grype:v0.97.1`) instead of downloading anything, so the
  SBOM now runs `anchore/syft:v1.42.3` the same way. That removes the failure
  mode rather than tolerating it and pins the generator's version, which the
  action resolved fresh each day. The retry is the BELT, not the fix — three
  attempts with backoff for registry blips, and the last is NOT swallowed,
  because nothing downstream reads the SBOM (grype scans the archive directly;
  it becomes an attestation only once images are pushed to a registry) and a
  gate with no consumer that silently stops producing is the rot this repo
  keeps closing. ANTI-VACUITY, because syft can exit 0 having catalogued
  nothing and an empty document looks exactly like a good one: the step counts
  packages and treats zero as a failed attempt. Both failure modes were driven
  locally before shipping — an unreachable syft image and an empty document
  each exit 1 — and the two `docker save` calls became one, the scan step
  having been building its own copy of an archive the SBOM step now needs.
- 2026-08-12 — AND MY GREP FOR THE EVIDENCE MATCHED THE PROSE DESCRIBING THE
  EVIDENCE. Checking the above in CI, a scan for `SBOM: [0-9]+ packages` across
  13 jobs returned 26 lines, thirteen of them an identical `288` — which read
  like every job cataloguing the same image, the one defect that would make an
  SBOM worthless while every job stayed green. It was not: the checkout step
  logs the PR event payload, and the PR BODY I had written contained the string
  `SBOM: 288 packages` in its results table. The real evidence was the other
  thirteen, one per job, and their VARIATION is what proves each SBOM describes
  its own image — `vault-web` reporting 14 packages against `identity`'s 193 is
  the zero-runtime-dependency origin showing up in its own bill of materials.
  Two rules. A grep over CI logs is searching a document that CONTAINS YOUR OWN
  WRITING about what you expect to find, so anchor it on the log's job/step
  columns rather than on a phrase. And a count that is suspiciously uniform
  deserves the same "measure it" reflex as one that is suspiciously wrong —
  here the uniformity was an artifact of the observer, and the same instinct
  applied to `if-no-files-found: warn` (4 of 13 artifacts, which was only the
  API's 30-per-page default) stopped a second false alarm.
- 2026-08-12 — THE EXTENSION HAS RUN IN A BROWSER, AND CI RUNS IT EVERY TIME,
  which retires the residual M16 carried from PR2b through the PR5 review.
  `.github/workflows/extension.yml` gains a `browser-smoke` job that EXTRACTS
  THE PACKED ARCHIVE and drives those bytes in Chrome over CDP: the manifest is
  accepted, the service worker boots, `chrome.offscreen.createDocument` succeeds
  from it, the offscreen document comes up, `/lib/vault-crypto/index.js`
  resolves at the absolute path the client really loads, and a REAL SRP-6a
  unlock against a stand-in speaking the real protocol returns an unlocked vault
  whose item decrypts to its title — with a wrong Secret Key refused BY THE
  SERVER. The central claim is then asserted over bytes that crossed a real
  socket out of a real browser, which is a stronger statement than the same
  assertion against a recording transport in Node. Every one of those was on
  PR2b's own "unexercised" list, and the jsdom double that stood in for them is
  the double PR3b proved MORE GENEROUS THAN THE PLATFORM.
  CHROME IS DELIBERATELY NOT PINNED in that job, inverting this workflow's rule
  for the packaging jobs. Those must pin because a moving toolchain moves the
  digest; this one is watching for the PLATFORM to change under the extension —
  a headless mode that stops loading extensions, an offscreen `reason` that
  stops being accepted, a CDP command that moves — and pinning would hide
  exactly what it exists to notice.
- 2026-08-12 — TWO DEFECTS IN MY OWN HARNESS, both found by mutating it rather
  than by reading it. (1) A VACUOUS PASS ON THE MOST IMPORTANT CLAIM: the
  stand-in's `/__requests` introspection route sat behind the same CSRF check as
  the protocol routes, so the harness's fetch was refused 403 and the
  "nothing key-derived reached the wire" assertion searched an ERROR OBJECT for
  secrets and found none. It passed. The anti-vacuity check beside it —
  "the run actually exercised the transport", asserting a request count —
  failed and is the only reason this was caught. An egress assertion over an
  empty haystack is indistinguishable from a clean one, which is precisely why
  it needs a companion that counts. (2) A BROKEN EXTENSION MADE THE HARNESS
  HANG: deleting the packaged `lib/vault-crypto` — the exact defect that shipped
  once and made the extension inert — left `chrome.runtime.sendMessage` waiting
  on an offscreen document whose module never initialised, and the promise never
  settles, so the run burned ten minutes and would have burned the job's whole
  `timeout-minutes` in CI. A timeout is the least useful failure a gate can
  produce: it says nothing about WHICH claim broke. Every evaluation is bounded
  now, and the same mutation fails in 31 seconds naming the crypto load. Both
  mutations are confirmed red; a third, planting the vault password in a request
  body, is caught by name ("LEAKED: the vault password").
- 2026-08-12 — ATTACHED IS NOT READY, and `browser-smoke`'s first red run was
  MY HARNESS rather than the extension. `Target.attachToTarget` succeeds as soon
  as the service-worker target EXISTS, while the worker's `chrome` bindings are
  installed a moment later — so readiness was asserted with a proxy, the very
  next `Runtime.evaluate` threw (`chrome.runtime.getManifest`, 55ms after
  attach), and every check downstream inherited it. The predicate is the
  capability actually needed now — the worker EVALUATES — polled to a deadline.
  A SECOND DEFECT HID THE FIRST: `ev` reports a thrown evaluation as `{__error}`
  and the caller did `String(v)`, so CI printed `[object Object]`. The failure
  could not say why, so the cause had to be REPRODUCED LOCALLY instead of read —
  which is the whole cost of a gate that cannot report itself. Details render
  through `describe` now, and `ev` prefers the exception's `description` over
  `text`, whose value is the bare word "Uncaught"; mutation-tested through all
  three states (`[object Object]` → `ERROR: Uncaught` → the real TypeError).
- 2026-08-12 — THE SOAK IS THE EVIDENCE THE MERGE SAID IT OWED, and it is worth
  the entry mostly for what it nearly measured instead. At merge the only
  post-fix run was green on Chrome 151 while the failure had been on Chrome 150,
  so it moved two variables at once and established nothing about the fix —
  recorded that way rather than claimed. Seven runs later, ALL SEVEN DREW
  Chrome 150.0.7871.128, the exact build that flaked, and all seven passed
  11/11: that version went from 1-pass-1-fail before the fix to 7-for-7 after
  it. Not proof — an intermittent failure hides, and a rate estimated from two
  runs is a terrible estimator — but it is a sample ON THE BUILD THAT FAILED,
  which is the only kind that could bear on the question at all.
  TWO NEAR-SILENT FAILURES IN THE SOAK ITSELF, both of which would have INFLATED
  the result. The workflow's `concurrency` group is keyed on event + ref with
  `cancel-in-progress`, so six dispatches on ONE branch cancelled each other and
  left a single run: "6 dispatched" followed by a green reads as six passes
  unless the conclusions are checked, and five of them said `cancelled`.
  Distinct refs give distinct groups. And the collection loop DID NOTHING —
  `for r in $RUNS` does not word-split in zsh, so it ran once with the whole
  string as one run id and every `gh run view` failed quietly; the background
  watcher carried the same bug and would have polled a nonexistent run forever
  rather than ever reporting. The tell was one line of output where seven were
  expected.
  THE SOAK STAYED OFF `main` DELIBERATELY: `attest` fires on any non-pull_request
  event there, so six dispatches would have minted six duplicate signed
  attestations for an artifact that already has one. A supply-chain artifact is
  not something to churn for a measurement.
- 2026-08-12 — THREE PREDICATES IN ONE SESSION WERE WEAKER THAN WHAT THEY
  CLAIMED, all of them mine, and the pattern is worth more than any one of them.
  The smoke harness waited for a service-worker TARGET TO EXIST rather than for
  the worker to RUN CODE. A CI watcher exited on `pending == 0`, which is also
  true before anything has started, and reported "no checks reported" as a
  settled result. Its fix — a floor of 20 checks — then still accepted 26 checks
  belonging to the PREVIOUS COMMIT, which is how a stale failure was reported as
  current. Each fix addressed the instance rather than asking what the predicate
  was supposed to MEAN, which for the watcher is "every check FOR THIS COMMIT has
  finished" and for the harness is "the worker can execute". That is the M16
  review's own rule — a rule applied to one member of a category is a rule
  half-applied — arriving three times in the session that recorded it. The
  watcher binds to the HEAD sha now, where staleness cannot satisfy it by
  construction.
- 2026-08-12 — M16 CLOSED, and the last thing it owed was a SENTENCE. docs/03
  §6j had recorded, since PR1's live drive measured it, that revoking a paired
  device is not instant downstream: identity deletes the row and answers 401 at
  once, but every peer resolves a caller through `HttpSessionVerifier`, whose
  POSITIVE cache holds for one TTL — so the vault answered 200 immediately after
  a revoke and 401 thirty-three seconds later. The window is a deliberate trade
  (negatives are never cached, precisely so an identity outage cannot lock out
  valid tokens) and shortening it would put an introspection on every request in
  the product. What was wrong was the SCREEN: "that takes effect immediately"
  above the list, "can no longer be used" after the click. THE M9 SHAPE
  INVERTED — not a control reading as an outage, but an outage-free UI reading
  as a STRONGER control than it is, on the one surface a person uses when they
  believe a device is compromised. One `PROPAGATION_SENTENCE` now serves both
  sites, because the confirmation someone reads while acting is not the
  paragraph they may never have read. The number is DERIVED from
  `SESSION_CACHE_TTL_MS` rather than typed out — `step-up.test.ts` already pins
  that to auth-guard's `DEFAULT_CACHE_TTL_MS` by READING the file (the web app
  cannot import a Nest package), so one existing check now keeps a security
  claim honest as well as a retry loop, and raising the TTL moves the sentence
  instead of quietly making it false. Mutation-tested by restoring both original
  strings; the pin names the old wording explicitly, so the specific regression
  is what turns it red rather than a generic assertion about the paragraph.
- 2026-08-12 — M17 IS ACCOUNT RECOVERY AND ABUSE BOUNDS (approved), displacing
  the subscription manager, which is re-sequenced rather than dropped. Chosen by
  a structured selection — five file-scoped evidence lenses, three judges ranking
  from deliberately conflicting priorities (risk, user value, dependency order),
  one synthesis — and every load-bearing claim re-verified by hand afterwards,
  because a verdict is not evidence. WHAT DECIDED IT: identity declares 23 routes
  and NOT ONE changes a password, resets a forgotten one, or changes an address;
  every "password reset" string in the docs refers to the VAULT password, so the
  account half was never even recorded as a deferral. There is no rate limiting
  anywhere — no throttler dependency in any `package.json`, and
  `recordLoginFailure` writes `login.failed` rows nothing reads. And
  `grep -rniE "webauthn|passkey"` across the BFF, web app, vault origin and
  extension returns ZERO hits, so identity's four relying-party routes have been
  unreachable since M2 and TOTP is the only usable factor — while docs/03 lists
  account takeover as risk #1 with "passkey nudges" among its residual
  treatments. The two halves ship together because a reset route without a bound
  is an enumeration and mail-bomb oracle, and a bound without a reset route is a
  lockout primitive.
- 2026-08-12 — THE RUNNER-UP LOST ON ORDER, NOT ON MERIT, and the disagreement is
  worth keeping because averaging it would have hidden the real argument. A
  value-first reading ranked the ASSETS SURFACE first and was right about its own
  lens — assets exposes 13 owner-facing routes against a BFF client with three
  methods, there is no `[assetId]` route, and `CreateAssetInput` carries no
  `inTrust`, so the in-trust badge can only ever read ZERO for an estate created
  through the product while the readiness page advises users about designations
  it makes impossible to create. The objection ("no customer opens the app to
  admire a password reset") is fair. It loses on COST-OF-DELAY ASYMMETRY: assets
  is flat-cost and unblocks nothing, while a general rate limiter touches every
  request path, so every surface added first is another surface to bound and
  another e2e to reconcile. Assets follows immediately. Stated rather than
  implied: nothing is deployed, so the recovery gap is not a live exposure today
  — it is a rising build cost and a hard gate on deploying at all, which is
  exactly why the case is sequencing rather than alarm.
- 2026-08-12 — RECORDED AS AN ESCALATION RATHER THAN A RECOMMENDATION: the M5
  cloud half is blocked on MONEY, not engineering (AWS org, ~$420–1,100/mo dev
  tier, a CI OIDC role), and about a third of docs/03's open residuals are
  structurally behind it — TB4's decrypt-rate baseline and KMS circuit breaker
  (the threat model's own "single most important insider control"), §5.3
  canaries, §5.6 Vault-Locked backups, and the audit chain's S3 Object Lock
  anchor, an M1 open item now sixteen milestones old. A dependency-first reading
  ranked it FIRST and it is not something an engineering decision can resolve, so
  it sits in docs/04 as a named escalation with two facts attached: the delay
  cost is mechanical (the compose topology must be encoded a second time in
  Terraform, and ten services is cheaper than thirteen), and the M4 publish CLI
  refuses placeholder-`legalReview` templates under `NODE_ENV=production`, so a
  production environment has NO ACTIVE TEMPLATES and generation returns
  `template_not_found` until that is resolved.
- 2026-08-12 — M17 PR1, THE ABUSE BOUNDS, and the measurement that shaped them.
  The obvious implementation — add `login.failed`/`login.succeeded` to M16's
  `SECOND_FACTOR_FAILURES`/`SUCCESSES` — DESTROYS the step-up cap, because
  `failedAttempts` counts failures SINCE THE LAST SUCCESS and the watermark is a
  single shared subquery, so a success of any kind in the set clears the window
  for every kind in it. Measured against real Postgres before a line was
  written: four `stepup.denied` rows plus one `login.succeeded` row reads as
  FOUR denials under the shipped sets and ZERO with login folded in — a plain
  password login, proving no second factor at all, resetting the second-factor
  cap and handing docs/03 §6j's stated residual (an attacker who holds the
  password can walk the account total to its ceiling) an unlimited reset. So the
  kind sets are PARAMETERS to the repo predicate now rather than imports, bounds
  are declared as data in `rate-bounds.ts`, and `test/rate-bounds.spec.ts`
  asserts they are PAIRWISE DISJOINT. A shared import is what made one bound's
  success another bound's amnesty.
- 2026-08-12 — A 429 ON LOGIN MANUFACTURES THE ORACLE IT WAS ADDED TO CLOSE, and
  this is the single most important line in M17 PR1. Past the threshold a real
  address would answer 429 while an address with no account answers 401 forever
  — nothing was ever counted for it, since `recordLoginFailure(null, …)` writes a
  NULL user — which is a perfectly reliable, timing-independent account-existence
  oracle created BY the control, defeating the `dummyVerify` equalization
  `password.ts` calls mandatory. Login's rate refusal is therefore the SAME 401
  `invalid_credentials` a wrong password gets, and the bound's visibility is the
  audit trail rather than the status code. M16's `too_many_attempts` stays
  correct on `stepup`/`totp/verify`, which already require a resolved
  authenticated caller. REGISTER answers 429 and that is safe for the mirror
  reason: its bound is keyed on the submitted address alone and counted whether
  or not an account exists, so the refusal depends on nothing the caller does not
  already know. Rejected as too clever: making the address half 429 and the
  account half 401, which is non-leaking only while the address cap fires first —
  an invariant nobody would think to preserve through a later edit.
- 2026-08-12 — ORDERING IS THE CONTROL, in both directions, and neither
  placement is the obvious one. The ADDRESS bound is checked BEFORE the user
  lookup, which is safe because its answer is existence-independent and is the
  only thing standing between an unauthenticated caller and 64 MiB of Argon2id.
  The ACCOUNT bound is checked AFTER the password verification, which looks
  wasteful and is the only correct placement: it can only be evaluated once the
  user is resolved, so checking it earlier would let an over-cap account answer
  fast while an unknown address still paid a full hash — the account-existence
  timing channel this route burns a dummy verification to close, re-opened by
  the control protecting it. Both orderings are pinned by source-level
  assertions, because both produce a working rate limiter and only one closes
  the channel; a runtime test cannot tell them apart.
- 2026-08-12 — THE BLIND INDEX DOES NOT GO IN `auth_events`, so the address-keyed
  bound is PER PROCESS and says so. The account-keyed half is structurally blind
  to most of its surface (a NULL user on every unresolved identifier; register's
  duplicate path writes no row in either direction), and the selector that would
  fix that is the email blind index. Putting it in that table would permanently
  and unshreddably record a correlatable identifier for addresses belonging to NO
  ACCOUNT — people who never registered, typed at a login box by somebody else,
  with no erasure path — because the table is append-only and carries no
  `dek_id`. It would also invert M9's "no blind index, lookup by user id only",
  and its index is a plain `CREATE INDEX` inside the migrator's BEGIN/COMMIT,
  which `005` already records as taking a SHARE lock on the auth write path.
  Consequences accepted and written in docs/03 §6k rather than implied: the
  in-memory half survives no restart, is not shared across replicas, and is
  capacity-bounded — so a caller can evict their own counter by spraying.
  Eviction fails OPEN deliberately, because failing closed would let whoever
  fills the map deny logins to every user in the product.
- 2026-08-12 — M16'S TWO-SCOPE ESCAPE DOES NOT PORT TO LOGIN, and the
  replacement is shown rather than asserted. The per-session scope is what
  stopped the step-up cap being a renewable owner-lockout; login has no
  credential at the point of failure, so no restructuring invents one and anyone
  who knows an address can hold that account at its ceiling. What bounds the
  harm is that the bound touches the LOGIN ROUTE ONLY —
  `findLiveByAccessHash`/`findLiveByRefreshHash` consult no counter, so an owner
  already signed in stays signed in and reaches every route in the product. That
  is not M16's situation, where the refusal blocked the one action that could
  clear the window and simultaneously blocked vault open, generation, export,
  beneficiary changes, deletion and §5.1's liveness proof. `login-bound.int.spec.ts`
  drives an attacker to the ceiling and asserts the owner's access AND refresh
  tokens still resolve. Twenty per fifteen minutes is chosen so no legitimate
  user meets it, which makes reaching it a burst signal rather than a support
  ticket.
- 2026-08-12 — AND MY OWN FORGIVENESS TEST WAS NAMED FOR A BOUNDARY IT NEVER
  REACHED, caught by mutation rather than review. "A successful login forgives
  the address" ran to one short of the cap, succeeded, then made ONE further
  attempt — which stays under the cap whether or not the success cleared
  anything, so deleting `loginAddresses.clear` left it green. It runs a second
  full round of failures now, where the absence of forgiveness puts the count at
  the cap and refuses before the lookup. The M13 rule restated: a test named for
  a property must exercise the boundary that property decides. Eleven other
  mutations were red first time, and the harness itself verifies the bytes
  changed before drawing any conclusion.
- 2026-08-12 — M17 PR1 DRIVEN LIVE, and the address bound is visible in the
  TIMINGS rather than inferred: ten wrong passwords at ~110ms each (one Argon2id
  verification apiece), then the eleventh at 27ms — refused before any work —
  and the correct password refused straight after with a byte-identical
  `401 {"error":"invalid_credentials"}`. Same shape against an address with NO
  ACCOUNT, which is the half the ledger structurally cannot see. The account
  ceiling refused a correct password at twenty failures since the last success,
  wrote `login.rate_limited | decision=account_rate`, left the count it bounds
  unmoved, and — the property that replaces M16's per-session escape — the
  owner's pre-existing access token answered 200 at `GET /v1/auth/session` and
  their refresh token answered 200 at `POST /v1/auth/refresh`. Register allowed
  twenty and answered 429 on the twenty-first with a null-actor ledger row.
- 2026-08-12 — THE DEPLOY-ORDER HAZARD WAS OBSERVED AT LAST, upgrading the
  2026-08-10 entry that recorded it as an absence read out of `ingestor.ts`
  rather than seen. With identity ahead of audit, the consumer logged
  `audit_event_rejected reason=schema_violation` once per event with a rising
  `rejectedTotal`, and `audit_events` held none of them — the new
  `AUDIT_ACTIONS` members are unknown to an older consumer, which is
  indistinguishable from malformed input to it. After rebuilding the consumer:
  zero rejections, and both scopes land with the designed attribution
  (`actor=null {"scope":"address"}` and
  `actor=set {"scope":"account","attempts":"20"}`). DEPLOY CONSUMERS FIRST;
  nothing enforces it, and the loss is silent in the one log whose completeness
  is the point.
- 2026-08-12 — AND MY FIRST LIVE PROBE OF THE ACCOUNT CEILING WAS WRONG IN THE
  MOST PLAUSIBLE WAY. It seeded twenty `login.failed` rows at `now() - 1 minute`
  — BEHIND the `login.succeeded` row its own sign-in had just written — and the
  predicate, which counts since the last success, correctly returned zero, so
  the login succeeded. That reads exactly like a bound that does not work. What
  separated a broken probe from a broken control was querying the ledger
  ordering before concluding anything, which is the repo's own rule (before
  believing an observation that contradicts the source, check what produced it)
  applied to a measurement rather than to an artifact. Also caught in the same
  session: `docker compose build … | tail` reported success while the build had
  failed with `DeadlineExceeded`, because `$?` was `tail`'s — the 2026-08-11
  lesson repeating, and the reason every gate in this session was re-run with
  its output redirected and its real exit code echoed.
- 2026-08-12 — M17 PR2: THE ACCOUNT PASSWORD CAN BE CHANGED, and the version
  image stops keeping the old one. Identity had no such route in sixteen
  milestones and no deferral written anywhere, because every "password reset"
  string in the docs refers to the VAULT password. The gate is BOTH halves and
  each covers what the other cannot: the current password is the one thing a
  stolen SESSION does not carry, so requiring it stops a hijacked bearer locking
  the owner out; step-up is the one thing a stolen PASSWORD does not carry, so
  requiring it stops somebody who learned it from making it permanent. The
  step-up half is CONDITIONAL on `SecondFactorGate`'s existing predicate,
  because an account with no verified factor has nothing to prove and an
  unconditional gate would make its password unchangeable forever — the worst
  answer for exactly the users least protected. Asked BEFORE the password check,
  so the route is not a free password oracle and the refusal's timing does not
  vary with whether the guess was right.
- 2026-08-12 — THE M6 VAULT REDACTION ARGUMENT DOES NOT TRANSFER, AND ITS
  JUSTIFICATION DOES. `vault_keysets` drops `wrapped_master_key` because a
  superseded wrapping is a LIVE capability against the CURRENT secret; an old
  Argon2id hash is only a verifier for a RETIRED password, login reads the live
  row alone, and nothing in the repo reads `users_versions` at all. So the vault's
  reason is refuted here. What DOES transfer is that comment's argument for
  keeping full row images everywhere else — "the ciphertext in it is readable
  with the same key as the live row", i.e. crypto-shredding reaches the capture —
  because `password_hash` is the ONE column in `users` for which that is false:
  a plain TEXT verifier, not a `*_ct` + `dek_id` pair, so it sits outside the
  envelope and erasure never reaches it. A row image that survives a shred must
  not contain a credential verifier. `email_ct` and `dek_id` are KEPT, which is
  the same rule applied rather than copied. Migration 008 ships in the same
  commit as the first write because `CREATE OR REPLACE FUNCTION` only affects
  FUTURE captures — a redaction one release late leaves verifiers nothing can
  retract.
- 2026-08-12 — IDENTITY GETS A TRANSACTION LAST OF THE NINE SERVICES, and the
  attribution half is why it could not be deferred. `withTransaction` makes the
  hash write and the session revocation commit together (a hash without the
  revocation leaves every credential minted under the old password live), but
  the load-bearing part is `set_config('app.actor_id')`: identity was the ONE
  service that never set it, so every row `trg_users_versions` has ever written
  came back with a NULL actor. That is what makes redaction defensible rather
  than merely safer — the trade is "drop the verifier, keep who and when", and
  without attribution there is no who and the capture would be pure liability.
- 2026-08-12 — THE FIFTH NOTIFICATIONS EDGE, with the cheap option RULED OUT
  rather than skipped. docs/04 decision 1 offered "a fifth edge, or a route
  through an existing holder"; the second is impossible as a NARROW grant,
  because `SendSchema` is built per-ROUTE from `ESTATE_NOTIFICATION_KINDS` and
  no per-holder subsetting mechanism exists anywhere — identity would receive all
  ten estate kinds including `settlement.case_opened` and every `emergency.*`.
  Nor is there a peer path: notifications has no Kafka consumer and identity
  holds no credential to profile, settlement or vault. The REAL alternative was
  widening the VERIFY edge, whose holder is already identity alone, and it is
  declined on that edge's own recorded reasoning: it was split from RECIPIENTS
  so the first future holder of a resend capability would not inherit a power it
  should not have, and a support tool or BFF-side resend is exactly that holder —
  it must not arrive carrying the ability to tell a user their password changed,
  which is the message an attacker would most like to send because it is a
  phishing pretext a recipient acts on. `identity.password_changed` is a SYSTEM
  kind and, within that, a member of a narrower `ACCOUNT_SECURITY_KINDS`: three
  send routes, three disjoint vocabularies, each schema built from its own list.
  The body carries NO variables at all — not even a timestamp, though "changed
  at 14:02" reads better — because the moment the wire carries one, a holder
  chooses part of what the user reads.
- 2026-08-12 — VERIFIED RATHER THAN ASSUMED, which the M17 plan explicitly owed:
  adding a system kind does NOT change the three "ten estate notifications"
  claims in the credential graph, the notifications controller and its config.
  `ESTATE_NOTIFICATION_KINDS` is still ten; the count was measured off the built
  package rather than reasoned about, and no edit was needed. The SEND edge's
  "identity is deliberately NOT here" comment WAS edited, because identity now
  mails on two of its own edges and the sentence had to say so.
- 2026-08-12 — A COVERAGE FLOOR DROPPED AND WAS NOT LOWERED. PR2's new code is
  mostly SQL, which the PG-gated int suite proves and identity's DATABASE-FREE CI
  run cannot see, so that gate went under its floor. The answer was
  `test/db.spec.ts` — `withTransaction`'s failure paths (rollback runs, the
  connection is released on every path, a FAILING rollback does not mask the
  error that caused it) — which is control flow rather than SQL semantics, is
  owed on its own terms, and is exactly what the int suite cannot isolate because
  every case there commits. Floor ratcheted 70/68/41/68 → 70/68/42/69. The
  database-free step added on 2026-08-12 is what made the drop visible at all.
- 2026-08-12 — MEASURED WHILE STOPPING: `pnpm -r run test` on this box fails two
  `apps/vault-extension` specs at ~988s each that pass in 65s run alone. It is
  CONTENTION, not a regression — those suites run PBKDF2 at 650k iterations and
  the repo-wide parallel run starves them past the jest timeout. Before treating
  a full-repo red as a real failure, re-run the failing package in isolation.
- 2026-08-12 — M17 PR2 DRIVEN LIVE, audit rebuilt and restarted BEFORE the
  producers: zero `schema_violation` rejections against eight in PR1's drive,
  which is the deploy-order lesson applied rather than rediscovered. A wrong
  current password answered 401 and changed nothing (two sessions still live,
  zero version rows); the change answered 204, evicted the other device while
  the caller's own session stayed 200, and killed the old password. The version
  image came back `password_hash present: false, email_ct present: true, dek_id
  present: true, actor: set` — the redaction, the deliberate keeps and the new
  attribution in one row. Ledger: `password.change_failed` then
  `password.changed`, and no `stepup.granted`. A real SES message reached the
  owner; the send log recorded `identity.password_changed |
  outcome=sent_unverified`, which is M14's machinery correctly noting an address
  this probe account never proved; the audit event carried
  `{"notified":"delivered","revokedSessions":"1"}`.
- 2026-08-12 — THE MIGRATE JOBS ARE SEPARATELY BUILT IMAGES, and rebuilding a
  service does NOT rebuild its migrator. `docker compose … run --rm
  migrate-identity` exited 0 while 007 remained the highest applied migration,
  because the migrator image predated 008 and had nothing new to apply. Exit 0
  from a migrator means "nothing to do" as readily as "it worked". Build
  `migrate-<svc>` alongside `<svc>`, and verify against `schema_migrations`
  rather than against the exit code — the stale-artifact rule, in a place the
  2026-08-06 entry did not name.
- 2026-08-12 — AND TWO MORE OF MY OWN PROBES LIED, both in the same session,
  both the same class. An unquoted conditional header inside a shell function —
  `${4:+-H "authorization: Bearer $4"}` — WORD-SPLITS on the space and hands
  curl four broken arguments, which presented as a flat `400` from a route that
  in fact answered 204; use an array. And `node apps/stack/dist/generate-env.js`
  exited 0 having written nothing, because the entrypoint is
  `generate-env-cli.js` and I had invoked the module: the tell was the file's
  MTIME, not the exit code. The rule this repo keeps restating, three more times
  in one afternoon: when an observation contradicts the source, suspect the
  observation first.
- 2026-08-12 — I SHIPPED A RED CI BECAUSE I RAN `build` AND `test` AND NOT
  `typecheck`, which is the 2026-08-12 entry "A GREEN JEST RUN IS NOT A
  TYPECHECK" committed by me four entries after writing it down. They are
  DIFFERENT TURBO TASKS over different file sets: `build` compiles `src`, and
  `typecheck` is `tsc --noEmit` over the package including its TESTS. M17 PR2
  added a method to `NotificationsPort`, and the only thing that broke was a
  hand-written port double in `apps/services/vault/test/notifier-adapters.spec.ts`
  — invisible to `pnpm build`, invisible to `pnpm -r run test` (ts-jest compiles
  per-file and the double satisfied every call the suite makes), and caught only
  by `@estate/service-vault#typecheck` on CI. THE RULE: widening a shared port
  or contract type means running `pnpm -r run typecheck`, because the implementors
  that break are usually TEST doubles and no other gate in this repo looks at
  them. Corollary already recorded and re-earned: a double must be faithful about
  what it REFUSES — vault's new entry returns `{accepted:false}`, because vault
  holds no account-security credential and a double that quietly succeeded would
  make a path that should never be reachable look healthy.
- 2026-08-12 — AND THE SECOND RED CI WAS THE SAME MISTAKE ONE LAYER OVER: I ran
  `pnpm -r run test` and CI runs `pnpm test -- --coverage`. Coverage THRESHOLDS
  only arm when coverage is collected, so a package whose floor my change had
  broken passed locally and failed there — twice, in `@estate/notifications-client`
  (a new client method with no test) and `@estate/service-notifications` (a new
  controller and guard). THE RULE, now general: before pushing, run CI's OWN
  command list — `pnpm format`, `pnpm build`, `pnpm lint`, `pnpm typecheck`,
  `pnpm test -- --coverage` — rather than the subset that happens to be
  convenient. Three of those five had never been run in this session, and each
  of the three caught something the others could not.
- 2026-08-12 — A TEST I ADDED PASSED VACUOUSLY AND I NEARLY KEPT IT. Adding a
  sixth call to the notifications-client credential-partitioning sweep left its
  exact five-element expectation GREEN — because that client had no `security`
  credential, so the new call short-circuited without a round trip and appended
  nothing. The tell was that an assertion listing exactly what each route
  presents did not change when a route was added. Fixed by giving the fixture the
  credential and the expectation its entry, then mutation-tested BOTH halves of
  the mapping: pointing the security route at the verification path is caught,
  and presenting the verification credential on the security route is caught. The
  second mutation's first anchor did not exist (prettier had reflowed the call
  across lines) and the harness's "assert the bytes changed" check is what stopped
  that from reading as a passing test.
- 2026-08-12 — A TEST OF MINE PASSED LOCALLY BY WRITING INTO THE LIVE DATABASE,
  and CI is the only reason I found out. `password-change.int.spec.ts` reset its
  fixtures with `DELETE FROM ${schema}.users`, which fires `trg_users_versions` —
  and that trigger's body references `users_versions` UNQUALIFIED, so it resolves
  through the CONNECTION's search_path rather than through the schema named in
  the statement. The admin client had none. On any machine running the stack
  there IS a `public.users_versions`, so every reset silently wrote its rows
  there and the suite went green; on CI's database, which has no such table, it
  failed with `relation "users_versions" does not exist`. MEASURED afterwards:
  212 junk rows in the real append-only table, from my own test runs. Fixed two
  ways — TRUNCATE instead of DELETE (fires no row triggers at all, so the reset
  cannot write anywhere) and `SET search_path` on the admin connection, so a
  future case that does need a DELETE does not rediscover this. VERIFIED by
  running the spec against the CORE cluster, which has no `public.users_versions`
  and is therefore CI's exact situation: the pre-fix version reproduces the CI
  error there and the fixed one passes.
  THE GENERAL RULE, and it is not about triggers: AN INTEGRATION TEST THAT
  SCOPES ITSELF WITH A SCHEMA PREFIX IS ONLY SCOPED FOR THE STATEMENTS IT
  WRITES. Anything the database resolves on its own behalf — a trigger body, a
  function, a default expression — uses the connection's search_path, so a
  scratch schema is not isolation unless the connection is pinned to it.
- 2026-08-13 — M17 PR3, PASSWORD RESET, and the decision that most weakens it,
  taken deliberately and against my recommendation: a reset requires the mailed
  code and NOTHING ELSE, even for an account holding a verified TOTP or passkey.
  The consequence is written in docs/03 §6m in plain words — for such an account
  control of the mailbox is control of the account, so a verified second factor
  does not protect against mailbox compromise — and what it buys is that nobody
  is ever permanently locked out, since TB7 does not exist and there are no
  recovery codes. What bounds the damage: the VAULT is untouched (2SKD derives
  Zone A's master key from the vault password and Secret Key, never the account
  password, and the mailed body says so because the vault origin already tells
  users Estate cannot reset that password for them), every session is revoked so
  the owner notices, the owner is mailed on completion, and every step is
  audited.
- 2026-08-13 — THE RESET MINTS NOTHING, which answers "does redemption grant
  step-up?" structurally rather than as a rule somebody has to keep. The M15 PR4
  escalation is the precedent: an unauthenticated redeem route that granted
  step-up let a stolen 60-second handoff code reach `POST /v1/vault/reset` and
  crypto-shred a Zone A vault, and a reset code granting step-up would be that
  primitive delivered by email to a code living thirty minutes. A fourth
  `recovery` audience would NOT have helped — `AllowSessionAudiences`
  unconditionally prepends `account` and identity binds no service-wide list, so
  a completion route admitting it would also be reachable by every ordinary
  account session. docs/04 decision 2 told PR3 to "assert what a reset session
  CANNOT do", which presumes one exists; `test/mint-paths.spec.ts` asserts the
  SET of mint paths instead and proves the reset absent from it — a stronger
  claim, because a capability never created cannot be mis-scoped.
- 2026-08-13 — THE REQUEST ROUTE IS ENUMERATION-SAFE BY CONSTRUCTION: it answers
  202 for every input and fires the mint-and-send WITHOUT awaiting it, so an
  address with an account cannot answer measurably later than a stranger's.
  Register's own docstring records that timing residual as still open; this route
  avoids inheriting it, which matters more here because a hit tells an attacker
  where to point a mailbox compromise. The consequence accepted with it: the
  caller is never told whether a mail was sent, refused by the floor, or had
  nowhere to go. Two bounds behind it, and the PER-ADDRESS one is primary —
  the per-account floor can only be evaluated after an address resolves, so it
  sees nothing at all for an address with no account, which is most of what an
  abuser sends.
- 2026-08-13 — A SIXTH NOTIFICATIONS EDGE, not a widening of VERIFY, despite the
  identical holder and a near-identical payload. The capability differs even
  though the wire looks the same: a verification code proves a MAILBOX and is
  redeemed by somebody already signed in, while a reset code REPLACES the account
  password and is redeemed with no session at all — so whoever can cause one to
  be mailed and can read that mailbox owns the account. Four send routes on that
  callee now build from four closed kind lists, so no holder of one can fire
  another's, and the two mailed-code patterns are anchored on different prefixes
  so neither route can mail the other's code.
- 2026-08-13 — THREE OF THE FOUR MUTATIONS THAT SURVIVED WERE MY MUTATIONS BEING
  UNFAITHFUL, which the harness's "assert the bytes changed" check does not
  catch: a replacement can change bytes and not behaviour. One made the guard
  fall through to a throw the fire-and-forget catch absorbs; one resolved a
  second lookup that also returned null. The fourth was real and is the useful
  one: a case named "TWO CONCURRENT REDEMPTIONS … exactly ONE success" passed
  with `markRedeemed`'s preconditions DELETED, because it duplicated the UPDATE
  inline — so it proved that Postgres honours a predicate, which was never in
  doubt, rather than that the repo's statement carries one. It drives the repo
  through two open transactions now. TWO properties are recorded as
  OVER-DETERMINED rather than contorted into mutability: an unknown address
  cannot be mailed however that guard is mutated, and expiry is refused at both
  the service read and the CAS.
- 2026-08-13 — A STATEFUL BOUND BREAKS TEST ISOLATION IN A WAY THAT LOOKS LIKE
  THE BOUND WORKING. The per-address reset bound lives on the service instance
  for the process's lifetime — exactly as in production — so the eleventh
  `request()` in one spec file was silently refused and a later case failed with
  "no code was mailed". The first fix, giving each case its own time window,
  broke the re-issue floor for a reason worth keeping: `created_at` is stamped by
  the DATABASE while the floor compares against the SERVICE's injected clock, so
  moving one forward moves them out of the same frame. Isolating by ADDRESS
  instead separates the cases on the axis the bound actually keys on and leaves
  both clocks alone. The general rule: when a fixture and the database each carry
  a clock, a fake date far from wall time is not a neutral choice.
- 2026-08-13 — M17 PR3 SHIPPED A RECOVERY CEREMONY THAT COULD NOT COMPLETE, and
  CI was green over it. `sendPasswordReset` emitted `{userId, code}` at a route
  whose `RecoverySchema` is `.strict()` and requires `kind`; every send answered
  400, and because identity RETIRES a code whose send fails, each request minted
  a code, mailed nothing and revoked it. Measured rather than reasoned about:
  `password_resets` held one row with `revoked=t, spent=f`, the SES mailbox held
  no `PR1-…` message, and `auth_events` had `password.reset_requested` with no
  send behind it. THE WHOLE PR WAS INERT IN PRODUCTION — the M16 PR2b shape (an
  extension that could never unlock a vault) in the milestone that cites it.
  TWENTY-SEVEN TESTS PASSED OVER IT because the wire body is DECLARED TWICE and
  each side's suite validated its own declaration: the client spec asserted
  method, URL and credential and never the body — its own fixture used the code
  `'PR1-ABCD'`, which `RESET_CODE_PATTERN` rejects — while the service specs
  built valid payloads by hand, so they only ever exercised bodies somebody had
  already made valid. Nothing anywhere put one side's OUTPUT into the other
  side's PARSER. Same drift class as `GQL_ERROR_CODES` (2026-08-10) and the
  `notification_sends` kind CHECK falling behind the wire enum (M14 PR0), and
  the remedy is M14 PR0's: DERIVE THE CASES, DO NOT LIST THEM.
  `apps/services/notifications/test/wire-parity.spec.ts` drives the REAL client
  over a recording transport and parses each emitted body with the schema its
  route really uses — it lives on the service side because the client package
  cannot import the service (wrong direction, and it would create a package
  edge), and it is derived in BOTH directions: the covered set comes from the
  client's own prototype (so a seventh method turns it red) and each declared
  path is checked against the controller source (so a renamed route cannot leave
  the fence parsing bodies nothing routes to). Fixed by having the client SEND
  the kind rather than by dropping it from the schema: it is what
  `notification_sends.kind` records, and a route that infers the kind logs what
  it assumed rather than what the caller asked for.
- 2026-08-13 — AND MY OWN NEW FENCE HAD A CONTROL NAMED FOR A PROPERTY IT NEVER
  TOUCHED, caught by mutation within minutes of writing the entry above. The
  "the schemas are STRICT" case parsed `{definitely: 'junk'}` and asserted the
  parse failed — which the REQUIRED-FIELD checks already guarantee, so it passed
  identically under `.passthrough()` and the mutation survived. Strictness is
  only observable on a body that is otherwise VALID, so the control now takes
  the real emitted body and adds one unknown key. The M13 lesson ("a test named
  for a property it never touched") committed inside the fix that cites it, for
  the second time in this repo — and the only reason it was found is that the
  mutation list included the property rather than only the defect.
- 2026-08-13 — A SERVICE THAT MAKES AWAITING INEXPRESSIBLE FORCES ITS TESTS TO
  SLEEP, and CI flaked on the sleep within two runs. PR3's `requestReset`
  returned `void` and detached `mintAndSend` internally — deliberately, so no
  caller could reintroduce the account-existence timing oracle — and the int
  spec's only way to drive the path was 25 microtask drains plus a bare 25ms
  `setTimeout` racing four real Postgres round trips: green on the first CI
  run, red on the second, which is the M8 PR4 determinism contract violated by
  a test the production shape forced. THE FIX IS M14's OWN SHAPE, which was
  sitting one file away: `ensureVerificationRequested` is awaitable and the
  DETACH lives in the caller. `requestReset` is `async` now, the controller
  does `void …requestReset(email).catch(() => {})`, every sleep in both spec
  files is deleted (the int spec awaits the real chain; 5/5 repeated runs
  green), and the timing property moved with the detach: a source-level pin
  asserts the handler is SYNCHRONOUS (a sync method structurally cannot await)
  and that the call site is `void …catch` — the M17 PR1 ordering-pin rule,
  because a runtime test cannot tell a fast await from no await. Both
  mutations (controller awaits; catch dropped) turn it red. The general rule:
  structural inexpressibility at the WRONG layer exports the hazard to every
  test as a race — put the awaitable surface where tests need it and pin the
  detach at the one call site where the timing property actually lives.
- 2026-08-13 — AN UNKNOWN FLAG IS NOT A REFUSED FLAG, and I rotated every stack
  secret out from under the running volumes proving it. Probing whether the env
  generator mints the M17 credential edges, I ran `generate-env-cli.js --out
  <scratchpad> --force`; `--out` is not a flag the CLI has, unknown arguments
  are silently ignored, and it wrote the REAL `.env.stack` — twice — with
  `--force` bypassing the exact guard whose docstring says why it exists ("new
  keys orphan every ciphertext in the volumes"). The tell was the same one the
  2026-08-12 entry records for the same CLI family: the output said `wrote
  .env.stack` while I was reading the exit code. RECOVERED WITHOUT A RESET
  because every running container still held the old coherent env: a script
  inverted the compose file's environment mappings (PREFIXED → service var),
  read each container's env via local `docker inspect` (never printed), and
  restored 34 secrets in place; the doctor passed, and — the case the overwrite
  would have broken silently — containers RECREATED from the restored file come
  up healthy and run the full reset ceremony. Two rules. A CLI that accepts
  arguments it does not implement must be probed with a HARMLESS invocation
  first (`--help`, or a copy of the target file moved aside), never with the
  destructive flag attached. And the answer to "does the generator handle X"
  was in the SOURCE the whole time (`generate-env.ts` derives credentials from
  the credential graph, so new edges are minted automatically) — running a
  writer to answer a read question is the wrong instrument even when it works.
- 2026-08-13 — M17 PR4, THE ADDRESS CHANGE, and the decision everything else
  fell out of: VERIFY-THEN-SWITCH, forced rather than chosen. Login resolves
  users by `email_bidx`, so a change that stored an unproven address would lock
  its owner out of LOGIN ITSELF the moment their sessions lapsed — which
  disqualifies change-then-verify before any security argument is needed. The
  new address is proved by an `EC1-` code mailed to it before anything on file
  moves; the old address, login and every notification keep working until the
  proof lands, so an abandoned or mistyped change costs nothing. This is also
  how the M14 forward commitment ("clear `verified_at` in the same statement")
  was discharged ONE STEP STRONGER than it asked: no unproven address ever
  reaches the delivery store, so the bit is never cleared — `RecipientsRepo.
  replace` swaps the address and stamps the proof in one statement, and the
  comment that carried the commitment was rewritten to say it is discharged
  (the M16 rule: a fence a document claims and nobody wrote is worse than none;
  a commitment a document says is open when it is closed is the same shape).
  The staged address is encrypted at REQUEST time as `users.email` under the
  live DEK, so the switch moves CIPHERTEXT — no decrypt inside the transaction,
  and a key rotated mid-ceremony refuses via a `dek_id` predicate restated
  inside the UPDATE itself (the M7 CAS shape, applied to key identity).
- 2026-08-13 — THE SEVENTH NOTIFICATIONS EDGE NAMES A DESTINATION, and owning
  that plainly beat disguising it. The challenge mail is inexpressible on every
  prior wire — every other send resolves its recipient from the encrypted
  store by user id, and the ceremony is by definition a challenge to a mailbox
  the store does not hold. Widening VERIFY was rejected because its recorded
  grant ("can only mail a code to whatever address is already on file") is
  precisely what a future resend-tool holder must keep inheriting; RECIPIENTS
  was rejected because a repoint credential gaining a carrier send is two
  capability classes back under one secret, the M9 finding restated. So
  `NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN` (identity alone) opens the one
  route whose payload names where mail goes, its grants sentence says so in the
  first line, and what bounds it is structural: the body is doctrine-clean, the
  service delivers once and STORES NOTHING (no recipient row created, read or
  touched — an int case plants a verified recipient and proves a challenge
  aimed elsewhere leaves it byte-identical), and the code completes nothing
  without the current password and a fresh factor. SIX DERIVED FENCES went red
  and then green in sequence as the edge landed — the graph fence, wire-parity,
  the send-log kind sweep, the template registry, the client partitioning
  sweep, and the stack parity pair — which is the M14-PR0 remedy (derive the
  cases) now catching a new capability at every layer it crosses without one
  hand-remembered list anywhere.
- 2026-08-13 — THE OLD-ADDRESS NOTICE IS AN ORDERING PROPERTY, NOT A WIRE
  PROPERTY. No route anywhere can mail an address that is not the stored one,
  and the person who most needs "your sign-in address was changed" is the
  reader of the mailbox being LEFT. The answer is sequencing: the notice goes
  out AFTER the switch commits but BEFORE the recipient replacement, so the
  store still resolves the old address — get it backwards and the takeover
  notice goes to the attacker. Pinned by an int case asserting the effect
  sequence verbatim. The copy was written for the one case that matters (a
  reader who did not make the change) and does NOT offer sign-in as the remedy,
  because that reader structurally cannot sign in — login uses the new address
  and the reset mails the new address. Recorded in §6n as a plain limitation:
  the notice is a DETECTION control; response is support until TB7.
- 2026-08-13 — THE ATTEMPT CAP IS ATTRIBUTABLE BY DESIGN, because the SELECTOR
  IS THE CALLER. PR3's reset deliberately has no attempt column (the redeemer
  is anonymous; a wrong guess resolves no row — the M14 round-2 lesson), and
  the change ceremony is its mirror: the redeemer is AUTHENTICATED, completion
  resolves the caller's own live change and compares digests, so a wrong guess
  of ANY shape burns one attempt on their own pending change. The same
  authentication is what lets refusals stay uniform without an enumeration
  argument — what the uniformity protects here is a PROGRESS METER (the M13
  §6g rule), plus one genuinely cross-account fact: the raced-register refusal
  at the switch answers the same `invalid_code` because "taken" would leak the
  other account, and it burns NO attempt — the code was right, the world
  changed.
- 2026-08-13 — THE NO-DB FLOOR WENT BACK UP, 69/67/41/68 → 70/67/43/69,
  reversing PR3's exception one PR after taking it. PR3 lowered because its
  new code was mostly SQL; PR4's ceremony carries a real decision layer (the
  gate order, the detach split, five open refusals, the effect ordering, the
  cancel asymmetry) and all of it is proven with the repo faked — plus the
  audit emitters' PII-firewall property (every detail value matches a closed
  token grammar or a stringified count), driven through the REAL AuditEmitter
  so its schema validation runs and only the transport is doubled. The two
  SQL-only repo files remain int-only, which is what the floors' split
  measurement exists to accommodate.
- 2026-08-13 — I RE-COMMITTED THE PR2 SEARCH-PATH DEFECT IN THE MILESTONE THAT
  CITES IT, and CI is again the only reason I know. PR4's freshness case
  planted an ancient `verified_at` with an admin UPDATE on
  `notification_recipients` — a table whose versions trigger resolves
  `notification_recipients_versions` UNQUALIFIED, against the CONNECTION's
  search_path. The notifications int spec's admin client, unlike identity's
  (which PR2 fixed), had never been pinned: every local run silently wrote its
  version rows into the live `public.notification_recipients_versions` (10
  junk rows measured and cleaned) and went green, while CI's database has no
  such table and failed honestly. The email-change int spec I wrote the same
  day pinned its connection FROM BIRTH because it copied identity's harness —
  which is the sharp edge of the lesson: THE RULE LIVED IN A FILE HEADER, NOT
  IN THE HARNESS, so a spec descending from the fixed lineage inherited the
  fix and a spec in the unfixed lineage inherited the hole. Fixed by pinning
  the connection; verified the PR2 way (the spec run against the AUTH cluster
  — CI's exact situation — fails before the pin and passes after; zero new
  rows in the live table after a core run) and mutation-tested by reverting
  the pin and watching the auth-cluster run go red.
- 2026-08-13 — M17 PR5, THE PASSKEY SURFACE, and the scope line drawn where the
  facts put it: WEB-ONLY, with the cost said on screen. The fact sweep
  established that extending the ceremony to the vault origin is an identity
  change (`rpOrigin` is ONE string; the assertion routes are account-audience;
  the vault edge allowlists exact routes) — so §6o records the residual
  plainly: a passkey-only account cannot complete any Zone A step-up-gated
  ceremony, and the passkeys section tells users to keep an authenticator app
  enrolled. TWO DEFECTS FOUND IN SHIPPED MACHINERY BEFORE BUILDING ON IT (the
  PR4 pattern, second PR running): `hasCredentials` — the WebAuthn half of
  `SecondFactorGate.holdsVerifiedFactor` — ignored `revoked_at`, latent only
  because nothing wrote that column, and PR5's revoke route is the writer that
  would have armed it (revoking the last passkey on a TOTP-less account =
  permanent enrolment lockout); and the same-authenticator-on-a-second-account
  unique violation was an unhandled 500. The rule both fixes restate: THE
  PREDICATE LANDS WITH THE WRITER, never after it.
- 2026-08-13 — REVOKING A FACTOR IS NOT REVOKING A SESSION, and the asymmetry
  is now written as data. M16 made session revocation ungated ("taking one away
  can only reduce authority"); passkey revocation is STEP-UP GATED because
  removing a factor weakens the gate that protects everything else — ungated,
  a stolen bearer strips the factors, `SecondFactorGate` disarms (no factor ⇒
  nothing to prove ⇒ enrolment ungated), and the thief enrols their own: the
  2026-08-12 escalation through the back door. `factor-routes.spec.ts` gained
  a `ROUTE_STEPUP` gate class AND the assertion that verifies it against the
  controller's real decorators — a label nobody checks is the
  fence-that-claims-without-checking shape — mutation-tested by stripping the
  guard (red) before anything shipped on it.
- 2026-08-13 — THE CEREMONY CODEC IS HAND-ROLLED AND THE PROMPT'S PASSKEY PATH
  IS SELF-CONTAINED, each for a recorded reason. The codec (~140 lines) is the
  node:crypto/clamd/SRP precedent: @simplewebauthn/browser would put a
  dependency tree on the second-factor path to save mechanical base64url
  conversion over a FIXED field list, and the fixed list is itself the honest
  shape. Browser-side ceremony failures (a closed sheet, a timeout) get their
  own local vocabulary and never launder into platform copy — a cancellation
  reading as a platform refusal is the M9 rule's client-side mirror. The
  StepUpPrompt discovers the caller's passkeys ITSELF, on mount, failing to
  silence — so all four prompt-and-retry callers gained the option with zero
  changes and TOTP is never hostage to a nicety; the ceremony await sits under
  the same ownership counter as every other await, proven by a case that
  settles the platform sheet AFTER Cancel and asserts nothing applied.
  WEBAUTHN_FAILED is mapped BY TOKEN before status because identity answers
  400 and 401 with one token, and the 401 half collapsing into UNAUTHENTICATED
  would forget a valid session over a refused ceremony (the M16 PR2b lesson,
  one wire over). Failed assertions finally write a ledger kind — the
  2026-08-10 entry claimed they "emit their own kind" and the code emitted
  NOTHING, so the log was corrected by making it true, with the kind in no
  rate-bound set (a passkey is not brute-forceable, and counting it would let
  a flaky authenticator lock out its own owner).
- 2026-08-13 — M17 PR6 security review (seven file-scoped discovery lenses over
  the merged milestone — never a diff range, the M13 rule — then TWO
  adversarial verifiers per deduped candidate on different angles, production
  reachability and is-it-already-a-decision, both defaulting to refuted; 12
  raw, 12 unique, 2 confirmed, 10 refuted). EVERY confirmed finding was
  re-proved BY EXECUTION against the running stack before a line changed, and
  every fix mutation-tested by reverting it. ELEVENTH milestone running where
  every confirmed finding sits in machinery the milestone introduced, and both
  falsify a claim it made about itself.
  THE WORST ONE IS A ROUTE THE MILESTONE'S OWN FRAMING HID: `POST
  /v1/auth/password` verifies the current password and had NO BOUND OF ANY
  KIND. Measured rather than argued — twenty-five wrong guesses from one
  session, twenty-five plain 401s, no refusal ever, and the twenty-sixth (the
  right one) took the account over; the same volume at `POST /v1/auth/login`
  produced ten `login.failed` and four `login.rate_limited`. One
  credential-guessing action, two routes, one bounded. The gap is exactly §6k's
  sentence: PR1 bounded "the routes that take a password from an
  UNAUTHENTICATED caller", and this route READS as authenticated — while the
  entire reason it asks for the current password is the stolen-session threat,
  so its caller is the party the bound is for. It bit hardest on FACTORLESS
  accounts, which `SecondFactorGate` deliberately lets through (the bootstrap),
  so nothing else stood in the way. THE GENERAL RULE: a bound's scope statement
  is a claim about which routes check a secret, and "authenticated" is not the
  same question as "does not check a secret".
- 2026-08-13 — THE PER-SESSION SCOPE THAT COULD NOT PORT TO LOGIN PORTS HERE,
  which is why the fix is M16's two-scope shape rather than login's
  account-only one. `LOGIN_BOUND` has `maxPerScope: null` because
  `recordLoginFailure` runs before any session exists — no credential at the
  point of failure, so no per-credential budget, and the recorded cost is that
  an attacker can deny NEW logins. The change route HAS a credential at the
  point of failure, so a stolen session exhausts its OWN budget and stops while
  the owner's other sessions keep theirs: the cap cannot become the
  owner-lockout that an account-only bound would be on a route the owner needs.
  The refusal is 429 with its own token (safe here and not on login: the route
  already required a resolved authenticated caller, so it tells them about
  themselves) and its own ledger kind, because a refusal counted by the bound
  that produced it feeds its own counter — the M16 lesson, applied rather than
  rediscovered. A reset deliberately does NOT clear the window: it revokes
  every session, so the attacker's credential is already dead, and admitting a
  kind reachable WITHOUT proving the current password would let the reset path
  launder the guessing window.
- 2026-08-13 — PR5's OWN LEDGER CORRECTION WAS INCOMPLETE, which is the same
  defect one layer down. PR5 added `webauthn.assertion_failed` to correct a
  2026-08-10 decision-log entry claiming failed assertions "emit their own
  kind" while the code emitted nothing — and recorded on only two of the four
  failing branches. The two that short-circuit EARLIEST stayed silent: no live
  challenge, and a credential id that names nothing or names somebody ELSE's
  authenticator. Measured: ten probes against a live account produced ZERO
  `webauthn.*` rows, and the foreign-credential probe — the class no browser
  produces by accident — was precisely the invisible one. The lesson is about
  the SHAPE of a correction: adding an event where the failure is most
  convenient to catch is not the same as adding it everywhere the failure
  happens, and a docstring that says "every assertion failure" is checkable
  only by counting the throw sites.
- 2026-08-13 — TWO REFUTATIONS WORTH AS MUCH AS THE FINDINGS, both because the
  behaviour was ALREADY WRITTEN DOWN. A lens flagged the account-cap refusal
  running a full Argon2 before refusing (and skipping the in-memory address
  record) as an unbounded-cost hole; §6k already records the address bound as
  per-process, best-effort and evadable, and the one-hash cost on a refusing
  path is stated inline — the residual is real and documented, which is the
  difference between a finding and a rediscovery. Another flagged historical
  `users_versions` rows retaining the Argon2id verifier; refuted on ORDERING —
  the migrator applies 001→011 before the app serves, so a fresh deploy
  installs the redacting trigger before any `users` UPDATE, which migration
  008's own comment states. Both are why the verify phase runs two angles: the
  is-it-a-decision verifier is what stops a review from re-litigating settled
  trade-offs as though they were defects.
- 2026-08-13 — AND TWO NOVEL-BUT-UNREACHABLE CANDIDATES ARE RECORDED RATHER
  THAN FIXED (docs/03 §6p): a crypto-shredded DEK at email-change completion
  would surface as a 500 instead of the uniform `invalid_code` (no code path
  destroys a DEK — `destroyDek` still has zero callers), and clone detection
  rejects a counter-regressed assertion without revoking the credential, so a
  later higher-counter assertion from either copy still succeeds. Both arm the
  day an erasure route or an automatic-revocation policy lands. The M14
  precedent cuts both ways and the choice is stated: M14 FIXED its latent
  crypto-shred defect because the fix was one predicate in machinery already
  being touched, while these two need decisions (what should a shredded
  account's ceremony answer; is automatic revocation on a heuristic the right
  response) that belong to the milestone that makes them reachable. Writing
  them down is the part that is not optional.
- 2026-08-13 — CLONE DETECTION NOTIFIES THE OWNER AND DELIBERATELY DOES NOT
  REVOKE, which is the M17 PR6 review's item ANSWERED rather than adopted. The
  obvious fix — revoke the credential whose signature counter regressed — is
  wrong for a reason the code already encodes: `storedCounter > 0` means SYNCED
  passkeys (iCloud Keychain, Google Password Manager) report 0 and never reach
  the branch, so it fires only on counter-maintaining authenticators, where a
  regression is a clone OR a firmware/state bug. Destroying a factor on a
  heuristic is the M6 rule pointed the wrong way, and on an account holding no
  TOTP it lands the owner in exactly the bootstrap-lockout state M17 spent a
  milestone making survivable. So: reject the assertion (unchanged), tell the
  owner, and let them revoke from the surface M17 PR5 shipped.
  `identity.passkey_clone_detected` rides the ACCOUNT-SECURITY wire because it
  carries nothing — no credential id, no device name, no counter — and the
  wire has no field for text. THE ORDERING IS THE M13 RULE APPLIED: the notify
  runs BEFORE the audit emit, because `webauthnCloneDetected` reaches Kafka and
  propagates broker failures by design, so emitting first would let an audit
  outage swallow the one control that makes the signal actionable by the person
  it is about; the delivery outcome then rides that event as
  `notified: delivered|failed`, so a warning that did not land is visible
  rather than absent. Pinned by three cases — the credential SURVIVES (with the
  repo double gaining a real `revokeCredential` mock, since an undefined one
  makes `not.toHaveBeenCalled` pass vacuously), the notify-then-audit order,
  and the failed-send outcome. The derived fences absorbed the new kind with no
  edit at all (the templates registry and the int-spec kind sweep both loop over
  `ACCOUNT_SECURITY_KINDS`), which is M14 PR0's "derive the cases, do not list
  them" paying off; only the client package's LITERAL surface assertion needed
  updating, and that it failed is the fence working.
  WHAT STAYS OPEN, recorded in §6p rather than implied: a cloned credential
  remains usable until the owner acts. That is the deliberate cost of not
  acting on a heuristic, and what would change it is a SECOND signal, not a
  lower threshold on this one.
- 2026-08-13 — AND THE CLONE BRANCH WAS DEAD THE WHOLE TIME, which only the
  live drive found — after the notification had already been written into it.
  `@simplewebauthn/server`'s `verifyAuthenticationResponse` runs its OWN
  counter check (`(counter > 0 || credential.counter > 0) && counter <=
  credential.counter` throws) because we handed it `storedCounter`, so it threw
  BEFORE our clone branch could run and every regression landed in the generic
  verify catch. Measured rather than reasoned about: a forced regression on the
  running stack produced two `webauthn.assertion_failed` rows and ZERO
  `webauthn.clone_detected`. So `webauthn.clone_detected`, its audit action and
  the M2 comment describing the control have been dead code since M2 — and the
  M17 PR6 review's clone item ("rejects but never revokes") was moot, because
  the branch it described never ran. Shipping the notification as first written
  would have added a zero-callers path INSIDE dead code, which is the defect
  class this repo keeps closing, one level deeper than usual.
  THE FIX IS TO OWN THE POLICY: the library is handed `counter: 0` — its
  documented "this RP does not track counters" value — and the check runs below
  it, on a VERIFIED assertion. The ordering is the security half and is not
  incidental: checking the counter before verification would act on unsigned
  attacker-supplied bytes, letting anyone holding a session make the platform
  mail an owner a clone warning at will. The trigger set is unchanged for every
  reachable state (stored 5 / presented 3 and stored 5 / presented 0 both still
  refuse), so no refusal is given up and the signal is gained. Pinned by
  asserting the ARGUMENT the library receives, which is the only place the
  property lives. THE GENERAL LESSON: when a dependency and our own code check
  the same invariant, one of them is dead — and which one is not visible in
  either file. Only running it says.
- 2026-08-13 — M18 IS THE TB4 DECRYPT-RATE BASELINE (approved) — the detection
  half of the M5 split, on the M8 take-over precedent: take the deliverable,
  shrink the cloud half, revise the sentences. Chosen because discovery
  FALSIFIED docs/04's claim that the baseline is structurally blocked behind
  the AWS spend: the signal is complete locally — every Zone B service emits
  `crypto.field.decrypted` FAIL-CLOSED (plaintext is withheld if the audit
  sink rejects, packages/crypto dek.ts), so the stream is a complete record of
  released plaintext — and only the ENFORCEMENT half (suspending a KMS grant)
  needs real IAM. Three PRs: PR1 attribution + the debts it makes acute, PR2
  the detector, PR3 the security review. Five-lens discovery (audit pipeline,
  doc commitments, the crypto signal, candidate homes, measured rates from the
  live stack) ran before scoping; four load-bearing claims re-verified by hand.
- 2026-08-13 — M18 settled design, six decisions. (1) GRAIN is per
  (service × actor class × actorId), with the SERVICE derived from the decrypt
  field name's first dotted token — the audit envelope carries no producing-
  service field, the prefixes are disjoint per service today but UNFENCED, so
  PR1 closes them into a registry in @estate/contracts (the AUDIT_ACTIONS
  shape) and an UNREGISTERED prefix becomes its own reportable class, never
  silently absorbed. (2) THE SIGNAL IS THE AUDIT STREAM, NEVER KMS LOGS: the
  5-minute DEK cache means N decrypts under a hot key are N audit events and
  ZERO KMS operations, so KMS-side detection structurally cannot see read
  volume — the doc's KMS-centric framing gets revised, not just deferred.
  (3) THE MECHANISM IS THE M16/M17 RATE-BOUNDS SHAPE: counts derived from the
  append-only ledger by windowed query, no counter state an attacker can
  reset, thresholds as reviewed CONSTANTS per (prefix class × actor class) —
  deliberately NOT a learned baseline, because an attacker can train a learned
  one and cannot train a reviewed commit; the anomaly action
  (`crypto.decrypt_rate.exceeded`) is never in its own counted set. (4) THE
  DETECTOR LIVES IN THE AUDIT SERVICE on the settlement-driver pattern
  (powerless, unref'd interval, errors swallowed-and-logged so ingest — the
  paging signal — cannot be killed by its advisory neighbor), on its OWN pg
  connection, gaining the service's first Kafka producer so the anomaly event
  flows through the sanctioned AuditEmitter path into the verified chain;
  zero-credential fence unchanged, no HTTP, and consumer-first deploy ordering
  self-satisfied because emitter and consumer are one image. (5) THE ALERT
  SINK IS THE CHAIN + A LOG, NO OWNER NOTIFICATION: the reader is a security
  operator who does not exist until TB7, and making audit a notifications SEND
  holder would falsify its fenced zero-credential posture. (6) THRESHOLDS COME
  FROM MEASUREMENT FIRST: the live dataset holds ZERO contact/profile/document
  decrypts while the repo's own record says one contact-detail page is ~100
  events, so PR1 drives the real surfaces and records ceilings BEFORE any
  number is pinned. Zone A out of scope by construction (no server decrypt
  path; vault burst detection is `vault.open.failed`, a different signal);
  settlement and vault are legitimately silent, and their silence is not an
  outage. PR1 also fixes two debts found in discovery: documents'
  getEvidenceContent audits an OPERATOR evidence read as actorType 'user' (the
  wrapper default — pass 'operator', which exists in the enum), and
  settlement's "decrypted only on explicit read" comment describes a read
  route that does not exist (the claim-without-mechanism rule: correct the
  prose, do not add the route).
- 2026-08-13 — M18 PR1 SHIPPED: `DECRYPT_FIELD_PREFIXES` (fourteen prefixes,
  eight services; `distributions` registered despite settlement being
  encrypt-only, so a decrypt ever appearing under it attributes rather than
  falling to unknown), the documents operator-attribution fix (pinned with an
  owner-read control proving ordinary reads still audit as 'user'), audit
  migration 002 (partial (occurred_at, actor_id) WHERE decrypt — occurred_at
  LEADS because the sweep is a time-range over all principals; the suggested
  actor-first order cannot serve it), and the MEASURED CEILINGS (peak per
  principal per minute: contact 160, profile 50, asset 30, doc 10,
  notification_recipient 16 under the nil-UUID service sentinel, mfa_methods 2,
  assistant_message 2, everything else 0; ordinary journey users peak at 4).
  THE FENCE'S CLOSURE RULE WAS DELETED ON ITS FIRST RUN, and that is the
  entry's load-bearing lesson: "no unregistered dotted literal in crypto files"
  looked like the assertTokenizerCoversTools shape and found ~170 legitimate
  literals from OTHER vocabularies sharing those files (identity's ledger kinds
  alone are 122) — an exclusion list that size is the permanently-red gate
  people learn to ignore, the M5 lesson from the other direction. What
  remains is the pair the registry actually owes the detector — a registered
  token in the WRONG service's source is red, a registered prefix ABSENT from
  its own service's source is red — with per-service floors, and the
  unknown-prefix net moves to where it can be loud without lying: the
  detector's own reportable class plus PR2's zero-anomaly e2e gate. Division
  of labor: the fence keeps the REGISTRY true, the detector keeps the UNKNOWN
  loud. Six fence mutations red on the assertions that name them.
- 2026-08-13 — THE STACK REBUILD LIED THREE WAYS BEFORE IT RAN, all variations
  of recorded lessons, recorded because the costume changed. `pnpm stack:up`
  died on this pnpm's `--` forwarding (already in memory — the doctor read
  literal `--` as an env-file path). The parallel image build OOM-killed
  (`ResourceExhausted`) TWICE — `COMPOSE_BAKE=false` did NOT disable bake
  delegation (the log's "load local bake definitions" is the tell) — and my
  `&& echo OK || echo FAILED` wrapper reported the background task "completed"
  over a dead build both times: the piped-exit lesson wearing a new costume
  (never wrap a gate's exit in an echo). The stack then ran on MIXED-VINTAGE
  images — migrate-audit and documents from 2026-08-11, audit from that
  morning — which would have made the measurement substrate silently predate
  M17 PR2-6 AND the fix under test; caught by `docker image inspect
  --format '{{.Created}}'` per container, the stale-artifact rule's cheapest
  instrument. The reliable rebuild shape on this box: ONE `docker compose
  build <service>` per invocation, sequentially, failures propagated, then
  verify image Created timestamps before believing anything. migrate-audit's
  own log (`audit_migrations_applied count=1`) was the second tell — a
  migrator that applied one migration when the tree holds two has not seen
  your file.
- 2026-08-13 — M18 PR2 SHIPPED: the decrypt-rate detector inside the audit
  service. The shape is everything the decision log promised — windowed GROUP
  BY over the 002 index on the detector's OWN pg session, pure evaluator over
  `decrypt-rate-bounds.ts` (reviewed constants from PR1's measured table), the
  service's FIRST Kafka producer feeding `crypto.decrypt_rate.exceeded`
  through AuditEmitter onto its own topic and so into the verified chain,
  episode dedup failing in the EXTRA-event direction, faults swallowed-and-
  logged and never fatal (a detector error must not kill ingest, the paging
  signal) — plus three decisions taken while building. (1) EVERYTHING OUTSIDE
  THE REVIEWED TABLE IS BOUND 0: an unregistered prefix, an unmodelled
  (prefix × principal) combination, and encrypt-only `distributions` each
  breach at the FIRST decrypt, because a read path nobody reviewed is itself
  the anomaly — and `undecidedPrefixes()` plus its spec force every registered
  prefix to carry a VISIBLE decision (bound row or encrypt-only reason), so
  the zero default can never be reached by forgetting. (2) THE DETECTOR IS
  STARTED FROM main.ts, not a lifecycle hook: suites construct classes
  directly and never run main, so the timer structurally cannot run under
  jest — the settlement-driver rule achieved by PLACEMENT, because audit's
  config deliberately has no NODE_ENV to key on. (3) THE E2E GATE PAIRS A
  POSITIVE CONTROL WITH THE FALSE-POSITIVE ASSERTION: the brief's bare
  "zero anomaly events after the journey" is vacuously green over a DEAD
  detector (the M8 dead-consumer shape), so the test bursts 101 step-ups past
  the smallest bound (identity's TOTP path has no replay ledger, so repeated
  codes are cheap; successes are uncounted by the M16 cap), polls for exactly
  that anomaly — which also makes the negative half deterministic, since the
  tick that catches the burst evaluated a window covering the whole journey —
  then asserts EVERY anomaly in the store names the deliberate bound.
  Asserting "all rows are the burst's bound" rather than "count == 1" is what
  keeps repeated local runs green while CI sees exactly one. Counts
  25/4→26/4 (both workflow twins) and 16/13→16/14. Six mutations red
  (threshold off-by-one, self-feeding SQL, unknown-prefix absorbed, sentinel
  folded, dedup dropped, audit-grows-a-prefix fence); the self-feeding
  mutation went red one case EARLY — the widened counted set surfaces the
  chain's own anomaly event as a missing_field breach in the episode case,
  which shares cumulative counts — recorded as cascade attribution, not
  papered over with a widened regex.
- 2026-08-13 — M18 PR2's docs delta is the KMS-framing correction, stated
  once here for the grep trail: docs/03 §4 TB4 and §5.3 no longer claim KMS
  sees read volume (the 5-minute DEK cache means N reads under a hot key are
  N audit events and ZERO KMS operations — bulk UNWRAPS across many users
  remain KMS-visible and rate-limited, which is the half KMS keeps); §6q
  records the detector, its alert-sink decision (chain + log line, NO owner
  notification — audit's zero-credential posture is fenced), the per-process
  episode residual, the provisional unexercised bounds, and the
  rebuild-trips-by-design note; docs/05's "cannot test anomaly detection"
  split into detection-local / response-cloud; docs/04's escalation list
  shrank by the detection half (the M8 take-over precedent).
- 2026-08-13 — M18 PR3 security review (six file-scoped discovery lenses over
  the merged range, each in its OWN DETACHED WORKTREE pinned to the reviewed
  commit — the 2026-08-12 rule, and no agents were lost this time — then TWO
  adversarial verifiers per deduped finding on different angles, both
  defaulting to refuted; 22 raw, 11 unique, 12 verdicts, 4 fixed). TWELFTH
  milestone running where every confirmed finding sits in machinery the
  milestone introduced. THE WORST ONE FALSIFIED THE MILESTONE'S OWN
  PROMISE IN BOTH DIRECTIONS: the episode reconciliation ran AFTER the emit
  loop inside one try, so a failed emit skipped it and a principal whose
  episode had cleared stayed marked announced — its next genuine episode
  swallowed as a duplicate, a LOST anomaly under a docstring, a §6q
  paragraph and a decision-log entry all promising the fail direction was
  always an EXTRA event. Reproduced against the real detector before the fix
  ([A, B] where [A, B, A] was owed) and again by me independently. The same
  shared try let one unemittable breach cancel its neighbours.
  AND THE ADVISORY DETECTOR COULD KILL INGEST: neither pg client had an
  `error` listener, node-postgres emits one on connection-level death, and
  an unhandled 'error' event is an uncaught exception — so a failover or an
  idle-session reaper on the detector's mostly-idle connection would have
  killed the audit service, bypassing the fatal path entirely (no
  `audit_service_fatal` line, no handle release), for the one component
  whose docstring says its faults must never do that. Reproduced against the
  live cluster (57P01 → uncaught → exit). The fix is a connection wrapper,
  not a listener: a pg Client NEVER RECONNECTS, so a listener alone trades a
  crash for permanent silent deafness — one warn line a minute, no alerting,
  process healthy. It also connects lazily (an advisory component must not
  make boot load-bearing) and carries a query timeout, without which a
  black-holed socket leaves the re-entrancy guard latched for the OS
  keepalive interval with nothing logged — the M8 dead-consumer shape,
  arrived at from a third direction.
- 2026-08-13 — M18 PR3's other two fixes, and the lesson each carries. EVERY
  PROJECTION REBUILD FIRED THE LOUDEST ALARM IN THE TABLE: the rebuild has
  TWO sentinel decrypt sites and the bounds table modelled only the ledger
  replay, so the live-view diff (`asset.<id>.<col>`) resolved to
  `unmodeled_principal`/0 and breached at count 1 on any valued estate — the
  "read path nobody reviewed" class raised by a reviewed path, which is
  precisely how an alarm stops being read (the M5 permanently-red-gate
  lesson, reached through a loud DEFAULT rather than a noisy check). The
  general rule: when a fail-closed default is LOUD, every legitimate path
  must be enumerated by EXECUTION, not by memory — I had checked the
  services' decrypt call sites and still missed a second site inside a file
  I had already read. And TWO NOTIONS OF "A PRINCIPAL" IN ONE DETECTOR: the
  sweep groups by `actor_type` (a column) while bounds key on the principal
  CLASS that folds the sentinel's two actor types together, so the two rows
  were never merged — each under the bound while their sum exceeded it.
  Whenever a query's GROUP BY and a decision's key are different
  vocabularies, the gap between them is an evasion path.
- 2026-08-13 — M18 PR3: A MUTATION SURVIVED AND THE HONEST ANSWER WAS THAT MY
  FIX HAD TWO HALVES AND ONLY ONE WAS LOAD-BEARING. Reverting the
  reconcile-before-emit ordering alone left the suite green, because the
  per-emit catch already stops a throw from escaping the loop; reverting BOTH
  halves turns it red on the assertion that names the property. The repo's
  rule says a surviving mutation means a weak test OR an unfaithful mutation
  — this is the third case, a change that is defence in depth rather than the
  fix, and the code now says which half is which instead of implying both.
  Recorded because the tempting move was to weaken the mutation until it went
  red and call the fix proven.
- 2026-08-13 — M18 PR3 recorded-not-fixed, in docs/03 §6q: the window keys on
  PRODUCER-authored `occurred_at` (the ingestor preserves it and there is no
  server-authored ingest-time column), so ingest lag or a slow producer clock
  silently drops counts and a far-future timestamp pins an episode forever —
  the fix is a schema change (an ingest-time column, or windowing on `seq`)
  belonging to whichever milestone needs it; an emit outage longer than the
  300s window LOSES the anomalies raised inside it, because the retry is
  bounded by the window that produced them; "a complete record of released
  plaintext" holds only for code going THROUGH FieldCrypto, since the package
  exports the AEAD open() and a Zone B process holds unwrapped DEKs for five
  minutes — in-process compromise decrypts with no event and no KMS call,
  which is the enforcement chokepoint's job, not this detector's; and the
  false-positive gate runs in the development profile only.
- 2026-08-13 — M19 IS THE ASSETS SURFACE (approved; the 2026-08-12 runner-up
  chosen): four PRs — PR1 hardens the shipped M3-era service + the repo-wide
  route↔consumer fence (no new surface, the M13 "order is the point"
  precedent), PR2 the BFF/web read+write surface, PR3 the beneficiary
  ceremony, PR4 the review. Scope forks decided: the fence is REPO-WIDE
  owner-facing (its motivating cases — settlement's 25, M17's recovery
  routes — sit outside assets), and PR2 makes RETIRED assets visible
  (status + includeRetired + getAsset serves retired; a sold house must not
  vanish from a product whose own comment says "asset history is the
  product"). Discovery corrected the selection sweep: `CreateAssetSchema`
  has accepted the full input set since M3 and `PATCH /v1/assets/:assetId`
  already does null-clears edit semantics — the sweep's route list missed
  it — so M19 needs NO service DDL; the whole gap is BFF/GraphQL/web. The
  executor estate surface, Plaid UI, temporal/asOf UI, pagination and §5.5
  beneficiary visibility are named OUT.
- 2026-08-13 — M19 PR1 hardening, three fixes and a first. (1) THE M7
  EXECUTOR-INVENTORY ROUTE HAD NEVER EXECUTED: `GET /v1/estates/:ownerUserId/
  assets` (docs/03 §5.1 control 5) shipped in M7 PR2 with zero callers, zero
  e2e references and zero int coverage — an entire authorization path no test
  had ever run; it now has both layers (a controllable StageAuthority double;
  int cases asserting the staged question is asked on the CALLER's own
  bearer, the refused path's uniform 403, executor-attributed decrypts and
  the onBehalfOf audit event), with the full-stack journey deliberately
  absent — the stack cannot lapse a real waiting period, and the seam's
  settlement side already had its own suites. (2) UNIFORM 404 ON CROSS-OWNER
  PROBES: Cedar's deny answered 403 where a missing row answered 404, an
  existence oracle on every asset-scoped path; `assertCanOrNotFound` now
  answers the byte-identical missing-row 404 (the M10 PEP / M13 profile rule,
  third service). The executor route's 403 stays — its param is an owner id
  the caller already knows. Documents' own oracle stays open as recorded.
  (3) THE LIST DECRYPTED FOUR FIELDS PER ROW for a page that renders one:
  `AssetSummaryDto` (an explicit interface, deliberately NOT `Omit` — a field
  added to the full DTO must not join the hottest wire shape silently)
  decrypts exactly `est_value`; detail keeps the full DTO, and the executor
  inventory KEEPS full DTOs because it is the executor's only read surface.
  Both consumers verified unaffected (the BFF never read the dropped fields;
  the assistant's schema strips them by design). All fixes mutation-tested;
  the harness refuses no-op mutations and reads only the jest summary line.
- 2026-08-13 — M19 PR2 SHIPPED THE READ+WRITE ASSET SURFACE, and the two
  decisions worth keeping are both about keeping distinctions apart. (1) TWO
  ASSET SHAPES ON THE WIRE, list and detail, never one nullable type: the
  list structurally cannot carry costBasis/location/notes (the service
  decrypts exactly est_value per list row — PR1's narrowing), and a shared
  type would make "not carried" indistinguishable from "not set", the M11
  missing-field rule violated at the TYPE level. The BFF client's detail
  schema REQUIRES the fields the list lacks, so a version-skewed response is
  refused rather than half-trusted. (2) NULL-VS-ABSENT SURVIVES ALL THREE
  HOPS: GraphQL coerced args keep an omitted argument and an explicit null
  apart, JSON.stringify drops undefined and keeps null, and the service's
  UpdateDetails reads null as CLEAR — so the web edit form sends ONLY changed
  fields, a field edited to empty travels as null, and untouched fields are
  absent. Pinned by wire-level assertions at each layer and proven live: the
  browser cleared notes_ct at the database while location_ct survived, and
  the ledger's history entry reads "notes cleared". IDEMPOTENCY IS
  PAYLOAD-KEYED (`command-id.ts`): one browser-minted eventId per payload,
  held across retries of the SAME payload, regenerated the moment the payload
  changes — because attempt one may have committed despite a client-visible
  failure, and an edited payload reusing the old id would be answered with
  the ORIGINAL ack while the edit silently vanished. VERSION_CONFLICT's only
  remedy is RE-READ (a never-auto-retries pin); the copy generalized to
  surface-neutral wording rather than minting an asset-specific code.
- 2026-08-13 — M19 PR2's RETIRED-ASSET VISIBILITY, as approved: status +
  retiredAt on both DTOs, getAsset serves retired records (commands still
  404 — "the command surface treats a retired asset as gone; the READ
  surface serves its record"), the list gains ?includeRetired, and the asOf
  replay honors the flag (an asset retired before the as-of date is honest
  temporal data when asked for). The web shows retired rows behind a
  deliberate toggle, excluded from every total. THE LIVE DRIVE FOUND THE
  DISPLAY CLASS AGAIN (tenth milestone running): with Show retired on, the
  trust card COUNTED a retired in-trust asset (client-side arithmetic over
  the loaded list) beside a server-computed value that correctly excluded it
  — one card disagreeing with itself; the count is live-only now, pinned by
  a fixture that renders exactly that pair. Also from the drive: the whole
  journey's decrypt budget measured in the real audit chain (asset_list=2 —
  ONE per row, the PR1 narrowing live; asset_read=13; asset_history=3, once,
  on demand; net_worth=1), and decrypt-rate-bounds.ts recalibrated by
  reviewed commit per §6q — the provisional asset_event/user row has its
  first real measurement. DELIBERATELY NO STACK-E2E ADDITIONS (counts
  unchanged in both workflow twins): int + resolver suites + the real-browser
  drive cover the layers, and the exact-count dance is saved for PR3, whose
  step-up ceremony is the thing that genuinely wants a cross-service leg.
- 2026-08-13 — THE ROUTE↔CONSUMER FENCE (M19 PR1,
  `packages/auth-guard/test/route-consumers.spec.ts`): zero-callers made
  data, the credential-graph shape applied to the product surface. Routes are
  DERIVED from comment-stripped controller source across all nine services;
  routes behind credential-graph guard CLASSES are excluded (one fence per
  fact — `opens` already covers them, and a handler-level credential guard
  would surface as a route DEMANDING an entry, the fail-safe direction);
  `ROUTE_CONSUMERS` maps each of the 150 non-internal routes to consumer
  FILES verified to contain a URL template addressing the route
  (interpolations collapsed to wildcards, matched segment-wise, vault's
  `/api/…` templates matched under edge rewrites that are themselves
  asserted against server.ts source) or to a grouped substantive exemption.
  Checked in BOTH directions with anti-vacuity floors; mutation-tested six
  ways, all red. STATED LIMITS: path-based matching (a literal covers every
  method on its path), and tests are deliberately not consumers. FIRST-RUN
  FINDING: M17's six recovery/address-change routes (password, reset ×2,
  email-change ×3) have NO product consumer — the milestone that closed
  "identity has no password reset" left the ceremonies unreachable from the
  product; recorded as EXEMPT_RECOVERY_SURFACE naming the pending frontend
  slice. Assets' own write surface is exempt "pending M19 PR2/PR3", and
  those PRs flip the exemptions to consumers in the same change as the
  clients — the M9 PR2 holders-flip pattern.
- 2026-08-13 — M19 PR3, THE SERVICE CHANGE IS TWO LINES AND BOTH ARE THE
  ZERO-CALLERS SHAPE IN MINIATURE. The remove route finally passes `eventId`:
  `RemoveBeneficiarySchema` accepted it since M3 and the controller never
  bound the query parameter — an idempotency key that existed at every layer
  except the one connecting them, found by wiring its first consumer. And
  `runCommand` gained an idempotent-replay PRE-CHECK (`findByEventId` before
  the transaction, answering the original ack with `replayed: true`), because
  the idempotency the unique index promises was UNREACHABLE for any command
  whose precondition examines state its own first execution changed: a
  retried remove re-ran softRemove's designation-exists precondition against
  the world the first execution had altered and 404'd — the retry of a
  SUCCESSFUL command reporting the command had never been possible. The index
  stays as the race backstop for two concurrent firsts; the pre-check serves
  the sequential retry, which is what retries actually are. Pinned at the int
  layer (a replayed remove answers its original ack), because the defect
  lived in ordering a fake repo cannot see — the M13 SQL-pin rule.
- 2026-08-13 — M19 PR3's MEMBERSHIP CHECK LIVES IN THE BFF BECAUSE THE BFF IS
  THE ONLY LAYER THAT SEES BOTH CLUSTERS. docs/02 §8 forbids a cross-cluster
  FK, so nothing in the database makes `asset_beneficiaries.contact_id` name
  a real contact; assets holds no profile credential by design. Designate
  therefore refuses a contactId absent from the caller's own contacts
  (INVALID_REQUEST, before the write) or the designation would be dangling
  FROM BIRTH. Remove is DELIBERATELY unchecked — a designation whose contact
  was deleted must stay removable or the dangling row is permanent — and the
  asymmetry is pinned by a mutation that ADDS the check to remove and goes
  red. Names compose ONLY when designations exist (each name is one audited
  decrypt; a zero-designation read costs zero), and a dangling contactId
  renders `name: null`, never dropped. The direct-API residual (a caller
  speaking to assets directly mints a dangling designation in their own
  estate) is recorded in docs/03 §6r rather than closed: every closure either
  builds a cross-cluster projection or hands assets a credential, for a
  hygiene property whose failure renders honestly and stays removable.
- 2026-08-13 — M19 PR3's CEREMONY: ONE StepUpPrompt, and the retry binding is
  a DISCRIMINATED UNION carrying the refused action's own arguments — the
  M13-review defect (a shared handler running a different action than the one
  refused) has no shape to reoccur in, because the pending state carries
  {kind, contactId, designation, sharePct} and the retry dispatches on THAT,
  never on what the form now says. THE PICKER FORM HIDES WHILE THE CEREMONY
  IS UP: the first version showed two "Cancel" buttons at once (the picker's
  and the prompt's — the M15 identical-label ambiguity), caught by this PR's
  own test asserting the hidden form and the restored values after cancel.
  Contacts load lazily (picker open only), ack.version flows up through
  onVersionBumped so no re-read and no decrypt is spent on a number the ack
  already carries, and readiness findings about a specific asset deep-link to
  /assets/[id] — the incoherence the milestone exists to close, closed
  literally. DELIBERATELY NO STACK-E2E: the service-level
  designate-through-real-step-up leg has existed in stack.e2e.spec.ts since
  the M3 era, the BFF has resolver suites including the membership refusal,
  and the UI was proven in the real browser.
- 2026-08-13 — M19 PR3's PRE-PUSH REVIEW FOUND THAT THE IDEMPOTENCY FIX WAS
  ITSELF INCOMPLETE, in the direction its own comment claimed was covered. The
  replay fast path reads on the POOL, outside the transaction — so a retry
  RACING its still-in-flight original sees nothing, serializes behind
  `lockById FOR UPDATE`, and after the original commits dies at If-Match (409,
  the product path — `expectedVersion` is non-nullable on the mutation) or at
  softRemove's already-removed precondition (404). Neither reaches the append,
  so the unique index the comment credited as "the backstop for two carriers of
  one id" is STRUCTURALLY UNREACHABLE for a remove race: a COMMITTED command
  answered as impossible, in exactly the window (a slow original) where
  timeout-driven retries happen. Measured 404 before the fix. Closed by
  RESTATING the predicate under the row lock (the M7 read-then-restate shape),
  where the retry's fresh READ COMMITTED snapshot sees the committed event; the
  pool read stays as the fast path, and the catch's remit narrows to CREATE
  races, which take no row lock. The general rule: a pre-transaction read and
  the transaction it guards are separated by every commit that lands between
  them, so a check that must hold AT THE WRITE has to be restated where the
  write serializes — and a comment assigning the leftover case to a backstop
  is worth checking against the code path that backstop actually sits on.
- 2026-08-13 — AND THAT PRE-CHECK HAD OPENED AN EVENT-EXISTENCE ORACLE AHEAD
  OF THE UNIFORM 404 THE SAME MILESTONE SHIPPED. Running before `lockById` and
  `assertCanOrNotFound`, it answered 409 for an eventId naming ANY user's
  ledger event and 404 for an unknown one (measured: 409 vs 404) — so M19 PR1
  closed the 404-vs-403 oracle and M19 PR3 re-opened a narrower one two PRs
  later, because a new fast path was added ABOVE the authz it was supposed to
  sit under. Fixed by scoping the lookup to the CALLER: a foreign id behaves
  exactly like an unknown one and dies at the uniform 404, pinned by a probe
  asserting the two responses are byte-identical. THE LESSON IS ABOUT
  ORDERING, not about idempotency: any read placed before the authz gate
  answers a question about somebody else's data, however narrow the answer
  looks — an optimization that moves work earlier moves it out from under
  every control it used to sit beneath.
- 2026-08-13 — M19 PR3 review, the display half: `100 - total.sharePct` is
  ARITHMETIC ON A FLOAT and rendered "97.94200000000001% unassigned" for a
  2.058% share. Measured across the legal 3-decimal domain (PctSchema admits
  3dp): 32,448 of ~100,000 valid shares print noise. `apps/web/src/lib/
  percent.ts` formats at the WIRE'S OWN precision — 3dp is not a display
  preference but the full precision of the value, so rounding there can never
  hide a digit the server sent — and is applied to ECHOED values too, so the
  next computed percentage cannot skip it by looking like all the others. This
  is the formatMoney rule arriving for the product's other numeric type: a
  number a person reads goes through a formatter, and the moment one is
  COMPUTED rather than echoed that stops being style and becomes correctness.
  Pinned twice: in the formatter's own spec over the whole 3-decimal domain,
  and at the COMPONENT, because the defect was a raw interpolation there
  rather than a broken formatter.
- 2026-08-13 — M19 PR3 DRIVEN IN THE REAL BROWSER against images rebuilt from
  the reviewed commit, and the whole ceremony is visible in one audit trail:
  the step-up prompt with its designate-specific wording and the picker form
  HIDDEN behind it (exactly one "Cancel" in the DOM, `Share %` gone — the M15
  identical-label rule holding live rather than in a test), a genuine TOTP
  elevation, the retry applying, and `2.058% designated (97.942% unassigned)`
  — the precise value that printed 97.94200000000001 before the review's
  formatter fix. Then the share-sum refusal with its own copy, appending
  NOTHING to the ledger; a designated contact deleted from /people (profile
  permits it — a designation is not a role, so `contact_in_use` never fires),
  rendering as "No longer in your contacts" and still removable with no
  membership question asked; and the readiness finding "Shore Road cottage
  names beneficiaries AND sits in your trust" CLICKING THROUGH to that
  asset's own page — the M10 incoherence closed end to end. THE DECRYPT
  BUDGET WAS MEASURED RATHER THAN REASONED ABOUT: five `contact.name`
  decrypts for one designation on a one-contact estate — picker 1, membership
  checks 3 (the refused attempt plus two retry polls; the elevation
  propagated on the SECOND poll, not the seventeenth), name composition 1 —
  which turns the review's "up to ~20 loads" worst case into a number, and it
  is the number that went into docs/03 §6r.
- 2026-08-13 — M19 PR4 security review (seven file-scoped discovery lenses over
  the merged milestone range — never a diff range, the M13 rule — each in its
  OWN worktree PINNED with `git checkout --detach <sha>`, then TWO adversarial
  verifiers per candidate on different angles, both defaulting to refuted; 31
  agents, 0 errors, 20 raw, 20 unique, 12 confirmed, 8 dropped under the cap and
  logged BY NAME, then hand-verified — all eight were real and all eight were
  fixed). Both HIGH findings were re-proved BY EXECUTION against the running
  stack before a line changed. THIRTEENTH milestone running where every
  confirmed finding sits in machinery the milestone introduced, WITH ONE
  EXCEPTION that is the most interesting item in the review (the 429 entry
  below).
  THE WORST ONE: RETIREMENT — THE SERVICE'S ONE IRREVERSIBLE VERB — WAS NOT
  STEP-UP GATED. Every other command APPENDS a correction (an edit is an event,
  a removed designation keeps its history), so retire is the only one that ends
  an asset, and docs/01 §5's deletion-request clause covers it — assets' own
  beneficiary route has complied since M3. It shipped in M3 under CallerGuard
  alone, was dormant while nothing called it, and went live the moment M19 PR2
  put a Retire button on screen: a stolen bearer could retire an estate one
  asset at a time with no second factor. What ships with the gate is the part
  that generalises — `route-gates.spec.ts` declares each route's gate class as
  DATA with a `because` reason, DISCOVERS routes from Nest's RUNTIME metadata
  (`__guards__`/`path`/`method`) rather than from decorator text, and asserts
  bidirectionally with anti-vacuity floors. Anchoring on what the runtime reads
  is the 2026-08-07/2026-08-12 rule: a fence keyed on an identifier a caller
  chose can be renamed into invisibility. Residual recorded in docs/03: the
  fence covers assets ONLY, and generalising it touches eight services.
- 2026-08-13 — A GLOBALLY-UNIQUE IDEMPOTENCY INDEX IS A CROSS-USER EXISTENCE
  ORACLE. M3's `ux_asset_events_event_id` was unique across the whole table and
  `findByEventId` carried no owner predicate, so a stranger's `eventId` answered
  409 while an unused one answered 201 — measured live (201/409/201) before any
  fix. The ids are CLIENT-generated by design, which is what makes a retry a
  no-op and also what makes an observed id a probe. FIXED BY SCOPING, NOT BY
  CATCHING: migration `002_event_id_per_user.sql` re-creates the index on
  `(user_id, event_id)` and `findOwnByEventId` carries the owner, so a foreign
  id is byte-identical to an unused one at BOTH layers — catching the 409 and
  rewriting the answer would have left the oracle in the database for the next
  caller. NO pre-flight is needed because the migration WIDENS what is permitted
  (no existing row can violate it), which is the precise opposite of
  `002_dek_unique_active`'s situation and worth saying out loud so the rule is
  not cargo-culted. The pre-`002` constraint name is deliberately NOT also
  accepted by the conflict mapper: a database that has not run the migration
  must fail loudly rather than quietly serve the old behaviour.
- 2026-08-13 — SEPARATE POOL QUERIES ARE SEPARATE SNAPSHOTS, AND THE ORDER
  DECIDES WHICH WAY THE RACE FAILS. `getAsset`/`listAssets`/`listEstateAssets`
  read the projection row and the latest ledger seq in two queries, ROW FIRST —
  so a command committing between them returned OLD state paired with a NEW
  version, and the caller's next `If-Match` passed against state they had never
  seen. A silent lost update, produced by an optimistic-concurrency token that
  was itself correct. Reversed, the same race returns new state with an old
  version and the write is refused with a spurious 409 the surface already
  handles by re-reading. THE ORDER IS THE CONTROL, pinned by a test that commits
  an update from inside `ledger.latestSeq`; `latestSeqByAssets` became
  `latestSeqByUser` so a list can read versions BEFORE it knows its rows. The
  cost is accepted and stated in docs/03: an unlucky reader is told to reload
  when nothing was wrong with what they held, which is the only side of the
  trade that cannot silently discard an edit.
- 2026-08-13 — A CONSTRAINT TRIGGER IS ONLY REACHED BY A RACE, WHICH IS WHEN A
  500 IS LEAST DESERVED. The ledger's share-sum CHECK (the repo's one CONSTRAINT
  TRIGGER, which exists because that invariant spans rows) surfaced as an
  unhandled 500 — the app-level check catches every ordinary case, so the only
  callers who ever see the trigger are two concurrent designations, and they got
  a server error instead of the 422 the app-level path returns for the identical
  situation. Mapped to `share_sum_exceeded`. THE PIN SAYS WHAT IT PROVES: no
  test in the repo provokes the real trigger (the mutation for this one SURVIVED
  first time, which is how that was discovered), so the unit case makes the repo
  double raise the real Postgres error shape and states that it proves the
  MAPPING and not the trigger — the M13 rule that a test must say WHICH layer it
  is measuring.
- 2026-08-13 — AN AUDIT EVENT EMITTED AFTER THE WORK IT DESCRIBES IS NOT A
  RECORD OF THE WORK. The executor inventory (`estate.viewed`, docs/03 §5.1
  control 5) was emitted AFTER the decrypt loop, so a failure mid-loop released
  an executor's view of somebody's estate with no event saying it happened —
  on the one read path whose whole justification is that it is logged. Emitted
  BEFORE the loop now, carrying the row count. Same shape as the M9 "the step
  that cannot be undone runs last" rule pointed at evidence rather than at state:
  the RECORD goes first when the thing it records is a disclosure.
- 2026-08-13 — THE ROUTE↔CONSUMER FENCE PR1 SHIPPED HAD FOUR HOLES, which is
  this repo's standing expectation of new trust machinery meeting itself one PR
  later. Its verb list omitted `Search`/`Head`/`Options`/`All`, so a route
  declared with any of them was INVISIBLE to a fence whose only job is to see
  every route; a decorator the parser could not read was silently SKIPPED (now
  collected into `unparseable` and asserted empty, the anti-vacuity habit); a
  consumer template's `:p` matched a LITERAL route segment, so a client
  addressing one path could satisfy a different route; and the vault edge's
  rewrites were HAND-COPIED — derived from `apps/vault-web/src/server.ts` now,
  with the derivation itself asserting the `/api/` prefix is absent and that no
  pair reaches `/v1/auth/handoff`. The tightened matcher then produced four
  FALSE POSITIVES on `/v1/analysis/*`, where the BFF genuinely addresses all
  four routes through a closed `AnalysisName` union; the answer was a DECLARED
  exception (`consumedByName`, with its reason) rather than loosening the rule
  globally — a matcher relaxed to admit one legitimate shape re-opens the hole
  the tightening closed.
- 2026-08-13 — ONE M19 FINDING WAS OLDER THAN M19 AND WAS FIXED ANYWAY, BECAUSE
  M19 IS WHAT MADE IT REACHABLE. Identity's step-up cap (M17 PR6) answers 429
  `too_many_attempts` and the BFF's shared `mapError` had no 429 branch, so a
  control firing exactly as designed fell through to `Error('identity responded
  with status 429')` and reached the browser as "something went wrong on our
  side" — the M9 rule inverted, and the identical shape the 404 branch three
  lines below it already names. M19 PR3 and PR4 put step-up ceremonies on the
  assets surface (a designation, a retirement), so the cap is now reachable from
  two more places. PROVEN BY EXECUTION before it was fixed: five wrong codes at
  `POST /v1/auth/stepup` answer 401 `invalid_code`, the sixth answers 429.
  `TOO_MANY_ATTEMPTS` is its OWN code because it is the only refusal in the
  union whose remedy is to WAIT — every other one is fixed by doing something
  differently NOW — so folding it into `INVALID_CREDENTIALS` would render
  "codes change every 30 seconds, enter the current one" at somebody whose
  current code will also be refused. The 429 branch is STATUS-keyed rather than
  token-keyed on purpose: 429 means one thing on every route, and a future bound
  arriving with a token this edge has not learned should still be told apart
  from an outage. The copy says to wait and says nothing is wrong with the code;
  it deliberately does NOT name a number of minutes, because that window is a
  reviewed constant in a service the web app cannot import and a figure people
  plan around must not be a second copy free to drift. The derived
  `error-codes.test.ts` fence caught the BFF/web drift by itself, which is the
  fence working rather than something to route around.
- 2026-08-13 — TWO SURVIVING MUTATIONS IN ONE SESSION, AND NEITHER MEANT WHAT IT
  LOOKED LIKE. One anchored on `return dtos;`, which occurs several times in the
  file, so `indexOf` mutated the FIRST — the RED it produced was about a
  different statement and was untrustworthy even though it was red. The other
  found no test anywhere provoking the share-sum trigger, which is a real gap
  and produced the pin above. Added to the list of ways a harness lies here:
  beyond `git checkout --` on uncommitted work, `node -e` losing `$1` to shell
  expansion, grepping for `✕` outside verbose mode, and length-instead-of-content
  no-op checks, there is now ANCHORING ON A NON-UNIQUE STRING. A mutation is only
  evidence about the test if you know which bytes it changed.
- 2026-08-14 — A PERMISSION THE PLATFORM DID NOT HONOUR WAS RECORDED AS ONE IT
  DID, found while scoping M20 and fixed on its own branch first, because a live
  defect must not hide inside a feature change. `permission_grants` accepted any
  lowercase token as a `resource` and any of three actions; the row was stored,
  audited `permission.granted`, and listed back to the owner under "What this
  role may read". Exactly ONE pair is read by anything —
  `effectiveContactReadGrants`, profile's only grant reader and the enforcement
  behind docs/03 §5.5, filters `pg.resource = 'contact' AND pg.action = 'read'`.
  MEASURED against real Postgres over the six combinations the people surface
  offered: one conferred access, five conferred nothing, and two of those five
  were buttons an owner could press. THIS IS WORSE THAN A REFUSAL — a refused
  grant is visible and can be worked around, while an accepted one that confers
  nothing produces a durable false belief about who can see an estate, with a
  written record saying so, discoverable only by noticing that nothing happened.
  Nobody gains access they should not have; the harm is that the owner's model of
  their own estate is wrong in the permissive direction, which is the direction
  that stops them arranging real access.
  THE DEFECT WAS A DRIFT BETWEEN TWO INTERNALLY-CONSISTENT LISTS and neither
  side's tests could see it: the surface's `RESOURCES` had three entries, the
  reader had one, both had been that way since M13, every suite green. The
  zero-callers shape inverted — not a route with no consumer, but a consumer with
  no enforcement. Fixed with `enforced-grants.ts` (the honoured pairs as data,
  reason per entry) and a `422 grant_not_enforced` refusal placed AFTER the
  ownership check so it cannot become an oracle (the M10 rule). THE CHECK IS ON
  THE PAIR AND LIVES IN THE SERVICE, not in the zod schema: `contact` and `read`
  are each enforced while `contact`+`download` is not, so a per-field enum could
  never express it — and keeping the schema to SHAPE leaves a malformed body an
  ordinary 400 while an unenforced pair gets its own token, since "we have not
  built this" and "your request was malformed" send a person to different places.
- 2026-08-14 — TWO FENCES, BECAUSE NEITHER SIDE OF THAT DRIFT COULD SEE IT ALONE.
  `apps/services/profile/test/enforced-grants.spec.ts` asserts the declared table
  equals the literals the reader's SQL really filters on, and that no undeclared
  file reads grants (derived from the directory, not a hand-kept list). It
  REFUSES a SQL shape it cannot parse rather than matching nothing — a second
  enforced pair needs an `IN`, and a fence that stops matching goes green (the
  2026-08-07 lesson). `apps/web/src/components/RoleControls.enforced.test.ts`
  asserts what the surface OFFERS equals what profile ENFORCES by reading the
  other file (the compose-parity mechanism; the web app cannot import a Nest
  package), with anti-vacuity floors on both scans because two regexes that
  quietly match nothing agree perfectly. One case exists purely to make the
  equality TOTAL: an entry missing its `grantable` flag fails safe at runtime
  (no button) and fails SILENT at the fence (absent from both lists), so the flag
  is required per entry. Nine mutations, all red, all restored — the two that
  matter being the refusal deleted (red at the service AND over real HTTP against
  real Postgres) and `grantable: true` put back on assets.
  THE INT SUITE'S OWN FIXTURES HAD TO CHANGE, and that is the sharpest part: two
  existing cases used `document`/`read` and `asset`/`read` as convenient grants
  and passed. A test that reaches for an inert value as a fixture is how a
  promise with no enforcement behind it survives a test run — the M13 "a test
  named for a property it never touched" shape, one layer over, in a fixture
  rather than an assertion.
- 2026-08-14 — SAYING WHAT IS NOT SHAREABLE IS PART OF THE FIX, not decoration.
  Dropping the two buttons would have left a page that silently only ever
  mentions contacts, which produces the same wrong belief more quietly — an owner
  assumes the share was arranged elsewhere. So the surface names both omitted
  resources and states that nobody but the owner can read them whatever role they
  hold, and the link-redemption panel's "anything they choose to share with you"
  is narrowed to what a role can actually be allowed. Grants written before the
  vocabulary closed still render with their label and stay withdrawable: hiding
  an inert row strands it, and dropping the label renders it as a bare token.
  RECORDED OPEN in docs/03 §6s rather than implied: there is NO mechanism by
  which an owner can share an asset or a document with a role-holder — not a
  broken one, none — so §5.5's "unless the owner explicitly opens visibility" is
  intent rather than a shipped control, and §5.5 now says so beside it. Building
  it is a cross-cluster authorization change; the fence forces a new enforced
  pair to arrive in the same change as the code that reads it.
- 2026-08-14 — THE TB4 INSIDER ALARM FIRED ON AN OWNER READING THEIR OWN ESTATE,
  and the fix is a second DIMENSION rather than a bigger number. MEASURED before
  it was argued: seven ordinary `/assets` page loads of a 120-asset estate raised
  `crypto.decrypt_rate.exceeded` (`asset_user count=1680 bound=1500`). The count
  was right — a page load issues Assets and NetWorth together, so it costs 2
  decrypts PER ASSET OWNED — and `asset` is the ONE bound whose legitimate volume
  scales with ESTATE SIZE rather than with activity, while the 1500 was itself
  calibrated on the M19 PR2 journey, an estate of a handful of assets. Estate size
  is unbounded, so no constant survives it: raise the number and you
  false-positive on some larger estate while blinding the detector for every
  smaller one. A security alarm firing on the product's own happy path is the M5
  permanently-red-gate lesson arriving at the control docs/03 §4 calls the single
  most important insider control there is. `DecryptRateBound` gained an optional
  `maxDistinctSubjectsPerWindow` and a breach now needs BOTH thresholds strictly
  exceeded; the subject is the row id already inside the field name, located by a
  position declared per prefix in `DECRYPT_FIELD_SUBJECTS` and counted by the
  sweep's own `count(DISTINCT CASE … split_part …)`.
  THE DETECTION THRESHOLD IS UNCHANGED AND THAT IS THE WHOLE ARGUMENT: distinct ≤
  count always, and a table invariant keeps the distinct threshold at or below the
  count threshold, so anything clearing the count bound on DISTINCT rows clears
  both — a mass read of N different assets breaches at exactly the N it did
  before. What is suppressed is precisely RE-READING, which moves no plaintext the
  principal had not already seen. Recorded as the cost (docs/03 §6q(ii)): an
  estate above 1500 distinct assets still trips on one page load, which is the
  threshold doing its job where the two readings converge, and the honest price of
  a constant — the detector runs in the audit cluster and cannot ask how large an
  estate legitimately is without a cross-cluster read its fenced zero-credential
  posture forbids.
- 2026-08-14 — A DECLARATION THAT CAN ONLY SUPPRESS IS A BLIND SPOT WHEN IT IS
  WRONG, so `DECRYPT_FIELD_SUBJECTS` is deliberately sparse and pinned to source.
  `doc` is the recorded trap and is ABSENT: its field is
  `doc.<ownerUserId>.v<n>.<sha>`, so the tempting segment 2 holds the OWNER — the
  same value for every document a person holds — and declaring it would collapse a
  whole library to one subject and suppress a mass document read. Sampling the
  live stream shows a UUID there and invites exactly that mistake, so the position
  is read from the code that BUILDS the string:
  `packages/contracts/test/decrypt-field-subjects.spec.ts` pins every declared
  position to its constructor in the owning service's source (identifier included,
  so reordering a constructor's arguments is red rather than silent) and asserts
  BOTH halves of the `doc` case — undeclared, and segment 2 really is the owner.
  The fence found its own defect on its first run: it read a backtick span inside
  a `//` comment (`asset.estate.viewed`, an audit action) as a template literal,
  which is the repo's `code()` rule restated for a scanner that must keep template
  bodies intact. Merging the sentinel's two actor types SUMS distinct counts,
  which over-counts deliberately — an upper bound errs toward breaching, the only
  direction a suppressing condition may fail in.
- 2026-08-14 — THE LIVE PROOF IS ONE TABLE, AND THE COUNTERFACTUAL IS IN IT.
  Three principals in one database: the PRE-fix run (1680 decrypts / 120 distinct)
  raised an anomaly carrying `count: 1680` and no distinct fields; two POST-fix
  runs with byte-identical economics raised none; and in the same window a
  1501-asset estate read ONCE (3002 decrypts / 1501 distinct) breached with
  `distinctSubjects: 1501, distinctBound: 1500`. The positive control is what
  makes the silence meaningful — without a breach in the same window, "no anomaly"
  is vacuously green over a dead detector (the M8 dead-consumer shape). The int
  layer runs the EXPORTED `DECRYPT_RATE_SQL` rather than a copy, because whether
  Postgres extracts the segment the declaration names is a question only Postgres
  answers. Eight mutations red, including the one that matters most — raising the
  distinct threshold above the count threshold, which is the only way this
  mechanism could introduce blindness the count bound did not already have.
- 2026-08-14 — OBSERVED WHILE DRIVING IT, out of scope and recorded so it is not
  rediscovered as a mystery: a sustained asset-create loop twice killed the assets
  service with a V8 `Deoptimizer` fatal ("unreachable code", node 22.22 on
  arm64), leaving the container `running=true` with `restarts=0` and the port
  answering nothing — the M8 "up with a dead service" shape produced by a RUNTIME
  crash rather than by our code. It reproduced under load and not otherwise (1501
  creates in 6.7s on the retry), and the 1501-asset list read itself takes 0.8s,
  so the headers timeouts that first looked like a slow product were the crash.
  The tell was `restarts=0` alongside a dead port: a container that never
  restarted cannot have exited, so the process died without the container
  noticing.
- 2026-08-14 — A DISCRIMINANT IS NOT AN ANSWER, and three identity call sites
  read one as though it were. `SendOutcome` is
  `{accepted: true; delivered: boolean; …} | {accepted: false}`: `accepted` says
  a healthy notifications service REPLIED, `delivered` says the mail went, and
  the type's own docstring states the rule ("Callers record either as a
  non-delivery"). The service answers `accepted: true, delivered: false` for
  `no_recipient` and `carrier_failure` (a crypto-shredded DEK lands there too).
  The mailed reset code, the reset-completed notice and the password-change
  notice all read `outcome.accepted` alone — and each of those booleans renders
  as the literal string `delivered` or `failed` in an APPEND-ONLY audit event,
  so a notice nobody received was recorded as delivered. The M14 PR0 shape (an
  audit claim inverted), sitting on the account-recovery ceremony whose entire
  failure mode is a user who cannot get in — and reachable rather than
  theoretical, because M9's recipient feed is fire-and-forget, so a registration
  during a notifications outage leaves no recipient row and that user is exactly
  the one who later cannot sign in. TYPESCRIPT CANNOT CATCH THIS BY
  CONSTRUCTION: the union forces a narrowing on the discriminant before
  `delivered` may be read, so STOPPING AT THE NARROWING GUARD TYPE-CHECKS
  PERFECTLY while meaning something else.
  Fixed as ONE SPELLING, not three edits — `wasDelivered` in
  @estate/notifications-client, used at all seven identity sites including the
  four already correct, because one behaviour with several spellings grows one
  bug per copy (the M8 PR2 seven-audit-producers shape). The fence then makes
  the wrong one unwritable: a consumer may not NAME the discriminant unless it
  is one of three declared notifications ADAPTERS. CORRECTED, because the first
  version of this entry got their reason wrong: they do NOT name it to answer
  "is the service reachable" and they do NOT turn it into a 503 — that refusal
  comes from `deliversToRealChannels`, a property of the adapter CLASS checked
  by the service elsewhere. They name it because TypeScript will not let them
  read `delivered` or `recipientVerified` off the union without narrowing on
  `accepted` first, and each then collapses the refused arm to
  `delivered: false` — which is `wasDelivered` computed by hand, so
  "the only derivation" is true of every CONSUMER and not of the repo. They are
  additionally held to using it only as a NEGATED gate (`if (!x.accepted)`), so
  an adapter cannot start deriving a delivery fact any other way.
  Mutation-tested four ways (each defect reverted, an adapter deriving delivery,
  a dropped table entry), all red on the assertion that names the property.
- 2026-08-14 — AND NO TEST COULD SEE IT, because NO DOUBLE EVER ANSWERED ON THE
  DISAGREEING ARM. Of 38 specs in identity's test directory, 13 name `accepted`
  and 12 produce an outcome, every one of them `delivered: true` — so the arm
  where the discriminant and the answer differ was never once exercised. THE
  FIRST WRITE-UP OF THIS ENTRY SAID "every one answered a bare
  `{accepted: true}`" AND THAT IS FALSE, caught by an adversarial lens and then
  measured: FOUR did (which is not a valid `SendOutcome` at all, since the
  accepted arm carries `delivered`, `channel` and `recipientVerified`), while
  THREE PRODUCED FULLY VALID FOUR-FIELD OUTCOMES AND WERE EXACTLY AS BLIND. That
  is the better point and the one I had missed: the mechanism was never a
  malformed literal, so "make the doubles well-typed" would not have found it —
  only answering on the other arm does. The compiler could not help either,
  because they reach their constructors through `as never` or
  `as unknown as NotificationsPort`, and A CAST ON THE OUTER OBJECT LEAVES THE
  INNER METHOD'S RETURN TYPE INFERRED and never compared to the port. The M16
  PR2b `chrome-double.ts` lesson one layer beneath the fixtures. Worse, the case
  that LOOKED like coverage — auth.service.spec's "NOTIFIES the owner, and puts
  the outcome on the audit event" — only ever used `{accepted: false}`, the arm
  where the discriminant and the answer AGREE, so it was green throughout: the
  M13 "a test named for a property it never touched" shape, selecting the one
  arm that could not fail. Outcomes are four named constants typed as
  `SendOutcome` now (the one place no cast intervenes) and the fence forbids a
  hand-rolled `accepted:` literal in that directory. The three adapters are left
  alone, and that reason was overstated too: only VAULT doubles the client port
  faithfully (`notifier-adapters.spec.ts`, typed `Promise<SendOutcome>`) —
  settlement's `HttpNotifier` and profile's `HttpLinkNotifier` are NEVER
  constructed in a test, their suites doubling the service-level port above
  them. What makes them safe is not their doubles but that all three read
  `outcome.delivered` explicitly on the accepted arm, so an incomplete literal
  fails SAFE; that two of the three translations are untested is a residual now
  written in docs/03 §6t rather than implied to be covered.
- 2026-08-14 — A BULK REGEX REWROTE MY OWN PROSE, which is a new way for a
  mechanical edit to lie. Converting the doubles with a
  `{ accepted: true }` → `DELIVERED` replacement also rewrote three COMMENTS I
  had just written explaining why that literal is invalid, so two of them ended
  up asserting the opposite of the truth ("the previous double answered
  `DELIVERED` — a shape the real service CANNOT produce"). Green everywhere; the
  code was right and the explanation had been inverted. The rule the repo
  already applies to scanners — a scan of source means a scan of CODE, strip
  comments — applies to REWRITES of source as well, and the cheap check is to
  grep the changed files for the replacement token appearing inside a comment.
  Also relearned in the same pass: an "insert after the last `import` line"
  heuristic lands INSIDE a multi-line import block and produces a syntax error
  in a file the suite never selected, so `tsc --noEmit` caught what jest did not
  — a green jest run is not a typecheck, for the third time.
- 2026-08-14 — CORRECTED WHILE FIXING IT: the reset's retire-on-failure comment
  claimed retiring prevents "a TTL-long lockout over a mail that does not
  exist". It does not. `lastMintedAt` orders over ALL rows including revoked
  ones, so retirement cannot shorten the re-issue floor — and the unconditional
  retire before every mint already stops a stale code blocking the next one, so
  nothing was locked out either way (`RESET_FLOOR_MS` and `RESET_TTL_MS` are
  both 30 minutes). The code is retired because a live reset code that reached
  no mailbox should not exist, which matters most in the `carrier_failure` case
  where the carrier may have taken the message before failing. Recorded because
  the plan that opened this work repeated the comment's claim as the harm, and
  the real harm is narrower and worse: not a lockout, an inverted record.
- 2026-08-15 — M20 IS THE ACCOUNT SURFACE, and it exists because M17 built five
  recovery ceremonies that nothing in the product can reach. The route↔consumer
  fence (M19 PR1) named them on its FIRST RUN as `EXEMPT_RECOVERY_SURFACE`:
  password change, reset request, reset complete, and the three address-change
  legs — a milestone that closed "identity has no password reset" and left every
  ceremony unreachable. Five PRs: PR0 the delivered-vs-accepted defect found
  while scoping (merged as #101), PR1 the password change, PR2 the address
  change, PR3 the reset on the `(auth)` group, PR4 session continuity, PR5 the
  review. THE SURFACE IS `/security`, NOT A NEW `/account` PAGE (user-selected
  over the plan's own proposal): the page already carries the verified-address
  banner, passkeys, paired devices and the standalone step-up, so the account's
  security controls end up in one place rather than two — and its one-prompt
  invariant, its session card and its step-up plumbing are reused rather than
  reimplemented. Discovery falsified the plan's `/account` premise before any
  code was written, which is the reason the question was put to the user rather
  than assumed.
- 2026-08-15 — M20 PR1: THE EDGE ADDS NO GATE, WHICH IS THE WHOLE DESIGN. The BFF
  forwards the caller's own bearer, holds no credential, and deliberately does
  NOT re-validate the new password — identity's schema is the gate and a second
  copy at the edge is a copy free to drift from the one that decides (the M12
  upload-client rule), pinned by a spec asserting a four-character password
  reaches identity and is refused THERE. `changePassword` also deliberately does
  not parse its response: identity answers 204, and `parseBody` would throw
  'identity response was not JSON' on an empty body, turning every SUCCESSFUL
  change into an error. The four refusals stay four codes because their remedies
  are four — re-check the password, find your authenticator, wait, choose a
  longer one — and `TOO_MANY_ATTEMPTS` in particular is a control firing, which
  the M9 rule says must not read as an outage.
- 2026-08-15 — `INVALID_CREDENTIALS` NOW MEANS A THIRD THING, and this is the M12
  finding arriving for the third time on the third surface. Identity answers one
  token for a rejected password, a rejected TOTP code, and now a rejected
  CURRENT password. M12 fixed the first collision with `stepUpMessageFor` (copy
  telling users their email and password combination was wrong, on a form with
  neither field on it); `passwordChangeMessageFor` is the same fix again, and its
  sentence also states that NOTHING CHANGED — the fact a person most needs after
  a refusal on the one route that rewrites their credential. The rule this keeps
  restating is narrower than "step-up": a form whose only field is a secret must
  never explain a refusal in the vocabulary of a different secret.
- 2026-08-15 — A MUTATION PROVED MY OWN FIX WAS BELT AND NOT THE CONTROL, and the
  honest answer was to say which half is load-bearing rather than weaken the
  mutation. The step-up retry CARRIES the submitted attempt, which is the M13
  review's fix for a retry that ran the action from the picker's CURRENT state.
  Reverting the carry to read the live inputs left all 31 tests green — because
  the real control is that the prompt REPLACES the form, so while a change is
  pending there are no inputs to edit and the values cannot move. My test was
  named for a property it never touched: the M13 defect, committed by me, in the
  test that cites it. Fixed by asserting the REPLACEMENT (mutating that turns it
  red) and keeping the carry as belt for a stated reason — the moment somebody
  makes the form merely DISABLED rather than unmounted, a plausible and otherwise
  harmless edit, the values become live again and the carry becomes the only
  thing between a step-up and a password the user never confirmed.
- 2026-08-15 — THE PASSWORD MINIMUM WAS DECLARED FOUR TIMES WITH NOTHING
  COMPARING THEM: identity's zod schema, the browser's pre-flight, its hint text
  and its error copy. Change the gate and three surfaces tell users something
  false — the `GQL_ERROR_CODES` drift class in a new place.
  `apps/web/src/lib/password-policy.test.ts` reads identity's `auth.controller.ts`
  AS TEXT and asserts every password minimum it declares is either this app's
  constant or a bare presence check (`min(1)`), with an anti-vacuity floor;
  mutating identity to `min(14)` turns it red. The web app cannot import a Nest
  package, so this is the compose-parity mechanism again — the same one that
  keeps the session-cache sentence honest.
- 2026-08-15 — AN EXEMPTION IS A CLAIM ABOUT THE WORLD AND IT ROTS. The
  route↔consumer fence asserted every route is consumed OR exempt, which stays
  green forever once a consumer lands for an exempt route — precisely the state
  PR2 and PR3 will create if nobody remembers. It now also asserts NO EXEMPTION
  IS STALE: an exempt route that some consumer file really addresses fails with
  the flip instruction by name. Verified with the exact regression (leaving
  `identity POST /v1/auth/password` exempt after wiring its client). The general
  shape: a fence with a declared escape hatch needs a check pointing AT the hatch,
  or the hatch is where the next zero-callers gap hides.
- 2026-08-15 — THE SECURITY PAGE TOLD EVERY ACCOUNT IT HAD A SECOND FACTOR, found
  by driving M20 PR1 in a real browser and older than the PR by eighteen
  milestones. GraphQL serialises an enum as its member NAME, so the wire carries
  `"NONE"` — and `apps/web` had declared `MfaLevel` as `'none' | 'mfa' |
  'stepup'` since M2, which made every `session.mfaLevel === 'none'`
  PERMANENTLY FALSE at all three of its call sites. MEASURED against an account
  with no `mfa_methods` row and `sessions.mfa_level = 'none'`: "MFA enrolled" and
  "Re-enroll authenticator app" on /security, and the same claim on the home
  page's session card; after the fix, same account and same session, "MFA not
  enrolled" and "Set up authenticator app". Not an authorization defect —
  `SecondFactorGate` reads the database and never the browser — but a
  misstatement about a control in the direction that stops someone acting: the
  account most in need of a second factor is the one told it already has one,
  and on this page that claim now sits directly above a password change whose
  step-up gate is conditional on exactly that factor.
- 2026-08-15 — WHY NOTHING CAUGHT IT, which is the transferable part. `tsc`
  compares values against the DECLARATION and the declaration was the thing that
  was wrong, so a comparison that can never be true type-checks perfectly — the
  same shape as PR0's discriminated union, where narrowing on `accepted`
  type-checked while meaning something other than "delivered". And every fixture
  said `mfaLevel: 'mfa'`, so the suite agreed with itself in a vocabulary the
  wire does not speak (the M15 "a fixture that invents an enum tests the fixture"
  rule). The two tests that pressed the authenticator button were green under the
  defect because both used the ENROLLED branch; the `NONE` branch every new
  account hits had never been rendered by a test at all, and `SessionCard` had no
  test file whatsoever. Fixed at three layers: the union, a behavioural pin on
  the factorless branch for BOTH surfaces, and a fence.
- 2026-08-15 — `graphql/enum-parity.test.ts` DERIVES EVERY ENUM MIRROR FROM THE
  BFF'S SDL, because fixing `MfaLevel` alone would have left four more copies
  nobody compares. It parses the `typeDefs` tagged template for `enum X { … }`,
  parses `client.ts` for `export type X = 'A' | 'B'`, and asserts equality both
  ways with anti-vacuity floors on both scans — two regexes that quietly match
  nothing agree perfectly. The two verification enums were INLINE unions inside
  the operation types, checked by nothing, so they were promoted to exported
  types in the same change: a uniform rule with no escape hatch, one entry after
  I wrote down that a fence's escape hatch is where the next gap hides.
  Mutation-tested seven ways — the lowercase union restored, a mirror renamed
  away, a new SDL enum with no mirror, the SDL scan broken to match nothing, and
  each of the three live comparison sites reverted — all red on the assertion
  that names the property. Direction is stated rather than implied: this checks
  SDL → app and cannot check the reverse, because most unions in that file
  (`GqlErrorCode`, `GqlFailureCode`) are not GraphQL enums, so a renamed enum
  fails loudly on its new name and leaves the old union as harmless dead code.
- 2026-08-15 — MEASURED WHILE DRIVING, and it is evidence for M20 PR4 rather than
  a defect in PR1: a signed-in browser reports "Your session has ended. Please
  sign in" after FIFTEEN MINUTES, while its `sessions` row is live and its
  refresh token good for thirty days. The web app has no refresh wiring at all,
  so the access token's TTL is the whole usable session. Confirmed by reading the
  row rather than inferring from the message — `revoked_at IS NULL` with
  `now() > access_expires_at` — which is what separates "expired" from "revoked",
  two states the UI renders identically today.
- 2026-08-15 — M20 PR2, THE ADDRESS CHANGE, and every decision in it falls out of
  one property of the route it consumes: THE 202 IS NOT A DELIVERY RECEIPT.
  Identity answers the request BEFORE it knows whether it will send anything —
  the availability lookup, the encrypt, the stage and the mail all run detached,
  precisely so an address that already belongs to somebody else is answered
  identically to a free one and simply never mailed. So the client returns
  `void` (there is no field a caller could mistake for confirmation, which
  forces the honest copy rather than merely permitting it); the success sentence
  is CONDITIONAL — "if *address* isn't already in use here, a code is on its way
  to it" — with its own test asserting the ABSENCE of a we-have-sent claim; and
  the refusal for identity's `too_soon` is named `CODE_REQUESTED_RECENTLY` and
  not `CODE_ALREADY_SENT`. That last rename is not pedantry: `too_soon` covers
  BOTH the per-account re-issue floor and the per-DESTINATION bound, and the
  destination bound fires on volume aimed at an address that may have staged
  nothing and mailed nothing, so a code asserting a send would put "use the one
  we sent you" in front of somebody with an empty inbox. A refusal on a route
  arranged so that no answer implies delivery must not imply one either.
- 2026-08-15 — TWO ROUTE-SPECIFIC ERROR MAPPERS, because the shared one is wrong
  here in two different ways. `mapError` keys 400 on the STATUS and answers
  INVALID_REQUEST, while identity answers **400** for a rejected ACCOUNT
  PASSWORD, for both re-issue bounds, and for every refused code — so without
  the mappers a wrong password and a rate refusal would both reach the browser
  as "review your request", and the completion leg's single uniform refusal
  would flatten into the same. The completion mapper additionally may not fall
  through to the shared 401 branch, which maps `invalid_code` to
  INVALID_CREDENTIALS: the login vocabulary, on a form whose only field is a
  mailed code — the M12 collision, avoided by construction rather than
  rediscovered on a fourth surface. The `mapVerifyError` precedent, applied
  twice, and the identity-client spec pins all three 400 tokens apart.
- 2026-08-15 — THE COMPLETION FORM IS ALWAYS AVAILABLE, and that follows from a
  GAP rather than from a preference: identity exposes no read of a pending
  change, so the page cannot know on load whether one is outstanding. A code
  field that appeared only after a request made in THIS tab would strand anyone
  who closed the page, or who reads their mail on a device other than the one
  they asked from — which is most people. So the field, the confirm button and
  the ungated cancel render unconditionally, and the cancel's copy states what
  is now TRUE ("there is no pending address change") rather than claiming an
  action happened, because identity's cancel is idempotent and silent: 204
  whether or not anything was pending.
- 2026-08-15 — THE M15 IDENTICAL-LABEL RULE BIT WITHIN MINUTES, AND MY OWN
  EXISTING TESTS ARE WHAT CAUGHT IT. The new section needs the account password,
  so it got a field labelled "Current password" — the same label the
  password-change section two sections up already uses — and twelve
  password-change assertions turned red on `getByLabelText` finding two. That is
  exactly the defect `StepUpTarget`'s docblock warns about, arriving in the
  component that hosts the warning. Fixed by naming what the field IS rather
  than which one: "Account password". "Current" earns its place upstairs by
  contrasting with "New password", and there is nothing here for it to contrast
  with, so the word was carrying no meaning and all of the ambiguity. The page's
  two mailed-code fields (`EV1-` verification, `EC1-` change) are kept distinct
  for the same reason, pinned by a whole-page label-uniqueness assertion in
  `AccountSecurity.test.tsx` — the only place both panels are rendered together,
  and therefore the only place the property is observable at all.
- 2026-08-15 — ONE PAGE, TWO PANELS, ONE FACT. Completing an address change does
  two things in one statement: it moves the address AND vouches for it
  (`replaceRecipient` repoints and stamps `verified_at`, because redeeming the
  mailed code proved the mailbox seconds earlier). `EmailVerificationPanel` is a
  SIBLING holding its own copy of that status, so a previously-unverified owner
  would finish the ceremony and go on reading "your email address hasn't been
  confirmed yet" directly above the sentence saying it has — one page
  contradicting itself about a control, which is the shape M19 PR2 found in the
  trust card and M20 PR1 found in the session card. THE FIX IS A RE-READ, NOT A
  SHARED BOOLEAN: a small page-level client wrapper bumps a key and re-mounts
  the panel, so the authority stays the SERVER (the ConsentControls rule) rather
  than a flag two components must keep in step. Residual stated in docs/03 §6v
  rather than papered over: the app-shell `UnverifiedAddressBanner` lives outside
  that tree and re-reads only on navigation, so it can keep asking for a
  confirmation that has just happened — the harmless direction, and closing it
  properly needs a shared client cache this app does not have.
- 2026-08-15 — THE SAME MUTATION SURVIVED AS IN PR1, AND FOR THE SAME REASON,
  which is worth recording because the second instance is what makes it a
  pattern rather than an anecdote. Reverting the step-up retry to read the live
  inputs instead of the carried attempt left all 44 web tests green — because
  the prompt REPLACES the form, so under a pending change there is nothing to
  edit and the values cannot move. The carry is belt on both surfaces; the
  replacement is the control, and it is what the tests assert. Ten of the other
  eleven mutations were red on the assertions that name their property,
  including the two that matter most — a success sentence claiming a send, and
  a flipped route left `{ exempt: … }` (which the stale-exemption check added in
  PR1 catches, one PR after being written for exactly this).
- 2026-08-15 — M20 PR3, THE RESET SURFACE, is the first ceremony in the product
  a signed-OUT caller drives — hence the `(auth)` route group (`/reset`, linked
  from the login page) rather than `/security`, which every other M20 slice
  extends. Two mapper decisions, EACH THE INVERSE OF ITS SIBLING AND FOR THE
  SAME UNDERLYING REASON. The request leg KEEPS the shared status-keyed
  `mapError`, where PR2 needed a route-specific one: on this route the only 400
  identity can produce IS a malformed body — the unknown address, the 30-minute
  floor and the per-destination bound are all deliberately inside the uniform
  202 (proven on the wire: `{ok:true}` byte-identical for an address with no
  account and for the floored real one) — so a route-specific mapper would be
  a second copy with nothing to distinguish. And the completion leg reuses
  PR2's completion mapper, renamed `mapCodeRedemptionError` at its second
  caller (one behaviour, one spelling — the M8 PR2 rule), so neither
  mailed-code surface can leak a refused code into the login vocabulary.
  THIRD SURFACE, THIRD REMEDY for the one uniform refused-code answer: the
  verification panel says "send yourself a new one" (it has a resend button),
  the address change says "cancel and start again" (it has a cancel), the
  reset says "ask for a new one above" (the request form is on the same page)
  — the remedy varies because the surfaces genuinely offer different ways out,
  and a shared sentence would name a control two of the three do not have.
- 2026-08-15 — A RESET SIGNS YOU IN NOWHERE, AT EVERY LAYER, and the layer M20
  PR3 adds holds the line by doing NOTHING: identity mints no tokens (§6m's
  mint-paths fence), so the BFF completion resolver touches no cookies in
  either direction — there is nothing returned to set, and the stale pair a
  previously-signed-in browser may hold names a session the completion just
  revoked server-side, so the M8 logout rule (never clear cookies for a
  session that was not revoked) has nothing to protect. The surface then says
  BOTH consequences out loud — signed out everywhere including this device,
  signed in nowhere — because a user who expects a reset to sign them in reads
  the login screen as the reset having failed, and the success state REPLACES
  both forms and offers exactly the one next step. Measured live: the
  completing browser landed on the signed-out shell, the pre-reset session's
  token answered 401, old password 401 / new password 200, and the trail
  carried `reset_failed | system | {}` for the wrong guess (no actor, empty
  detail — the uniform refusal preserved in the audit stream) and
  `reset_completed {"notified":"delivered","revokedSessions":"1"}` with both
  delivery-log rows `sent_unverified` — §6t's `wasDelivered` recording the
  carrier's real answer for an address this account never proved.
  `EXEMPT_RECOVERY_SURFACE` is DELETED rather than emptied — a named empty
  exemption invites the next route to reuse it without re-arguing — and all
  six M17 recovery routes now have product consumers. Ten mutations, ten red:
  the belt-vs-control survivor of PR1/PR2 has no analogue here, because a
  signed-out surface has no step-up prompt to carry an attempt through.
- 2026-08-15 — M20 PR4, SESSION CONTINUITY, and the constraint that shaped the
  whole client design: identity's rotation-reuse detection (M16) treats an
  already-rotated refresh token as THEFT and revokes the session — the right
  answer to a thief, and a SELF-revocation if two of the owner's own requests
  refresh concurrently, because every tab shares one cookie jar. So
  single-flight is a CORRECTNESS requirement, not an optimization: an in-tab
  promise latch plus a cross-tab Web Lock (`estate.session.refresh`), and the
  tab that waited still sends its own Refresh afterwards — by then the jar
  holds the winner's NEW token, so that is an ordinary second rotation.
  Measured live: an assets page racing several queries into an expired access
  token produced EXACTLY one rotation (`refresh_token_prev_h` still held the
  pre-drive hash). The retry itself cannot repeat a side effect —
  UNAUTHENTICATED means a guard refused before any handler ran, and a token
  dying BETWEEN two downstream hops re-runs a resolver whose asset commands
  carry payload-keyed eventIds (M19), making even a genuinely raced commit an
  idempotent replay. RESIDUAL, recorded not closed (docs/03 §6x): a LOST
  Set-Cookie response leaves the browser holding the rotated-away token, and
  its next refresh reads as theft — one session revoked, a false
  `rotation_reuse_detected` in the ledger, unclosable client-side because
  cookies ARE the response, and deliberately not weakened server-side since a
  grace window for the previous token is precisely the replay the detection
  refuses.
- 2026-08-15 — NULL AND "REFRESHABLE" ARE DIFFERENT FACTS, and flattening them
  is what made the app read signed-out at every 15-minute expiry while a
  30-day refresh token sat in the jar. `Query.session` answered null for "no
  credentials at all" and for "dead access token with a refresh cookie behind
  it" alike; it now throws UNAUTHENTICATED for the second — the client's
  refresh-once-and-retry trigger — so an anonymous visitor still costs no
  identity call, and "Your session has ended" is TRUE when a surface renders
  it, because reaching a caller now means the refresh itself was refused
  (expired-vs-revoked, materialized on screen at last). Cookies clear in ONE
  failure direction: identity refusing the credential as dead clears the pair
  (dead server-side — the M8 rule protects LIVE sessions, and without the
  clear every page load repeats the session → refresh → refusal dance), while
  an identity OUTAGE clears nothing (M16 PR2a: an outage must not wear the
  face of a revocation). And the `Refresh` operation itself — at every layer
  since M8, called by nothing for twelve milestones — is the reason
  `operation-consumers.test.ts` now exists: every GraphQL operation must have
  a product caller, with NO exemption mechanism (the PR3 rule), the reverse
  direction being the compiler's since `OperationName` is a closed union. Its
  first run named exactly one uncalled operation, and this PR is its caller.
- 2026-08-15 — "THE RETRY CANNOT REPEAT A SIDE EFFECT" WAS TRUE OF ONE HOP AND
  FALSE OF THE PRODUCT, caught by reviewing PR4's own claim before pushing it
  — the repo's recurring class (a milestone asserting something about itself
  that the code does not do), this time in the same commit that wrote the
  sentence. UNAUTHENTICATED does mean a guard refused before any handler ran,
  so a single-hop retry is safe; but ELEVEN BFF resolvers WRITE AND THEN READ
  BACK (`addContact` → `contacts`, `addFamilyMember` → `family`, `saveProfile`
  → `profile`, the grant/revoke pairs), and if the write lands while the
  read-back is refused, re-running the resolver re-runs the write.
  `createContact` and `createFamilyMember` carry NO idempotency key, and two
  contacts of one name are legitimate so no unique index catches it either —
  one click, two rows, silently. The asset commands are safe (payload-keyed
  `eventId`, M19) and the profile grants are safe (M13's unique indexes answer
  409), which is exactly the trap: safety is a PER-RESOLVER fact the transport
  cannot see, so a transport that retries "because most things are idempotent"
  is guessing. Only QUERIES retry now, decided by reading each operation's own
  document rather than from a hand-kept list that goes stale at the
  fifty-seventh mutation, with the fence asserting the classification is TOTAL
  so a third document kind cannot appear unnoticed (unrecognized ⇒ treated as
  a mutation ⇒ not retried, the safe default made explicit). A refused
  mutation reports its own `SESSION_RENEWED` — renewed, nothing performed, try
  again — because reporting the original UNAUTHENTICATED would render "your
  session has ended" over a session just successfully renewed, which is the
  false sentence the whole PR exists to delete, one case over. Recorded as the
  cost (docs/03 §6x): a refused mutation costs one repeated click, and what
  would buy the retry back is an idempotency key on profile's creates — a
  profile-service change, not a transport one.
- 2026-08-15 — A FAN-OUT REVIEW THAT DIES ON CREDITS PRODUCES NOTHING, AND
  "NOTHING" IS NOT "CLEAN". PR4's three-lens adversarial workflow burned 4.2M
  subagent tokens over 147 tool uses and returned `{raw: 0, confirmed: []}` —
  all three lenses errored out of usage credits mid-run, which the result
  object alone does not distinguish from three lenses finding nothing. The
  `<failures>` block and the journal are where that shows. Re-running the same
  fan-out would have re-spent the tokens; instead the lens PROMPTS were used
  as a checklist and worked by hand, which found the write-then-read-back
  defect above in a fraction of the cost. Two rules: read the failure block
  before believing an empty result (a killed run and a clean run look
  identical in the return value), and a review's VALUE is in the questions it
  poses — those survive the harness dying and can be answered directly.
- 2026-08-15 — M20 PR5 security review (five file-scoped discovery lenses over
  the milestone's OWN FILES — never a diff range, the M13 rule — each in its own
  worktree pinned with `git checkout --detach <sha>`, then two adversarial
  verifiers per candidate on different angles, both defaulting to refuted; 21
  agents, no losses; 11 raw, 8 verified, 3 dropped under the cap and LOGGED BY
  NAME, hand-verified afterwards and all three real, so eleven fixed). Every
  finding was re-derived from source by hand before anything changed.
  FOURTEENTH milestone running where every confirmed finding sits in machinery
  the milestone introduced — with one exception, and the exception is the HIGH.
  A SECOND ROUTE READS THE ACCOUNT PASSWORD AND HAD NO BOUND: M20 PR2's
  `POST /v1/auth/email/change/request` takes the current password for exactly
  the reason `POST /v1/auth/password` does (the stolen-session threat) and ran
  the identical gate order — conditional step-up, then verify — with nothing in
  the gap where the M17 PR6 review had put `PASSWORD_CHANGE_BOUND` on the other
  route after measuring twenty-five unbounded guesses taking an account over.
  MEASURED ON THE RUNNING STACK, on a factorless account (the class
  `SecondFactorGate` deliberately admits so the bootstrap stays reachable, and
  therefore the class that reaches a password check at all): 25 wrong guesses
  got 25 × `400` and no refusal EVER, against the bounded twin's `401 × 5 →
  429` — and all 25 `email_change.denied` rows landed with NO SESSION ID, so
  even the per-session half would have been blind to them. Every other bound on
  that route sits DOWNSTREAM of the verification (the re-issue floor and the
  per-destination bound both run after it), so nothing else could catch it, and
  recovering the password THERE defeats the bounded route rather than tripping
  it. Fixed with `AccountPasswordGate` (the `SecondFactorGate` precedent)
  injected into both services, and `PASSWORD_CHANGE_BOUND` widened to
  `ACCOUNT_PASSWORD_BOUND` counting BOTH routes' failure kinds — the M16
  chokepoint rule, because two budgets of five are a budget of ten to anyone
  willing to alternate. THE REFUSAL KIND IS DELIBERATELY UNCHANGED
  (`password.change_rate_limited`): renaming a ledger kind the audit consumer
  knows makes every event of that kind a `schema_violation` for the length of a
  rolling deploy (2026-08-12). Post-fix, same attack: `400 × 5 → 429`, all five
  rows attributed, and the password route answers `429` HAVING SPENT NOTHING OF
  ITS OWN — the shared budget visible from outside — while a fresh session still
  gets an ordinary `400` and the correct password still returns `202`.
  THE GENERAL SHAPE: a bound that lives as a private method on one service is
  reachable only from the class that owns it, so the second route did not bypass
  the control so much as never meet it.
- 2026-08-15 — AND THE FENCE WENT GREEN BECAUSE ITS CORPUS WAS ONE FILE, which
  is the same failure one layer up. `rate-bounds.spec.ts` asserts that every
  guessing bound covers the routes that check its secret — over
  `auth.service.ts` ALONE. That was faithful while every bounded route lived in
  that class and stopped being faithful the moment one moved to
  `email-change.service.ts`. A FENCE WHOSE INPUT IS NARROWER THAN ITS CLAIM GOES
  GREEN FOR THE SAME REASON IT IS WRONG. The corpus is derived from the
  directory now with a floor asserting it, and the fence gained the check it
  never had: every `hasher.verifyPassword` call site must be DECLARED with the
  bound that covers it, in both directions, plus an assertion that the gate
  precedes the verification (a bound evaluated after the guess is scored is not
  a bound, and its timing must not vary with whether the guess was right).
  Anchored on the VERIFICATION CALL rather than on a route decorator or a method
  name — the 2026-08-07/2026-08-12 rule, since a caller can rename its way out
  of a name-keyed scan but not out of the call that scores a guess.
  Mutation-tested with the exact regression (a new undeclared route reading the
  password) and with the corpus narrowed back to one file.
- 2026-08-15 — M20 PR5's other seven, each falsifying a claim the milestone made
  about itself. (1) AN OUTAGE WORE THE FACE OF A REVOCATION: `refreshSession`
  collapsed "identity refused the credential" and "the refresh never completed"
  into one boolean, so a dropped connection rendered "Your session has ended.
  Please sign in again." over a live 30-day session whose cookies the BFF had
  deliberately left in place — the M16 PR2a rule, broken by code citing it three
  lines above; three outcomes now, and only a REFUSAL reports the session ended.
  (2) `SESSION_RENEWED` INVITED THE RETRY THE NO-RETRY RULE EXISTS TO PREVENT:
  a mutation refused with UNAUTHENTICATED may have written on its first hop, so
  "Nothing was changed — please try that again" was the one thing that must not
  be said; it names the uncertainty and sends the reader to reload. (3) THE
  STEP-UP PROMPT NEVER CLOSED on a non-step-up refusal — the sections render it
  INSTEAD of their form, so a refusal after a genuine elevation left an error
  about a field no longer on screen; four call sites, two of them pre-existing,
  all fixed, because fixing two and not two would read as intentional. (4) THE
  PAGE CONTRADICTED ITSELF ABOUT A CONTROL: a password change and an
  address-change completion each revoke every other session and neither re-read
  the devices list. (5) THE STALE-EXEMPTION CHECK (added one PR earlier, for
  exactly this class) could only see files ALREADY declared as consumers, so a
  brand-new client module calling an exempt route was invisible to the check
  whose whole job is that; swept from the tree now. (6) THE PASSWORD-POLICY
  FENCE WAS KEYED ON THE FIELD NAME and two of identity's password fields are
  both literally `password` — one about to be STORED, one about to be COMPARED —
  so `RegisterSchema.password` dropping to `min(1)` was excused as a presence
  check and satisfied a file whose header claims the assertion is TOTAL; keyed
  on the (schema, field) pair now, classified as data, total in both directions.
  (7) `loadSession` READ A MISSING FIELD AS DATA, white-screening the page on a
  version skew — in the one loader on that page not following the rule the two
  below it state. Seventeen mutations, seventeen red.
- 2026-08-15 — NO FINDING WAS REFUTED THIS ROUND, WHICH IS A REASON FOR MORE
  HAND-CHECKING RATHER THAN LESS. Every previous review's verifiers killed
  several candidates; when they kill none, the cheapest explanation is that the
  verify phase agreed too easily, so all eight were re-derived from the source
  before a line changed and the three dropped under the cap were verified by
  hand rather than assumed low-value — all three were real (a comment asserting
  the reset surface "does not exist yet" when PR3 shipped it; three different
  counts of the step-up targets in three files, of which only the union was
  right, so the prose no longer carries a number; and a LINE-BASED
  comment-stripper reading whole paragraphs of block comment as code). A dropped
  finding is a finding nobody looked at, not a finding somebody ranked low.
- 2026-08-17 — M21 IS THE TB7 OPERATOR PLATFORM, MINIMUM SLICE (approved), and
  what selected it is a defect in the selection process itself rather than a
  ranking. Six file-scoped evidence lenses, three judges on deliberately
  conflicting priorities (risk, user value, dependency order), one synthesis —
  and then every load-bearing claim re-verified by hand, because a verdict is
  not evidence. The dependency lens governed and the reason generalizes: AN ITEM
  NOBODY HAS COSTED IS AN ITEM EVERYTHING CAN DEFER TO. docs/03 named TB7 as the
  owning milestone for TWELVE distinct deferred items across nineteen lines
  while the doc's own summary said "five places", and TB7 appeared in no
  milestone list, carried no size, and had never been scoped. The undercount is
  the mechanism, not a typo: TB7 looked small, so deferring to it looked cheap,
  so more work was deferred to it, which made it look smaller relative to what
  it owed. THE ENABLING MEASUREMENT, which I verified myself rather than
  accepting: settlement carries 25 zero-consumer routes, and the group holding
  most of them is MISLABELLED — twelve of `EXEMPT_TB7_OPERATOR`'s sit in
  `admin.controller.ts`, whose own header says a grieving executor should not
  face an MFA prompt to look at a checklist. Those are EXECUTOR routes. The
  true operator-only surface is ~10, which is what makes a minimum slice
  possible at all and what splits M21 from M23.
  CORRECTED, and the correction is the same class of defect the entry is
  about: this first named `EXEMPT_SETTLEMENT_REPORTING` as the group holding
  the 25 and the twelve. It holds NEITHER. Measured — 8 routes in
  `EXEMPT_SETTLEMENT_REPORTING` (reporter/owner-facing) and 17 settlement
  routes in `EXEMPT_TB7_OPERATOR`; 25 is their SUM across two groups, and the
  twelve admin-controller routes are all in the second. Citing the wrong
  constant sends the next reader to a group of eight looking for twenty-five,
  which is exactly how an item stays uncosted.
- 2026-08-17 — M21 PR0 IS DOCS AND A FENCE AND NO PRODUCT CODE, which is the
  M13 "order is the point" precedent: the milestone that exists because prose
  hid twelve deferrals does not begin by writing more prose. THE §4 TB7 BLOCK
  ASSERTED FOUR CONTROLS IN THE PRESENT TENSE — just-in-time elevation, peer
  approval, session recording, separation of duties — and one sentence carried
  all four. Rewritten into what is TRUE TODAY AND CHEAPLY SO (no standing
  production access, because there is no production), what is PARTIALLY REAL
  (separation of duties exists at the ROW rather than the role: reviewer ≠
  reporter and requester ≠ approver are DDL CHECKs, which is a stronger
  mechanism over a much narrower surface), and what is DEFERRED WITH AN OWNER
  NAMED. Also corrected in the same pass: CLAUDE.md's own coverage line said
  "target 95% backend / 90% frontend" while the ENFORCED rule is each package's
  ratcheting `coverageThreshold`, and 17 of 24 backend packages sit below 95 on
  statements (`packages/db` 25, audit 57, assets 60). A bar nothing measures is
  a bar nobody meets, so the line now states both numbers and which one is the
  gate.
- 2026-08-17 — THE RESIDUAL SWEEP: 107 bullets in docs/03 §6, each now opening
  with exactly one of `**[ACCEPTED]**`, `**[OWNER: M25]**`/`**[OWNER: E1]**`, or
  `**[CLOSED: §6n]**`. The result is a fact about the programme that nobody
  could read off the prose: 40 permanent trade-offs, 60 owned, and NINETEEN of
  the sixty owned by ONE owner — E1, the AWS half — so the largest single block
  of outstanding security work in this repo is blocked on money rather than on
  engineering. THE TAG LEADS THE BULLET because the failure being fixed is that
  you could not SEE the deferrals: a trailing tag is greppable, a leading one is
  scannable, and scanning is what nobody could do before. Rejected as the
  cheaper fence: "the bullet must mention a milestone somewhere" — which goes
  green on `M4's decision`, a CITATION rather than an assignment, and on dozens
  of incidental references. Anchor on a mark a human put there on purpose, which
  is this repo's rule (the credential graph keyed on a property name, the
  route-audience fence on a decorator identifier, the password-policy fence on a
  field name) arriving in a document instead of in source.
- 2026-08-17 — THE PARSER TOOK THREE ITERATIONS AND EACH WRONG ONE WAS WRONG IN
  A DIFFERENT DIRECTION, which is the entry worth keeping. (1) BY REGION alone
  over-collected: a block that ended only at a heading swallowed
  `**§5.2 emergency-access controls, now shipped**` — five bullets describing
  controls that SHIPPED, which a disposition tag would be actively wrong about.
  Caught because an independent classification of the corpus disagreed with the
  parser about two bullets. (2) Ending a block at any bolded lead-in then
  UNDER-collected, 108 → 72, because §6j organises by PR and mixes decisions
  with residuals under one lead-in. (3) BY LANGUAGE alone is far worse (18 of
  107), because most residuals simply DESCRIBE the residual — "*Autofill does
  not resist phishing.*" — and name no marker word at all. The union is what
  ships: 89 by region, 18 by language, and the disposition of a long bullet is
  usually in its LAST sentence, so the whole bullet including continuations is
  the unit. THE BOUND IS STATED RATHER THAN DISCOVERED LATER: a residual written
  as prose, outside a declared region and using none of the marker phrases, is
  invisible — not closable by a better regex, because the doc's structure
  genuinely does not distinguish those bullets. What closes it is the forcing
  function: EVERY §6 DELTA MUST DECLARE A RESIDUAL REGION, so the next
  milestone's residuals land somewhere the region rule already sees. Three
  deltas had none and now do (§6r, §6u, §6y).
- 2026-08-17 — THE MARKER SET IS DATA AND ITS COMPLETENESS IS ASSERTED, because
  under-collecting is this fence's silent failure and a delta opening its
  residuals with a sixteenth idiom would contribute ZERO bullets while the file
  stayed green. A regex over "any bold label mentioning residual" both
  over- and under-matches — it swallows `**§6l's residual was a promise the code
  did not keep.**` (a FINDING) while missing `**Two residuals.**` (a region) — so
  `REGION_MARKERS` is twelve exact strings, `NON_REGION_LABELS` is four exact
  strings each with a reason, and every bolded lead-in in §6 that mentions a
  residual must be in one list or the other. The OWNER vocabulary is DERIVED
  from docs/04's own two tables rather than held as a second copy: renumber M27
  in the plan and a free-standing list would keep blessing an id nothing plans
  to build. Eight mutations, eight red — including one that reported a NO-OP
  because I wrote a curly apostrophe where the doc has a straight one, which is
  the ninth way this repo has now caught a mutation harness lying and the reason
  every harness here asserts the bytes changed before drawing a conclusion.
- 2026-08-17 — THE SWEEP FOUND FOUR THINGS THE CLASSIFICATION AGENTS DID NOT,
  and all four are citations rather than controls. (1) docs/03 §6j cited
  `test/second-factor-kinds.spec.ts` as the fence closing the attempt-cap
  bypass; M17 renamed it to `rate-bounds.spec.ts` and the file does not exist —
  the control is real and the citation is DEAD, which is exactly what stops the
  next person looking. (2) §6k's own list of bounded routes ("login, register
  and password change") predates §6y and omits the address-change request route
  that now shares `ACCOUNT_PASSWORD_BOUND`. (3) §6g pointed at "edge work (§4
  TB1)" for the redeem-route cap, which resolves to an owner only because M17
  PR1 later amended TB1 — a pointer to a CATEGORY is how a deferral goes
  uncosted, so E1 is named in the bullet itself. (4) §6j's "no user-reachable
  session revocation" is genuinely CLOSED in its headline and carries an unowned
  REMAINDER in its last sentences: `sessions.ip_ct` and `sessions.device_id` are
  declared in `001_auth_schema.sql` and written by nothing, so an owner with two
  browser sessions or two paired extensions sees rows they cannot tell apart, on
  the one screen whose purpose is to end the compromised one. Split out under
  its own owner — A REMAINDER RIDING A CLOSURE is the shape this sweep exists to
  surface, and the closure's own framing ("a row identifies a credential by what
  it can REACH rather than by where it is") is what made it read as settled.

- 2026-08-17 — M21 PR1 GAVE THE OPERATOR ALLOWLIST A CEREMONY, and the reason it
  needed one is that CREATING an operator was the only privileged act in the
  product with no entry in the append-only trail. `settlement_operators` decides
  who runs docs/03 §5.1's mandatory human review — approve a death case, lock an
  account, confirm a verification, approve a distribution, approve a stage of
  access to a dead person's estate — and every one of those ACTIONS emits an
  audit event while BECOMING able to perform them emitted nothing, in either
  direction, with no action in `AUDIT_ACTIONS` that could have carried one.
  Three more measured facts underneath it: `OperatorsRepo.grant`/`.revoke` had
  ZERO CALLERS while their docstring called them "the CLI-only write path", the
  CLI having reimplemented both in raw SQL — and the two had ALREADY DRIFTED
  (`isUniqueViolation(err)` in the repo, an inline `err.code === '23505'` in the
  CLI), which is the M8 PR2 seven-audit-producers shape arriving in the table
  that decides who may approve a death case; `granted_by` has been declared
  since M7 and written by nothing, so every row said only that somebody holding
  the database made a grant; and NO TEST HAD EVER EXECUTED THE CLI, which had no
  exports, no `require.main` guard and no package script, so it was structurally
  untestable while sitting inside the coverage denominator at 0%.
- 2026-08-17 — THE CEREMONY REFUSES TO WRITE WHAT IT CANNOT RECORD. A broker is
  REQUIRED for `grant` and `revoke`; `list` changes nothing, needs none, and is
  handed a producer that THROWS — an assertion that the read path is silent
  rather than a stub for it. The template-publish CLI's precedent (fall back to
  an in-memory producer when no broker is configured) is right for a template
  and wrong here: it would make an UNAUDITED GRANT THE QUIET DEFAULT on every
  machine without `KAFKA_BROKERS`, which is every developer laptop. `--by` is
  required and is ATTRIBUTION, NOT AUTHENTICATION — whoever runs this holds the
  connection and could write the row by hand — so what it buys is that a row
  with `granted_by IS NULL` is VISIBLY one that did not come through the
  ceremony, which is exactly what the settlement e2e's seeding INSERT produces
  and what its comment now says instead of claiming to BE the write path.
  Ordering inside the transaction is the M9 rule: the INSERT rolls back and the
  Kafka emit does not, so the row goes first and a failed emit rolls the grant
  back rather than leaving it unrecorded.
- 2026-08-17 — A REPEAT GRANT DID NOT WORK, AND THREE GREEN SPECS SAID IT DID —
  found by driving the live stack, which is the eleventh milestone running where
  that is what found it. `grant` recovered from the partial index's unique
  violation by RE-READING the existing row, which is fine against a connection
  POOL (each statement gets its own implicit transaction) and IMPOSSIBLE inside
  the CLI's own `BEGIN`/`COMMIT`, because Postgres aborts a transaction on a
  failed statement and refuses every command until rollback. So the second grant
  died with `current transaction is aborted` while the unit spec (fake repo, no
  transaction), the int spec (pooled `Db`) and the fence all passed: **THE
  HARNESS WAS MORE PERMISSIVE THAN THE ONLY PATH THAT EVER REALLY RUNS**, the
  `chrome-double.ts` shape one layer beneath the fixtures. Fixed by NEVER
  RAISING THE ERROR — `ON CONFLICT (user_id) WHERE revoked_at IS NULL DO
  NOTHING`, naming the index's own predicate so a revoked row is not a conflict
  — which makes the pooled and transactional contexts agree rather than making
  the recovery cleverer; the int spec gained an `inTransaction` helper that runs
  a command the way `main()` does, and reverting the fix reproduces the live
  failure verbatim. THE GENERALIZATION WAS CHECKED RATHER THAN ASSUMED: the
  service's three other unique-violation catches (`contact-attempts.repo`,
  `dek.repository`, `settlement.service`) all `return` or `throw` immediately
  and issue no follow-up statement, so none of them has it — which is also the
  rule for the next one, since the defect is not "catching a unique violation"
  but "issuing another statement afterwards on the same connection".
- 2026-08-17 — THE PROPERTY IS CHECKED RATHER THAN ASSERTED.
  `operator-write-path.spec.ts` scans the settlement service's own source in
  both directions: only the ceremony may call the repo's write methods, only the
  repo may write the table in SQL (the method-name scan alone is evadable by the
  inline statement that was there before), THE CEREMONY REALLY DOES CALL THEM
  (without which the fence passes vacuously the day somebody reverts to raw SQL,
  which is the state PR1 found the repo in), and no controller mentions either.
  A source scan rather than a runtime guard because there is no runtime seam —
  the CLI and the service share one class by design, so the difference between a
  sanctioned and an unsanctioned call is WHERE IT IS WRITTEN. Its corpus is
  RECURSIVE and asserted equal to the PLATFORM's own recursive read, an oracle
  the file did not write: the tree is flat today, so a non-recursive walk passes
  every other assertion in the file and would stop covering the service the day
  somebody adds `src/operators/`. That is docs/03 §6y's M21 item — a fence whose
  input is narrower than its claim goes green for the same reason it is wrong —
  discharged for this fence rather than restated, and mutation-tested by
  planting a nested file and reverting the walk.
- 2026-08-17 — A RUNBOOK COMMAND THAT HAS NOT BEEN RUN IS A GUESS. docs/05's new
  operator section verifies the grant reached the trail with `docker compose …
  exec -T pg-audit psql`, and the obvious spelling of it FAILS: compose resolves
  the whole project before `exec`, so without `--env-file .env.stack` the file's
  own variables are blank and it refuses with `invalid compose project`. The
  failure was masked twice over — piping to `tail` gave `EXIT=0`, which is the
  standing zsh trap in this repo — and was only visible by reading the message.
  Every command in that section was run against the live stack before it was
  written down. The section also states the deploy-order requirement, because
  `AUDIT_ACTIONS` is a closed vocabulary and an `audit` container older than the
  two new actions treats each as a `schema_violation` and drops it: the grant
  happens and the trail silently does not record it, which is the exact outcome
  the fail-closed broker gate exists to prevent, arriving from the other end.
  Measured after rebuilding the consumer first: six events in the verified
  chain, every one attributed, zero rejections.
- 2026-08-17 — M21 PR2 IS NOT THE OPERATOR SESSION AUDIENCE, and the scope
  change came from measuring the machinery before building on it (approved).
  Three facts read out of shipped code. (1) THE AUDIENCE CANNOT NARROW
  ADMISSION: `AllowSessionAudiences` is typed
  `(...audiences: Exclude<SessionAudience, 'account'>[])` — the default is
  unconditionally prepended and cannot even be NAMED at a call site — and
  `CallerGuard.audiencesFor` returns `[...new Set([...serviceWide,
  ...perRoute])]`, so decorating an operator route yields
  `['account','operator']`: every ordinary account session, admitted exactly as
  today. (2) NOTHING CAN MINT ONE: `auth_handoffs` carries
  `CHECK (audience IN ('vault'))` — a list with exactly one member, and NOT the
  `= 'vault'` equality this entry first quoted, a misquote that matters because
  the session-audience fence parses the `IN (…)` shape and rewriting the DDL to
  match the prose would blind it (M21 PR2.5 added a refusal for any audience
  CHECK it cannot read, precisely so that rewrite turns red instead of quiet) —
  and a new ceremony at identity cannot be operator-gated — identity holds no settlement
  credential, there is no dblink between the auth and core clusters, and
  identity has no concept of a role. (3) ITS VALUE IS SUBTRACTIVE — what `vault`
  and `extension` buy is that every service which has NOT opted in refuses the
  session — and that is worth exactly nothing until something mints one and an
  operator has a reason to hold it. So the audience ships in PR3 alongside the
  surface that is its only consumer, and PR2 hardens the enforcement it would
  have sat on top of. Recorded as a scope change in docs/04 rather than
  silently absorbed: a plan that quietly re-aims is a plan nobody can audit.
- 2026-08-17 — ONE SERVICE HELD FOUR ANSWERS TO ONE QUESTION AND THEY HAD
  DRIFTED. "Is this caller an operator?" was asked in `settlement.service.
  assertOperator` (private, throws), `admin.service.assertOperator`
  (byte-identical, separately declared), a bare `isOperator` branch inside
  `assertCaseVisible` (returns the case instead of throwing), and an inline
  `isOperator || isExecutorOf` in `setDistributionStatus` — WHICH WAS THE ONLY
  ONE OF THE FOUR THAT READ THE ALLOWLIST ON THE TRANSACTION HANDLE. The two
  §5.1 routes that begin and end a death case (`startReview`,
  `confirmVerification`) resolved it on the POOL and only then opened the
  transaction they were guarding. The M8 PR2 seven-audit-producers shape, in the
  code that decides who may approve a death case. `OperatorGate` is the one
  spelling now: no default handle (a write passes its own `tx`, a read with
  nothing to be consistent with passes the pool) with THE FIVE POOL SITES
  DECLARED AS DATA and every other call fenced to `tx` — the handle being the
  thing that had already drifted, so it is checked rather than conventional —
  and the gate is consulted BEFORE the case row is locked so a non-operator is refused without learning
  whether the case id names anything — the uniform-404 rule, preserved rather
  than newly added and now visible in one ordering instead of implied by four.
  WHAT THE TX HANDLE BUYS IS STATED EXACTLY, because the tempting claim is
  wrong and I nearly shipped it: these transactions are READ COMMITTED, so each
  statement takes a fresh snapshot and a revoke committing after the gate's read
  is still unseen at commit time. Moving the read inside NARROWS the window and
  DOES NOT CLOSE IT; closing it needs a share lock on the allowlist row, which
  is real contention on every operator action bought to serialize against an
  adversary who must be an operator being revoked in that exact instant. Not
  taken, recorded in docs/03 §6aa. The property secured is CONSISTENCY, not
  atomicity.
- 2026-08-17 — A PEP WHOSE INPUT IS A LITERAL CANNOT DENY ANYTHING. `assertCan`'s
  second argument IS the `isSettlementOperator` attribute `settlement.cedar`
  matches on, and three call sites — `startReview`, `decideReview`,
  `confirmVerification` — passed the literal `true`. It was SOUND, and sound for
  a reason nothing enforced: an assertion had run a few lines above. Delete that
  line in a refactor and the route opens to any authenticated caller while the
  policy goes on evaluating happily against a constant asserting the very thing
  nobody checked — a POSITIONAL dependency between two adjacent statements, with
  nothing making them adjacent. `assertIn` RETURNS the measured answer now, so
  removing the check removes the argument and the compiler enforces what
  proximity used to. The two remaining literals are `false` at the owner's `void`
  and `manage` paths and are CORRECT: measuring the allowlist there would WIDEN
  the decision for an owner who is also an operator, which is the direction
  settlement.cedar deliberately avoids by never carrying an `owner` attribute —
  declared as data with a reason per entry, so a third one is a visible decision.
  Fenced in both directions (never `true`; `false` only at declared sites;
  everything else the resolved variable), with the corpus recursive and asserted
  equal to the platform's own recursive read.
- 2026-08-17 — THE EIGHTH WAY A MUTATION HARNESS HAS LIED HERE, and it is the
  first that corrupted the tree rather than the conclusion. The script saved a
  backup of each target at the top of EVERY invocation — including `restore` —
  so each restore copied the MUTATED file over its own backup and then restored
  that. Every restore was a no-op and the mutations ACCUMULATED: the failure
  count climbed 1 → 2 → 3 → 9 → 11 across runs while each individual mutation
  read as correctly red. It was caught not by the harness but by an editor
  notification showing a line still mutated after a "restore", and repaired with
  an explicit undo before re-running. THE RULE, now that the list is long enough
  to generalize: pristine copies are taken ONCE, by the caller, before any
  mutation; the harness NEVER re-derives a baseline from the working tree; and
  restore VERIFIES byte-for-byte against the pristine copy and fails loudly if
  it differs. Same family as `git checkout --` on uncommitted work, `node -e`
  losing `$1` to shell expansion, grepping for `✕` outside verbose mode,
  length-instead-of-content no-op checks, and anchoring on a non-unique string —
  every one of them produces a conclusion about a test drawn from a measurement
  that did not happen.
- 2026-08-17 — THE PRE-MERGE PASS FOUND THE FENCE I HAD JUST WRITTEN BREAKING
  THREE RULES THIS REPO ALREADY HAD WRITTEN DOWN, which is the M21 PR2 entry
  worth keeping. (1) THE CEDAR CHECK ASSERTED A NAME, NOT PROVENANCE:
  `expect(c.arg).toMatch(/^isOperator$/)` says the argument is SPELLED
  `isOperator` and says nothing about where the value came from — so
  `const isOperator = true` beside a discarded gate call passed GREEN, and so
  did a brand-new route with no gate call at all, both executed rather than
  argued. The fence written to stop a literal reaching Cedar admitted one. It
  checks BINDING now (the argument must be assigned by a `gate.is`/
  `gate.assertIn` call in the same method), which is what makes removing the
  check remove the argument rather than leaving a constant behind. (2) TWO OF
  ITS THREE BLOCKS DID NOT USE THE RECURSIVE CORPUS its own header claimed —
  one read a single hardcoded filename, the other a hardcoded two-file list —
  so a third service file reading the allowlist on the pool before a
  transactional write was invisible; the same false claim had been copied into
  the commit message, docs/03 §6aa and docs/04. (3) THE READER CHECK WAS KEYED
  ON THE PROPERTY NAME `operators`, the exact anchoring mistake the credential
  graph made twice (2026-07-28, 2026-08-07) and the route-audience fence made
  once (2026-08-12): it derives the field from whatever is DECLARED as an
  `OperatorsRepo` now, and adds the raw-SQL SELECT scan its PR1 sibling already
  had for writes. THE LESSON IS NOT "FENCES ARE HARD": it is that a fence
  written in the same sitting as the fix it protects inherits the author's
  model of the defect, so it tends to check the SHAPE the defect happened to
  take rather than the property. Eight mutations, eight red.
- 2026-08-17 — AND MY OWN ANTI-VACUITY COUNT CAUGHT A COORDINATE BUG IN THE
  REWRITE, which is the argument for having one. The new fence slices two views
  of each file at one set of offsets — calls come from the view with string
  literals blanked, the Cedar ACTION from the view that still has them — and
  the first version SHORTENED one view and not the other, so every offset past
  the first string literal was wrong: it silently lost an `assertCan` call and
  credited another to the wrong method. Both masks are LENGTH-PRESERVING now
  (comments and literals become spaces, newlines kept), so there is one
  coordinate system. A fence that mis-attributes is worse than one that finds
  nothing, because it still goes green.
- 2026-08-17 — A DOUBLE DISCARDED THE PARAMETER THAT WAS THE SECURITY PROPERTY.
  `InMemoryOperators.isOperator(_q2, userId)` threw its handle away, so NO
  behavioural test — unit or Postgres-backed — could tell `assertIn(tx, u)`
  from `assertIn(this.db, u)`, and the source fence was the only thing in the
  repository that could see the rule the gate's docstring calls its contract.
  The double is more permissive than the real thing, one layer beneath the
  fixtures (the M16 PR2b `chrome-double.ts` shape). It records now, `fakeDb()`
  hands the callback a DISTINCT object which is what makes the question
  answerable at all, and two service tests assert BOTH sides of the rule — a
  transactional caller does not ask the pool, and `queue` does. Mutating
  `startReview` to the pool handle turns the first red.
- 2026-08-17 — EVERY CASE-SCOPED READ IN SETTLEMENT WAS A CASE-EXISTENCE
  ORACLE, found by the same pass, measured live before it was believed, and
  PRE-EXISTING rather than introduced by M21 PR2. `getCase` and the four admin
  reads that funnel through `assertCaseVisible` (timeline, stages, tasks,
  distributions) answered 404 for an unknown case id and 403 for a real one, so
  any authenticated caller holding an id learned whether a death case exists
  for it — the same defect M19 PR1 closed in assets one milestone earlier, in
  the service whose ids name death cases. It is fixed here because PR2's own
  §6aa was about to claim this service preserved the uniform-404 rule, which on
  those five routes it did not: a milestone that states a property owes the
  property. `assertCanOrNotFound` is the assets precedent applied, deliberately
  NOT used on the operator write paths, where a non-operator is refused before
  any lookup and so learns nothing either way. THE TWO TESTS COVERING THIS WERE
  THEMSELVES THE LESSON: one asserted a stranger got 403 and the next, named
  "404s an unknown case rather than leaking its absence differently", asserted
  an unknown id got 404 — together they asserted the leak and called it the
  opposite. One test now, comparing the two answers, because neither alone can
  see the property. A THIRD WITNESS SAT ONE LAYER UP, and it is how the fix
  actually presented: `apps/e2e/test/settlement.e2e.spec.ts` pinned
  `expect(403, { error: 'forbidden' })` for a stranger reading a real case, so
  the leak was written into the file whose whole subject is the §5.1 chain, and
  the repair showed up as a RED E2E rather than as a red unit test. The general
  shape is that a defect asserted at three layers is not a coverage gap — every
  layer was covered — it is three copies of one wrong belief, and the only test
  that can see it is the one comparing the two answers rather than checking
  either alone.
- 2026-08-17 — A COUNT IN A SHIPPED COMMENT IS A MEASUREMENT, AND MINE WAS
  WRONG. The gate's docstring said the service had "FOUR independent
  operator-admission paths" and enumerated four shapes as though that were the
  inventory; `git grep 'operators.isOperator(' 56c8fbd` returns SEVEN, six on
  the pool and one on a transaction. The same figure had been copied into the
  gate's own spec, docs/03 §6aa, docs/04's table and the commit message. The
  four shapes were real and the count of paths was not, which is the harm — a
  wrong measurement in shipped prose is what stops the next person taking it.
- 2026-08-17 — M21 PR2.5 IS A COUNT SWEEP WITH ONE REAL DEFECT IN IT, split out
  of PR3 on the M14 PR0 rule that a live defect must not hide inside a feature
  branch. THE DEFECT: a single operator evidence read emitted TWO audit events
  DISAGREEING ABOUT THE ACTOR CLASS. M18 PR1 corrected the `crypto.field.decrypted`
  side to `actorType: 'operator'` and left `document.evidence.accessed` nine
  lines away on the audit wrapper's `'user'` default — in the trail kept for
  exactly the docs/03 §5.1 investigations, in a method whose own docstring says
  the actor is not the owner. The M17 PR6 shape verbatim (a correction applied
  where the failure was convenient to catch rather than everywhere it happens),
  and the test covering it asserted only the decrypt event, so the suite was
  green over a pair that contradicted each other. It asserts the PAIR now, which
  is the only assertion that can see the property — the same lesson as M21 PR2's
  two settlement tests that between them asserted a 403/404 oracle and called it
  the opposite.
- 2026-08-17 — THE AUDIENCE FENCE COULD BE BLINDED BY VALID SQL, closed before
  M21 PR3 writes the migration that would have done it. `session-audience.spec.ts`
  parses `CHECK (audience IN (…))` and every assertion in the file reads
  `effectiveCheck` = "the LAST statement to define a CHECK" — so a migration
  written `CHECK (audience = 'operator')` is not merely unmeasured, it hands
  every assertion an OLDER constraint and they pass against a database that no
  longer matches. Proven by planting `999_mutation_probe.sql` in that form: the
  new refusal went red and the other sixteen tests stayed GREEN, which is the
  blindness demonstrated rather than argued. The fence now detects any CHECK
  constraining `audience` in a shape it cannot read and fails naming the file.
  SHARPEST PART: docs/03 and this log both MISQUOTED the shipped
  `auth_handoffs` DDL as `CHECK (audience = 'vault')` when it is
  `CHECK (audience IN ('vault'))` — so the likeliest route to blinding the fence
  was somebody "correcting" the SQL to match the prose. Both corrected; a
  misquote of a security constraint is an instruction to reintroduce it.
- 2026-08-17 — AND THE RESIDUAL FENCE PR0 SHIPPED WAS UNDER-COLLECTING, found by
  adding one anti-vacuity check to it. Its corpus is `- ` bullets, and FIVE
  declared residual regions (§6b twice, §6f, §6s, §6t) stand over PROSE
  PARAGRAPHS: the marker is recognized, the block opens, zero bullets are
  collected, and every assertion in the file passes over content it never saw.
  §6b's two were TB7 deferrals, so THE MILESTONE SCOPED FROM THAT COUNT HAD NOT
  COUNTED ITS OWN — the `[OWNER: M21]` total went 14 → 18 once they were tagged,
  the fourth upward move of a figure that has never once been revised down
  (five → twelve → fourteen → eighteen). PR0 stated its bound as "a residual
  outside a declared region and using none of the marker phrases is invisible";
  this is narrower and worse — INSIDE a declared region and still invisible. A
  region that collects nothing is now an error naming the file, line and label.
  THE GENERAL RULE, which this repo keeps arriving at from new directions: an
  anti-vacuity check belongs on every LEVEL of a scan, not just its total. This
  fence already asserted that the corpus was non-empty overall, which is exactly
  why five empty regions inside it were invisible.
- 2026-08-17 — THE REST OF PR2.5 IS TEN COUNTS AND CITATIONS THAT ROTTED, and
  the reason they are worth a commit is that every one of them is a MEASUREMENT
  a reader would take on trust. A fence test named "the five" iterating seven
  (M16 PR4a widened `EXTENSION_ROUTES` and the name kept the old number); this
  log claiming EIGHTEEN refused vault routes where the deriving spec asserts
  sixteen, and "the worst fourteen" where `MUST_REFUSE` holds twelve; the same
  entry listing `identity:refresh` as a fourth admitted route when it carries no
  guard at all and is unauthenticated by construction — a conflation that hides
  a completely different security argument (nothing to admit; the audience
  survives refresh only because `rotateTokens` omits the column); my own M21
  entry naming `EXEMPT_SETTLEMENT_REPORTING` as the group holding 25 routes and
  the twelve admin-controller ones when it holds NEITHER (8 there, 17 in
  `EXEMPT_TB7_OPERATOR`, and 25 is their sum); settlement's `config.ts` calling
  itself "TWO credentials" beside comments numbered THIRD and FOURTH; its README
  crediting `NOTIFY_MODE` to a milestone that shipped twelve milestones ago; and
  my own PR2 `assertCanOrNotFound` docstring crediting one method with five
  routes when four of them reach the uniform 404 through `admin.service.ts`
  throwing directly, because that controller has no PEP at all. THE PATTERN IS
  ONE PATTERN: a number or a name in prose beside a mechanism that derives one
  is a second copy free to drift, and it drifts silently because nothing
  compares them. Where a count had a deriving spec the prose now points at it
  and states none; where the count IS the point it is measured and the
  measurement is named.
- 2026-08-17 — MIGRATION 004's STALE CITATION IS DELIBERATELY NOT FIXED, and
  saying so is the fix. It names `@estate/auth-guard` as where `SESSION_AUDIENCES`
  lives; M16 PR1 moved the definition to `@estate/contracts` so the BFF could
  label sessions without depending on a NestJS guard package. The citation still
  RESOLVES — auth-guard re-exports — and the migrator checksums every applied
  file, so editing a comment there raises `MigrationDriftError` on every database
  that has run it and blocks the next migration until it is restored. The M16
  PR4a precedent (`006_extension_audience.sql` still says "five vault routes")
  applied to a second case: a migration records what was true when it ran, and
  the live fact goes in the spec the migration points at — which is where the
  correction now is, in `session-audience.spec.ts`'s own header.
- 2026-08-17 — THE NINTH WAY A MUTATION HARNESS HAS LIED HERE, and it is the
  first that made every GOOD run look broken. JEST WRITES ITS SUMMARY LINE TO
  STDERR, INCLUDING ON SUCCESS, and the harness read `execFileSync`'s return
  value — stdout only — so every passing run reported `NO SUMMARY LINE` and all
  five cases printed FAIL while their mutations were behaving perfectly. The
  failure direction was the harmless one this time (RED read as unknown, not
  GREEN read as proven), but the mechanism is identical to the 2026-08-10 case
  of grepping for `✕` outside verbose mode: A CONCLUSION ABOUT A TEST DRAWN FROM
  A MEASUREMENT THAT NEVER HAPPENED. Merge the streams (`sh -c '… 2>&1'`) and
  assert on the summary line. Also adopted here and worth keeping: A CHECK ON AN
  ALREADY-CORRECT TREE CANNOT BE TESTED BY DELETING THE CHECK — that goes green
  for want of a defect rather than for want of a checker — so each fence is
  probed TWICE, once with the defect planted (expect red) and once with the
  defect planted AND the check neutered (expect green), which is the pair that
  identifies the check as the thing that saw it. The second probe is what proved
  §6b-back-to-prose is invisible to a residual fence with no empty-region check:
  9 of 9 green over two untagged TB7 deferrals.

- 2026-08-18 — M21 PR3a IS A BOUNDARY WITH NOTHING BEHIND IT, and the split from
  PR3b is the whole point: an audience is worth exactly what the services that
  REFUSE it make it worth, so the boundary is reviewable on its own and the
  screens are reviewable on their own (the M15 PR1->PR2 precedent, where the vault
  origin proved its boundary before any key material stood behind it). Three
  decisions, each a rejection as much as a choice. (1) AN AUDIENCE IS A
  RESTRICTION, NEVER A CLAIM ABOUT ITS HOLDER - `operator` says only that this
  credential may be spent in fewer places than an ordinary session - so THE MINT
  IS ROLE-BLIND and that is not a gap. Identity holds no settlement credential,
  there is no dblink between the auth and core clusters, and identity has no
  concept of a role, so a mint that checked would need a new trust edge to answer
  a question the audience is not asking; `OperatorGate` against
  `settlement_operators` remains the one answer to "may this person act", exactly
  as PR2 left it, and what an operator GAINS by minting is a credential worth LESS
  than the account session they already held. (2) THE ROUTE IS THE SELECTOR, NOT A
  FIELD: two mint routes rather than one taking `{audience}`, so nothing on the
  wire names an audience - no field for a caller to set, no parameter for a schema
  to widen by accident, two separately guarded and separately audited ceremonies -
  while REDEMPTION STAYS AUDIENCE-BLIND, one route and one response shape, with the
  audience travelling on the `auth_handoffs` row only the mint could write. M16 PR1
  is the precedent pointing the other way: `HandoffService.mint`'s audience
  parameter was typed as the full union with only a DDL CHECK behind it, and it was
  DELETED rather than narrowed. (3) A SECOND ISOLATED ORIGIN, NOT A SECOND PATH ON
  THE FIRST - `operator.localhost` is a different HOST because cookie scope ignores
  the port, and reusing the vault origin would put an operator credential in reach
  of the code holding Zone A key material. `AUDIENCE_ADMITTERS.operator` is EMPTY
  and exactly three identity handlers are widened per route (`session`, `stepUp`,
  `logout`), so a redeemed operator session is refused by every service in the
  product INCLUDING settlement, whose queue it exists to reach; `handoff` and
  `handoff/operator` are absent, so a leaked code cannot chain itself forward in
  either direction. Migration `012_operator_audience.sql` WIDENS the
  `auth_handoffs` CHECK to `IN ('vault', 'operator')` rather than rewriting its
  shape, which is the form PR2.5 taught the audience fence to require.
- 2026-08-18 - THE EDGE DOES NOT RE-CHECK THE AUDIENCE IT REDEEMS, and the reason
  is the same one that makes a second copy of any decision wrong. It could not
  usefully: the redeem response deliberately does not carry an audience, and the
  callees enforce it in both directions already (vault refuses `operator`,
  settlement will refuse `vault`). What makes the absence safe is that the browser
  client DISPLAYS the audience it reads back from `/api/auth/session`, so a session
  of the wrong kind is visible rather than silently tolerated. The operator
  interstitial also gets its own route with NO NAV ENTRY: minting is role-blind so
  the page works for everybody, which is correct, and a product for 10M users
  should not put "open the operator console" in an estate's own navigation.
  Discoverability is PR3b's question, once there is a surface behind it.
- 2026-08-18 - A FENCE THAT DERIVES FROM ONE FILE CANNOT SEE THE SECOND EDGE, and
  it would have gone green WRONGLY rather than merely gone quiet.
  `route-consumers.spec.ts` derives each edge's rewrites from its `server.ts` so a
  browser client's `/api/...` literals resolve to the upstream routes they really
  reach - and it read `apps/vault-web/src/server.ts` alone. A second edge whose
  route table has a different shape contributes ZERO rewrites, and the operator
  origin's `/api/auth/session` then resolves through the VAULT's table BY
  COINCIDENCE, satisfying the fence while proving nothing about the edge under
  test. That is docs/03 section 6y's "a fence whose input is narrower than its
  claim goes green for the same reason it is wrong" arriving in a fence written two
  PRs after the rule. Closed with a declared `EDGE_SERVERS` list, dual-shape
  matching, a PER-EDGE anti-vacuity floor, and an exact assertion of the operator
  edge's three rewrites.
- 2026-08-18 - AND THE RESIDUAL FENCE HAD STOPPED MATCHING AT SECTION 6aa, found
  while adding 6bb to it. Three patterns were written `6[a-z]?`, which needs a
  literal `.` after one optional letter and therefore fails on `## 6aa.`. TWO
  MIS-ATTRIBUTED - a two-letter section's bullets were reported under 6z, the last
  single-letter heading that matched, so a failure would have sent the reader to
  the wrong section - and THE THIRD WAS BLIND: `## 6aa.` failed its first test and
  passed the fallback `^## `, so the lead-in classification scan turned OFF at 6aa
  and left 6aa and 6bb outside it entirely. A residual lead-in written there with
  an unrecognised idiom would have been unclassified and unreported. Nothing went
  red, because every bullet in those sections happened to be tagged. BOTH ARE
  CLOSED BY COMPARISON RATHER THAN BY A FLOOR: the parser's own section set is
  compared against an independently permissive read of the file, and the
  classification scan's REACHED sections are compared against the parser's. A count
  could not do it - mis-attribution preserves totals, which is exactly why the
  existing floor (`seen >= REGION_MARKERS.length`) was satisfied throughout. The
  general rule this repo already has, restated for a new level: AN ANTI-VACUITY
  CHECK BELONGS ON EVERY LEVEL OF A SCAN, and where the scan has a reach, the check
  is a SET COMPARISON and not a count.
- 2026-08-18 - TB7's OPERATOR-READS SENTENCE WAS WRONG IN BOTH HALVES, and the
  correction is prose rather than a route. It said "the events exist - settlement
  and documents emit them, and an executor inventory read carries `estate.viewed`".
  MEASURED: `AUDIT_ACTIONS` carries 23 `settlement.*` actions and EVERY ONE IS A
  WRITE, so the queue an operator works from, the case they open and the timeline
  they read leave no trace that they were read; documents emits exactly one
  operator read (`document.evidence.accessed`, whose actor class disagreed with its
  own paired decrypt event until M21 PR2.5); and `estate.viewed` is
  `asset.estate.viewed`, an ASSETS event describing an EXECUTOR's inventory read -
  a different actor class entirely, cited in a paragraph about operators. The read
  events land in PR3b with the screens that make the reads, because adding them now
  would be a routeless event, which is the zero-callers shape this milestone exists
  to close; correcting the claim rather than adding the route is the M18 PR1
  precedent, where settlement's "decrypted only on explicit read" comment described
  a read route that did not exist. The harm in a wrong claim of this kind is not
  the sentence - it is that a reader who believes it stops looking.
- 2026-08-18 - M21 PR3a DRIVEN LIVE, and the CSP had to be measured TWICE because
  the first measurement was of the wrong world. The whole ceremony ran in a real
  browser against the running stack: sign in, `/operator`, the step-up prompt
  (`#operator-launch-code`, labelled "Confirm it's you"), a genuine TOTP code, a
  top-level form POST across the origin boundary, landing on
  `http://operator.localhost:3011/` reading "Session type: operator", "Identity
  check: Not recently confirmed" - the M15 PR4 rule holding, since redemption
  grants no step-up - and `document.cookie` EMPTY, the `__Host-` cookie being
  `HttpOnly` on an origin whose client never needs to read it. The app's nav
  carries no `/operator` entry (`hasOperatorLink: false`), which is the decision
  above made observable rather than asserted. THE CSP PROBE FIRST REPORTED `eval`
  AND `new Function` AS ALLOWED, which would have been a false claim in the
  reassuring direction: the browser tool evaluates in an ISOLATED WORLD whose CSP
  is not the page's (the M15 PR1 finding, met again). Chased rather than reported -
  a probe module was served from the origin's own tree, and direct `<script>`
  injection was itself refused by Trusted Types, so the probe had to arrive through
  a modified shell. From the PAGE world: `trustedTypes.createPolicy` TypeError,
  `innerHTML` TypeError leaving ZERO child nodes, `eval` EvalError, `new Function`
  EvalError, and a cross-origin `fetch` at the app's BFF refused by
  `connect-src 'self'`. The container was then RECREATED rather than edited back,
  because a restore that leaves the artifact byte-identical is the only restore
  worth trusting (probe 404, zero references in the served shell).
- 2026-08-18 - THE STACK COUNTS WERE MEASURED IN BOTH PROFILES, and the production
  half came with its own control. Development moved 26 -> 32 passed with pending
  unchanged at 4; the six operator-origin tests sit OUTSIDE the profile split (a
  plain `describe`, the M15 vault-origin precedent) because nothing about this
  origin needs a third-party credential. My own summary had said five, and the
  measurement said six - which is why the number comes from `--json` rather than
  from counting `it(` blocks. The PRODUCTION count was measured STRUCTURALLY, by
  running the suite under `STACK_PROFILE=production` against the development stack
  and reading which tests EXECUTE versus skip: 22 executed, 14 pending, all six
  operator tests passing. Exactly ONE test failed, and it is the control rather
  than a defect - `production rehearsal: arms an emergency-access escrow` failed
  because M14's arming gate is production-scoped and legitimately answers 201
  instead of 503 on a development stack. That is verbatim the reason the M15 PR1
  entry gives for never DERIVING these numbers, reproduced as evidence that the
  profile switch is real. Stated rather than implied: what was measured locally is
  the COUNTS, which is what the two workflow twins assert; a full production
  rehearsal is what CI's own blocking production leg runs.
- 2026-08-18 - A TEST NAMED FOR A COMPARISON THAT CHECKED A CONSTANT, found by a
  hand adversarial pass over PR3a's own new machinery before merging it - which is
  this repo's standing expectation that new trust machinery is defective, met for
  the fifteenth milestone running. `stack.e2e.spec.ts`'s "serves the shell under a
  CSP at least as strict as the vault origin's" asserted a list of FIXED STRINGS
  and never fetched the vault's policy at all, while a comment beside it claimed
  this origin was "STRICTER than the vault's in one directive: no `data:` in
  img-src". MEASURED, from the two live origins rather than from the source: the
  policies are BYTE-IDENTICAL, twelve directives each, and the vault's `img-src` is
  `'self'` with no `data:` too. The distinctive strictness is against the MAIN APP,
  which needs `data:` for M12's document viewer - a true sentence about the wrong
  neighbour. THE HARM IS THE COPYING: the false half had reached docs/03 §6bb,
  docs/04's PR3a section before the two headers were ever compared - THREE places,
  and my first write-up of this correction said four, adding "and the PR body" to a
  body that never carried it, which is the 2026-08-06 rule (a doc claiming evidence
  it does not have is a defect even when the fix it justifies is sound) turned on
  the correction itself -
  which is exactly PR2.5's subject arriving one PR later in the milestone that
  wrote it. THE FIX IS TO MAKE THE NAME TRUE rather than to correct the comment:
  the test fetches BOTH live headers and compares them directive by directive - for
  these allowlist-shaped policies, "no weaker" means omit nothing the vault names
  and, per directive, allow no source the vault does not - with an anti-vacuity
  floor, because two empty maps compare equal perfectly. That converts a false
  claim into a real gate on the property worth having: a second isolated origin
  must never drift weaker than the first, and the realistic regression is somebody
  relaxing this one for a charting library on an operator console.
  Probed THREE ways against a mutated edge run as a host process on a spare port
  (cheap enough that the mutation did not need an image rebuild). Widening
  `connect-src` - A DIRECTIVE THE OLD TEST NEVER ASSERTED AT ALL - turns it red
  naming the offending source; dropping `object-src` entirely turns it red on the
  omitted-directive branch; and the SECOND PROBE of the 2026-08-17 pair - the same
  mutation with the comparison loop neutered - goes green, which is what identifies
  the loop as the thing that saw it rather than some incidental assertion.
  The harness also earned its keep by REFUSING two bad operations of mine rather
  than silently no-op'ing: a restore whose pristine path landed in the wrong argv
  slot died with ENOENT, and an anchor carrying a `\n` through a shell argument
  reported `ANCHOR NOT UNIQUE: 0 occurrences`. Both would previously have read as
  "the test does not catch this". That is the accumulating-mutation defect closed by
  construction rather than by care.
- 2026-08-19 - THE HEAVIEST GATE IN THE REPO HAD NO LEVER, discovered by needing
  one. The post-merge Stack run for `388d22b` sat in `queued` for over seventy
  minutes having created ZERO jobs. It was not capacity and not an incident: two
  LATER runs of the same workflow on the same repo started and finished normally
  while it sat there, the Actions status page read operational throughout, and
  Stack had completed on twelve previous pushes to `main`. It simply could not be
  recovered — `cancel` and `force-cancel` both answered HTTP 500, `rerun` was
  refused as "already running", and with only `push` and `pull_request` declared
  there was no way to ask for a fresh one. The only available resolution was to
  wait for somebody to push to `main` again, which the `concurrency` group is
  documented to use to cancel the wedge — STATED AS THE MECHANISM RATHER THAN AS
  AN OBSERVATION, since a run that refuses `cancel` and `force-cancel` with HTTP
  500 has not been watched accepting a concurrency cancellation either. IT WAS
  WATCHED AT THE MERGE AND IT DID NOT (see the entry below); the scoping is the
  only reason the shipped sentence was not simply wrong.
  `workflow_dispatch` is that manoeuvre made available on purpose: security.yml's own comment already records the same
  lesson from the other direction, where a trigger that could only fire at 06:00
  UTC is how a sweep failed seventeen consecutive runs unnoticed. A GATE YOU
  CANNOT INVOKE IS A GATE YOU CAN ONLY OBSERVE.
  ADDED TO `ci.yml` IN THE SAME CHANGE, for the category rather than the
  instance — the wedge was a Stack run, so fixing Stack alone was the tempting
  move, and this repo's own M17 PR6 rule is that a rule applied to one member of
  a category is a rule half-applied. Nothing about the failure mode is specific
  to Stack. `notify-failure.yml` is DELIBERATELY still without it and that is not
  an omission: it is `workflow_call`-only, and a reusable workflow is invoked by
  its callers rather than by events.
  MEASURED WHILE WIRING IT, because the obvious assumption is wrong in the
  direction that matters: a dispatch reads the workflow file AT THE REF IT IS
  GIVEN, not from the default branch. `gh workflow run stack.yml --ref
  <this-branch>` created a run, while `--ref main` answered HTTP 422 "Workflow
  does not have 'workflow_dispatch' trigger" — so the lever can be rehearsed on
  the branch that adds it, and exists ON `main` only once merged there, which is
  precisely why it could not be tried against the wedge that motivated it.
  AND THE SURVEY THAT JUSTIFIED IT WAS WRONG THE FIRST TIME, which is the part
  worth keeping. `grep -q workflow_dispatch` over each file reported FOUR of six
  already carrying the trigger; one of those four was `notify-failure.yml`, where
  the string occurs only inside a comment. Parsed as YAML it is three of six. A
  GREP IS NOT A PARSE, and I had written the grep's number into a shipped comment
  before checking it — the same class as the counts PR2.5 spent a whole PR
  correcting, committed two PRs later while citing them.
- 2026-08-19 - A COUNT OF WHAT EXISTS CANNOT DETECT WHAT WAS NEVER CREATED, and
  the CI watcher I wrote for that merge reported success over a check set missing
  the two jobs that mattered. It gated on `total >= 20 && completed == total`;
  when the Stack workflow wedged, its two jobs were never registered as check
  runs at all, so twenty-one OTHER checks satisfied a floor that had been
  calibrated against a number which assumed they were present, and the watcher
  printed `ALL COMPLETE / failing: none`. Both halves of the predicate were true
  and the conclusion was false. This is the 2026-08-12 entry's own lesson - a
  watcher that exits on `pending == 0`, which is also true before anything has
  started - arriving in a watcher written hours after reading it, which is why it
  is recorded again rather than treated as already learned. THE FIX IS TO BIND TO
  THE EXPECTED SET, NOT TO A COUNT: enumerate the WORKFLOWS a sha should run and
  assert each reached a conclusion, because a workflow that produced no jobs is
  invisible to any predicate phrased over the jobs that exist. The same shape as
  the M21 PR3a residual-fence finding one day earlier - where a scan's REACH had
  to be compared as a set because mis-attribution preserves totals - and the
  same remedy.
  What `main` actually had, measured rather than assumed once the mistake was
  caught: `stack-from-images` DID run at `388d22b` and asserted
  `passed=32 failed=0 pending=4` against the SHIPPED IMAGES, which is the
  higher-fidelity half of the two stack gates (stack.yml runs services from
  `dist` on the runner). So the development profile was verified on `main` by the
  stronger gate; the production rehearsal was verified on the PR against an
  identical tree and not on `main`. Stating that split precisely is the point -
  "all green" was the claim that was wrong, not the underlying evidence.
- 2026-08-19 - AND THEN THE REPLACEMENT WATCHER WAS WRONG TWICE MORE, within
  minutes of the entry above, which is why the progression rather than any one
  instance is the lesson: THREE SUCCESSIVE SURVEYS OF THE SAME QUESTION WERE
  EACH WRONG ONE LEVEL DOWN. (a) `gh run list --commit 4c7fc88` — an ABBREVIATED
  sha — exits 0 with `[]`, so the set-bound watcher written to fix the count
  defect reported all five workflows MISSING while four were running and one had
  already passed. An empty result and a filter that matches nothing are
  indistinguishable, which is the standing zsh lesson arriving through `gh`: the
  sha is resolved with `git rev-parse` now, and a filter that has matched NOTHING
  after a grace period reports MISCONFIGURED OBSERVER rather than a missing gate,
  because those are different facts with different remedies. (b) The expected set
  was hand-listed as five workflows from parsing each file's `on:` KEYS —
  and `Extension` declares `paths:` filters it does not match on a PR touching
  two workflow files and CLAUDE.md, so it was legitimately absent and would have
  been reported missing forever. PARSING THE EVENT KEYS IS NOT PARSING THE
  EVENT'S PREDICATE. The expected set is DERIVED now, by evaluating each
  workflow's `paths`/`paths-ignore` against the commit's own changed files (four
  expected here, not five). The general shape: grep → parse-the-keys →
  parse-the-predicate, each step correcting the last, and each intermediate
  answer confident enough to be written down. Neither of these was a CI defect;
  both times the thing observed was fine and the observer was broken, which is
  the direction that wastes the most time because there is nothing to find.
- 2026-08-19 - AND THE PREDICTION WAS MEASURED AT THE MERGE AND WAS FALSE, which
  is the entire argument for scoping a claim you have not observed. The
  expectation, written into a shipped comment and into the entry above, was that
  `concurrency` grouping on the ref with `cancel-in-progress` would let a new
  `main` run clear the wedge. HALF OF IT HELD. Cancellation in that group WORKS:
  a dispatch created 19 seconds after the merge's own push run superseded it, and
  that run reached `completed/cancelled` about seventy seconds later. What it does
  NOT do is reach a WEDGED run — two fresh runs arrived in the 05:24 run's own
  group and its `updatedAt` still equalled its `createdAt` eleven hours on, so
  nothing has ever touched it. The control is what makes that conclusive rather
  than suggestive: at the same moment, `gh run cancel` was ACCEPTED on an ordinary
  pending run and answered HTTP 500 on the wedge, so unreachability is a property
  of THAT RUN and not of queued runs, and the tempting reading ("you cannot cancel
  something that has not started") is ruled out. A healthy run creates its jobs
  within a minute — the restored one had 2 jobs in 44s — where the wedge has
  created zero, ever, which is also the cheapest way to tell a slow start from a
  dead run.
  THE LEVER IS STILL THE FIX AND THE REASON CHANGED: it cannot evict the corpse,
  it buys a FRESH VERDICT, which is what was actually missing. And it is a
  FOOT-GUN — dispatching on a ref that already has a live run in the same group
  CANCELS that run, which is how the first half above got measured: my probe
  superseded the merge's own Stack run, I then cancelled the probe, and `main`
  briefly had no `stack.yml` verdict at all until it was restored by dispatching
  again with the group idle. Both facts are now in the workflow's own comment.
  The general shape, and the reason this is a decision-log entry rather than a
  commit message: A PREDICTION IN SHIPPED PROSE IS A LIABILITY WITH A KNOWN
  EXPIRY, so it must either be labelled as one or be measured before it ships —
  here it was labelled, the measurement arrived hours later, and the label is the
  only reason the correction is an addendum instead of a retraction.
- 2026-08-19 — AN APOSTROPHE UNHOOKED A BLOCKING GATE, AND IT HAD BEEN INERT FOR
  EVERY RUN SINCE. `images.yml`'s exact-count step wrapped its assertion in
  `node -e '...'` with twenty lines of prose INSIDE the single quotes; M21 PR3b
  added the word `console's`. Nothing escapes inside single quotes — that is the
  whole point of them — so the apostrophe CLOSED the string, bash parsed the
  remainder as shell, and hit what looked like a redirection. MEASURED by
  extracting the step verbatim from the YAML and running it against a fabricated
  result file with deliberately wrong counts (99 passed / 7 pending): identical
  CI error, and `passed=…` NEVER PRINTED. Bash sets up redirections BEFORE
  executing a command, so node never ran at all. The gate did not mis-assert; it
  did not execute. It went red, which is the safe direction, but only by
  accident — the shell error is what failed the step, and a quoting mistake that
  still parsed would have gone green over an unevaluated assertion. The counts
  themselves were fine: `stack.yml`'s twin passed, so the numbers were verified
  by the other gate the whole time.
  THE PIPELINE ITSELF SUPPLIES THE SAME ANSWER IN THREE REAL RUNS, assembled
  only afterwards and stronger than the reconstruction: `main` at `7664d87`
  (the last Images run before this branch) printed `passed=32 failed=0
  pending=4`; `f4c1391`, the first run carrying the apostrophe, printed nothing
  and died on the shell error; `4bd732e`, with the logic extracted, prints
  `passed=33 failed=0 pending=4`. Working, inert, working — and the middle term
  is the one NO gate would have reported had the parity been even.
  THE TWIN WAS BALANCED ONLY BECAUSE SOMEBODY HAD ALREADY BEEN BITTEN: line 226
  of stack.yml read `profile'"'"'s block`, the close-reopen dance that is the
  only way to put an apostrophe inside single quotes. An unreadable workaround
  in one copy and the defect in the other is the same finding twice, so the fix
  is not "escape it properly".
  FIXED BY MOVING THE PROSE OUT OF THE SHELL, not by escaping it. The prose is
  worth keeping — this repo records why every number is what it is — so it is a
  YAML `#` comment now, which no shell ever parses, and the LOGIC is
  `.github/scripts/assert-stack-counts.mjs`. The two call sites still pass their
  OWN numbers as arguments: images.yml runs the stack from BUILT IMAGES and
  stack.yml from `dist`, so a number derived from the other would stop being a
  measurement, and only the MECHANISM is shared. Proven by extracting both new
  steps verbatim and driving eight cases through them — matching counts exit 0
  and print `passed=…`, a moved count and a failing suite each exit 1 with
  distinct messages, an absent file says "the suite did not run", and neither
  profile's numbers satisfy the other's expectation.
- 2026-08-19 — THE TEST HAD TO DRIVE A SUBPROCESS, BECAUSE THE DEFECT WAS THAT
  NOTHING RAN. A unit test of the comparison would have been green throughout
  the entire inert period — the arithmetic was never wrong. So
  `assert-stack-counts.test.mjs` invokes the SCRIPT the way a workflow does and
  asserts on its exit status and output, with the `passed=…` line as the
  evidence it evaluated at all rather than merely exited. The pure-function
  cases sit underneath, for the messages. `node --test` on the
  `.github/scripts/*.test.mjs` glob already runs in ci.yml, whose own comment
  says "there is no excuse for the next one either" — so this arrived covered
  without new wiring.
  AND MY SURVEY OF THAT WIRING WAS WRONG, in the direction that would have added
  work: I reported `notify-failure.test.mjs` as a test nobody runs. It runs.
  ci.yml invokes it through a GLOB, so the filename appears nowhere in the
  repository and a grep for it returns nothing. A GREP IS NOT A PARSE — the rule
  this repo wrote down eight days earlier, committed by me while investigating a
  defect of the same family, and it survived long enough to be seeded into a
  review agent's prompt as a false premise.
- 2026-08-19 — THE FENCE PARSES THE QUOTING, BECAUSE NOTHING CHEAPER CAN.
  `workflow-shell.mjs` extracts every `run:` block from every workflow and
  tracks shell quoting state across the whole body. A grep cannot answer this in
  either direction: `grep "'"` matches every workflow in the repo, counting
  apostrophes per line calls `"don't"` inside double quotes a defect, and a
  quote legitimately opened on one line closes many lines later — the property
  belongs to the whole script, so answering it is a parse. It deliberately is
  NOT a shell parser: it tracks the states that decide whether a quote is open
  at the end (bare / single / double, with backslash escapes where they apply,
  and `#` comments, without which every `# don't` in the repo is a false
  positive and the next real finding is ignored). No YAML parser resolves from
  the repo root with bare node — measured, MODULE_NOT_FOUND for both `yaml` and
  `js-yaml` — so the extractor is hand-written and REFUSES a `run:` shape it
  cannot read, naming file and line, rather than skipping it.
  WRITTEN BEFORE THE FIX, so the mutation test is the genuine historical defect:
  against the still-broken tree it reported exactly one finding across 47 blocks
  with zero refusals, and it was the real one. Its first version mis-attributed
  by one line — a block scalar's body starts AFTER the `run:` key while a
  single-line body sits on it, and collapsing the two sent the reader one line
  early. A fence that mis-attributes still goes red, and still points at the
  wrong place.
  Six probes, each confirmed: the apostrophe defect reintroduced (red), an
  unterminated double quote elsewhere (red), the extractor broken so it scans
  nothing (red on the anti-vacuity floor, "saw 0"), a `run:` written as a quoted
  YAML scalar (red on the refusal path, not skipped), the count decision
  neutered (red in its own suite), and THE SECOND PROBE OF THE PAIR — the defect
  planted AND the quoting checker neutered — GREEN, which is what identifies the
  checker as the thing that saw it rather than some incidental assertion.
- 2026-08-19 — AND MY OWN FENCE SHIPPED BLIND TO THE WORSE HALF OF ITS OWN
  DEFECT CLASS, found by a parallel audit of the CI configuration and confirmed
  by execution before it was believed. `unterminatedQuote` asked whether a quote
  was left OPEN, which is the ODD-apostrophe case — the one that fails loudly.
  An EVEN number RE-BALANCES the quotes, and that case is SILENT-GREEN.
  MEASURED with `// it's the console's round trip` inside a `node -e` body: bash
  splits it into THREE arguments, node evaluates only the first —
  `const r = {...}; // its`, which is VALID JAVASCRIPT — exits 0, and the
  assertion has vanished with the step passing. Strictly worse than the defect
  that prompted the fence, because that one at least went red. Two lenses
  reached it independently.
  THE FIX IS ON THE CAUSE RATHER THAN THE SYMPTOM, which is what lets one rule
  cover both parities: a `'` that CLOSES a single-quoted string and is
  immediately followed by a WORD CHARACTER is an accidental close — `console's`
  is exactly that, the quote shutting at `console` with `s` running on. A
  deliberate close is followed by whitespace, `)`, `;`, `|`, `&` or another
  quote, INCLUDING `'\"'\"'`, the escape dance, whose close is followed by `"` —
  so stack.yml's years-old workaround is not a false positive. It fires at the
  first accidental close and never counts apostrophes, so parity is irrelevant.
  Zero false positives across all 47 run blocks in the repo. Mutation-tested as
  a pair: the even-parity defect planted goes RED, and planted with the
  accidental-close check neutered goes GREEN — which is what identifies the new
  check, rather than the old one, as the thing that sees it.
  THE LESSON IS ABOUT WHAT A FENCE MEASURES. I wrote a checker for "is a quote
  left open", which is the symptom I had just spent an hour measuring, and
  called it a fence against apostrophes in prose. The two are not the same
  question, and the half I missed was the half that goes green. A fence written
  in the same sitting as the defect it answers inherits the author's model of
  that defect — the M21 PR2 lesson, arriving in the very next fence I wrote.
- 2026-08-19 — I ATTACKED MY OWN RULE AND IT HAD AN EVASION, found within the
  hour and by the obvious attack: I keyed the accidental-close check on `'`
  FOLLOWED BY A WORD CHARACTER, because the one example I had was `console's`.
  A possessive PLURAL closes the string exactly as thoroughly and is followed by
  a SPACE. MEASURED with `// the gates' numbers and the twins' numbers` inside a
  `node -e` body: the unterminated check is blind (two apostrophes re-balance),
  the word-character check is blind (a space is not a word character), bash
  exits 0, and the assertion never runs — the same silent-green failure, one
  rule over, in the fix for the previous silent-green failure.
  THE RULE WAS KEYED ON THE SYMPTOM SHAPE RATHER THAN ON THE STRUCTURE, which is
  this repo's own recurring lesson about fences written in the same sitting as
  the defect they answer. The structure was in front of me the whole time: every
  embedded script here opens with a quote that is the LAST thing on its line and
  closes with one that is the FIRST thing on its. So a multi-line body that
  closes anywhere but at the start of a line has been cut short — by an
  apostrophe, a stray quote, or anything else, at any parity, whatever follows
  it. That is a property of the SHAPE, so it does not have to guess about prose.
  Both earlier defects and the plural evasion all fall out of it.
  ONE EXEMPTION, and it is the only one: a close IMMEDIATELY followed by another
  quote is shell CONCATENATION — `'\"'\"'` — so the body has not ended. Verified
  by running the dance and watching it work. A fence must flag what is broken,
  not what is merely ugly. And that exemption HAD NO TEST until I went looking:
  the escape-dance case asserted only the word-character rule, so mutating the
  concatenation branch stayed green. It asserts both now, and the mutation is
  red.
  Also caught by a test rather than by me: a `python` replacement that added the
  new import SILENTLY DID NOT MATCH, because I asserted the anchor and not the
  import line. A replacement that does not replace reads exactly like a change
  that did nothing — the same family as a mutation that does not mutate.
- 2026-08-19 — THE STEP THAT RUNS EVERY `.github/scripts` FENCE COULD NOT
  DETECT ITS OWN DISARMING, found by a parallel audit of the CI configuration
  and confirmed by two independent verifiers, both by execution. `ci.yml`'s
  helper-test step was one line — `node --test .github/scripts/*.test.mjs` —
  and with `nullglob` off (the default) an unmatched glob reaches node as the
  LITERAL pattern; node 22 expands it itself, finds nothing, prints
  `1..0 / # tests 0` and EXITS 0. The contrast that proves the mechanism is
  node's own: a missing path WITHOUT a `*` makes it exit 1, so the
  metacharacter is what suppresses the failure. A verifier then demonstrated it
  end to end — plant the real apostrophe defect in a workflow, rename the test
  files from `.test.mjs` to `.spec.mjs` with every assertion still on disk, and
  the same defect in the same file goes from exit 1 to exit 0.
  MATERIALITY HAD ALREADY LANDED RATHER THAN BEING PROSPECTIVE: that step is
  the SOLE invoker of every `.github/scripts/*.test.mjs`, no jest project covers
  `.github`, and the two fences committed hours earlier — the stack count gate
  and the workflow quoting fence — run exclusively through it. The fence I wrote
  to catch a disarmed gate was itself reachable only through a gate that could
  be disarmed silently.
  TWO FLOORS, because the two failures are different: a FILE-COUNT floor catches
  the rename, the move and the pattern edit, and a PASSING-TEST floor catches
  three surviving files with their assertions gutted. Both proven by execution
  against a copy of the real tree — normal 34/34 exit 0, renamed exit 1 naming
  the count, emptied exit 1 reporting 3 passing (node counts a file with no
  subtests as one passing test, which is exactly why a file-count floor alone is
  not enough).
- 2026-08-19 — A CONCURRENCY COMMENT DESCRIBED A DEDUP THAT CANNOT HAPPEN, and
  the verifier settled it against the repo's own history rather than by reading.
  `ci.yml` said it skipped the branch-push run when a PR run for the same commit
  existed; the group is `ci-${{ github.ref }}`, which is `refs/heads/<branch>`
  for a push and `refs/pull/<n>/merge` for a pull_request — different groups, so
  neither event can ever cancel the other. MEASURED over 400 runs grouped by
  sha: 67 shas received BOTH a push run and a pull_request run, and 64 of those
  pairs ran both to completion with no cancellation at all; the three that
  contain one are same-event supersession. The block is worth keeping for what
  it really does — superseding an older run when a newer commit lands on the
  same ref — so the comment now says that, with the measurement beside it. A
  wrong claim about a gate is worse than no claim, because it stops the next
  person looking.
- 2026-08-19 — TWO MORE WAYS THE HARNESS TRIED TO LIE, both caught by guards
  this repo already had. `$M mutate …` ran nothing, because zsh does not
  word-split an unquoted variable, so the whole string became one command name —
  the recorded zsh trap, inside the harness built to avoid this class; it
  reported HARNESS REFUSED rather than a green, which is the direction that
  costs a minute instead of a wrong conclusion. And a restore of `ci.yml`
  ABORTED because I had never taken a pristine copy of it: the harness compares
  its restore byte-for-byte against a copy the CALLER took once, before any
  mutation, so a file it was never given cannot be silently overwritten with
  whatever the tree happened to hold. That is the 2026-08-17
  accumulating-mutation defect closed by construction. Its diff was then read
  before restoring, rather than trusting `git checkout --` on a tree with
  uncommitted work.
- 2026-08-19 — THE APP'S `form-action` ORIGINS NEVER REACHED THE BUILD, in
  either of the two layers that carry them, and it was found by a discovery
  sweep for M21 PR3b rather than by any gate. `docker-compose.stack.yml` has
  passed `VAULT_ORIGIN` (M15) and `OPERATOR_ORIGIN` (M21 PR3a) as build args to
  `infra/docker/web.Dockerfile`, which declared `ARG BFF_URL` and no ARG for
  either — `grep -c ORIGIN` returned 0 — so Docker warned about unconsumed args
  and carried on; and `turbo.json`'s build task declared
  `env: ["BFF_URL", "NEXT_STANDALONE"]`, so Turbo 2's STRICT env mode would have
  stripped them even with an ARG. MEASURED WITH A CONTROL, which is what makes
  it a fact rather than a reading: one `turbo run build --filter=@estate/web
  --force` with the two origins set to probe values left ZERO files under
  `.next` containing either, while the same command with
  `BFF_URL=http://probe-bff.example:9999` — the one variable that WAS declared —
  put it straight into `routes-manifest.json`. Same build, same mechanism, one
  declaration apart.
  WHAT IT COST: `form-action 'self' ${vaultOrigin} ${operatorOrigin}` is the
  only directive permitting the top-level form POST that opens the vault origin
  and the operator console, so any deployment whose origins are not literally
  the localhost defaults ships an app whose own browser refuses BOTH handoffs —
  M15's Zone A entry and M21 PR3a's operator entry, which is also PR3b's only
  entry path. Latent solely because nothing is deployed and the compose values
  happen to equal the fallbacks; it arms on the first real hostname.
  THE M8 PR5 DEFECT VERBATIM, in the same `turbo.json`, whose own comment
  describes it ("omitting it here is exactly how the web image silently proxied
  to itself"). M16 PR4b hit it a second time for the extension and shipped
  `turbo-env.spec.ts` — a DERIVED fence over that package's build inputs. The
  app, where the defect actually was, had nothing: `csp.test.ts` pins that
  `next.config.ts` READS `process.env.VAULT_ORIGIN`, and pinning a read is blind
  to whether the value arrives. THREE FENCES EACH CHECKED THEIR OWN LAYER AND
  NOTHING CHECKED THE CHAIN — compose-parity compared compose's literal to
  `topology.ts`, csp.test compared next.config's source to a pattern, and the
  images workflow proved liveness and `public/` assets. Every one green.
  FIXED IN ALL THREE PLACES plus two new checks, one cheap and one decisive.
  `apps/web/src/lib/build-inputs.test.ts` DERIVES the variable set from
  `next.config.ts` and requires each to carry a classification —
  `deployment` (must be an ARG so a deployment can set it), `fixed` (the image
  decides it and it must NOT be an ARG), `ambient` (the toolchain sets it) —
  with a reason per entry, then checks turbo's declaration, the Dockerfile's ARG
  and ENV, and that compose passes it at all. Seven mutations red, including the
  anti-vacuity one where the env-read scan itself stops matching. And
  `images.yml` now BUILDS THE WEB IMAGE WITH NON-DEFAULT ORIGINS
  (`*.probe.invalid`, RFC 2606 reserved so it can never resolve) and asserts the
  SERVED `Content-Security-Policy` names them AND does not name the fallbacks —
  the assertion that was missing, because a value that arrived and a value that
  fell through are indistinguishable until you make them differ. Both directions
  were driven against a real standalone server before shipping: the fixed build
  passes all four checks, the pre-fix build fails all four.
  THE RULE: A FENCE PER LAYER IS NOT A FENCE ON THE CHAIN. Where a value crosses
  N boundaries, N green fences prove nothing about the artifact; only reading the
  value back out of the artifact does, and it must be a value that could not have
  arrived by accident.
- 2026-08-19 — M21 PR3b IS THE OPERATOR SCREENS, and the first thing it found is
  that THE QUEUE COULD NOT REACH A CLOSEABLE CASE. `listOpenForReview` selects
  `('reported','verifying','waiting_period')` and the post-verification verbs act
  on `('verified','active','distributing')` — disjoint, measured, and no document
  named it — so `close`, stage decisions and distribution approvals were reachable
  only by an operator who already held a case id from somewhere else: three of the
  six verbs this milestone names had a surface that could not reach them. `GET
  /v1/settlement/administrable` is the second worklist (chosen over widening the
  first), and the two status sets are declared together and pinned disjoint
  against the DDL's own CHECK rather than against a list retyped in a spec. A
  SIBLING of `queue` and not `cases/administrable`, because the latter is a
  literal segment competing with `cases/:caseId` in a different controller, which
  Nest resolves in module-registration order — a path that cannot collide beats a
  path whose correctness is a property of a list. Also found before any screen
  existed: `markReviewStarted` moved a case to `verifying` and recorded the
  claiming operator NOWHERE (`human_review_by` is first written at approval), so a
  shared work queue had no claim marker and two operators could independently run
  one §5.1 review, which the reviewer-≠-reporter CHECK does not prevent; and ALL
  23 SETTLEMENT AUDIT ACTIONS WERE WRITES, so an operator working the queue or
  reading a death case left no trace of having looked, in the service whose whole
  subject is a §5.1 investigation. TWO read actions, not one per route —
  `settlement.queue.viewed` and `settlement.case.viewed` with `detail.surface`
  naming which of the five reads — and the gate is consulted UNCONDITIONALLY
  rather than as the second arm of the visibility chain, so an operator who is
  also the reporter is still recorded and the claim does not turn on the order of
  an `if`.
- 2026-08-19 — THE AUDIENCE IS DECORATED PER HANDLER AND NEVER SERVICE-WIDE, for
  a mechanical reason rather than a stylistic one: `CallerGuard.audiencesFor`
  returns the UNION of the service-wide list and the per-route one, so binding
  `operator` in settlement's `ALLOWED_SESSION_AUDIENCES` could never be narrowed
  by a decorator and would hand a console credential the decedent's own `void`,
  the owner's waiting-period settings and a reporter's case listing. FOUR OF THE
  THIRTEEN ARE A REAL WIDENING AND ARE RECORDED AS ONE: `getCase`, `timeline`,
  `listStages` and `listDistributions` authorize through the Cedar `read` permit
  and `assertCaseVisible`, which admit the decedent, the reporter and the estate's
  executor as well as an operator, so a console credential reaches those people's
  own cases too. The alternative — four operator-only read projections — is a
  second copy of an authorization decision, which is how two copies drift apart.
  Decided by the user: decorate all twelve reads and REWRITE THE COPY, so PR3a's
  claim that the credential "reaches none of your estate" is replaced in the
  change that made it false, restated in the EXTENSION shape (what the credential
  CANNOT do), with the executor overlap an `[ACCEPTED]` residual in docs/03 §6cc.
  AN AUDIENCE IS A RESTRICTION ON WHERE A CREDENTIAL MAY BE SPENT, NEVER A CLAIM
  ABOUT ITS HOLDER — `OperatorGate` against `settlement_operators` remains the
  only answer to "may this person act".
- 2026-08-19 — THE SERVICE-LOCAL AUDIENCE SPEC IS THE PIECE NEITHER EXISTING
  FENCE COULD BE. @estate/auth-guard's fence checks the TABLE against this
  service's decorators and a prototype scan checks the metadata; neither can see
  that `CallerGuard`'s reflector is `@Optional()` and `audiencesFor` falls back to
  the service-wide list when it is absent — so a perfectly decorated route on a
  container where `Reflector` does not resolve is SILENTLY INERT: 401, no error,
  no log, every source fence green. The new spec drives a REAL guard, admits an
  operator session on `queue`, refuses it on `void` with the same generic 401 an
  invalid token gets, and reproduces the inert case with no reflector — which is
  what proves the first assertion measures the reflector rather than a default
  that happens to agree. It also pins that an ACCOUNT session still reaches the
  console routes, because a decorator must never take authority away.
- 2026-08-19 — THE EDGE LEARNED A PATH SHAPE, AND THE SHAPE IS WHERE THE SAFETY
  ARGUMENT LIVES. PR3a matched `r.path === pathname`, which cannot express
  `cases/:caseId`, and nine of the thirteen handlers carry a parameter. TEMPLATES,
  NOT PREFIXES: a `:name` segment matches exactly ONE non-empty path segment and
  can never span a `/` — `URL.pathname` leaves `%2F` percent-encoded and the
  matcher splits on the literal separator, so a smuggled separator arrives as one
  opaque segment settlement refuses, while `..` and `%2e%2e` never arrive at all
  because the WHATWG parse collapses both before the table is consulted (measured,
  not assumed). `startsWith` would make every row a tree, and a tree under
  `/api/auth/` reaches `/v1/auth/handoff`, the credential this origin must never
  help mint. THE METHOD IS PART OF THE ROW, because two settlement routes share a
  path and differ only by verb: `GET cases/:caseId/stages` is the operator's read
  and is admitted, `POST` on the same path is the EXECUTOR's request and is not —
  a path-only table would forward both and lean on `CallerGuard` to refuse the
  second, which it would, but the edge would be claiming a capability it does not
  have. THE QUERY STRING IS DROPPED BY NEVER BEING READ: the upstream path is
  built from the template plus the captured segments, and a row naming an
  uncaptured parameter is a process that will not start (the `assertSubjectFree`
  precedent), because a literal `:caseId` travelling upstream reads to the
  operator as an outage.
- 2026-08-19 — TWO DERIVATION HOLES IN THE ROUTE↔CONSUMER FENCE, one of which
  PR3b would itself have opened. The operator-shape regex required a row to close
  immediately after `rewriteTo`, so giving each row a `method` would have made it
  read ZERO of sixteen — while the per-edge floor stayed green on the vault edge's
  rows and the operator edge's three unchanged identity ones. A FLOOR CANNOT SEE A
  PARTIAL READ, so rows are parsed as blocks and a completeness assertion counts
  `rewriteTo:` occurrences as a second, deliberately dumber reading of the same
  file. The other hole is the block regex itself: `{[^{}]*}` does not span a
  nested brace, so a row written with an object spread is not unreadable, it is
  INVISIBLE — and an invisible EXTRA row leaves a set comparison passing. The
  fence also could not see a path built from a file-local constant
  (`${CASES}/${id}/timeline` collapsed to `:p/:p/timeline`), so it resolves
  same-file `const X = '…'` before collapsing interpolations; that direction
  failed safe, but a fence going red for a reason that is not its property is how
  an escape hatch gets widened. TWO EXEMPTIONS HONESTLY DO NOT FLIP: `POST
  cases/:caseId/stages` and `POST cases/:caseId/distributions` are executor writes
  whose PATHS are addressed by the console's GET rows, and this fence matches by
  path — its header always said so and nothing had exercised the imprecision.
  `consumed()` would claim a caller that does not exist and `{ exempt }` would be
  flagged stale, so the collision is DECLARED (`pathSharedWith`, the
  `consumedByName` precedent) with four assertions making it checkable, including
  that no edge table names this method on this path.
- 2026-08-19 — THE CONSOLE'S CEREMONY POLLS, IT DOES NOT POLL THE CASE, AND THE
  CASE ID NEVER ENTERS THE URL — three decisions that are not UI preferences.
  (1) Identity grants the elevation; settlement learns of it by introspecting the
  token through `HttpSessionVerifier`'s short-TTL positive cache, so for up to one
  TTL after a genuine step-up the peer still answers from a cached un-elevated
  session and a SINGLE-SHOT retry leaves the prompt doing nothing for someone
  whose code was accepted — the M13 review's finding against the main app, whose
  polling shape this ports rather than the vault origin's single-shot one (the
  vault re-proves a factor to VAULT, which identity's own session state reaches
  first-hand). CANCEL ABORTS THE LOOP and so does starting a fresh attempt: a
  step-up prompt is a CONSENT ceremony, and here the stakes are a death case,
  where a surviving retry could confirm a verification and revoke every session a
  living person holds. The ownership marker is a COUNTER rather than a boolean
  because Cancel restores the form, so a second attempt can begin while the first
  is in flight and a boolean cannot tell "nobody owns this" from "somebody else
  does". (2) Each case read emits an operator read event on that estate's own
  death-case trail, so a console that refreshed itself would turn one screen,
  abandoned over lunch, into hundreds of recorded reads — M12's
  audited-volume-is-a-UI-constraint rule arriving where the subject of the trail
  is a dead person's estate; a case is re-read when somebody acts on it, pinned by
  a test that opens a case, counts exactly four reads, and then waits. (3) Which
  screen the console is on is module state and nowhere else: a hash route would
  accumulate death-case references in an operator's browser history and put one in
  the address bar, which is the part a screen-share catches. The cost is that a
  refresh returns to the worklists.
- 2026-08-19 — A REFUSED LIST COSTS ITS OWN PANEL AND NEVER READS AS AN EMPTY
  ONE, because a short worklist of death reports is indistinguishable from a quiet
  week — which is also why ONE unparseable row fails the whole list rather than
  being dropped. Three smaller copy decisions with the same shape: `UNAUTHENTICATED`
  gained a sentence of its own, having fallen through to "something went wrong"
  while a console session lasts fifteen minutes and cannot be renewed, so an
  expired credential read as a fault; `UNAVAILABLE` says BOTH true things (the
  session survives an outage AND nothing was committed) because that one code
  reaches two surfaces; and a timeline detail is SCALARS ONLY, because
  `String({})` is `'[object Object]'`, which on an audit surface is a sentence
  that looks like a value and is not one.
- 2026-08-19 — THE E2E REFUSAL LIST IS SPLIT, NEVER SHORTENED, and the split is
  the milestone. Until PR3b every service answered a redeemed operator session
  with 401 and one loop said so. Settlement now answers two ways: **401** means
  the AUDIENCE was not admitted and `CallerGuard` never let the request reach the
  handler (`GET /v1/settlement/cases` is owner-facing and stays that way), and
  **403** means the audience WAS admitted and the NEXT control stopped it — the
  probe user is not on `settlement_operators`, so `OperatorGate` refuses inside
  the transaction that would have acted. Collapsing those into "it is refused"
  would hide the boundary moving: a route silently losing its decoration, and the
  allowlist silently ceasing to be consulted, both still refuse, with different
  numbers. A new test drives the claim THROUGH the edge, which nothing had done —
  an allowlisted operator gets 200 on both worklists carrying nothing but the
  cookie they arrived with, a console session belonging to a non-operator gets 403
  on the same path, and `/api/settlement/settings` (a real settlement route this
  origin deliberately does not carry) dies at the edge with 404 and no request
  leaving the box. Minting an operator handoff is role-blind by design, so
  ARRIVING proves nothing; this is where that stops being a sentence in a
  docstring and becomes two status codes from two users.
- 2026-08-19 — A PARAGRAPH OF REASONS HAS NO MECHANISM BEHIND IT, which is how
  the audience declaration's own enumeration of the absences rotted inside two
  PRs of PR2.5 — the milestone spent entirely on counts that rotted. The
  `operator` docblock named `listMyCases`, WHICH IS NOT A HANDLER IN THIS PRODUCT
  (`listMine` is), omitted four refusals outright (`reportableEstates`,
  `addEvidence`, `setDistributionStatus`, `vaultRelease`), mis-grouped two more as
  executor-only when the SERVICE admits an operator on both — `listTasks` through
  `assertCaseVisible` and `setDistributionStatus` through the gate, so their
  absence is a PRODUCT decision rather than an authorization one, which is worth
  saying rather than letting the list imply otherwise — and carried a duplicated
  paragraph and a heading still describing PR3a's contents. The fix is not a
  better paragraph: `session-audience.spec.ts` now asserts the enumeration is
  TOTAL in BOTH directions against the refused set it derives from the real
  decorators. A refused handler missing from the prose is an absence nobody
  decided; a NAME in the prose that is not a handler is a reason pointing at
  nothing, which is worse, because it reads as covered.
- 2026-08-19 — AND THE STEP-UP COUNT HAD ROTTED THE SAME WAY, in code shipped
  four days earlier. `step-up.ts` said "Eight of this console's thirteen routes
  are `StepUpGuard`-ed"; SIX carry the guard. The eight was a count of on-screen
  BUTTONS (approve and reject are two of them over one route), and the sentence
  then travelled verbatim into a commit message and the docs/04 record. Corrected
  by MEASURING it and by moving it to where it is measured: a declared table pins
  which console routes need a fresh factor, checked against the real
  `@UseGuards(StepUpGuard)` decorators in both directions, and the client's
  comment points at that spec instead of restating a number. Two things fell out
  of writing it. `startReview` is the one console verb with no guard, and stating
  that forced the reason to be written down rather than inherited — claiming a
  case commits to nothing, is undone by rejecting, and the DECISION that follows
  IS gated, so gating the claim would put a factor in front of picking up work,
  the M6 rule that the protective action must never be harder than the permissive
  one. And Nest stores method-level `@UseGuards` ON THE HANDLER FUNCTION, not at
  `(prototype, key)`: the first version read the wrong place, reported every route
  ungated, and was caught by its own anti-vacuity floor (`gated > 0`) within
  minutes of being written — a floor earning its place on the day it was added.
- 2026-08-19 — M21 PR3b REVIEW ROUND: A STEP-UP PROMPT HAD THREE DOORS AND
  ABORTED ON TWO. Pressing "Back to worklists" while a ceremony was polling
  removed the form and CLOSED THE CASE two seconds later — measured before it
  was believed, and again live against the running stack. The back controls
  cleared the module's `pending` reference, which forgets the ELEMENT and not
  the CEREMONY: the polling loop lives in a closure that outlives it, so it kept
  retrying and landed an irreversible verb on a death case after consent was
  withdrawn, with nothing on screen to say so. This is the M13 review round 3
  finding ("Cancel did not cancel") arriving through the one door this console
  has and the main app does not — and `step-up.ts` ALREADY HAD THE RIGHT
  MECHANISM, an ownership counter re-checked after every await and every sleep.
  The back path never bumped it because `stepUpPrompt` RETURNED AN ELEMENT and
  there was nothing to bump it with. It returns a handle now (`{form, abort}`),
  `abort()` takes a ceremony out of play without pretending the parent
  cancelled, and one `dismissPrompt()` is the single door for everything outside
  the loop. THE GENERAL SHAPE: when a module owns a lifecycle and hands its
  caller only a rendering of it, every caller that discards the rendering
  silently keeps the lifecycle.
- 2026-08-19 — AND THE FENCE IS THE PART THAT GENERALISES, because the scenario
  test cannot cover the next screen. `console.spec.ts` pins the back control on
  the CASE screen; the case-unavailable screen already has a second one, and the
  next screen with a way out will be a third. So a source scan asserts the
  assignment to `pending` lives in exactly three functions — the one door, the
  LOOP clearing its own prompt on a terminal outcome, and the opener. Attribution
  is by top-level function span, so a nested callback is credited to the function
  that declares it, which is the point: the defect was an assignment inside a
  callback in `renderCase`. Mutation runs: 5/5 red for the fence and 3/5 for the
  behavioural tests — AND THE TWO GREENS ARE WHY THE FENCE EXISTS, since one of
  them was the second back control that no scenario reached. A surviving mutation
  is a question about coverage, not a verdict on the fix.
- 2026-08-19 — "ABORTS" IS NARROWED RATHER THAN OVERCLAIMED, in the same commit
  that made it stronger. Aborting stops the LOOP: no further attempt is issued
  and no result acted on. It cannot recall a request ALREADY ON THE WIRE, whose
  transaction may commit at settlement while the client has stopped observing —
  bounded to one action, one the operator consented to by submitting a code,
  inside the ~100ms of a retry in flight. Recorded [ACCEPTED] in docs/03 §6cc,
  because closing it means making the outcome conditional on something the client
  can still withdraw, which is a settlement change and not a browser one. A claim
  nobody can keep is worse than a narrower one, and this is the third M21 entry
  turning that rule on my own prose.
- 2026-08-19 — A SENTENCE CORRECTED TWICE WAS STILL FALSE IN THE PLACE IT IS
  READ FIRST. PR3b widened the operator audience to thirteen settlement routes,
  four of which reach a case through `assertCaseVisible` — which admits the
  decedent, the reporter and the executor — so "it reaches none of your own
  estate" became an absolute the platform does not keep. It was rewritten in
  `sessions.ts` and on the console's own screen, and LEFT STANDING in
  `OperatorLaunch`, the interstitial, where a user meets it before either. Its
  own test PINNED the false version, so the suite was green over it; and the
  comment in the file that WAS corrected names the console screen as the other
  copy without mentioning this one. All three specs now assert the ABSOLUTE IS
  GONE rather than that the new words are present, because the regression to
  guard against is a rewrite back rather than a deletion.
- 2026-08-19 — TWO EDGE FINDINGS, both LOW, both a claim the code did not keep.
  `/open` answered 500 on a malformed percent-escape — `decodeURIComponent`
  throws on `%zz`, on a bare `%`, and on a truncated multi-byte sequence — where
  every other refusal gets a uniform 303, on the endpoint whose own comment says
  it distinguishes nothing. And the route-table validator's paragraph forecloses
  "the literal `:caseId` travels upstream" while testing `startsWith(':')`, THE
  SAME TEST THE REWRITER USES, so a parameter written MID-segment was invisible
  to both; it also admitted a row under no reachable prefix, a dead entry that
  reads as a granted capability. The validator is EXPORTED and its refusals
  DRIVEN now, replacing a source scan for its own error string plus a
  `[\s\S]{0,400}` bridge — the exact mechanism this repo recorded as a mistake
  in 2026-08-08. A scan for a thrown string cannot tell a check that fires from
  one that cannot.
- 2026-08-19 — MEASURED BEFORE BELIEVED, closing the one link a file-scoped lens
  could not reach: a `%2F` captured by a `:name` segment survives
  `fetch(base + path)` to the upstream as ONE segment (probed against a real
  `node:http` server, which saw `/cases/a%2Fb/timeline`). The lens's whole
  verdict that parameters cannot span a separator rested on the edge not
  decoding-then-re-serialising, and it said so rather than assuming — which is
  what made the assumption cheap to close.
- 2026-08-19 — THE LIVE DRIVE TOOK THREE ATTEMPTS TO REACH THE RACE, and each
  failure is the lesson. First: the prompt had already closed before Back was
  pressed (`submitLabel: null` at 1.4s), because more than 30 seconds of
  introspection cache had lapsed while I generated the TOTP code — so the
  approve was the HAPPY PATH completing, not the race, and reading the case as
  `waiting_period` afterwards would have looked exactly like the fix failing.
  Second: no prompt opened at all, the session still being step-up fresh from
  the first, which is `guarded()`'s try-bare-first decision working. Only a
  FRESH console session — un-elevated by construction, since redemption grants
  no step-up — puts a cold cache and a live refusal in the same window. With
  that, the submit button read "Applying…" at the moment Back was pressed, and
  afterwards the case was still `verifying` with `human_review_by` NULL, no
  `settlement.case.approved` anywhere, and `auth.stepup.granted` on that session
  eighteen seconds earlier in the same trail. THE RULE: when a live probe of a
  race produces the outcome you feared, check whether the race was open at all
  before concluding anything — a timing artifact and a broken fix look identical
  in the result row.
- 2026-08-19 — THE DEPLOY-ORDER HAZARD, THIRD RECORDING AND FIRST TIME IT COST A
  CONTROL. The console's four `settlement.case.viewed` events were missing from
  the trail entirely while the audit consumer logged `audit_event_rejected
  reason=schema_violation` with `rejectedTotal` at 52: a consumer predating a new
  `AUDIT_ACTIONS` member treats every instance as malformed input, silently.
  Previously this had swallowed convenience events; here it swallowed the read
  events that are PR3b's whole answer to docs/03 §4 TB7's operator-reads
  paragraph — so "the reads are recorded" would have been a documented claim with
  an empty table behind it. Rebuilt consumer first, re-opened the case, all four
  land (one per surface, `actor_type: operator`) with zero rejections after.
  Nothing enforces the ordering. The tell is cheap and worth knowing: an expected
  event missing from `audit_events` should send you to the CONSUMER's log before
  the producer's code.
