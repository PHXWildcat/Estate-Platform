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
- Tests accompany every PR: unit + integration; target 95% backend / 90% frontend.
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

