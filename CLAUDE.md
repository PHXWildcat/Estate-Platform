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
  M4 gap is NOT closed (corrected in docs/04 M7).
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
  clamd + tesseract + LocalStack (with volumes — keys must not vanish while
  Postgres volumes persist, stranding DEKs) + Redpanda. .env.stack is
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
  and the M4 legal-hold gap (zero holders; the stack makes it visible, not
  closed).
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
  holders is deliberately NOT provisioned (documents' legal hold). The service
  absorbs the variable and its guard fails closed on the empty value; minting a
  secret nobody can present would be exactly the aspirational grant the
  credential graph exists to forbid. The generator, the doctor and the
  entitlement spec all agree on that subtraction.
