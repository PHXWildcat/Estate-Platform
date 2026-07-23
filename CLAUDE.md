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
