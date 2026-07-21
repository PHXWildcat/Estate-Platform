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
