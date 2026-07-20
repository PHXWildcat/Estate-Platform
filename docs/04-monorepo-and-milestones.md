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

### M1 — Secure walking skeleton (in progress)
Foundation packages (`config`, `contracts`, `crypto`, `db`, `audit-emitter`,
`auth-guard`) + **identity service** (auth-cluster DDL per docs/02 §1, registration with
encrypted email + blind index, Argon2id, passkeys, TOTP, sessions with refresh rotation,
step-up ≤5 min window, Cedar deny-by-default PEP) + **audit service** (Kafka consumer,
append-only hash-chained `audit_events`, chain verification) + thin BFF and Next.js auth
flows. **Acceptance:** E2E register → login → step-up → gated action → audit event
verified in chain; automated schema-convention checker passes (soft delete, `_versions`
tables, REVOKEs); no plaintext PII in logs under integration inspection; coverage gates
95/90.

### Later milestones (rough order, one per bounded context)
M2 profile & contacts (role assignments, permission grants, Cedar policies) ·
M3 asset ledger (event-sourced `asset_events` → `assets_view`, then Plaid isolate) ·
M4 documents (template matrix, generation pipeline, S3 doc vault) ·
M5 Terraform/EKS to a real dev environment ·
M6 vault (Zone A) ·
M7 settlement (Temporal) ·
M8 AI assistant (privacy proxy) · then referral, notifications hardening, search.
Vault and settlement come late deliberately: highest-risk domains land on mature
primitives.
