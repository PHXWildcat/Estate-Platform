# Estate Planning Platform

Enterprise-grade estate planning platform. **Security is the highest priority — above
features, velocity, and convenience.** Start with the source-of-truth docs:

| Doc | Contents |
| --- | --- |
| [docs/00-requirements.md](docs/00-requirements.md) | Product requirements, quality bar |
| [docs/01-system-architecture.md](docs/01-system-architecture.md) | 11 services, three trust zones, AWS |
| [docs/02-database-schema.md](docs/02-database-schema.md) | Six-cluster Postgres design, DDL, encryption |
| [docs/03-threat-model.md](docs/03-threat-model.md) | Adversaries, attack scenarios, controls |
| [docs/04-monorepo-and-milestones.md](docs/04-monorepo-and-milestones.md) | Repo layout, boundary rules, milestones |

## Layout

- `apps/services/*` — one NestJS app per bounded context; each owns its migrations and
  its database cluster. Services never import each other.
- `apps/web`, `apps/bff` — Next.js frontend and GraphQL BFF (persisted queries).
- `packages/*` — shared internals: `crypto` (server-side envelope encryption),
  `vault-crypto` (client-side Zone A — deliberately separate), `contracts`, `db`,
  `audit-emitter`, `config`, …
- `infra/` — container builds and the local stack's supporting images: one
  parameterized `node-service.Dockerfile` for every Node service plus a separate
  `web.Dockerfile`, and the clamd signature, LocalStack provisioning and TLS
  terminator `docker-compose.stack.yml` runs on. Terraform, Helm and ArgoCD land
  with the deferred cloud half of M5 (see docs/04) — they are not here yet.

## Getting started

Requirements: Node ≥ 22.11, pnpm 10 (`npm i -g pnpm@10`), Docker (for local infra).

```sh
pnpm install          # frozen, catalog-pinned; dependency build scripts are blocked
docker compose -f docker-compose.dev.yml up -d   # 6× Postgres, Redpanda, LocalStack
pnpm build            # turbo-ordered package/service builds
pnpm test             # unit tests everywhere; set PG_TEST_URL to include DB integration
pnpm lint && pnpm format
```

Postgres integration tests are gated on `PG_TEST_URL` (CI always sets it; locally e.g.
`postgres://estate:estate_dev@localhost:5433/auth`).

## Non-negotiables (enforced in code and CI)

- Three-zone trust model; Zone A is zero-knowledge — see docs/01 §1.
- No hard deletes; `_versions` shadow tables; crypto-shredding for legal erasure.
- Append-only, hash-chained audit; audit payloads carry IDs/enums only (the
  `@estate/audit-emitter` shape guard rejects anything else at runtime).
- Every field decryption is an audited event (`@estate/crypto` fails closed).
- Step-up MFA (fresh ≤ 5 min) for sensitive operations.
- Secrets never in the repo; gitleaks, CodeQL and dependency review run on every
  push and PR. They are not yet merge-blocking — `main` has no branch protection,
  so a red gate stops a merge only because a human reads it (docs/04, boundary
  rule 5).
