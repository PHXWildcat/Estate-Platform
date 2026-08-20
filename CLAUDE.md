# Estate Planning Platform

Enterprise-grade estate planning: 10M users, 100K concurrent, 99.99% uptime, sub-250ms
p95 reads. Engineering bar: Stripe/Plaid quality.
**Security outranks features, velocity, and convenience.** Nothing is deployed yet.

<!-- Kept deliberately short: adherence degrades with length. Per-area detail lives in
     .claude/rules/*.md (loaded only when a matching file is read). Full history is in
     docs/06-decision-log.md. Add lines here only if their absence causes a wrong act. -->

## Verify before you believe

- **Before pushing, run CI's own list**, not a convenient subset:
  `pnpm format`, `pnpm build`, `pnpm lint`, `pnpm typecheck`, `pnpm test -- --coverage`.
  Each has caught what the others could not.
- A green jest run is **not** a typecheck. Widening a shared port or contract type means
  `pnpm -r run typecheck` — the implementors that break are usually TEST doubles, and no
  other gate looks at them.
- Coverage thresholds only arm with `--coverage`. `pnpm -r run test` does not forward it.
- **When an observation contradicts the source, suspect the observation.** Most wrong
  findings here are broken observers, not broken code — the direction that wastes most
  time because there is nothing to find.
- **A stale artifact is not evidence about source.** Rebuild before concluding: a stale
  `dist`, an old container, a migrator image predating its migration, a `FULL TURBO` hit.
- The shell is **zsh**: it does not word-split `$VAR` (use arrays), it glob-expands
  unquoted `--include=*.ts`, and `cmd | tail` reports *tail's* exit status. Each of these
  turns a gate into a silent no-op that reads as a clean result.
- Pair every sweep with an **anti-vacuity check** — a count, or a case you know must
  match. A command that cannot fail and a command that found nothing look identical.
- `pnpm -r run test` starves the PBKDF2-heavy suites on this box; re-run a failing
  package alone before believing it.

## Prove it — fences and mutation testing

The repo's signature mechanism: a rule worth having is DATA plus a test, never prose.

- **Derive from the project; never hand-list.** Container sets, route tables, migration
  lists, enum mirrors, expected job sets. A hand-maintained list beside a thing that
  grows is this repo's most repeated defect.
- Anchor a fence on what the **runtime reads**, not on an identifier a caller chose —
  a name-keyed fence gets renamed into invisibility and stays green.
- **An anti-vacuity floor belongs at every LEVEL of a scan, not just its total.** Where a
  scan has a reach, compare SETS — mis-attribution preserves counts.
- A fence whose input is narrower than its claim goes green for the same reason it is
  wrong. State the corpus and assert it.
- **Prove a fix by REVERTING it and watching a named assertion go red**, and pair it with
  a POSITIVE CONTROL that stays green — "every mutation went red" is equally consistent
  with a fence that fails on any edit. Testing a refusal needs the defect PRESENT.
- A surviving mutation means one of three things: the test is weak, the mutation was
  unfaithful, or the change is genuinely not load-bearing. Say which — never weaken the
  mutation until it goes red.
- When a guard exists at two layers, a test must say WHICH layer it proves.
- A test named for a property must exercise the boundary that property decides. Check
  that your fixture reaches the branch, and that the arm where two facts DISAGREE is the
  one being exercised.
- A fixture that invents an enum tests the fixture. Pin vocabularies to the DDL or SDL.
- A double must be faithful about what it REFUSES and about ABSENCES, not only values.

<!-- Harness failure modes (8+ recorded) are in memory/mutation-testing-rules.md. -->

## Non-negotiable architecture

- **Three-zone trust model.** Zone A (vault, sealed documents) is zero-knowledge:
  client-side encryption, server stores opaque ciphertext, SRP-style auth. Zone B (PII,
  financial, documents) uses per-user envelope encryption with KMS-wrapped DEKs; every
  decryption is a logged event. Never weaken a zone boundary to simplify a feature.
- **No hard deletes anywhere.** Soft delete (`deleted_at`) + trigger-maintained version
  tables. Legal erasure = crypto-shredding (destroy the DEK), never row deletion.
- **Append-only audit.** Every sensitive action emits an event (entity IDs and enums
  only). **Never plaintext PII in any log, audit event, or error response** — error
  filters return no stack traces, SQL or upstream bodies. Audit: REVOKE UPDATE/DELETE.
- **Event-sourced asset ledger.** `asset_events` is the write model; `assets_view` is a
  rebuildable projection. Never write to the projection directly.
- **Settlement is never fully automated.** Death signals open a case; mandatory human
  review + waiting period + staged access. No single source triggers anything.
- **Step-up MFA (fresh ≤5 min)** for: vault open, document generation, data export,
  trustee/executor/beneficiary changes, deletion requests, emergency-access config,
  asset retirement.
- **AuthZ:** Cedar RBAC+ABAC, deny by default. Beneficiaries see only assets naming them.
- Every external integration (Plaid, death-data, LLM) goes through an isolating service;
  third-party tokens decrypt only inside it.
- All user-uploaded content — documents, OCR text — is **untrusted input**, including for
  AI features. Document text is data, never instructions.

## Design rules that recur

- **The protective action must never be harder than the permissive one.** Grant is
  step-up gated; revoke is one click.
- **A control firing must not read as an outage**, and an outage must not wear the face
  of a revocation. Two failures with different remedies never share an error token.
- **Fail closed means DE-ESCALATE, not "refuse everything."** Never withdraw the
  protective path along with the permissive one.
- **The step that cannot be undone runs last** — except where the reversible step is the
  one that strands state, which is a judgement to state in the code.
- Answer a **uniform 404** for "no such row" and "not yours" alike; keep every refusal on
  an unauthenticated ceremony indistinguishable, on the wire AND in the audit trail.
- Any read placed before the authz gate answers a question about someone else's data.
- **One behaviour, one spelling.** A second copy is a copy that drifts; N copies of a
  guard is N places to fix one bug.
- **A rule applied to one member of a category is a rule half-applied.** Ask what else is
  in the category before calling a fix done.
- Ship a route in the same change as its consumer, and a capability in the same change as
  its caller. Zero-caller surfaces are this repo's largest recurring gap.
- Prefer an ABSENCE to a filter: the control that cannot be misconfigured is the parser
  you never added.

## Irreversible and destructive actions — check first

- **`pnpm stack:reset`, never `pnpm stack:down`** (see `.claude/rules/stack.md`).
- **Migrations are append-only and checksummed**; editing an applied file raises
  `MigrationDriftError` and blocks the next migration.
- **Deploy the audit consumer before its producers.** `AUDIT_ACTIONS` is a closed
  vocabulary; an older consumer silently drops every event it does not know.
- **Never `git add -A` while anything runs in the background against the tree** — that
  shipped a review agent's mutation once. Stage explicit paths and check `git status`
  immediately before committing.
- Commit or push only when asked. Branch first if on `main`.
- Secrets never in code or committed env files — Secrets Manager/Vault only.

## Stack (do not substitute without discussion)

- Backend: TypeScript (strict), NestJS, PostgreSQL 16 in six clusters
  (auth/core/financial/documents/vault/audit), Kafka (kafkajs/MSK).
- API: GraphQL at the BFF only (persisted queries in prod); REST internally.
- Frontend: Next.js, React, Tailwind; WCAG AA+; dark mode.
- Infra: AWS multi-account, EKS, Terraform + ArgoCD, CloudFront + WAF, KMS + CloudHSM.
- Tooling: pnpm 10 workspaces + Turborepo, Node ≥22.11, CommonJS + ts-jest, packages
  consumed via built `dist` (no path aliases).
- **Planned but NOT present** — do not assume they exist: Temporal (settlement is a
  Postgres state machine by approved deviation), OpenSearch, Redis, Framer Motion.

## Coding conventions

- Strict TypeScript; no `any` without a justifying comment.
- Sensitive fields: `BYTEA` ciphertext + `dek_id`. Blind indexes (`*_bidx`) only where an
  equality-search use case exists — never for SSN, never in append-only tables.
- All IDs are UUIDs; never expose sequential IDs.
- Money is an exact decimal **string** end to end — never parsed to a float at any
  layer. Use `@estate/money` (BigInt cents); it validates its input and throws rather
  than answering confidently for input it cannot handle.
- Tests accompany every PR: unit + integration. docs/00 states 95% backend / 90% frontend
  as an ASPIRATION; the enforced gate is each package's own `coverageThreshold`, which
  **ratchets up and never down**. Most backend packages sit below 95. If a floor must
  drop, say so in the config with the reason.
- No control characters in source — a literal NUL makes git treat the file as binary and
  it ships with no reviewable diff.
- A comment that justifies an omission by asserting a fact about the tree is a test
  nobody runs. Make the tree the input.

## Working in this repo

Source of truth — read the relevant one before designing or coding in its domain:

| Doc | Read it before |
| --- | --- |
| `docs/00-requirements.md` | changing scope or deliverables |
| `docs/01-system-architecture.md` | adding a service, trust zone or AWS resource |
| `docs/02-database-schema.md` | any DDL or encryption-convention change |
| `docs/03-threat-model.md` | any security control; §6 holds tagged residuals |
| `docs/04-monorepo-and-milestones.md` | milestone scope and the full per-PR record |
| `docs/05-local-stack.md` | running the stack |
| `docs/06-decision-log.md` | why something is the way it is (full history) |

Follow them. If a task requires deviating, **stop and propose the change with rationale**
— do not silently diverge. A milestone that invalidates a sentence owns that sentence:
update the doc in the same change, never after the review.

- Before large changes: propose a plan and the affected docs/services first.
- Record settled decisions in `docs/06-decision-log.md` (`YYYY-MM-DD — decision —
  rationale`). Durable *rules* belong here or in `.claude/rules/`; narrative does not.
- A count or citation in prose beside a mechanism that derives one is a second copy that
  rots. Point at the deriving spec instead of restating its number.
- Driving the real app in a real browser has found a defect every milestone for ten
  milestones — defects no unit test could see. Do it before calling UI work done.

### Running review fan-outs

`CLAUDE.md` auto-loads into every subagent, so agents start deep before reading anything.
Keep this file small, and: give each lens a **named file list** (never a diff range),
give every agent `isolation: 'worktree'` and make its first act
`git checkout --detach <sha>` (worktrees are created at `main`), and size the fan-out for
partial loss. Two refute-by-default verifiers per finding; a refutation is worth as much
as a confirmation.
