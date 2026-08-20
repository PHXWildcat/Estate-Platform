---
paths:
  - "packages/db/**"
  - "**/migrations/**"
description: Migration and Postgres rules — append-only, checksums, int-test isolation
---

# Migrations and Postgres

- **Migrations are append-only.** `packages/db/src/migrator.ts` records a sha256
  checksum per applied file and raises `MigrationDriftError` on mismatch — editing
  even a comment in an applied file blocks the next migration until it is restored.
  Never append to an applied file; add a new numbered one.
- A migration records what was TRUE WHEN IT RAN. A stale count or citation in an
  applied migration's comment is left alone; the live fact belongs in the spec that
  derives it.
- The migrator runs every file inside BEGIN/COMMIT, so `CREATE INDEX CONCURRENTLY`
  is structurally inexpressible. Against a populated table, build it out of band and
  let `IF NOT EXISTS` make the migration a no-op.
- A migration must NEVER choose which data dies. If a pre-flight finds ambiguity
  (duplicate rows that are identical as designations but not as rows), `RAISE` and
  roll back with a runbook in the file. SQL has no KMS access, and `destroyed_at`
  means crypto-shredded.
- A migration that WIDENS what is permitted needs no pre-flight; one that narrows does.
- Partial unique indexes cannot reference `now()`. If a predicate carries a clock in
  code, the index and the code will disagree about what is "live" — make all notions
  of liveness agree, and match the retirement predicate to the INDEX, not to the reader.
- SQL uniqueness treats NULLs as distinct: `COALESCE(col, nil-uuid)` when the NULL case
  is the common one, or the constraint permits unlimited duplicates of exactly that case.

## Integration tests
- **A schema prefix only scopes the statements you write.** Anything the database
  resolves on its own behalf — a trigger body, a function, a default expression — uses
  the CONNECTION's `search_path`. Pin the connection (`SET search_path`) or your test
  writes into the live tables and still passes.
- Prefer `TRUNCATE` over `DELETE` for fixture reset: it fires no row triggers.
- When a fixture and the database each carry a clock, a fake date far from wall time is
  not a neutral choice.
- A defect that lives in SQL must be pinned by a test that RUNS SQL. A fake repo cannot
  see a statement, so "the unit test is green" is not evidence about the repo layer.

## Version tables

- Row images are full `to_jsonb(OLD)` and are readable with the same key as the live row,
  so crypto-shredding reaches them — **except for anything outside the envelope.** A
  plain-TEXT credential verifier (`password_hash`) must be REDACTED in the capture
  trigger; ciphertext + `dek_id` columns are kept. A row image that survives a shred must
  not contain a credential verifier.
- Redact a captured column only when the prior value is an ATTACK ASSET rather than an
  audit record (a superseded key wrapping, a retired verifier). Everything with audit
  value survives, and attribution (`app.actor_id`) must be set or the capture is pure
  liability.
- `CREATE OR REPLACE FUNCTION` only affects FUTURE captures — ship a redaction in the
  same change as the first write that would need it.
