# @estate/service-audit

Kafka consumer worker (no HTTP surface in M1) that ingests audit events from
`estate.audit.events.v1` into the append-only, hash-chained `audit_events`
store in the `audit` cluster, plus a chain verifier. See docs/01 §2.11 and
docs/02 §6.

Messages are validated against `AuditEventSchema` (`@estate/contracts`) before
touching the database. Rejected messages are counted and logged by
topic/partition/offset and reason enum only — payload content is never logged
or echoed, since it may contain exactly the PII the schema rejected.

## Environment

| Variable        | Used by                | Meaning                                   |
| --------------- | ---------------------- | ----------------------------------------- |
| `DATABASE_URL`  | worker, migrate, verify | Postgres connection string (audit cluster) |
| `KAFKA_BROKERS` | worker                 | Comma-separated broker list               |

## Running

```sh
node dist/migrate-cli.js   # apply migrations/*.sql (via @estate/db Migrator)
node dist/main.js          # start the consumer (groupId: audit-service)
node dist/verify-cli.js    # full chain verification; exit 1 on tamper/corruption
```

## Chain format (v1)

- **Genesis:** `prev_hash` of the first event is 32 zero bytes
  (`GENESIS_HASH`), matching the seed row in `audit_chain_head`.
- **Recipe:** `event_hash = SHA-256(prev_hash || canonicalize(event))`.
- **Canonicalization contract** (`src/canonical.ts`): UTF-8 JSON, no
  whitespace, object keys recursively sorted (UTF-16 code-unit order),
  `JSON.stringify` string/number encoding, `undefined`-valued keys omitted.
  The event is hashed in its normalized, storage-equivalent form:
  `occurredAt` reduced to millisecond ISO-8601 UTC so the verifier can
  rebuild identical bytes from database rows.
- **Never change any of the above without a chain-format version bump** —
  every stored hash was computed under these rules.

Appends run in one transaction on a dedicated connection, serialized by
`SELECT ... FOR UPDATE` on the single `audit_chain_head` row; duplicates
(by `event_id`) are detected inside that critical section and never advance
the chain. `UPDATE`/`DELETE` are revoked from `PUBLIC` on the event tables.

## Tests

`pnpm --filter @estate/service-audit test`. The integration suite
(`test/chain.int.spec.ts`) needs `PG_TEST_URL` pointing at a scratch-capable
Postgres 16; without it the suite compiles but skips. It creates a random
schema, migrates, ingests, tampers, verifies, and drops the schema.

## Follow-ups

- **Monthly partitions:** M1 ships a single `DEFAULT` partition; add monthly
  `RANGE` partitions plus automation (pg_partman or a scheduled job), each new
  partition getting the append-only `REVOKE`, and a `legal_hold` flag to block
  archival (docs/02 §6).
- **S3 Object Lock (WORM) anchoring:** hourly job writing the chain head hash
  to S3 Object Lock in compliance mode in the log-archive account — the
  external trust anchor that makes even owner-level rewrites of the whole
  chain evident. Deploy-time work, not in this repo yet.
- **DLQ for rejected messages:** rejected offsets are currently only counted
  and logged. Design: forward the coordinates (topic/partition/offset,
  reason) — never the payload — to `estate.audit.events.v1.dlq` for operator
  triage and replay tooling, plus an alert on rejection-rate anomalies
  (audit-gap detection, docs/01 §6).
- **Network context columns:** `device_id`, `ip_ct`, `geo`, `user_agent` exist
  per docs/02 §6 but are inserted as NULL until producers put (encrypted)
  network context on the bus.
