---
paths:
  - "apps/stack/**"
  - "apps/e2e/**"
description: Local stack operation and e2e determinism
---

# Local stack

Runbook: `docs/05-local-stack.md`.

- **`pnpm stack:reset` (down -v), never `pnpm stack:down`.** LocalStack Community does
  NOT persist state while the Postgres volumes DO, so one plain restart strands every
  DEK and dangles every `object_key` with no error at the time. The data volumes are
  one unit.
- `.env.stack` is GENERATED and never committed; credentials are minted per
  credential-graph EDGE so a holder's copy equals the callee's inbound value by
  construction. The generator refuses to overwrite without `--force`, because new keys
  orphan every ciphertext in the volumes — and an UNKNOWN FLAG IS NOT A REFUSED FLAG,
  so probe a CLI with `--help` before attaching a destructive flag.
- AWS credentials are deliberately fake (`test`) so a wrong endpoint fails loudly at
  real AWS instead of silently minting real DEKs on a real account.
- Rebuild `migrate-<svc>` alongside `<svc>` — they are separately built images, and a
  migrator's `exit 0` means "nothing to do" as readily as "it worked". Verify against
  `schema_migrations`, not the exit code.
- Build images ONE `docker compose build <service>` at a time on this box; parallel
  bake OOM-kills and still prints `Container Running`.
- e2e determinism contract: no bare sleeps (poll to a deadline), topics provisioned
  before any service starts, infra images tag-pinned, `timeout-minutes` on the job.
- Stack test counts are MEASURED in both profiles, never derived — the production
  profile legitimately differs (production-scoped gates answer 503 where dev answers
  201). Assert exact passed AND pending counts; jest exits 0 for an all-skipped suite.
