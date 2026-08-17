# Settlement service

Death-verification intake and the estate-settlement case state machine
(docs/01 §2.7, docs/02 §7, docs/03 §5.1). This is the flow the threat model
rates Critical ("kill them on paper", risk #2): every convenience here is the
vulnerability, so every control below is deliberate friction.

## What PR1 ships

- **Intake that only opens a case.** Reporters must already be NAMED by the
  decedent's contact repository (`contacts.linked_user_id`); there is no
  lookup by email or arbitrary id anywhere in the service. Death-data
  provider matches are operator-filed signals (`data_provider`), never
  triggers. One OPEN case per decedent (partial unique index).
- **Mandatory human review** by allowlisted operators (`settlement_operators`,
  managed ONLY by `operator-cli` — no runtime grant API, asserted by
  `test/operator-write-path.spec.ts` rather than by this sentence). Reviewer ≠ reporter
  (DDL CHECK + row check). Approval starts the waiting period and locks the
  account to `deceased_pending` via identity's internal settlement-lock API —
  inside the case transaction, so an unconfirmable lock rolls the approval
  back.
- **The waiting period** (default 5 days, owner-configurable UP to 60,
  frozen while a case is open). The in-process workflow driver records
  escalating owner-contact attempts (12h schedule, channels cycling) in the
  append-only `settlement_contact_attempts` trail. The driver holds NO
  transition power: losing it degrades contact liveness, never safety.
- **Verification is human, twice-gated.** Timer expiry only makes a case
  eligible. An operator (again: never the reporter) explicitly confirms, and
  the confirmation re-checks owner liveness against identity's append-only
  step-up ledger — a step-up newer than the case voids it on the spot
  (`409 owner_alive`), restores the account, and flags the reporter.
  Verified ⇒ identity status `settlement` + every session revoked.
- **The owner's kill switch**: step-up-gated void at any pre-verification
  stage. Post-verification rescue is deliberately not self-serve.
- **Evidence-read authority** for the documents service: an operator's bearer
  is forwarded here; the answer names the evidence's recorded ATTACHER, which
  documents cross-checks against the row's real owner before decrypting.

## Production posture

- Intake and review-approve refuse `503 notifications_unavailable` while only
  the stub notifier is wired (M6 precedent) — a waiting period nobody can be
  told about is not a control.
- `IDENTITY_INTERNAL_TOKEN` unset (dev default) ⇒ identity's guard fails
  closed and the lock-touching transitions 503 until both sides are
  provisioned.
- **Two credentials, opposite directions, never the same value.** Each is named
  for the service whose internal routes it OPENS:
  `SETTLEMENT_INTERNAL_TOKEN` is what vault presents to
  *this* service's read-only gate route; `IDENTITY_INTERNAL_TOKEN` is what
  *this* service presents to identity's account-lock API. Production refuses to
  boot if they are equal. The M7 security review found them collapsed into one
  field, which meant the value provisioned to vault — the most exposed service
  in the product — was also accepted by `PUT /internal/v1/settlement-lock/:userId`,
  enough to irreversibly mark any living user deceased with no case, no
  operator and no waiting period.

## Environment

| Var | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | yes | core cluster (local port 5434; CI: `PG_TEST_URL`) |
| `PORT` | no | default 3007 |
| `IDENTITY_URL` | prod | session verification + settlement-lock API; dev default `http://localhost:3001` |
| `SETTLEMENT_INTERNAL_TOKEN` | prod (≥32 chars) | INBOUND: what vault presents to this service's gate route (the only holder — see `packages/auth-guard/src/credential-graph.ts`) |
| `IDENTITY_INTERNAL_TOKEN` | prod (≥32 chars) | OUTBOUND: presented to identity's internal routes; must match identity's value, and must differ from the inbound one |
| `KAFKA_BROKERS` | prod | audit emission |
| `NOTIFY_MODE` | no | `stub` only until the notifications milestone |
| `DRIVER_INTERVAL_MS` | no | contact-sweep interval, default 60000; driver disabled under NODE_ENV=test |

## Local development

```
docker compose -f ../../../docker-compose.dev.yml up -d pg-core
DATABASE_URL=postgres://estate:estate_dev@localhost:5434/core node dist/migrate-cli.js
PG_TEST_URL=postgres://estate:estate_dev@localhost:5434/core pnpm test
```

## The operator ceremony (`operator-cli`)

`settlement_operators` is the interim allowlist that decides who may run
docs/03 §5.1's mandatory human review. **There is no runtime grant API, and that
absence is the safety property**: a compromised operator session can act as the
operator it already is and cannot create another.
`test/operator-write-path.spec.ts` asserts it against the service's own source
in both directions, so it is checked rather than claimed.

```
pnpm --filter @estate/service-settlement build
DATABASE_URL=… KAFKA_BROKERS=localhost:19092 \
  pnpm --filter @estate/service-settlement operators grant  <userId> --by <authorizingUserId>
DATABASE_URL=… KAFKA_BROKERS=localhost:19092 \
  pnpm --filter @estate/service-settlement operators revoke <userId> --by <authorizingUserId>
DATABASE_URL=… pnpm --filter @estate/service-settlement operators list
```

- **A write REFUSES without `KAFKA_BROKERS`.** Granting the authority to
  approve a death case is not something this ceremony will do unrecorded, so it
  fails closed rather than falling back to an in-memory producer the way the
  template-publish CLI does. `list` changes nothing and needs no broker.
- **`--by` is required, and it is ATTRIBUTION rather than authentication.**
  Whoever runs this holds `DATABASE_URL` and could write the row by hand. What
  the flag buys is that the sanctioned path names a human in `granted_by`, so a
  row with `granted_by IS NULL` is visibly one that did not come through here.
- **Both writes emit** `settlement.operator.granted` / `.revoked` into the
  append-only trail, naming the authorizer as actor and the subject in `detail`.
  The row is written first and the event second, because the INSERT rolls back
  and the emit does not — so a failed emit rolls the grant back.
- **Repeats are no-ops, not second grants** (`already granted:` / `no active
  grant:`), and each records its own outcome. A revoked operator can be granted
  again; the index that makes the repeat a no-op is partial on the active row.
- **Revocation takes effect on the next request**, because `isOperator` is read
  per action rather than cached, and it notifies nobody — see docs/03 §6z.

The service shares the core cluster with profile: disjoint tables, its own
migrations dir, shared `schema_migrations` (Plaid precedent), plus READ-ONLY
use of profile's `contacts`/`role_assignments` (flagged in the decision log;
production grants are SELECT-only on those two tables).

## Deviations and deferrals (recorded in docs/04 + the decision log)

- Temporal is deferred behind the driver port (approved deviation from
  docs/01 §7; there is no deployment for its durability to protect yet).
- `resolution`/`resolved_at`/`verified_at` columns and the four PR1 tables are
  additive to docs/02 §7. Cases have NO `deleted_at` — a case is evidence.
- Date-of-death is not stored; PR2's timeline anchors on `verified_at`.
- PR2: staged executor access (inventory → documents → vault), the vault
  emergency-release gate, tasks/timeline, dual-control distributions with
  `settlement_deks`, documents legal-hold setter, case close. (The legal-hold
  SETTER was a route with no caller until M9 PR2: `src/documents-hold.ts` now
  sets/clears the estate-wide hold with the account lock at every case
  transition, holding `DOCUMENTS_INTERNAL_TOKEN` per the credential graph.)
