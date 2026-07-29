# The Local Stack — runbook and limits

The whole platform on one machine, at zero cost, with every external dependency
backed by a real local implementation rather than a stub.

Read the **What this does not prove** section before treating a green stack as
evidence of anything about production. It is the most important part of this
document.

---

## Running it

```bash
pnpm stack:env      # generate .env.stack (never committed)
pnpm stack:doctor   # preflight it
pnpm stack:up       # build and start everything
```

`pnpm stack:up` runs the doctor first and refuses to start if it finds an
error. Other commands: `stack:ps`, `stack:logs`, `stack:down`, and
`stack:reset` (which also destroys the volumes).

**Address the stack as `http://localhost:3000`.** The BFF sets `Secure` on its
session cookies whenever `NODE_ENV=production`, and browsers reject `Secure`
cookies over plain http on every host *except* localhost. Any other spelling
silently breaks login in the production profile.

### The two profiles

| | **development** (default) | **production** (`--mode production`) |
|---|---|---|
| KMS | LocalStack, `AwsKmsProvider` | LocalStack, `AwsKmsProvider` |
| Object store | LocalStack S3 | LocalStack S3 |
| Malware scan | real clamd | real clamd |
| OCR | Tesseract sidecar | Tesseract sidecar |
| Audit bus | Redpanda | Redpanda |
| Plaid | deterministic stub | **absent** |
| Every flow runs | yes | no — see below |

Both profiles run the **production adapters**. That is the point of the
milestone: `AwsKmsProvider`, `S3ObjectStore`, `ClamdScanner` and
`KafkaAuditProducer` had never executed anywhere before this, in any
environment, against anything.

The difference is `NODE_ENV`, and therefore which fail-fast guards are armed.

### What is deliberately inert in the production profile

Each of these is a control firing, not a defect. None of them will be "fixed"
by weakening the guard:

- **Settlement intake and review-approve answer `503 notifications_unavailable`.**
  So does every vault emergency-access route. Both refuse while only the stub
  notifier is wired, because a waiting period nobody can be told about is not a
  control (docs/03 §5.2, §5.1). The notifications milestone is what retires
  this.
- **Plaid is absent from the profile entirely.** Production requires
  `PLAID_MODE=live` with credentials that do not exist. A container that boots
  on invented credentials and fails every outbound call is worse than an
  absent one.
- **Document generation works, but proves nothing about legal sign-off.** See
  the limits section.

---

## What this does not prove

A green stack is a persuasive thing, and most of what it cannot exercise is in
the part of the threat model that matters most.

### KMS grant isolation is NOT tested

The decision log states that Plaid's isolation is "cryptographic, not
organizational — the asset service's KMS grant can never unwrap a token DEK."

**That property is not exercised here.** It is enforced by AWS IAM grants, and
LocalStack Community does not enforce IAM meaningfully. The stack provisions
six independent KMS keys, one per service KEK, which models the boundary; it
does not prove it. Any service in this stack that knew another's key id could
call `Decrypt` against it and succeed.

What *is* real is the **EncryptionContext binding**: `AwsKmsProvider` wraps
every DEK under `estate:kek = <alias>`, and KMS refuses a `Decrypt` whose
context differs. If LocalStack enforces that, cross-domain unwrapping fails
even without IAM — which is why the stack test asserts it rather than assuming
it. If it turns out LocalStack ignores EncryptionContext, that assertion fails
loudly and this section gets stronger wording.

`docs/03` §5.3 (insider bulk decryption) is precisely what this cannot test:
KMS rate limiting, anomaly detection, circuit breaking, CloudHSM roots, and
canary records are all cloud-posture controls with no local equivalent.

### Active templates are attorney-unreviewed exemplars

The seed job runs the template publish CLI with `NODE_ENV=development` **even in
the production profile**, because the M4 review made that CLI refuse
placeholder-`legalReview` sources under `NODE_ENV=production`, and the three
shipped exemplars are placeholders by design.

The guard is not weakened — it is respected, by seeding through the path it
permits. But the consequence must be stated: in the production profile, the
active will/POA/living-will templates are **not** attorney-reviewed, so
document generation succeeding there is not evidence that the legal sign-off
gate holds. docs/04's preferred fix for a real environment (a narrow,
dev-account-only opt-in flag) remains the answer there.

### Everything else in the cloud posture

None of this is exercised, and all of it is load-bearing in `docs/01` §3:

- IRSA and pod-level AWS permissions
- VPC and subnet isolation, security groups, RDS Proxy, no public endpoints
- WAF, Shield Advanced, CloudFront
- The multi-account organization boundary
- CloudHSM-rooted KEKs
- Istio mTLS / SPIFFE peer identity — the mesh that is supposed to *replace*
  the static service credentials this stack provisions
- Kyverno signed-image admission, read-only root filesystems, default-deny
  NetworkPolicies
- Aurora behaviour: failover, PITR, cross-region replication, backup vaulting

### The M4 legal-hold gap is still open

`DOCUMENTS_INTERNAL_TOKEN` is declared in the credential graph with **zero
holders**, because no in-repo client calls that route. The stack provisions it
to documents' inbound slot and to nobody else, so the route exists and refuses
every caller. The stack does not close the gap; it makes it visible.

---

## How it is wired

### Addressing

Inside the compose network, services use container names and container-side
ports. The `5433-5438` host mappings exist only for host tooling and
`PG_TEST_URL`.

| | in-network | from the host |
|---|---|---|
| Postgres | `pg-auth:5432` … `pg-audit:5432` | `localhost:5433` … `localhost:5438` |
| Kafka | `redpanda:29092` | `localhost:9092` |
| AWS | `http://localstack:4566` | `http://localhost:4566` |

### The environment is generated, never committed

`.env.stack` is produced by `apps/stack` and matched by `.gitignore`'s
`.env.*`. Regenerating mints new KMS master keys and blind-index keys, which
orphans every ciphertext already in the volumes — so the generator refuses to
overwrite without `--force`, and the message tells you to `stack:reset`.

**The three service credentials are derived from the credential graph**
(`packages/auth-guard/src/credential-graph.ts`). One secret is minted per
*edge* and written to the callee's inbound slot and to each declared holder's
slot, so agreement is structural rather than clerical, and two edges cannot
collide because they are independently random.

That closes a residual the graph module explicitly records as unenforced:
"nothing verifies that vault's `SETTLEMENT_INTERNAL_TOKEN` really is
settlement's inbound value." It closes it **for environments this generator
produces**. A hand-provisioned deployment is still unverified — but deriving
provisioning from the graph is the mechanism that carries over to a real
secrets store.

### AWS credentials are deliberately fake, and that is a control

`.env.stack` sets `AWS_ACCESS_KEY_ID=test`. Environment variables outrank
`~/.aws/credentials` in the SDK's chain, so if the endpoint override is ever
missing or wrong, the request reaches real AWS carrying an obviously invalid
key and is rejected. Without them, an ambient developer profile would make that
same misconfiguration **succeed silently against a real account** — minting real
DEKs and real charges.

The doctor enforces both halves: the endpoint must point at the stack, and the
credentials must not look real.

### Health probes are TCP, not HTTP

The runtime images are distroless — no shell, no curl — and every route in
every service is guarded, so an HTTP probe would have to be a new
*unauthenticated* route on nine hardened services to return anything but 401.
A TCP connect to the port each service already listens on proves the same thing
with no added surface, and Kubernetes `tcpSocket` probes work identically.

The audit service is headless and has no probe at all. Its liveness signal is
that it now **exits** on failure (M8 PR2) instead of sitting "up" with a dead
audit trail, so `restart` is what recovers it.

### Ordering

Migrations run as one-shot jobs before the services that need them. The two
co-tenanted clusters are sequenced — `profile → settlement` on core,
`assets → plaid` on financial — because settlement queries profile's `contacts`
and `role_assignments` unqualified, and because two migrators bootstrapping one
empty cluster is the race the advisory-lock fix in `@estate/db` addresses.

Topics are created explicitly by a one-shot job driven from `TOPICS` in
`@estate/contracts`. Redpanda ships `auto_create_topics_enabled` **off**
(unlike Apache Kafka), and nothing in the services creates topics, so without
that job the first produce fails and the audit consumer subscribes to a topic
that does not exist.

LocalStack's healthcheck waits for the **init hook**, not just for LocalStack:
it reports healthy as soon as its APIs answer, which is before the keys and
bucket exist.

---

## Resource budget

Roughly 4.5 GB across ~20 containers. Docker Desktop on the development machine
this was built on allocates 8 GB, which fits but is not generous — ClamAV's
signature database is the largest single consumer.

Use profiles to run less: omit `--profile edge` to skip the browser tier, or
`--profile plaid` to skip the one service that stays stubbed.
