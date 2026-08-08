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

**The vault is a SECOND origin: `http://vault.localhost:3010` (M15).** Do not
substitute `localhost:3010`, and the reason is measured rather than stylistic:
cookie scope IGNORES THE PORT, so the app's session cookies would be sent to a
same-host vault surface on every request — which is the entire property the
isolated origin exists to have. `*.localhost` resolves to loopback in Chrome and
Firefox and is a *potentially trustworthy* origin, so the vault's `__Host-`
prefixed `Secure` cookie is accepted there over plain http exactly as the BFF's
is on `localhost`. You do not normally type this address: the app's `/vault`
page mints a single-use handoff and posts you there.

### Testing it

```bash
# development profile (default): the whole journey
STACK_TEST=1 pnpm --filter @estate/e2e exec jest test/stack.e2e.spec.ts test/aws-conformance.spec.ts

# production profile: the fail-fast rehearsal
STACK_TEST=1 STACK_PROFILE=production pnpm --filter @estate/e2e exec jest test/stack.e2e.spec.ts
```

Both run in CI (`.github/workflows/stack.yml`, blocking, one job per profile).
The determinism contract is that there are **no bare sleeps** anywhere: every
wait is a poll with a deadline, topics are provisioned before any service
starts, and clamd's readiness is `clamdscan --ping` rather than a timer. A
`--json` result check asserts a minimum number of *passed* tests, because jest
exits 0 for a suite that skipped everything.

`.github/workflows/images.yml` runs the same spec against the **shipped
images** in a separate job — stack.yml proves the code integrates, that job
proves the artifact does.

### Host mode

CI's fast gate and the local inner loop run the node processes on the host
against the containerised infrastructure:

```bash
pnpm stack:env -- --addressing host --force
docker compose --env-file .env.stack -f docker-compose.stack.yml up -d --wait pg-auth pg-core pg-financial pg-documents pg-vault pg-audit redpanda localstack aws-tls clamav tesseract
node apps/stack/dist/run-services-cli.js .env.stack
```

The supervisor refuses a compose-addressed env file outright: container
hostnames do not resolve from the host, so every service would boot and then
fail per request — the slowest possible way to find that out. A parity spec
(`apps/stack/test/compose-parity.spec.ts`) asserts the compose YAML's
environment blocks and the supervisor's mapping agree key-for-key, so the two
paths cannot drift.

### The two profiles

| | **development** (default) | **production** (`--mode production`) |
|---|---|---|
| KMS | LocalStack, `AwsKmsProvider` | LocalStack, `AwsKmsProvider` |
| Object store | LocalStack S3 | LocalStack S3 |
| Malware scan | real clamd | real clamd |
| OCR | Tesseract sidecar | Tesseract sidecar |
| Audit bus | Redpanda | Redpanda |
| Notifications (M9) | real HTTP → SES v1 on LocalStack | real HTTP → SES v1 on LocalStack |
| Vault origin (M15) | `vault.localhost:3010`, real handoff | same — needs no third-party credential |
| AWS transport | plain http | **TLS, verified** |
| Plaid | deterministic stub | **absent** |
| AI assistant (M10) | deterministic stub gateway | **absent** |
| Every flow runs | yes | no — see below |

**Production reaches AWS over real TLS.** The production config refuses a
plaintext `AWS_ENDPOINT_URL` — wrapped DEKs must not cross the wire in the
clear — and LocalStack speaks http, so the production profile goes through an
nginx terminator (`aws-tls`) with a generated certificate the services
genuinely verify via `NODE_EXTRA_CA_CERTS`. Nothing anywhere sets
`NODE_TLS_REJECT_UNAUTHORIZED`, and the doctor treats that variable as an error
if it ever appears: switching verification off would turn the production TLS
requirement into decoration, which is the same class of mistake as relaxing the
guard it exists to satisfy.

Both profiles run the **production adapters**. That is the point of the
milestone: `AwsKmsProvider`, `S3ObjectStore`, `ClamdScanner` and
`KafkaAuditProducer` had never executed anywhere before this, in any
environment, against anything.

The difference is `NODE_ENV`, and therefore which fail-fast guards are armed.

### What is deliberately inert in the production profile

Each of these is a control firing, not a defect. None of them will be "fixed"
by weakening the guard:

- ~~Settlement intake and review-approve answer `503 notifications_unavailable`~~
  **RETIRED by M9.** The notifications service runs in both profiles with the
  real carrier path (SES v1 against LocalStack; sender identity verified at
  bootstrap), so intake, review-approve and the vault emergency-access routes
  now WORK in the production rehearsal — and the e2e proves it by reading the
  owner's actual email back out of LocalStack's `/_aws/ses` store. The 503
  gates themselves remain in the code as defense in depth (and now audit their
  refusal); what changed is that production configuration can no longer reach
  them, because `NOTIFY_MODE=http` / `EMAIL_MODE=ses` are production-pinned.
- **Plaid is absent from the profile entirely.** Production requires
  `PLAID_MODE=live` with credentials that do not exist. A container that boots
  on invented credentials and fails every outbound call is worse than an
  absent one.
- **The readiness page reads UNAVAILABLE in the production profile (M10 PR4).**
  The BFF is wired to the assistant in both profiles, but the assistant
  container is absent from production (below), so its four analysis cards say
  "we could not run this check" there. That is the stack's shape, not the
  product's — and it is the honest rendering, which is the point: a failed check
  never shows as an empty finding list.
- **The AI assistant is absent for the same reason (M10).** Production pins
  `LLM_MODE=anthropic`, and no Anthropic credential exists in this project. In
  development it runs its deterministic stub gateway and makes no network call
  to any provider — the stack can host KMS, S3, a virus scanner and an OCR
  engine, but it cannot host a model provider. Nothing anywhere in the stack
  mints an `ANTHROPIC_API_KEY`: the generator writes none, `serviceProcessEnv`
  maps `LLM_MODE` alone, the supervisor scrubs `ANTHROPIC_*` out of the ambient
  shell, and the doctor warns if one ever appears in the generated file —
  because a local stack that could reach a real provider is a local stack that
  could send retrieved estate content off the machine.
- **Document generation works, but proves nothing about legal sign-off.** See
  the limits section.
- **Estate-tax analysis works in development, and proves nothing about the tax
  table (M10 PR3).** The reference figures carry an `unreviewed-exemplar`
  sign-off block, and the analyser refuses (`503 reference_unreviewed`) wherever
  `NODE_ENV=production`. That refusal is NOT exercised by this stack: the
  assistant container is absent from the production profile entirely, so the
  gate is proven by unit tests rather than over the wire here. What the stack
  does prove is the other side — a green estate-tax estimate in development,
  which is **not** evidence that a tax professional has checked a single figure
  in it. The other three analysers condition only on the user's own account and
  carry no such gate.

---

## What this does not prove

A green stack is a persuasive thing, and most of what it cannot exercise is in
the part of the threat model that matters most.

### KMS grant isolation is NOT tested

The decision log states that Plaid's isolation is "cryptographic, not
organizational — the asset service's KMS grant can never unwrap a token DEK."

**That property is not exercised here.** It is enforced by AWS IAM grants, and
LocalStack Community does not enforce IAM meaningfully. The stack provisions
eight independent KMS keys, one per service KEK (M9 added notifications', M10
the assistant's), which models the boundary; it does not prove it. Any service in this stack that knew another's key id could
call `Decrypt` against it and succeed.

What *is* real is the **EncryptionContext binding**, and this is now measured
rather than assumed. `AwsKmsProvider` wraps every DEK under
`estate:kek = <alias>`, and `apps/e2e/test/aws-conformance.spec.ts` proves that
LocalStack **does** enforce it: a `Decrypt` with a foreign context
(`plaid/kek` against a blob wrapped for `documents/kek`) is refused, and so is
one with the context omitted entirely.

So the local stack genuinely exercises the cryptographic half of the isolation
claim — a DEK wrapped for one domain cannot be unwrapped as another, even with
the right key id. What it does **not** exercise is the IAM half: which
*principal* may call `Decrypt` on which key at all. That is the difference
between "a stolen ciphertext cannot be replayed across domains" (proven here)
and "a compromised asset service cannot reach the Plaid key" (not proven here).

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

### The M4 legal-hold gap — CLOSED (M9 PR2)

`DOCUMENTS_INTERNAL_TOKEN` now has a holder: settlement drives the estate-wide
legal hold from its case transitions through `documents-hold.ts`, and the
generator mints the credential to documents' inbound slot and settlement's
outbound slot from the graph edge like every other. The dev-journey stack test
proves it live: review-approve freezes the estate against a real
step-up-authorized deletion, and the reject transition releases it. (While the
gap was open, this section also claimed the stack provisioned the inbound slot
alone — it did not: a zero-holder edge was deliberately NOT provisioned at
all, and the guard failed closed on the empty value. That subtraction rule
survives for any future holder-less edge.)

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
| Vault origin | `vault-web:3010` | `http://vault.localhost:3010` |

### The data volumes are ONE UNIT — LocalStack cannot persist its keys

**Measured, not assumed.** LocalStack Community has no persistence
(`PERSISTENCE` is a Pro feature), and the volume mounted at
`/var/lib/localstack` holds the state *directory*, not the state. After a plain
`docker restart localstack`:

- every KMS alias is gone (`list-aliases` → 0 of 6);
- the S3 bucket and every object in it are gone;
- a previously wrapped DEK fails `Decrypt` with
  `NotFoundException — Key arn:…:key/… does not exist`.

The **Postgres volumes do persist**. So restarting that one container leaves
every wrapped DEK in the six clusters permanently unopenable and every
`document_versions.object_key` dangling, with no error at the time it happens.
The symptom arrives later as decrypt failures in a stack that looks healthy.

Two things make that loud instead of silent:

1. **The health marker is cleared first.** `/tmp/stack-init-complete` lives on
   the container filesystem, which *survives* `docker restart` even though the
   state does not — so a stale marker used to report a healthy, keyless
   LocalStack. The init hook now removes it before doing anything that can fail,
   so it only ever means "*this* run provisioned successfully".
2. **The init hook refuses to re-provision after key loss.** It writes an epoch
   file to the volume (which does persist) after a successful provision. Epoch
   present + KMS aliases absent means exactly one thing, and re-minting keys
   under the same aliases would hand the services a stack that boots cleanly and
   cannot read its own data. It exits non-zero with instructions instead; the
   container goes unhealthy and nothing that depends on it starts.

So: **`pnpm stack:reset` (compose `down -v`), not `stack:down`, is how you
restart from a stopped stack.** `stack:down` keeps the Postgres volumes, which
is only useful for inspecting them — the stack cannot be brought back up on
them. Set `STACK_ALLOW_KEY_LOSS=1` in localstack's environment to re-provision
anyway when you know the clusters are empty.

### The environment is generated, never committed

`.env.stack` is produced by `apps/stack` and matched by `.gitignore`'s
`.env.*`. Regenerating mints new KMS master keys and blind-index keys, which
orphans every ciphertext already in the volumes — so the generator refuses to
overwrite without `--force`, and the message tells you to `stack:reset`.

For a **second addressing** of a stack that is already running, derive rather
than generate:

```bash
node apps/stack/dist/generate-env-cli.js --addressing host --from .env.stack
```

`--from` carries every secret over verbatim and re-addresses only what
addressing decides (the set is computed by generating twice and diffing, not
hand-listed). Generating the second file independently would hand the host-mode
processes a different KMS master key and a different search-index key than the
composed stack wrote under — the same orphaning hazard, arrived at from the
other direction.

The doctor takes `--for compose|host` and refuses a file whose
`STACK_ADDRESSING` does not match the consumer about to read it, mirroring
`run-services-cli`'s long-standing refusal of the opposite direction.

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
credentials must not look real. It **parses** the endpoint rather than matching a
prefix — `https://localhost:anything@kms.us-east-1.amazonaws.com/` starts with
`https://localhost:` while addressing a host on the internet, and this check is
the thing standing between a misconfigured stack and real AWS calls.

**Residual (production, not the stack).** The SDK resolves the per-service
overrides `AWS_ENDPOINT_URL_KMS` / `_S3` / `_TEXTRACT`, and `endpoint_url` in an
AWS config file, *before* `AWS_ENDPOINT_URL`. Each service's
https-in-production guard only reads the plain name, so one of those set in a
production environment would send KMS traffic somewhere unvalidated. The stack's
preflight refuses any `AWS_ENDPOINT_URL_*` variable outright; production has no
equivalent check and closes this with the deployment's own configuration
management, not with code in this repo.

### Health probes are TCP, not HTTP

The runtime images are distroless — no shell, no curl — and every route in
every service is guarded, so an HTTP probe would have to be a new
*unauthenticated* route on ten hardened services to return anything but 401.
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
`--profile plaid` to skip the one opt-in service. (The assistant is stubbed
too, but sits in the default `services` profile — it comes up, goes down and is
reset with everything else, so no `stack:*` script needs another flag.)
