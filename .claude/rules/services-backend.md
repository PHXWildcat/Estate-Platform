---
paths:
  - "apps/services/**"
  - "apps/bff/**"
  - "packages/auth-guard/**"
  - "packages/contracts/**"
description: Cross-service rules — credentials, guards, audit, authz, error tokens
---

# Backend services

## Service-to-service trust
- The trust graph is DATA: `packages/auth-guard/src/credential-graph.ts`. Prose was
  wrong for two PR reviews once; a table fails the build instead.
- **ONE SECRET PER EDGE, PER DIRECTION**, with distinct guards per callee. Each var is
  named for the service whose routes it OPENS (`IDENTITY_INTERNAL_TOKEN`, …). Configs
  REFUSE TO BOOT in production when two credentials a service holds are equal.
- `holders` is minimal. A service that never asks a question must not hold the key to it.
- A credential edge with ZERO holders is deliberately **not provisioned**. Minting a
  secret nobody can present is the aspirational grant the graph exists to forbid.
- Services holding no credential at all (`ai-assistant`, the vault/operator edges)
  assert the granted set is BOTH equal to what they absorb AND explicitly `[]` —
  without the second assertion the test passes vacuously.

## Guards and audiences
- `CallerGuard.audiencesFor` returns the UNION of service-wide and per-route audiences.
  It can only WIDEN. Never bind a non-`account` audience service-wide to "then narrow it".
- Decorate per handler. Undecorated = deny by default.
- Fences anchor on what the RUNTIME reads (`provide: SERVICE_CREDENTIAL`, the metadata
  key, the config field) — never on an identifier a caller chose, which can be renamed
  into invisibility.

## Audit
- `AUDIT_ACTIONS` is a CLOSED vocabulary. A consumer that predates a new member treats
  every instance as `schema_violation` and DROPS it, silently. **Deploy the audit
  consumer before its producers.** Nothing enforces this; an expected-but-missing event
  should send you to the consumer's log before the producer's code.
- Audit details carry entity IDs, enums and stringified counts only — never plaintext PII.
- The RECORD goes first when the thing it records is a disclosure: emit before the
  decrypt loop, not after.
- Emit ordering vs. side effects: **the step that cannot be undone runs last.**

## AuthZ and error surfaces
- Cedar, deny by default. A PEP argument must be the MEASURED answer — a literal `true`
  makes the policy evaluate against a constant and deny nothing.
- Answer a **uniform 404** for "no such row" and "not yours" alike. A 403 on an id
  confirms the id names something real.
- Two failures needing different remedies must not share an error token. A control
  firing must not read as an outage.
- Fail closed means DE-ESCALATE, not "refuse everything" — never withdraw the
  protective action along with the permissive one.
- The protective action must never be harder than the permissive one (revoke ungated
  where grant is step-up gated).

## Transactions
- A pre-transaction read and the transaction it guards are separated by every commit
  that lands between them. A check that must hold AT THE WRITE is restated inside the
  statement's own `WHERE`, or under the row lock.
- Do not issue another statement on a connection after catching a unique violation
  inside a transaction — Postgres aborts the transaction and refuses everything until
  rollback. Use `ON CONFLICT … DO NOTHING` instead.

## Second factors, ceremonies and abuse bounds

- **Enrolling a factor is gated on proving an existing one** (`SecondFactorGate`), across
  BOTH TOTP and WebAuthn — a per-type predicate leaves a hole in both directions. It is
  conditional: an account with no factor cannot be gated, or a second factor becomes
  unreachable forever.
- Revoking a factor IS step-up gated (it weakens the gate protecting everything else);
  revoking a SESSION is not (it can only reduce authority).
- A bound's scope is "which routes check a secret" — **"authenticated" is not the same
  question as "does not check a secret."** A bound living as a private method on one
  service is reachable only from that class.
- A guessing bound is evaluated BEFORE the secret is scored, so its timing cannot vary
  with whether the guess was right; its own refusal kind is never in its counted set, or
  the counter feeds itself. Kind sets across bounds must be pairwise DISJOINT — one
  bound's success is otherwise another bound's amnesty.
- Rolling cooldowns, never sticky locks: a sticky lock is a denial-of-service primitive
  against the owner. Where a credential exists at the point of failure, add a per-session
  scope under the account ceiling.
- A rate refusal must not become an existence oracle — on login it returns the same
  uniform answer as a wrong password.
- Mailed/typed codes: canonical-fold on BOTH sides before hashing, measure length on the
  CANONICAL form, and answer ONE uniform refusal for unknown/expired/spent/revoked/raced.
  An attempt cap must key on something a wrong guess still resolves (the user), or it
  counts only replays of dead codes.
- An unauthenticated redeem route grants NO step-up. Redemption is authority to do one
  thing, never a credential that can mint another.

## Pointers

- **Before adding or firing a notification kind**, read `.claude/rules/notifications.md`
  — the wire deliberately has no field for text, and each edge has its own closed enum.
- **Documents/templates:** published template versions are immutable and content-pinned
  (`body_sha256`, verified on load, fail-closed). The publish CLI is the ONLY write path
  — git review IS the legal sign-off gate, so never add a runtime template-mutation API.
  Anything deciding execution formalities reads the sha256-verified template SOURCE, not
  the `templates` row.
