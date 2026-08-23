# @estate/service-vault

The Zone A password vault (docs/01 §2.5). It stores SRP verifiers and opaque
client-encrypted blobs, and it can read none of it.

Every other service in this repo decrypts under policy. This one has no policy
that would let it: there is no KMS grant, no DEK table, no `FieldCrypto`, and no
key material of any kind in its config. A full dump of the vault cluster —
by an attacker, an insider, or a subpoena — yields verifiers, salts, and
ciphertext.

## Where the crypto lives

All of it is in `@estate/vault-crypto` and runs on the user's device. This
service imports that package for the *server* half of SRP and for the
keyset-proof check. That direction is allowed; the client package imports
nothing (docs/04 boundary rule 3).

## The unlock flow

```
POST /v1/vault/srp/start    step-up   -> { handshakeId, srpSalt, kdfParams, serverPublic }
                                         client derives its keys and proof locally
POST /v1/vault/srp/verify   step-up   -> { serverProof, wrappedMasterKey, vaultSession }
```

The vault password never appears in a request body, a log, or a database column.
The wrapped master key is released only after the client's SRP proof verifies —
and even then it is wrapped by a key derived from the password and the Secret
Key, so the response is useless to anyone who intercepted it.

Two details that are load-bearing rather than incidental:

- **A handshake is consumed by the attempt, not by success.** Rate limiting is
  still a follow-up (below), so burning the challenge either way means each
  password guess costs a fresh round trip and leaves its own
  `vault.open.failed` audit event, instead of letting an attacker grind guesses
  against one challenge.
- **Every failure returns the same `srp_failed` token.** No keyset, expired
  handshake, and bad proof are indistinguishable from outside.

## Routes and gates

| Route | Gates | Notes |
| --- | --- | --- |
| `GET /v1/vault/keyset` | caller | Has this user enrolled? |
| `POST /v1/vault/keyset` | + step-up | Enroll. 409 if one exists. |
| `PUT /v1/vault/keyset` | + step-up + vault session + **SRP proof** | Password change. |
| `POST /v1/vault/srp/start` | + step-up | Challenge. |
| `POST /v1/vault/srp/verify` | + step-up | Releases the wrapped master key. |
| `POST /v1/vault/lock` | + vault session | Revoke the vault session. |
| `POST /v1/vault/reset` | + step-up | Destroys the vault (see below). |
| `GET /v1/vault/items` | + vault session | Paginated; returns whole blobs. |
| `POST /v1/vault/items` | + vault session | Client-supplied UUID. |
| `GET /v1/vault/items/:id` | + vault session | |
| `PUT /v1/vault/items/:id` | + vault session | Requires `If-Match: <revision>`. |
| `DELETE /v1/vault/items/:id` | + step-up + vault session | Soft delete. |

Step-up (docs/01 §5) covers opening a vault and touching its key material. Item
traffic rides the vault session instead, which is not a weaker gate: a vault
session exists only because someone completed SRP under a step-up-fresh account
session within the last 15 minutes.

`VaultSessionGuard` also binds the vault session to the account session that
opened it, so a stolen vault token is useless from a different login.

## Why keyset replacement needs a proof

`PUT /v1/vault/keyset` requires an HMAC over the new keyset under a key both
sides derive from the SRP session (`keyset_auth_key`). Without it, someone
holding exfiltrated bearer tokens could overwrite the keyset with a wrapping of
a fresh random master key and destroy every item irrecoverably — reading the
vault would be protected by cryptography while destroying it was protected only
by tokens. The proof makes replacement require knowledge of the *current* vault
password.

Storing a key derived from the SRP session key leaks nothing new: the server
computes that session key during SRP by construction, and an attacker with
database access could rewrite the row directly anyway. The control targets the
bearer-token attacker specifically.

## Reset destroys, it does not recover

A forgotten vault password is unrecoverable by design — nobody, including this
service, can decrypt the items. `POST /v1/vault/reset` is the escape hatch: it
soft-deletes every item and replaces the keyset so the user can start over.

The destruction is cryptographic, and it works only because the reset
transaction destroys **every** wrapping of the old master key. There are two,
and the M6 security review caught an earlier revision missing the second:

1. `vault_keysets.wrapped_master_key`, overwritten by the keyset replace (the
   version trigger deliberately never kept a copy), and
2. `emergency_access_configs.wrapped_master_key_recovery` — a second live
   wrapping under the recovery key, whose halves are held by the server and the
   grantees. Leaving it behind meant a designated contact could still wait out
   the period, release, and reconstruct the master key the owner had been told
   was destroyed.

So reset also retires the escrow and the owner's own published grantee keypair
(its private half is wrapped under the key being destroyed). Only then are the
retained item rows permanently opaque: structure preserved, meaning destroyed —
CLAUDE.md's crypto-shredding primitive, applied to a zone with no DEKs. After a
reset the user must re-arm emergency access against the new master key.

This is necessarily gated by session + step-up rather than by proof: you cannot
prove knowledge of a password you have lost. It is therefore the one route where
stolen bearer tokens can destroy (never read) a vault. Compensating controls are
step-up freshness, the distinct `vault.reset` audit action, and owner
notification once the notification port lands.

## Emergency access (docs/03 §5.2)

The flow that lets a designated contact open the vault when the owner cannot —
without letting them do it quietly. docs/03 §5.2 names the attack precisely: a
contact invoking access while the owner is alive but simply unaware. Every
control here answers that.

**The recovery key is split twice, at two levels:**

```
RK  =  platform_part  XOR  contacts_part
                            └── Shamir M-of-N across the grantees
```

The XOR split is a one-time pad, so either half alone is
information-theoretically useless. Every grantee in the world colluding still
cannot reconstruct RK without the platform releasing its half — which is what
makes the waiting period a real constraint rather than an honour system. The
Shamir layer then decides how many contacts must cooperate among themselves;
M-of-N is fully implemented, with threshold 1 as the default.

| Route | Gates |
| --- | --- |
| `POST /v1/vault/recovery-key` | caller + step-up |
| `GET /v1/vault/recovery-key/:granteeUserId` | caller |
| `GET,POST /v1/vault/emergency-access` | caller (+ step-up to configure) |
| `GET /v1/vault/emergency-access/granted-to-me` | caller |
| `POST /v1/vault/emergency-access/:id/request` | caller (grantee) |
| **`POST /v1/vault/emergency-access/:id/deny`** | **caller only** |
| `POST /v1/vault/emergency-access/:id/rearm` | caller + step-up |
| `DELETE /v1/vault/emergency-access/:id` | caller + step-up |
| `POST /v1/vault/emergency-access/:id/release` | caller (grantee) |

**Denial is deliberately not step-up gated.** It has to be one tap from a push
notification, possibly on a locked phone, possibly by someone elderly and
alarmed. A step-up challenge standing between an owner and "no" would be a
control that defeats itself.

**Denial is sticky.** A denied policy refuses further requests until the owner
re-arms it, and there is no time-based cooldown that would eventually let a
denied grantee back in on its own. That is the whole point: a cooldown just
tells a patient attacker how long to wait, and waiting the owner out is the
attack.

**Release is one-shot.** Once the platform half is handed over, the escrow is
spent — the owner has to build a new one. `revoked` cannot un-ring that bell,
so on the owner's next unlock the client is expected to re-split a fresh
recovery key (and may rotate the master key, which is cheap because per-item
keys mean rewrapping keys rather than re-encrypting blobs).

**Key authenticity is the owner's job, and the API is shaped to make that
visible.** The service hands out a grantee's public key, and the owner's client
is expected to confirm its short fingerprint with the grantee over a channel
this platform does not control before sealing a share to it. Without that step a
malicious server could substitute its own key and — since it already holds
`platform_part` and the recovery-wrapped master key — read the whole escrow. The
key each share was sealed to is recorded in `grantee_public_key_sha256`, so a
later substitution is detectable rather than silent.

**Notifications are a precondition, not a nicety.** The waiting period only
protects an owner who finds out a request is pending, so in production the
emergency-access routes refuse while only the stub notifier is wired
(`503 notifications_unavailable`). This is scoped to those routes rather than
being a boot-time check: the rest of the vault must keep working. Real channels
arrive with the notifications milestone.

**What this does not defend against, stated plainly:** the platform half is held
by the server, so a server that chooses to release it early defeats the waiting
period. That is inherent to the docs/01 design — a delay enforced by a party is
only as good as that party — and the compensating controls are the audit trail
and owner notification. What the split *does* guarantee is that a database dump
alone is not enough, and a rogue contact alone is not enough either.

## Schema notes (docs/02 §5)

- `vault_keysets` is versioned like every other table, **but the captured row
  image redacts `wrapped_master_key` and `srp_verifier`**. Elsewhere keeping the
  full prior row is right; here a superseded wrapping is not history but a live
  attack asset, because the master key does not change when the password does —
  a phished retired password plus a retained old wrapping would open the current
  vault. History keeps who changed the keyset, when, and under which parameters.
- `vault_items.item_type` is deliberate plaintext metadata, so a client can
  render a list without decrypting everything. The accepted leak is per-user
  item-type counts; titles, usernames and secrets are all inside `blob_ct`.
- Blobs are capped at 68 KiB (~64 KiB of content). Size is the only property
  the server can measure, and an unbounded opaque blob is both a storage DoS
  and a slow list endpoint.
- `vault_srp_handshakes` and `vault_sessions` are operational tables, not
  business data — the `auth.sessions` precedent: no soft delete, no version
  shadow.
- `emergency_access_policies` arrives in `002_emergency_access.sql` per docs/02
  §5, with three additions: `grantee_user_id` (this service cannot dereference a
  contact — contacts live in the core cluster and there are no cross-cluster
  reads — but it must authorize the grantee, so the owner's client submits both
  ids), `grantee_public_key_sha256`, and the sticky-deny columns.
  `emergency_access_configs` is new: docs/02 keeps everything per-grantee, but
  the two-level split has owner-level material that belongs to the escrow as a
  whole. It carries the same redacted version image as `vault_keysets`, for the
  same reason — a superseded platform half plus a superseded recovery wrap would
  together reconstruct an escrow the owner has already replaced.

## Audit

Eleven actions, IDs and enums only. The PII firewall is trivially satisfied:
the server could not log a vault secret if it tried. `vault.open.failed` in
particular is safe to emit on every failure, which is what makes docs/01 §6's
vault-access-burst detection possible.

There is deliberately no domain topic — no consumer exists (the M3 rationale),
and a vault payload on the bus is risk with no current upside.

## Known gaps, deliberately

- **No rate limiting or lockout on failed SRP proofs.** Same documented
  follow-up as identity's login rate limiting (edge WAF + Redis counters per
  docs/01). Interim controls are handshake burn-on-attempt and the
  `vault.open.failed` audit stream.
- **404-before-403 on item reads**, bounded by unguessable UUIDs — the same
  accepted class as M3's Plaid oracle and M4's documents oracle.
- **Audit emits after commit** (no transactional outbox yet) — the existing M3
  follow-up.
- **Large attachments** need a streaming path; the blob cap covers small ones.

## Local development

```bash
docker compose -f docker-compose.dev.yml up -d pg-vault
DATABASE_URL=postgres://estate:estate_dev@localhost:5437/vault node dist/migrate-cli.js
```

Integration tests need `PG_TEST_URL` pointed at that cluster; without it they
self-skip, and `test/ci-guard.spec.ts` fails the run in CI if it is missing.
