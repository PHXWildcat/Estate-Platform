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
| `PUT /v1/vault/items/:id` | + vault session | Requires `If-Match: <blobVersion>`. |
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

The destruction is cryptographic. Replacing the keyset overwrites
`wrapped_master_key`, and the version trigger never kept a copy, so the old
master key ceases to exist anywhere and the retained item rows become
permanently opaque. Structure preserved, meaning destroyed — CLAUDE.md's
crypto-shredding primitive, applied to a zone with no DEKs.

This is necessarily gated by session + step-up rather than by proof: you cannot
prove knowledge of a password you have lost. It is therefore the one route where
stolen bearer tokens can destroy (never read) a vault. Compensating controls are
step-up freshness, the distinct `vault.reset` audit action, and owner
notification once the notification port lands.

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
- `emergency_access_policies` from docs/02 §5 is **not** created here. It ships
  with emergency access (M6 PR2) so no dormant schema sits under migration
  drift detection.

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
