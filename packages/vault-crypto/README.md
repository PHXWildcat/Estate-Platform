# @estate/vault-crypto

Zone A client-side cryptography: the code that makes the password vault
zero-knowledge. It derives keys from the vault password **and** the Secret Key,
authenticates with SRP-6a so the password never reaches the server, and seals
vault items into opaque blobs the server can store but never read.

Everything here runs on the user's device. `apps/services/vault` imports this
package for the server half of SRP and for the keyset-proof check — that
direction is allowed; this package imports nothing.

## The rules this package exists to enforce

- **Zero runtime dependencies.** Not a preference: docs/03 rates vault
  client-side compromise (TB6, risk #4) as Critical, and docs/04 boundary rule 3
  names the empty dependency tree as the control. `test/zero-dependency.spec.ts`
  fails the build if a non-relative import appears in `src/`, and an ESLint
  fence in `eslint.config.mjs` catches it while typing. Everything is built on
  WebCrypto (`crypto.subtle`), `bigint`, and `Uint8Array`.
- **Never import `@estate/crypto`.** That is the Zone B server-side envelope
  layer; it handles plaintext DEKs and KMS material and must never ship to a
  client.
- **No plaintext ever leaves this package.** Nothing here builds a request body
  that contains the password, the Secret Key, or an unwrapped key.

## Key hierarchy

```
vault password ──PBKDF2-HMAC-SHA256(650k)──┐
                                            ├─XOR─► base ─HKDF─┬─► AUK ──wraps──► master key
Secret Key (128-bit, device-only) ──HKDF───┘                   └─► SRP x ─────► verifier (server)
                                                                       master key ──wraps──► per-item keys
```

- **Secret Key** — 128 bits generated on the device, shown once, never
  transmitted. It is what makes the server-held material (verifier, wrapped
  master key) useless to an attacker who has the database and a correct password
  guess.
- **PBKDF2, not Argon2id** — an approved, recorded deviation from docs/00.
  WebCrypto has no Argon2, and a WASM Argon2 would trade this package's real
  security property (an auditable, dependency-free surface on the device) for a
  defense the Secret Key already provides. `kdfParams` is versioned so Argon2id
  can be adopted later without a migration.
- **AES-256-GCM** — permitted by docs/01 §4 alongside XChaCha20-Poly1305, and
  the only one of the two that is native in both browsers and Node.
- **Non-extractable keys** — the master key and item keys are unwrapped as
  non-extractable `CryptoKey`s (docs/03 TB6), so a script injected into the
  vault origin can use them but cannot read them out. Only the password-change
  path takes raw master-key bytes, and it wipes them.

## AAD is mandatory

Every ciphertext is bound to its context, and the domains are separated so two
same-shaped secrets can never be swapped by a server that cannot read either:

| Ciphertext | AAD |
| --- | --- |
| item content | `estate.vault.item.v1\|userId\|itemId\|blobVersion` |
| item key wrapped by master key | `estate.vault.wrap.itemkey.v1\|userId\|itemId` |
| master key wrapped by AUK | `estate.vault.wrap.master.v1\|userId` |

`blobVersion` is the anti-rollback binding: create uses 1, and an update of
version N encrypts under N+1, which the server must then store. A blob replayed
at the wrong version fails to decrypt on the client.

## SRP profile

RFC 5054 Appendix A 4096-bit group, g = 5, SHA-256. Two deliberate departures
from the RFC, both pinned by `KDF_VERSION`:

- `x` comes from 2SKD rather than `H(s | H(I ":" p))`, so the verifier inherits
  the Secret Key's entropy.
- The identity `I` is the user's UUID, never their email — the same rule
  identity applies to TOTP provisioning URIs.

**The client pins the parameters.** `kdfParams` and the group identifier arrive
from the server at unlock time, so `assertSupportedKdfParams` rejects anything
outside the single supported profile *before* any modular exponentiation. Without
that check, a malicious server could substitute a degenerate group and recover
the SRP private key by small-subgroup confinement — the exact adversary Zone A
exists to defeat.

Known residual: `bigint` arithmetic is not constant-time. This is true of every
JavaScript SRP implementation; the exposure is bounded by network jitter, and no
code path here branches early on a secret comparison.

## Testing notes

- Jest runs under `testEnvironment: 'node'`, where `globalThis.crypto` is
  present on Node >= 20. In a browser, `crypto.subtle` is available only in a
  secure context (HTTPS or localhost).
- The PBKDF2, HKDF, and HMAC derivations are checked against `node:crypto` —
  an independent (OpenSSL) implementation — rather than against hand-copied
  vectors, so a transcription slip cannot make a test agree with a bug.
- The SRP group constant is checked with Fermat tests, so a mistyped digit in
  `N` fails the build instead of silently weakening the group.
