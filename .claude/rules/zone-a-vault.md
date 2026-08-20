---
paths:
  - "packages/vault-crypto/**"
  - "apps/services/vault/**"
  - "apps/vault-web/**"
  - "apps/vault-extension/**"
description: Zone A (zero-knowledge vault) rules — crypto, isolated origin, extension
---

# Zone A — vault, vault origin, extension

Zone A's adversary includes a **malicious server**. Nothing derived from the vault
password or Secret Key may leave the device.

## Crypto
- `packages/vault-crypto` has **ZERO runtime dependencies**, enforced by an ESLint
  `no-restricted-syntax` fence plus a source-scanning spec. Never add one.
  (`no-restricted-imports` does NOT work here: its gitignore-style `*` never crosses
  a `/`, so deep specifiers slip through.)
- Importers are declared data in `packages/vault-crypto/test/declared-importers.spec.ts`.
  A new importer arrives in that table or the build goes red.
- Key derivation is PBKDF2-HMAC-SHA256 (650k) + a 128-bit device Secret Key (2SKD) —
  an approved deviation from docs/00's Argon2id, because WebCrypto has no Argon2 and a
  WASM one would add a dependency tree to the highest-audit-surface code. `kdfParams`
  is versioned so Argon2id is a later drop-in. **Account** passwords keep Argon2id.
- The client PINS the parameters the server serves it (`assertSupportedKdfParams`)
  BEFORE any modpow — otherwise a malicious server substitutes a degenerate SRP group.
- Every ciphertext carries a domain-separated AAD. Item content AAD binds `blobVersion`;
  an update of version N encrypts under **N+1** while sending N in `If-Match`. Reversed,
  the row lands permanently unopenable and nothing in the response says so.
- One message for both halves of 2SKD: a wrong password and a wrong Secret Key say the
  same thing. Naming the half tells a thief which one they hold.

## The isolated origin (`apps/vault-web`)
- A different **host**, not a port: cookie scope ignores the port. `__Host-` prefixed,
  unconditional in every environment.
- Framework-free by design — hand-written DOM, no parser anywhere. That is what makes
  `script-src 'self'` with no `unsafe-inline`/`unsafe-eval` and `trusted-types 'none'`
  real rather than declared. Do not add React, a bundler, or a markdown renderer.
- `api.ts` is the ONLY module that may reach the network. No `console.*` in the client.
- The edge holds **no credential** in either direction; it forwards the caller's own
  bearer and matches an EXACT route allowlist (never a prefix — a prefix under
  `/api/auth/` reaches `/v1/auth/handoff`).

## Extension (`apps/vault-extension`)
- Keys live as non-extractable `CryptoKey`s in the **offscreen document's worker**.
  The service worker holds nothing; an offscreen teardown is a lock.
- Origin matching is the security property: registrable domain via the vendored,
  digest-pinned Public Suffix List — never a substring, never label stripping. Scheme
  binding is enforced; a confusable domain is **refused**, not warned about.
- Autofill does NOT resist phishing, and the fill's `input`/`change` events ARE the
  fill — so "nothing is auto-submitted" is not a promise this code can make. Fill the
  username field FIRST so an eager page never commits a lone password.
- The packed archive STORES every entry (no deflate): zlib differs between Node builds
  and would break reproducibility. Never reintroduce compression.
