# @estate/service-identity

Identity & Access service. Milestone 1 walking skeleton (registration, login,
sessions, TOTP step-up) plus Milestone 2 security hardening (WebAuthn/passkeys).
Owns the `auth` cluster; nothing else touches credentials (docs/01 §2.1).

## Endpoints

| Method | Path                    | Auth                    | Purpose                                                              |
| ------ | ----------------------- | ----------------------- | -------------------------------------------------------------------- |
| POST   | `/v1/auth/register`     | —                       | `{email, password}` → generic `201 {status:'ok'}` (no enumeration)   |
| POST   | `/v1/auth/login`        | —                       | `{email, password}` → `{accessToken, refreshToken, sessionId, userId}`; any failure is `401 {error:'invalid_credentials'}` |
| POST   | `/v1/auth/refresh`      | —                       | `{refreshToken}` → rotated token pair; replaying a rotated-away token revokes the session (`rotation_reuse_detected`) |
| POST   | `/v1/auth/totp/enroll`  | Bearer                  | → `{methodId, otpauthUri}` (URI labeled with user id, never email)   |
| POST   | `/v1/auth/totp/verify`  | Bearer                  | `{code}` → confirms enrollment                                       |
| POST   | `/v1/auth/stepup`       | Bearer                  | `{code}` → elevates session to `mfa_level='stepup'` for ≤5 minutes (TOTP) |
| POST   | `/v1/auth/webauthn/register/options`     | Bearer | → `PublicKeyCredentialCreationOptionsJSON`; mints + persists a single-use registration challenge |
| POST   | `/v1/auth/webauthn/register/verify`      | Bearer | WebAuthn attestation → `{verified:true}` or generic `400 {error:'webauthn_failed'}`; persists the passkey |
| POST   | `/v1/auth/webauthn/authenticate/options` | Bearer | → `PublicKeyCredentialRequestOptionsJSON`; `allowCredentials` scoped to the session user |
| POST   | `/v1/auth/webauthn/authenticate/verify`  | Bearer | WebAuthn assertion → elevates session to `mfa_level='stepup'` for ≤5 minutes (passkey step-up); generic `401 {error:'webauthn_failed'}` on failure |
| POST   | `/v1/auth/export-demo`  | Bearer + fresh step-up  | `204` — proves the step-up window end to end (accepts a step-up granted by TOTP **or** passkey) |

Access tokens are opaque 32-byte tokens sent as `Authorization: Bearer …`;
only SHA-256 hashes are stored. Argon2id (m=64MiB, t=3, p=4) for passwords.

### WebAuthn / passkeys (Milestone 2)

A passkey is a valid step-up factor per docs/01 §5: `authenticate/verify`
mirrors the TOTP `stepup` path exactly (same `SessionsRepo.grantStepUp`, same
`auth.stepup.granted` domain + audit event, distinguished only by
`method: 'webauthn'`).

- **Challenges** are minted by `@simplewebauthn/server`, persisted in
  `webauthn_challenges`, and consumed **single-use** (deleted on consumption,
  even if expired), so a challenge is never client-supplied or replayable.
- **Counter / clone detection**: `authenticate/verify` rejects an assertion
  whose returned counter does not advance past the stored `sign_count` (when
  the authenticator reports a non-zero counter) — two live copies of a
  credential is a clone signal (`webauthn.clone_detected`).
- **`is_hardware_key`** is set from the authenticator attachment
  (`cross-platform` ⇒ hardware roaming key; platform authenticators ⇒ false).
- Failure responses are generic (`webauthn_failed`) — no enumeration, no PII.

**Scoping decision (M2): both ceremonies are session-scoped.** `register/*`
and `authenticate/*` all require a live session (`SessionGuard`) and derive the
user from `req.auth.userId`; `authenticate/options` intentionally does **not**
accept an `{ email }` body. True passwordless **discovery login** (resident-key
first, no prior session — establishing a *new* session from a passkey alone) is
a larger feature and is **deferred to a later milestone**. The
`webauthn_challenges.user_id` column is nullable so that flow can reuse this
table unchanged.

## Environment

| Var                   | Required          | Notes                                                                  |
| --------------------- | ----------------- | ---------------------------------------------------------------------- |
| `DATABASE_URL`        | yes               | auth-cluster Postgres                                                  |
| `KMS_MASTER_KEY_HEX`  | yes (64 hex chars)| LocalKmsProvider master key — **dev/test only**, see TODOs             |
| `EMAIL_INDEX_KEY_HEX` | yes (64 hex chars)| HMAC key for the email blind index                                     |
| `KAFKA_BROKERS`       | prod: yes         | comma-separated; absent in dev/test ⇒ in-memory no-op audit producer. Production without it fails fast at startup. |
| `RP_ID`               | prod: yes         | WebAuthn Relying Party ID (registrable domain, no scheme/port, e.g. `estate.example.com`). Dev/test default: `localhost`. |
| `RP_ORIGIN`           | prod: yes         | Expected ceremony origin (scheme + host + port, e.g. `https://estate.example.com`). Dev/test default: `http://localhost:3000`. |
| `RP_NAME`             | prod: yes         | User-visible RP name shown by the authenticator. Default: `Estate Platform`. |
| `PORT`                | no (3001)         |                                                                        |
| `NODE_ENV`            | no                | `production` enables the fail-fast guards                              |

In production, `RP_ID` / `RP_ORIGIN` / `RP_NAME` **must** be set to real values
— the config fails fast at startup otherwise. A wrong RP ID/origin silently
breaks every passkey ceremony and weakens the origin binding that anchors
WebAuthn's phishing resistance, so a localhost default must never reach prod.

## Run

```sh
pnpm --filter @estate/service-identity build
DATABASE_URL=… node apps/services/identity/dist/migrate-cli.js   # migrations (never run at boot)
node apps/services/identity/dist/main.js
```

Tests: `pnpm --filter @estate/service-identity test`. The integration suite
(`test/identity.int.spec.ts`) is gated on `PG_TEST_URL` (same pattern as
`packages/db`) and skips when unset.

## Deviations from docs/02 §1 (all additive)

- `sessions.access_token_h` + `sessions.access_expires_at` — M1 uses opaque
  server-side access tokens (hashed at rest); OIDC/JWT arrives with the BFF
  milestone and retires these columns.
- `sessions.refresh_token_prev_h` — previous refresh-token hash kept for one
  rotation so replay of a rotated-away token is detectable and revokes the
  session.
- `deks` table — backs `@estate/crypto`'s `DekRepository` (wrapped per-user
  DEKs; `destroyed_at` = crypto-shredded), per the docs/02 conventions section.
- `webauthn_challenges` table — server-side single-use challenge storage for
  WebAuthn ceremonies (now used by the M2 passkey endpoints).
- Plain lookup indexes on session token hashes and `deks(user_id)`.

## TODOs (deliberate M1 cuts)

- **AWS KMS adapter**: replace `LocalKmsProvider` (CloudHSM-rooted KEKs,
  IAM-scoped grants) before any real deployment; add a production fail-fast
  guard mirroring the Kafka one.
- **WebAuthn passwordless discovery login**: M2 ships session-scoped passkey
  registration + step-up (above). Establishing a brand-new session from a
  resident-key passkey alone (no prior password session) is deferred; the
  schema already supports it (`webauthn_challenges.user_id` nullable).
- **WebAuthn registration audit → Kafka**: `webauthn.registered` is written to
  the append-only local `auth_events` ledger, but there is **no matching
  `AuditAction` enum value in `@estate/contracts`** yet (the enum grows one
  value at a time in review, and `packages/*` was out of scope for this
  change). Follow-up: add `auth.webauthn.registered` (and optionally
  `auth.webauthn.clone_detected`) to `AUDIT_ACTIONS`, then emit it via
  `EventsService` alongside the ledger insert. Passkey **step-up** already
  flows to Kafka via the existing `auth.stepup.granted` action
  (`detail.method='webauthn'`).
- **WebAuthn ceremony E2E**: the attestation/assertion ceremony is unit-tested
  with a mocked `@simplewebauthn/server` (`test/webauthn.service.spec.ts`) and
  the persistence half is integration-tested against real Postgres
  (`test/webauthn.int.spec.ts`, PG_TEST_URL-gated). A full end-to-end ceremony
  through the HTTP endpoints needs a virtual authenticator (e.g.
  `@simplewebauthn/server` test utilities or a headless WebAuthn CDP session) —
  deferred.
- **Cedar PDP/PEP** integration for authorization decisions.
- **Adaptive risk engine** (device fingerprints, IP intel, velocity) feeding
  `sessions.risk_score` / step-up requirements.
- Argon2 server-side pepper stored in KMS (docs/01 §4).
- Rate limiting / lockout counters (edge WAF + Redis counters per docs/01).
