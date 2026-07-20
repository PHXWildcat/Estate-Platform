# @estate/service-identity

Identity & Access service (Milestone 1 walking skeleton). Owns the `auth`
cluster; nothing else touches credentials (docs/01 §2.1).

## Endpoints

| Method | Path                    | Auth                    | Purpose                                                              |
| ------ | ----------------------- | ----------------------- | -------------------------------------------------------------------- |
| POST   | `/v1/auth/register`     | —                       | `{email, password}` → generic `201 {status:'ok'}` (no enumeration)   |
| POST   | `/v1/auth/login`        | —                       | `{email, password}` → `{accessToken, refreshToken, sessionId, userId}`; any failure is `401 {error:'invalid_credentials'}` |
| POST   | `/v1/auth/refresh`      | —                       | `{refreshToken}` → rotated token pair; replaying a rotated-away token revokes the session (`rotation_reuse_detected`) |
| POST   | `/v1/auth/totp/enroll`  | Bearer                  | → `{methodId, otpauthUri}` (URI labeled with user id, never email)   |
| POST   | `/v1/auth/totp/verify`  | Bearer                  | `{code}` → confirms enrollment                                       |
| POST   | `/v1/auth/stepup`       | Bearer                  | `{code}` → elevates session to `mfa_level='stepup'` for ≤5 minutes   |
| POST   | `/v1/auth/export-demo`  | Bearer + fresh step-up  | `204` — proves the step-up window end to end                         |

Access tokens are opaque 32-byte tokens sent as `Authorization: Bearer …`;
only SHA-256 hashes are stored. Argon2id (m=64MiB, t=3, p=4) for passwords.

## Environment

| Var                   | Required          | Notes                                                                  |
| --------------------- | ----------------- | ---------------------------------------------------------------------- |
| `DATABASE_URL`        | yes               | auth-cluster Postgres                                                  |
| `KMS_MASTER_KEY_HEX`  | yes (64 hex chars)| LocalKmsProvider master key — **dev/test only**, see TODOs             |
| `EMAIL_INDEX_KEY_HEX` | yes (64 hex chars)| HMAC key for the email blind index                                     |
| `KAFKA_BROKERS`       | prod: yes         | comma-separated; absent in dev/test ⇒ in-memory no-op audit producer. Production without it fails fast at startup. |
| `PORT`                | no (3001)         |                                                                        |
| `NODE_ENV`            | no                | `production` enables the fail-fast guards                              |

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
  future WebAuthn ceremonies.
- Plain lookup indexes on session token hashes and `deks(user_id)`.

## TODOs (deliberate M1 cuts)

- **AWS KMS adapter**: replace `LocalKmsProvider` (CloudHSM-rooted KEKs,
  IAM-scoped grants) before any real deployment; add a production fail-fast
  guard mirroring the Kafka one.
- **WebAuthn/passkeys**: skipped entirely in M1 (schema is in place; no
  half-implemented endpoints). `@simplewebauthn/server` is already a
  dependency.
- **Cedar PDP/PEP** integration for authorization decisions.
- **Adaptive risk engine** (device fingerprints, IP intel, velocity) feeding
  `sessions.risk_score` / step-up requirements.
- Argon2 server-side pepper stored in KMS (docs/01 §4).
- Rate limiting / lockout counters (edge WAF + Redis counters per docs/01).
