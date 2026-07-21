# @estate/service-profile — Profile & Contacts

The M2 product bounded context (docs/01 §2.2). Owns the **core** Postgres
cluster: user profile PII, estate contacts, the relationship graph, role
assignments, and granular permission grants. This is the first service to wire
the shared Cedar PDP (`@estate/authz`) into a real **PEP**, enforcing the
docs/03 §5.5 beneficiary-information-abuse boundary end to end.

Sibling of `@estate/service-identity` — it mirrors that service's structure,
DI wiring, config posture, envelope-encryption plumbing, and test harness.

## Security model at a glance

- **Field-level encryption (Zone B).** Every PII column is `BYTEA` AEAD
  ciphertext under a per-user DEK (envelope encryption; KEK alias `core/kek`).
  `state_of_residence` is plaintext by design (it drives document templates).
  SSN is stored full + a separate last-4 for display, and gets **no** blind
  index (docs/02 §8). Contact email carries a per-owner blind index for
  soft-delete-aware uniqueness/lookup without decryption.
- **Every decryption is audited.** Reads flow through `FieldCrypto`, which emits
  `crypto.field.decrypted` (fail-closed) before releasing plaintext.
- **Deny by default.** No endpoint returns core data without a Cedar `allow`.
- **No hard deletes.** Soft delete (`deleted_at`) + trigger-maintained
  `<table>_versions` shadow tables (INSERT-only). Legal erasure = crypto-shred
  the DEK, never row deletion.
- **PII firewall.** Audit payloads carry entity IDs + enum tokens only; errors
  are generic tokens; nothing echoes or logs submitted values.

## Trust assumption: `x-estate-user-id` (gateway-injected)

M2 does **not** yet call the identity service to verify a session. Instead the
caller's user id arrives in the `x-estate-user-id` request header, which the
**BFF / API gateway injects after verifying the session token and strips from
any inbound client request**. It is therefore gateway-injected, never
user-supplied. `CallerGuard` shape-checks it is a UUID and attaches it to the
request; a missing/malformed header is a generic `401`.

Real cross-service session verification (calling identity's
`/v1/auth/session`, or mTLS + signed identity assertions at the mesh) is a
later integration — see Follow-ups.

## Cedar PEP model

`ProfileAuthz` (`src/authz.service.ts`) wraps `PolicyDecisionPoint`
(constructed from `loadBundledPolicies()`), turning any non-`allow` into a
generic `403 { "error": "forbidden" }`.

Resources are modeled with two attributes:

- `owner` — an `User` entity ref. **owner.cedar** (bundled) permits the owner
  ANY action on a resource they own. Profile/family/contact **writes** and
  role-assignment **management** are owner-only via this policy.
- `grantees` — the set of `User`s who hold an **effective read grant** for
  _this specific_ resource. The PEP resolves effective grants from
  `permission_grants` / `role_assignments` (see below) and passes the resulting
  set on the resource; **profile.cedar** (added by this service) permits a
  `read` to any principal in `grantees`. Read-only — management stays
  owner-only. The set is always present (empty ⇒ matches no one).

Policy added to `packages/authz/policies/profile.cedar`:

```cedar
permit ( principal, action == Action::"read", resource )
when { resource has grantees && resource.grantees.contains(principal) };
```

### Effective-grant resolution (the §5.5 boundary)

A caller holds an effective read grant over an owner's contact when: they are
the platform user linked to a granted contact (`contacts.linked_user_id`), the
`role_assignment` is live, immediate, and inside its `[starts_at, ends_at)`
window, and it carries a live `permission_grant` with `resource='contact'`,
`action='read'`. The grant covers a contact when its scope names it
(`scope_id = <contactId>`) or is estate-wide (`scope_type='estate'`,
`scope_id IS NULL`). A role-holder can therefore read **only** the resources
their grant names — never enumerate the rest.

## Endpoints (REST, `/v1`, all behind `CallerGuard`)

| Method & path | Purpose | AuthZ |
| --- | --- | --- |
| `GET /v1/profile` | Read own profile (decrypted) | owner |
| `PUT /v1/profile` | Upsert own profile | owner |
| `GET /v1/profile/family` | List own family members | owner |
| `POST /v1/profile/family` | Create family member | owner |
| `PUT /v1/profile/family/:id` | Update family member | owner |
| `DELETE /v1/profile/family/:id` | Soft-delete family member | owner |
| `POST /v1/contacts` | Create own contact | owner |
| `PUT /v1/contacts/:id` | Update own contact | owner |
| `DELETE /v1/contacts/:id` | Soft-delete own contact | owner |
| `GET /v1/profiles/:ownerUserId/contacts` | **ABAC list** | owner or grant-holder |
| `GET /v1/profiles/:ownerUserId/contacts/:contactId` | **ABAC single read** | owner or named grant-holder |
| `POST /v1/role-assignments` | Grant a contact a role over a scope | owner |
| `GET /v1/role-assignments` | List own role assignments | owner |
| `POST /v1/role-assignments/:id/permissions` | Attach a permission grant | owner |
| `DELETE /v1/role-assignments/:id` | Revoke (soft-delete) a role assignment | owner |

The two `GET /v1/profiles/:ownerUserId/contacts...` routes are the ABAC
demonstrator: the owner sees all their contacts; a role-holder sees only the
contacts their effective grant names (or all under an estate-wide grant); a
caller with no grant gets a generic `403`.

All bodies are zod-validated (shape + length only); a parse failure is a
generic `400 { "error": "invalid_request" }` with field names withheld.

## Environment variables

| Var | Required | Notes |
| --- | --- | --- |
| `NODE_ENV` | no (default `development`) | `development` \| `test` \| `production` |
| `PORT` | no (default `3002`) | listen port |
| `DATABASE_URL` | yes | core cluster (local port 5434; CI: `PG_TEST_URL`) |
| `EMAIL_INDEX_KEY_HEX` | yes | 32-byte hex HMAC key for the contact email blind index |
| `KMS_MASTER_KEY_HEX` | dev/test only | 32-byte hex; drives `LocalKmsProvider` |
| `AWS_KMS_KEY_ID` + `AWS_REGION` | **production** | AWS KMS (CloudHSM-rooted `core/kek`) |
| `KAFKA_BROKERS` | **production** | audit emission must never silently no-op |

Config is zod-validated and **fails fast**: production requires Kafka + AWS KMS
(the in-process `LocalKmsProvider` is dev/test only); non-production requires
`KMS_MASTER_KEY_HEX`.

## Running

```sh
pnpm --filter @estate/service-profile build
# migrations are a deploy step, not a boot side effect:
DATABASE_URL=... node dist/migrate-cli.js
node dist/main.js
```

Integration tests are gated on `PG_TEST_URL` (CI-only; there is no local
Postgres in this environment) and run the real migrations into a scratch
schema. `test/ci-guard.spec.ts` fails CI if `PG_TEST_URL` is missing so the
suite can never silently skip.

## Deviations from docs/02 §2

- **`profiles` versions by `user_id`** (its `PRIMARY KEY`) rather than a
  surrogate `id`, because docs/02 §2 defines `profiles` with `user_id UUID
  PRIMARY KEY` and no `id`. It is verified in tests by a custom check rather
  than the generic id-based `checkConventions()` (which requires an `id uuid`).
- **`deks` table** added (backs `@estate/crypto`'s `DekRepository`), mirroring
  identity — required by the conventions section ("each row carries `dek_id`").
- Additive lookup indexes (owner/linked-user/FKs) and the per-owner
  soft-delete-aware unique index on `(owner_user_id, email_bidx)`.
- **ABAC scope stand-in:** with no asset service yet, the §5.5 boundary is
  demonstrated over `contacts` (grant `resource='contact'`, scope naming a
  specific contact id). Asset-scoped beneficiary ABAC lands with that service.

## Follow-ups

- Real cross-service **session verification** via the identity service (replace
  the trusted `x-estate-user-id` header).
- **Asset-scoped beneficiary ABAC** once the Asset & Accounts service lands
  (beneficiaries see only assets naming them — the true docs/03 §5.5 target).
- A richer **Cedar schema** with validation (typed actions/resources) and a
  core-cluster **domain-event** contract/topic (this service currently emits
  audit events only; no core event topic exists yet).
- **Step-up MFA** enforcement on sensitive mutations (beneficiary/trustee
  changes, exports) once the BFF propagates step-up context.
