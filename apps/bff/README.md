# @estate/bff

GraphQL BFF (Milestone 1, auth slice). The **only** GraphQL surface in the
platform (docs/01 §7): the web app talks GraphQL to the BFF; the BFF talks
REST to internal services (currently only `@estate/service-identity`).

## Endpoint

Single endpoint: `POST /graphql`. No GET, no GraphiQL, no landing page.
Every request must carry the header `x-estate-csrf: 1`; anything else is
rejected with a generic `403 {"error":"forbidden"}` before GraphQL executes.

## Schema (auth slice)

```graphql
type Query {
  session: Session # null when unauthenticated
}

type Mutation {
  register(email: String!, password: String!): Ok!
  login(email: String!, password: String!): Ok! # sets cookies; no tokens in body
  refresh: Ok! # rotates via the refresh cookie
  totpEnroll: TotpEnroll!
  totpVerify(code: String!): Ok!
  stepUp(code: String!): Ok!
  exportDemo: Ok! # step-up-gated demo action
}

type Session {
  userId: ID!
  mfaLevel: MfaLevel! # NONE | MFA | STEPUP
  stepUpFresh: Boolean! # step-up window (≤5 min) still open
}
type Ok {
  ok: Boolean!
}
type TotpEnroll {
  otpauthUri: String!
}
```

Errors carry a stable `extensions.code`: `UNAUTHENTICATED`, `STEPUP_REQUIRED`,
`INVALID_REQUEST`, `INVALID_CREDENTIALS`. Everything else is masked to a
generic message — raw identity responses, stack traces, and internal details
never reach clients.

## Cookie + CSRF model

The browser never sees tokens. On `login`/`refresh` the BFF calls identity and
stores the opaque access/refresh tokens in two cookies:

| Cookie           | Contents                       | Attributes                                            |
| ---------------- | ------------------------------ | ----------------------------------------------------- |
| `estate_access`  | identity opaque access token   | `HttpOnly; SameSite=Strict; Path=/` (+`Secure` in prod) |
| `estate_refresh` | identity opaque refresh token  | `HttpOnly; SameSite=Strict; Path=/` (+`Secure` in prod) |

Cookies are session cookies (no `Max-Age`) — token lifetime is enforced
server-side by identity. Authenticated resolvers read `estate_access` and
forward it to identity as `Authorization: Bearer …`; `refresh` reads
`estate_refresh`. Cookie values are never logged or echoed.

CSRF defense in depth: `SameSite=Strict` is the primary control; the mandatory
`x-estate-csrf: 1` custom header (unsettable cross-site without a CORS
preflight, which the BFF does not answer) covers legacy/edge cases.

## Persisted operations

Manifest: a JSON object mapping the **lowercase hex sha256 of the GraphQL
document** to the document string, produced by the client build:

```json
{
  "8c4f0a…64 hex chars…": "query Session { session { userId mfaLevel stepUpFresh } }"
}
```

Clients send the standard APQ shape — `extensions.persistedQuery.sha256Hash`
(plus `variables`) — with no `query` field.

Enforcement toggles on `NODE_ENV`:

- `production` — **only** manifest hashes execute. Arbitrary documents and
  unknown hashes get the generic error `Operation not allowed`. Introspection
  (`__schema`/`__type`) is additionally blocked by a validation rule.
  `PERSISTED_MANIFEST_PATH` is required (startup fails without it).
- anything else — arbitrary operations are also allowed (local dev tooling);
  manifest hashes still work if a manifest is configured.

## Environment

| Var                       | Required     | Default                 | Notes                                             |
| ------------------------- | ------------ | ----------------------- | ------------------------------------------------- |
| `PORT`                    | no           | `4000`                  |                                                   |
| `IDENTITY_URL`            | no           | `http://localhost:3001` | identity service base URL (internal network)      |
| `NODE_ENV`                | no           | `development`           | `production` ⇒ Secure cookies, persisted-only     |
| `PERSISTED_MANIFEST_PATH` | prod only    | —                       | path to the persisted-operations manifest JSON    |

Config validation errors name the offending variable, never its value.

## Run

```sh
pnpm --filter @estate/bff build
node apps/bff/dist/main.js
```

Tests: `pnpm --filter @estate/bff test` (no network/DB — fake identity client,
supertest against the composed express app).

## TODOs (deliberate M1 cuts)

- **Depth/complexity limits**: persisted-ops-only in production bounds the
  executable surface for M1; add explicit depth/complexity/token limits before
  arbitrary-operation surfaces (e.g. partner API) exist.
- **Rate limiting** at the gateway/WAF in front of the BFF (docs/01), plus
  Redis counters for login/refresh attempts.
- **Logout + session revocation**: needs a revocation endpoint in the identity
  service; the BFF then clears both cookies and revokes server-side.
- **Manifest deploy wiring**: generate the persisted-operations manifest in the
  web app's CI build and ship it to the BFF (config map / baked into the
  image); currently the manifest is hand-provided.
- **OIDC/JWT**: identity's opaque access tokens are an M1 bridge; when identity
  moves to JWT the BFF verifies locally instead of calling `/v1/auth/session`.
