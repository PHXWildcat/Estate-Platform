# @estate/service-plaid — Plaid isolating service

The TB5 isolation boundary for financial-account aggregation (docs/01 §2 #3,
docs/03 TB5, CLAUDE.md isolating-service rule): **Plaid access tokens decrypt
only inside this service.** Link/exchange, account + balance sync, verified
webhooks, and per-item revocation. No real Plaid credentials exist yet — the
default gateway is a deterministic in-process stub behind the same interface
the live REST gateway implements.

## Isolation model

- **Separate app, own future namespace.** Not a module inside the asset
  service: token-decrypt capability lives in its own process, and gets its own
  IAM role/KMS grant when EKS lands (M5).
- **Own KEK domain.** DEKs are wrapped under `plaid/kek` (never the asset
  service's `financial/kek`) and stored in this service's own `plaid_deks`
  table. The asset service's KMS grant cannot unwrap a Plaid token DEK even
  with full database access — the KMS grant, not the database, is the
  chokepoint (docs/03 TB4/TB5).
- **Two decrypt sites.** The access token is decrypted only in sync and
  revoke, as actorType `service` with purposes `plaid_sync` / `plaid_revoke` —
  each an audited `crypto.field.decrypted` event feeding the decrypt-rate
  baselines.
- **Shared financial cluster, disjoint tables.** Same bounded context as the
  asset service; this service owns `plaid_items`, `accounts`, `plaid_deks`
  and its own migrations dir. The shared `schema_migrations` table tolerates
  co-ownership (the migrator ignores rows not in its own dir; the advisory
  lock serializes runners; file names are disjoint).

## Deviations from docs/02 §3 (all additive, mirrored in the migration header)

- `plaid_items.item_id_ct` + UNIQUE `item_bidx` blind index — webhooks are
  routed by Plaid's `item_id`; equality lookup justifies a blind index per the
  docs/02 conventions. The raw item id is never stored or emitted in
  plaintext.
- `plaid_deks` table (+ `ux_plaid_deks_user_active` from day one) — see
  isolation model above.
- Soft-delete-aware lookup indexes on `plaid_items(user_id)`,
  `accounts(user_id)`, `accounts(plaid_item_id)`.

## Security posture

- **Webhook verification** (`webhook-verifier.ts`): full `Plaid-Verification`
  JWT check on node:crypto — alg pinned to ES256 (rejects `none`/HS256
  confusion), kid resolved through the gateway (cached, rotation-safe), ES256
  signature over the exact JOSE input, iat freshness ≤5 min, and a
  constant-time compare of `request_body_sha256` against the raw request
  bytes (`rawBody: true`). Failures are audited (`plaid.webhook.rejected`)
  and answered with a detail-free 401; verified bodies are still untrusted
  data (blind-index lookup, unknown items/codes ignored, 204 either way — no
  existence oracle).
- **Revocation** (TB5 "per-item revocable"): step-up-gated (deletion-class
  action, docs/01 §5); Plaid-side `item/remove` is attempted first but cannot
  block local revocation; item + accounts soft-delete in one transaction.
- **Anomalous-sync hook** (TB5): `SyncActivityMonitor` counts syncs per item
  in a sliding window and emits `plaid.sync.anomalous` (IDs/counts only) past
  the threshold; interface-shaped for a real metrics/SIEM detector later.
- **Config fail-fast** (`config.ts`): production requires AWS KMS, Kafka, and
  `PLAID_MODE=live` with credentials — a production deployment can never
  silently run the stub or the local KMS.
- **Events**: audit actions and the `estate.plaid.events.v1` domain topic
  carry IDs/enums/counts only — never tokens, institution names, balances, or
  masks (enforced by @estate/contracts schemas and asserted end-to-end).

## Trust-boundary deviations (M2-era, shared with profile/assets)

Caller identity via gateway-injected `x-estate-user-id`, step-up via
`x-estate-stepup-verified` — both at the documented M2 trust level; real
cross-service session verification upgrades all services at once.

## Tests

Unit suites (config matrix, gateway stub + mocked-transport live gateway,
webhook-verifier negatives, service flows, guards) run everywhere; the
integration suite (`plaid.int.spec.ts`) and the cross-service E2E
(`apps/e2e/test/plaid.e2e.spec.ts`, audit hash-chain proof) are PG-gated and
run in CI (`PG_TEST_URL`), guarded by `ci-guard.spec.ts`.
