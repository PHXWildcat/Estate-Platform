# AI assistant service

The AI estate assistant (docs/00 feature 6, docs/01 §2.8) and the isolating
boundary for model providers (docs/03 §4 TB5). This is the first component an
attacker can address in **natural language**, through document text the owner
uploaded and asked it to read, so risk #6 ("LLM prompt injection via uploaded
docs", H/M) stops being a forecast here. The controls below are ordered the way
they actually hold: the ones an injected instruction can argue with are the last
ones, and they are not the ones the guarantee rests on.

## What PR1 ships

- **No tool schema can name a subject.** A tool is handed its authority — the
  verified session subject plus that caller's own bearer — and declares only
  what to fetch, never whose data. `assertSubjectFree` refuses a parameter whose
  identifier contains a person-word (`user`, `owner`, `subject`, `behalf`, …) at
  registry construction, so a violating tool is a process that will not start
  rather than a request that quietly reads the wrong estate. Injected text can
  persuade the model to CALL a tool; it has no field in which to say whose
  estate it wants.
- **No sink.** Seven read-only retrievals across four consent scopes. There is
  no write tool, no send tool, no outbound-fetch tool and no web search, so a
  successful injection has nowhere to send anything — the worst it achieves is a
  misleading answer to the owner about the owner's own data. Adding an
  outward-facing tool would change risk #6's impact rating and requires
  revisiting docs/03 §6d.
- **Consent, checked before the tool runs.** `permits` requires the master
  switch AND the specific scope, and the executor consults it before parsing
  arguments and before calling `execute` — a gate that runs after execution is
  not a gate, because the peer read has already happened. A denial refuses the
  retrieval, is recorded as an `assistant_tool_calls` row with no ciphertext,
  and is audited: a control that fires silently reads as an outage.
- **The subject is never in the request.** Every route takes it from
  `CallerGuard`'s introspected session; `TurnSchema.strict()` refuses a body
  carrying `userId` or `onBehalfOf` rather than stripping it, and a conversation
  id in the path only selects WHICH conversation — ownership is a `WHERE` clause
  on every query, and someone else's conversation gets the same uniform `404` as
  one that never existed.
- **One transaction per turn.** The user's message, every retrieval it triggered
  and the assistant's reply commit together or not at all: the executor is
  handed the turn's transaction and holds no pool of its own, so a retrieval
  cannot outlive a turn that rolled back. A partial transcript is an account of
  an exchange that never happened, and the transcript is the only evidence of
  what the assistant was asked and what it read.
- **The transcript is ciphertext, and it is server-held on purpose.** Message
  bodies and tool results are AEAD-sealed under the owner's DEK from
  `assistant_deks`, wrapped by the dedicated `ai-assistant/kek` — never the core
  cluster's `core/kek`, though profile, settlement and notifications share the
  database — with the AAD bound to the row id, so a tamper that moves, reorders
  or relabels a turn leaves ciphertext that no longer opens. History is stored
  rather than client-supplied because a client could otherwise forge prior tool
  results, which is a self-service injection channel no framing closes.
- **Retrieved text is framed as untrusted data**, and this layer is documented
  as the weakest one. It neutralizes delimiter injection so content cannot
  terminate its own block; a sufficiently clever payload can still argue with
  it. That is why it is third on this list and not first.
- **An egress assertion before every provider call**, not once per turn — each
  iteration carries one more tool result, and a retrieved SSN enters the payload
  at the iteration that fetched it. A trip refuses the whole turn (`422
  egress_refused`, nothing persisted) and audits the detector CATEGORY only,
  never the matched value, or the control would become its own leak.
- **A bounded loop.** Six provider round-trips per turn; exceeding the budget
  ends the turn with a platform-authored message rather than an error, because
  the user's turn and every retrieval it caused are exactly the evidence worth
  keeping when a model has been told to "keep fetching".
- **Audit that cannot carry prompt content.** No method on `EventsService`
  accepts free text — parameters are UUIDs and closed-vocabulary tokens, and a
  hallucinated tool name is replaced by the constant `unknown` before it reaches
  either the audit store or the next prompt.

## Production posture

- **This service holds NO internal service credential, in either direction.**
  There is no `provide: SERVICE_CREDENTIAL` in `app.module.ts` and no
  `*_INTERNAL_TOKEN` anywhere under `src/**`; a repo-wide fence fails the build
  if one appears, and `packages/auth-guard/src/credential-graph.ts` lists this
  service as a holder of nothing (asserted from both ends in
  `test/config.spec.ts`). Inbound, callers authenticate on their own bearer via
  `CallerGuard` and no internal route exists for a peer to open. Outbound,
  assets, documents and profile are read by FORWARDING that same caller bearer,
  so the assistant sees exactly what the calling user could already see and a
  compromised assistant replays the sessions it is currently serving rather than
  minting authority it was never handed. A static key that opens another
  service's internal routes must not sit behind the largest prompt-injection
  surface in the product.
- **`LLM_MODE=anthropic` is refused, in every environment, until PR2 wires the
  adapter.** `loadConfig` rejects it outright and `llmGatewayFor` throws on the
  same arm, so the invariant is local to the selector as well as to the config:
  a mode whose adapter does not exist must fail at deploy time, never
  per-request. PR1 runs only the deterministic offline stub, which makes no
  network call and holds no credential — and says so in its own answers, so no
  operator mistakes a stub transcript for a model's words.
- **Consent is deny by default, structurally.** There is no `granted` boolean
  and no permissive column default anywhere: consent is the PRESENCE of an
  unrevoked row, so a user who has never answered and a user who has revoked
  produce the same empty set, and code that forgets to consult `consent.ts`
  reads nothing rather than reading a default. Granting is step-up gated
  (it widens third-party egress — export-class under docs/01 §5); revoking is
  deliberately NOT, on the M6 rule that the protective action must never be
  harder than the permissive one.
- Every peer read fails CLOSED and uniformly: a network failure, a non-2xx, a
  non-JSON body and a schema mismatch all answer `null`, because a
  partially-understood response feeding a model becomes a confidently wrong
  sentence about someone's estate.

## Environment

| Var | Required | Notes |
| --- | --- | --- |
| `DATABASE_URL` | yes | core cluster (local port 5434; CI: `PG_TEST_URL`) |
| `PORT` | no | default 3009 |
| `IDENTITY_URL` | prod | session introspection for `CallerGuard`/`StepUpGuard`; dev default `http://localhost:3001` |
| `ASSETS_URL` | prod | estate-summary and beneficiary tools; dev default `http://localhost:3003` |
| `DOCUMENTS_URL` | prod | document-inventory, search and content tools; dev default `http://localhost:3005` |
| `PROFILE_URL` | prod | non-identifying profile-facts tool; dev default `http://localhost:3002` |
| `KAFKA_BROKERS` | prod | audit emission; this trail is the only record of what estate data reached a model provider |
| `LLM_MODE` | no | `stub` only — `anthropic` is refused in every environment until PR2 |
| `KMS_MODE` | no | `local` \| `aws`; production pins `aws` (`LocalKmsProvider` is dev/test only) |
| `KMS_MASTER_KEY_HEX` | no | required when `KMS_MODE=local`; 32 bytes of hex |
| `AWS_KMS_KEY_ID` | prod | required when `KMS_MODE=aws`; wraps `assistant_deks` under `ai-assistant/kek`, never `core/kek` |
| `AWS_REGION` | prod | required when `KMS_MODE=aws` |
| `AWS_ENDPOINT_URL` | no | local KMS emulator; must be `https://` in production |

No credential variable appears in this table, and its absence is the design —
see "Production posture" above.

## Local development

```
docker compose -f ../../../docker-compose.dev.yml up -d pg-core
DATABASE_URL=postgres://estate:estate_dev@localhost:5434/core node dist/migrate-cli.js
PG_TEST_URL=postgres://estate:estate_dev@localhost:5434/core pnpm test
```

The service is the FOURTH tenant of the core cluster (profile, settlement,
notifications), owning a disjoint table set and its own migrations dir with the
shared `schema_migrations` (Plaid precedent). Unlike settlement it reads NOTHING
from a co-tenant's tables: every estate fact it shows a user is fetched over
HTTP on that user's own forwarded bearer, so it holds no cross-tenant read grant
and a compromised assistant cannot widen its reach by querying the cluster.

## Deviations and deferrals (recorded in docs/04 + the decision log)

- **No embeddings and no vector store**, deliberately — docs/01 §2.8 says
  "retrieval-augmented" and this implements retrieval as READ-ONLY TOOL CALLS
  over the user's own structured records. A vector index would copy estate
  content into a second store whose access rules can drift from the source's,
  and it would need its own encryption, its own consent story and its own
  deletion path; a tool call inherits all three from the service that owns the
  data. Revisit only with a threat-model delta.
- **Uploaded-document text has no read path in M10.** M4's OCR artifact is
  sealed with no decrypt counterpart, and this milestone does not add one, so
  the assistant cannot discuss anything a user uploaded — only generated
  documents, through the audited content route. That is a capability gap, not a
  control: closing it means building a bulk-readable text path, which is what
  docs/03 §5.3 exists to prevent, and it needs its own PR, its own consent scope
  and its own delta.
- **The egress assertion is narrow on purpose.** It refuses separated SSNs and
  Luhn-valid card numbers and deliberately passes names, emails and phone
  numbers — those are PR2's tokenizer's job, and a gate that fires on ordinary
  estate traffic is one people route around.
- **The stack wiring lands in PR2**, with the live provider: the compose
  service, the generated `.env.stack` entries, the preflight doctor's view of
  this service and the stack e2e journey arrive together, because a stack entry
  for a service whose only gateway is an offline stub proves nothing that the
  unit suite does not already prove.
- Conversations are outside staged settlement access (docs/03 §6a):
  `assistant.cedar` grants no role-holder verb, and its resource attribute is
  `subject` rather than `owner` precisely so `owner.cedar` cannot silently widen
  it to every verb the product later adds.
- PR2: the live ZDR-eligible provider adapter behind `LlmGateway`, the PII
  tokenizer docs/01 §2.8 calls the privacy proxy, and the request deadline that
  bounds the transaction a turn holds open.
