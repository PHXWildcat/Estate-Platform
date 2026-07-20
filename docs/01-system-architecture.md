# Estate Planning Platform — System Architecture

**Version:** 1.0 · **Status:** Foundation design for review
**Scope:** Production architecture targeting 10M users, 100K concurrent, 99.99% availability, sub-250ms p95 API latency for common reads.

---

## 1. Architectural Overview

The platform is a domain-decomposed, event-driven system deployed on AWS. It is not a single monolith and not a hundred nanoservices — it is **11 bounded-context services**, each owning its own data store, communicating asynchronously over Kafka for state propagation and synchronously over gRPC/REST only where request/response semantics are required.

The single most consequential decision in this architecture is the **trust partition**: the system is split into three trust zones with different threat assumptions, and data never flows from a higher-trust zone to a lower one without an explicit, audited policy decision.

| Zone | Contents | Server can read plaintext? |
|---|---|---|
| **Zone A — Zero-Knowledge** | Password vault, seed phrases, private keys, user-designated "sealed" documents | **No.** Client-side encrypted. Keys derived on-device from Secret Key + password (1Password-style 2SKD). |
| **Zone B — Server-Encrypted PII** | SSNs, DOBs, financial account data, estate documents, contacts | Yes, transiently, under envelope encryption with per-user DEKs in KMS/HSM. Decryption is a logged, policy-gated event. |
| **Zone C — Operational** | Audit logs, notifications metadata, feature flags, non-sensitive settings | Yes. Still encrypted at rest, but standard operational access. |

Rationale: "encrypt everything" is table stakes; the real design question is *who holds the keys*. Zone A guarantees that a full server-side compromise (including insiders and subpoenaed infrastructure) cannot yield vault contents. Zone B accepts server-side decryption because the product must *compute* on this data (document generation, net-worth math, AI assistance) — so the mitigation there is per-user keys, decryption-as-audited-event, and aggressive access policy, not zero knowledge.

## 2. Service Decomposition

```
                          ┌────────────────────────────────────────────┐
  Route53 → CloudFront →  │ WAF + Shield Advanced + Bot Control        │
                          └──────────────┬─────────────────────────────┘
                                         │
                              ┌──────────▼──────────┐
                              │  API Gateway (edge)  │  authN token check, rate limits,
                              │  + GraphQL BFF       │  request signing, schema validation
                              └──────────┬──────────┘
                 ────────────────────────┼──────────────────────── private subnets
                                         │ mTLS service mesh (Istio/App Mesh)
   ┌───────────┬───────────┬─────────────┼───────────┬────────────┬───────────┐
   ▼           ▼           ▼             ▼           ▼            ▼           ▼
 Identity   Profile &   Asset &      Document     Vault        Settlement  AI
 & Access   Contacts    Accounts     Service      Service      Service     Assistant
   │           │           │             │           │            │           │
   └───────────┴───────────┴──────┬──────┴───────────┴────────────┴───────────┘
                                  ▼
                        Kafka (MSK) — domain events
                                  │
              ┌───────────────────┼──────────────────────┐
              ▼                   ▼                      ▼
        Audit Service      Search Indexer         Notification Service
        (append-only)      (OpenSearch)           (email/SMS/push)
```

### Service catalog

1. **Identity & Access (IAM service).** Registration, WebAuthn/passkeys, TOTP, hardware keys, session management, device fingerprints, adaptive-auth risk engine, RBAC/ABAC policy decision point (Cedar). Owns the `auth` database. Nothing else touches credentials.
2. **Profile & Contacts.** User profile PII, estate contacts (trustees, executors, beneficiaries, professionals), relationship graph, granular per-contact permission grants. Field-level encrypted.
3. **Asset & Accounts.** Plaid integration (link, sync, webhooks), manual asset repository, valuations, ownership %, cost basis, beneficiary designations per asset. CQRS: write model is an event-sourced asset ledger; read model is a projected net-worth/dashboard view. Rationale: asset history *is* the product in estate contexts ("what did the estate hold on date of death?"), so an append-only ledger with temporal queries is a functional requirement, not architectural vanity.
4. **Document Service.** Template engine for state-specific instruments (50-state template matrix maintained under attorney review, versioned like code with legal sign-off gates), generation pipeline, execution-status tracking (signed/witnessed/notarized), OCR ingestion for uploads, version history.
5. **Vault Service (Zone A).** Stores only opaque ciphertext blobs and encrypted item metadata. Implements SRP-style authentication so the vault password never transits to the server. Emergency access via time-delayed key escrow: the recovery key is split (Shamir) between user-designated contacts and a platform share that releases only after a configurable waiting period + notification storm to the owner.
6. **Document Vault (Zone B storage).** S3 with per-object DEKs (envelope encryption), content-addressable versioning, legal hold flags, malware scanning on ingest, OCR + encrypted search index.
7. **Settlement Service.** Death-verification intake (LexisNexis/Evadata/obituary + certified death certificate upload verified by human review — *not* a claimed direct SSA DMF feed; DMF access is restricted and typically brokered through certified resellers), state-machine workflow (Temporal) with mandatory waiting periods, multi-party approval, account lock, executor dashboard, task/distribution tracking.
8. **AI Assistant.** Retrieval-augmented assistant over the user's own estate data. Runs behind a **privacy proxy**: PII tokenization before any model call, per-feature user consent flags, no training on user data, model calls confined to providers under zero-data-retention agreements. Outputs are education/analysis only and are watermarked in-product as non-legal-advice; anything document-affecting routes through the Document Service's review gates.
9. **Referral Service.** Professional directory, licensing verification (state bar / CPA license checks via provider APIs), geo matching, sponsored-listing disclosure flags, lead tracking.
10. **Notification Service.** Multi-channel (SES, SNS/Twilio, push, in-app), per-event-type user preferences, encrypted message center for sensitive content (email/SMS carry only "you have a message" pointers, never estate content).
11. **Audit Service.** Consumes every domain event plus explicit audit events; writes to an append-only store (Postgres partitioned tables + S3 Object Lock in compliance mode for WORM guarantees). Hash-chained records for tamper evidence.

## 3. Infrastructure

**AWS Organization, multi-account:**

- `security` — GuardDuty, Security Hub, IAM Identity Center, CloudHSM, break-glass roles
- `log-archive` — Immutable CloudTrail + audit-log replicas (Object Lock, no delete permissions for anyone)
- `prod`, `staging`, `dev` — Workload accounts; prod has no human write access (change via CI/CD only)
- `sandbox` — Plaid sandbox, template experimentation

**Runtime:** EKS across 3 AZs; Bottlerocket nodes; namespaces per service with default-deny NetworkPolicies; Istio mTLS (SPIFFE identities); IRSA for pod-level AWS permissions; no long-lived credentials anywhere. Containers distroless, non-root, read-only filesystems; images signed (cosign) and admission-controlled (Kyverno: signed-images-only, no-privileged, pinned digests).

**Data plane:** Aurora PostgreSQL — **six separate clusters** (auth, financial, documents, vault, audit, analytics) per the isolation requirement; IAM database auth; no public endpoints; access only through RDS Proxy from service subnets. ElastiCache Redis (sessions cache, rate-limit counters — never a source of truth). MSK with mTLS + per-service ACLs. OpenSearch in VPC, index-level encryption, search over tokenized/derived fields only (never raw SSN-class data).

**Edge:** CloudFront → WAF (managed rules + custom: geo anomaly, credential-stuffing rate rules, request-body inspection) → Shield Advanced with SRT engagement → API Gateway. TLS 1.3 only, HSTS preload, certificate pinning in mobile apps.

**IaC:** Terraform (remote state in dedicated account, state encryption, plan/apply via CI with mandatory review; drift detection nightly). Kubernetes manifests via Helm + ArgoCD (GitOps; cluster pulls, humans never push).

**Multi-region:** Active in us-east-1, warm standby in us-west-2. Aurora Global Database (RPO < 1s), S3 CRR, KMS multi-region keys with independent HSM-backed root in each region. RTO target 15 minutes, quarterly failover game days. Backups: continuous PITR + daily snapshots vaulted to an isolated account (AWS Backup Vault Lock) — this is the ransomware recovery path; restores tested monthly by automation that stands up a clone and runs data-integrity checks.

## 4. Cryptography

- **At rest:** AES-256-GCM everywhere. Envelope encryption: per-user (and per-object for documents) DEKs wrapped by domain KEKs in KMS, roots in CloudHSM. Automatic KEK rotation (annual, re-wrap only), DEK rotation on sensitive-field rewrite.
- **Field-level:** SSN, DOB, addresses, phone, email, account numbers, asset values stored as AEAD ciphertext with key-version tags; blind indexes (HMAC-SHA-256 with a dedicated index key) support equality lookup without decryption.
- **In transit:** TLS 1.3 external, mTLS internal, Kafka payloads additionally application-layer encrypted for Zone B topics (defense against misconfigured consumer ACLs).
- **Passwords:** Argon2id (m=64MiB, t=3, p=4 — tune to ~250ms on auth-service hardware), per-user salt + server-side pepper stored in KMS.
- **Vault (Zone A):** Client-side XChaCha20-Poly1305 or AES-256-GCM; key = HKDF(2SKD(password, secret-key)); SRP for auth. Server compromise yields ciphertext only.
- **Secrets management:** AWS Secrets Manager + Vault for dynamic DB credentials (per-service, 1-hour TTL). CI enforces secret scanning (gitleaks) — a leaked secret fails the build and auto-rotates.

## 5. Authentication & Authorization

**AuthN ladder:** Passkeys are the default and the marketing push; TOTP and hardware keys supported; SMS OTP allowed only as a recovery factor with risk-score gating (SIM-swap is a primary ATO vector for this user base). Adaptive engine scores every auth and sensitive action on device fingerprint, IP intelligence, impossible travel, velocity, and session behavior; scores map to step-up requirements. **Step-up MFA (fresh, ≤5 min) is mandatory for:** vault open, document generation, data export, trustee/executor changes, beneficiary changes, deletion requests, emergency-access configuration.

**AuthZ:** Cedar policy engine as a central PDP with per-service PEPs. RBAC supplies the role vocabulary (Owner, Trustee, Executor, Attorney, CPA, Advisor, Beneficiary, Family, Viewer); ABAC supplies the conditions that matter in estate planning — grants are scoped by *resource* (this trust, this account, this document), *time* (effective only after verified death; expiring guest access), *state* (settlement phase), and *attribute* (beneficiaries see only assets naming them, and only fields the owner exposed). Every permission grant is itself a versioned, audited object. Deny by default; no implicit inheritance across resources.

## 6. Observability & Detection

OpenTelemetry as the single instrumentation layer → Datadog (APM, logs, RUM) with Prometheus/Grafana for platform metrics and Sentry for frontend errors. Logs are PII-scrubbed at the collector (deny-list + ML redaction); raw PII never enters the logging pipeline — audit events reference entity IDs, not values.

Detection: GuardDuty + Security Hub + Falco (runtime) feeding a SIEM; detections-as-code with rules for the platform's specific nightmares — anomalous decryption volume per operator, audit-log gaps, settlement-trigger anomalies, vault-access bursts, cross-tenant query patterns. Every rule maps to a runbook and a paging policy.

## 7. Key Tradeoffs Made Explicit

- **Zero-knowledge only for Zone A.** Full zero knowledge would prohibit document generation, Plaid math, and the AI assistant — the product's core. Compensating controls: per-user keys, decrypt-as-event, insider-threat detection, and the option for users to "seal" any document into Zone A at the cost of server-side features on it.
- **Event sourcing only where history is a feature** (assets, audit, settlement). Profile/contacts use conventional tables + version history; full-system event sourcing would tax every team for benefit only three domains need.
- **Temporal for settlement workflows** rather than hand-rolled state machines: settlement runs for months, spans human approvals and waiting periods, and must survive deploys — exactly the durable-execution problem class.
- **Six databases raise operational cost** (migrations, cross-domain reporting) in exchange for blast-radius isolation and per-domain compliance scoping; cross-domain reads happen via events into the analytics store, never via cross-database joins.
- **GraphQL at the BFF only, REST/gRPC internally.** Persisted queries only in production (arbitrary client queries are an attack and cost surface); depth/complexity limits enforced at the gateway.
