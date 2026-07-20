# Estate Planning Platform — Product & Engineering Requirements

**Document:** 00-requirements.md · Source of truth for scope and quality bar.
Companion docs: `01-system-architecture.md`, `02-database-schema.md`, `03-threat-model.md`.

## Vision & quality bar

A production-ready, enterprise-grade estate planning platform — engineering quality
comparable to Stripe, Plaid, Wealthfront, and Apple. Not an MVP: design for a system
that will ultimately manage hundreds of billions of dollars of assets and millions of
users. The product should feel effortless while maintaining financial-institution-grade
security. Influences: Mint's dashboard, Wealthfront's portfolio UX, 1Password's
security model, Apple's UI polish, Plaid's connectivity.

## Security requirements (highest priority)

Assume the platform is a target for nation-state attacks, ransomware, insider threats,
account takeover, identity theft, supply-chain attacks, zero-days, privilege
escalation, social engineering, and AI-driven attacks.

**Principles:** Zero Trust, least privilege, defense in depth, secure by default,
privacy by design.

**Compliance targets:** SOC 2 Type II, ISO 27001, NIST CSF, NIST 800-53, OWASP Top 10,
CIS Benchmarks, GDPR, CCPA, HIPAA (medical POA data), PCI DSS (if payments exist).

**Encryption:**
- At rest: AES-256-GCM everywhere; HSM/KMS-managed keys, automatic rotation,
  envelope encryption.
- Field-level encryption required for: SSNs, birthdates, addresses, emails, phone
  numbers, asset values, documents, and all password-vault content.
- Passwords: Argon2id. Secrets: never in source; Secrets Manager / Vault.
- Password vault: zero-knowledge architecture.

**Authentication:** MFA, passkeys (WebAuthn/FIDO2), hardware security keys,
biometrics, TOTP. Step-up MFA required for login, vault access, document generation,
data export, adding trustees, and deletion. Adaptive authentication: device
fingerprinting, risk scoring, session anomaly detection, impossible-travel detection.

**Authorization:** RBAC + ABAC with extremely granular permissions. Roles: Owner,
Trustee, Executor, Attorney, CPA, Financial Advisor, Beneficiary, Family Member,
Read-only Viewer.

## Infrastructure

Cloud-native on AWS: Kubernetes, Docker, Terraform, CloudFront, WAF, Shield Advanced,
API Gateway, load balancers, private subnets. No public databases; everything behind
private networking.

## Stack

- **Backend:** TypeScript, NestJS, PostgreSQL, Redis, Kafka, search engine
  (OpenSearch/Elastic), GraphQL + REST, background workers, event-driven
  architecture, CQRS, event sourcing where appropriate.
- **Frontend:** React, Next.js, TypeScript, Tailwind, Framer Motion, WCAG AA+,
  responsive, dark mode, Mint-inspired dashboard.
- **Databases:** PostgreSQL, physically separated: authentication, financial data,
  documents, audit logs, password vault, analytics. Every change versioned; soft
  delete only; immutable audit logs.

## Logging & monitoring

Every action generates audit logs (login/logout, document viewed/generated,
beneficiary modified, password viewed, asset modified, trust changed, admin access)
with timestamp, IP, browser, device, geo, user, session. Monitoring: Datadog,
CloudWatch, Prometheus, Grafana, Sentry, OpenTelemetry; real-time anomaly detection.

## Core modules

1. **User profile** — name, DOB, SSN, address, email, phone, occupation, marital
   status, children, parents, emergency contacts.
2. **Estate contacts** — trustees, executors, beneficiaries, guardians, agents,
   attorneys, CPAs, advisors, doctors; each with contact info, relationship, role,
   permissions, notes.
3. **Financial account aggregation** — Plaid integration; auto-import checking,
   savings, brokerage, retirement, loans, credit cards, mortgages, investments;
   continuous sync.
4. **Manual asset repository** — cash, precious metals, jewelry, art, collectibles,
   businesses/LLCs, private equity, crypto, real estate, vehicles, aircraft, boats,
   IP, life/LTC insurance, annuities, safe deposit boxes, digital assets. Each asset
   supports photos, documents, appraisals, ownership %, cost basis, beneficiaries,
   notes, location.
5. **Estate documents** — generate wills, revocable/irrevocable trusts, pour-over
   wills, durable/financial/medical/mental-health POAs, living wills, HIPAA
   authorizations, guardian designations, certification of trust, property
   assignments, funding letters, beneficiary letters. State-specific; all 50 states;
   attorney-reviewed templates.
6. **AI estate assistant** — education, asset discovery, document explanation,
   funding recommendations, missing-document and beneficiary-conflict detection,
   estate tax estimation. Must preserve privacy (minimum necessary data to model
   providers) with clear user controls.
7. **Password manager** — enterprise vault for passwords, PINs, recovery codes, seed
   phrases, private keys, documents, licenses. Autofill, generator, emergency
   access, family sharing, encrypted attachments. Zero-knowledge.
8. **Secure document vault** — encrypted storage for legal, tax, identity, insurance,
   property, military, and medical documents. PDF OCR, search, version history.
9. **Estate settlement workflow** — verified death notification via legally available
   sources or authorized integrations (no assumed direct SSA access). On
   verification: lock account, preserve audit trail, notify designated parties
   (configurable), generate task checklist and estate timeline, track completion and
   distributions, store court documents, executor dashboard. Mandatory configurable
   waiting periods, legal verification, and human approval before sensitive actions.
10. **Referral marketplace** — attorneys, CPAs, real-estate agents, trust companies,
    advisors, probate specialists, moving/estate-sale/cleanout/funeral services.
    Match on geography, licensing, qualifications, preferences; disclose sponsorship.

## Cross-cutting features

- **Dashboard:** net worth, assets, liabilities, insurance, estate funding %,
  document completion %, beneficiary health, estate readiness score, security score,
  password health, outstanding tasks, notifications, timeline.
- **Search:** global across assets, documents, accounts, contacts, passwords,
  insurance, properties, beneficiaries.
- **Notifications:** email, SMS, push, in-app, encrypted messaging; configurable.
- **APIs:** secure REST + GraphQL; OAuth2, OIDC, short-lived JWTs, refresh tokens,
  rate limiting, versioning.
- **Compliance:** complete audit trail, legal hold, retention policies, right to
  delete where legally applicable, consent management.

## Testing & performance

- Coverage minimums: 95% backend, 90% frontend. E2E, security, load, chaos,
  penetration, dependency scanning, fuzzing, SAST/DAST.
- Performance: 10M users, 100K concurrent, sub-250ms common-operation latency,
  99.99% uptime, horizontal scaling, automatic failover, tested DR.

## Deliverables

1. Complete system architecture ✅ (`01-system-architecture.md`)
2. Database schema ✅ (`02-database-schema.md`)
3. API specification
4. Infrastructure-as-Code (Terraform)
5. Security architecture (partially in 01/03)
6. Threat model ✅ (`03-threat-model.md`)
7. UI/UX design system
8. Design system components
9. Frontend implementation
10. Backend implementation
11. CI/CD pipelines
12. Kubernetes manifests
13. Terraform infrastructure
14. Comprehensive documentation
15. Automated testing suite
16. Monitoring dashboards
17. Incident response runbooks
18. Backup & disaster recovery plan
19. Deployment guide
20. Operational playbooks
21. Security hardening checklist
22. Privacy impact assessment
23. Compliance mapping (SOC 2, ISO 27001, NIST, GDPR, CCPA, HIPAA where applicable)

## Engineering principles

- Correctness, security, maintainability, and privacy over feature velocity.
- Clearly distinguish fully automatable functionality from functionality requiring
  legal review or human approval.
- All external integrations use official, documented APIs or commercial data
  providers; flag where integrations (e.g., death notification) require licensed
  third parties because direct government feeds aren't available to private apps.
- Production-ready code: strong typing, documentation, automated tests, secure
  defaults.
- Every design decision records its rationale, security implications, scalability
  considerations, and operational tradeoffs.
