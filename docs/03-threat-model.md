# Estate Planning Platform — Threat Model

**Version:** 1.0 · Methodology: STRIDE per trust boundary + attacker-goal analysis, mapped to NIST 800-53 control families. This document is a living artifact; every new feature PR that crosses a trust boundary requires a threat-model delta.

---

## 1. What makes this platform's threat profile unusual

Most fintech threat models optimize for "attacker steals money today." This platform has three additional properties that reshape the model:

1. **It is a treasure map.** A single account enumerates every asset a family owns, where it is, what it's worth, who inherits it, and — via the vault — the credentials to reach it. Compromise value per account is far higher than a bank login.
2. **Death is a state transition with privileges attached.** The settlement workflow deliberately transfers access to third parties upon death. Any workflow that grants access on death can be attacked by *faking death* or by *being an insider to a real death* (the grieving-family window is a social-engineering goldmine).
3. **Authorized users are potential adversaries.** Trustees, executors, caregivers, and family members hold legitimate grants and also commit a large share of real-world elder financial abuse. The threat model must treat *granted* access as a monitored surface, not a solved problem.

## 2. Adversaries

| Adversary | Capability | Primary goals |
|---|---|---|
| Nation-state / APT | 0-days, supply chain, long dwell | Bulk PII, HNW-individual targeting, persistence |
| Organized crime | Credential stuffing, SIM swap, phishing kits, ransomware | Vault contents, asset intel for fraud, extortion |
| Malicious insider (platform) | Legitimate infra/DB access | Bulk decryption, audit tampering, targeted snooping |
| Malicious insider (estate) | Legitimate role grants | Over-broad access, premature settlement, distribution fraud |
| Opportunist / abusive family member | Owner's devices, shared knowledge, coercion | Account takeover of elderly users, beneficiary manipulation |
| Curious/negligent third-party pro | Attorney/CPA portal access | Data overexposure, credential mishandling |
| Automated/AI-driven attacker | Scaled spearphishing, voice cloning of "the deceased's lawyer" | Settlement-phase social engineering |

## 3. Trust boundaries

TB1: Internet → Edge (CloudFront/WAF/API GW) · TB2: Edge → Services (authn/z) · TB3: Service ↔ Service (mesh) · TB4: Services → Data stores · TB5: Platform → Third parties (Plaid, LLM providers, death-data providers, notification carriers) · TB6: Client device (Zone A crypto happens here) · TB7: Human operators → Production · TB8: Role-holders → Owner's estate data.

## 4. STRIDE highlights per boundary (top findings, not exhaustive)

**TB1/TB2 — Edge & AuthN**
- *Spoofing:* Credential stuffing and SIM-swap-based recovery abuse. → Passkey-first, SMS never sufficient alone, breach-corpus password checks, per-IP+per-account rate limits, device binding.
- *DoS:* Shield Advanced + autoscaling + per-tenant load shedding; settlement endpoints get separate quotas so an attack can't mask fraud attempts in noise.
- *Info disclosure:* GraphQL introspection off in prod; persisted queries only; error responses genericized.

**TB4 — Data stores**
- *Tampering:* Audit chain hash-anchored to WORM storage; DB roles cannot UPDATE/DELETE event tables; nightly chain verification with paging on gap.
- *Info disclosure:* Bulk-decryption detection — per-principal decrypt-rate baselines with hard circuit breakers (a service that normally decrypts 50 fields/min gets its KMS grant suspended at 50×, paging security). This is the single most important insider control: the KMS grant, not the database, is the chokepoint.
- *Elevation:* IRSA-scoped pod identities; no shared DB users; RLS as a second net under application authz.

**TB5 — Third parties**
- *Plaid token theft:* Access tokens decryptable only inside the sync worker's isolated namespace; tokens are per-item revocable; webhook signatures verified; anomalous sync patterns alert.
- *LLM data leakage:* Privacy proxy tokenizes names/SSNs/account numbers before provider calls; zero-retention contracts; per-feature consent; prompt-injection defense for any AI feature that reads user-uploaded documents (uploaded doc content is untrusted input — the assistant must never treat document text as instructions, and tool scopes for the assistant are read-only).
- *Death-data providers:* Treated as *signals*, never triggers. See §5.1.
- *Supply chain:* Pinned digests, SBOM + SLSA provenance, cosign verification at admission, dependency review gates, vendored critical libs, no postinstall scripts in CI.

**TB6 — Client**
- *Vault key theft via malware/XSS:* Strict CSP, Trusted Types, no third-party scripts on vault surfaces, WebCrypto non-extractable keys where platform allows, memory zeroization best-effort, clipboard auto-clear, re-auth on vault open.
- *Coercion/shoulder-surfing of elderly users:* Optional "trusted-contact review" mode where high-risk changes (new beneficiary + address change + export within 24h) trigger a notification hold.

**TB7 — Operators**
- No standing prod access; JIT elevation with peer approval and session recording; all operator reads of user data are themselves audit events surfaced to the user ("Anthropic-style" transparency: users can see that support accessed X on date Y); separation of duties between deploy, data, and key administration.

## 5. Platform-specific attack scenarios (the ones generic checklists miss)

### 5.1 Fraudulent death trigger ("kill them on paper")
**Attack:** Adversary (often a would-be heir or an account-takeover attacker who wants executor-level access) reports the owner dead with a forged certificate or exploits a false-positive from a death-data provider.
**Controls:** (1) No automated trigger from any single source — provider matches only open a *case*. (2) Mandatory human review of certified evidence. (3) Waiting period (default 5 days, configurable up) during which the platform aggressively attempts owner contact through every channel including hardware-key challenge; any owner sign-in with step-up MFA instantly voids the case and flags the reporter. (4) Account enters `deceased_pending` — reads freeze for role-holders; nothing unlocks early. (5) Executor access post-verification is *staged*: inventory first, vault emergency-access last, each stage separately approved. (6) The reporter's identity is verified and recorded; fraudulent reports are preserved for law enforcement.

### 5.2 Emergency-access abuse
**Attack:** A designated emergency contact invokes vault access while the owner is alive but unaware (hospitalized, traveling, cognitively declining).
**Controls:** Waiting period ≥ 24h (owner-configurable), multi-channel owner notification with one-tap deny, optional M-of-N Shamir requirement so no single contact can unlock alone, full audit visible to owner afterward, and scope limits (contacts can be granted vault subsets, not all-or-nothing).

### 5.3 Insider bulk decryption
**Attack:** Platform engineer or compromised service identity attempts mass read of SSNs/documents.
**Controls:** Per-user DEKs mean bulk access requires bulk KMS operations — rate-limited, anomaly-detected, circuit-broken (§4/TB4); CloudHSM roots mean even AWS-level compromise can't silently exfiltrate key material; canary records (fake users with tripwire fields) page on any access.

### 5.4 Grief-window social engineering
**Attack:** After a real death, attackers phish executors/beneficiaries ("probate portal fee required"), possibly with AI voice cloning of the family attorney.
**Controls:** All settlement communication happens in-app only; emails/SMS are content-free pointers by design, and onboarding for role-holders drills this ("we will never link you to a payment page"); executor dashboard shows verified contact cards for the estate's attorney/CPA; distribution approvals are dual-control with step-up MFA.

### 5.5 Beneficiary-conflict information abuse
**Attack:** A beneficiary with read access enumerates other beneficiaries' shares to contest or coerce.
**Controls:** ABAC default — beneficiaries see only assets naming them and only their own designation, unless the owner explicitly opens visibility; access-pattern anomalies (rapid enumeration) alert the owner.

### 5.6 Ransomware / destructive attack
**Attack:** Encrypt-and-extort against databases and object storage.
**Controls:** Immutable, cross-account, Vault-Locked backups the prod account cannot delete; monthly automated restore verification; event-sourced domains can rebuild projections; ransomware-specific runbook with decision tree and pre-negotiated IR retainer; audit chain proves data integrity post-recovery.

## 6. Risk register (top 10)

| # | Risk | L | I | Residual treatment |
|---|---|---|---|---|
| 1 | Account takeover of elderly / low-security users | H | H | Passkey nudges, trusted-contact review mode, adaptive step-up |
| 2 | Fraudulent settlement trigger | M | Critical | §5.1 layered controls; annual red-team of the flow |
| 3 | Insider bulk data access | M | Critical | KMS chokepoint + detection; JIT access; canaries |
| 4 | Vault client-side compromise (XSS/malware) | M | Critical | CSP/Trusted Types; isolated vault origin; bug bounty focus area |
| 5 | Plaid/aggregation token abuse | M | H | Namespace isolation, revocation drills |
| 6 | LLM prompt injection via uploaded docs | H | M | Untrusted-input framing, read-only tools, output filtering |
| 7 | Supply-chain compromise of a dependency | M | H | SLSA, pinning, admission control, egress allowlists |
| 8 | Legal/compliance failure in a state template | M | H | Attorney-gated template releases; per-state execution-requirement engine |
| 9 | Ransomware | M | H | §5.6; RTO 15m / tested restores |
| 10 | Notification-channel phishing of role-holders | H | M | Content-free notifications, in-app-only sensitive comms |

## 7. Validation program

- **Continuous:** SAST/DAST/dependency scanning in CI; fuzzing on parsers (document ingest, OCR, webhook handlers); secrets scanning; IaC policy checks (tfsec/OPA).
- **Quarterly:** External penetration test rotating focus (auth → vault → settlement → APIs); purple-team exercise against one §5 scenario.
- **Annually:** Full red team including social engineering of the settlement flow; SOC 2 Type II audit; DR failover game day; threat-model refresh.
- **Always-on:** Public bug bounty with elevated payouts for Zone A and settlement-flow findings.
