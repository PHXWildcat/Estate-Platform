import { z } from 'zod';
import { ActorTypeSchema } from './envelope';

/**
 * Audit action catalog. Grows one enum value at a time, in review — a free
 * string here would let arbitrary (possibly PII-bearing) text into the
 * append-only audit store.
 */
export const AUDIT_ACTIONS = [
  'auth.user.registered',
  'auth.login.succeeded',
  'auth.login.failed',
  'auth.stepup.granted',
  'auth.session.revoked',
  'auth.sessions.revoked_all',
  'auth.user.status_changed',
  'auth.webauthn.registered',
  'auth.webauthn.clone_detected',
  // M17 PR5: a passkey was removed from the account. The one factor-weakening
  // verb in the product, step-up gated at its route; the event is what an
  // owner's after-the-fact review keys on.
  'auth.webauthn.revoked',
  // M25 PR2: the owner asked for their account to be erased, or withdrew the
  // ask. The REQUEST is step-up gated and the WITHDRAWAL is not — so these two
  // are not a symmetric pair and should not be read as one. Both carry the
  // request id and nothing else: there is no PII in an erasure, which is the
  // one mercy of the subject matter.
  //
  // DEPLOY THE CONSUMER BEFORE THE PRODUCER. `AUDIT_ACTIONS` is closed, and a
  // consumer that predates a member drops every instance as a schema_violation
  // — observed for real in M23 PR4a. The event that says an account was marked
  // for destruction is the least survivable silent drop in the catalog.
  'auth.account.erasure_requested',
  'auth.account.erasure_cancelled',
  'crypto.field.decrypted',
  'crypto.dek.destroyed',
  // M18: the decrypt-rate baseline (docs/03 §4 TB4). Emitted by the audit
  // service's detector when a principal's windowed decrypt count exceeds its
  // reviewed bound. NEVER in the detector's own counted set (the M16
  // self-feeding-counter rule) — the counted set is exactly
  // 'crypto.field.decrypted'.
  'crypto.decrypt_rate.exceeded',
  // Profile & Contacts service (core cluster).
  'profile.updated',
  'family_member.created',
  'family_member.updated',
  'family_member.deleted',
  'contact.created',
  'contact.updated',
  'contact.deleted',
  'role.granted',
  'role.revoked',
  'permission.granted',
  // The withdrawal half of a permission grant. M2 shipped `permission.granted`
  // with no counterpart and no revoke route at all, so an owner could widen a
  // role-holder's reach and never narrow it — the inverse of the M6 rule that
  // the protective action must never be harder than the permissive one. A
  // revocation that leaves no trace is also the one an owner most needs to
  // prove later ("I took that access away on the 14th").
  'permission.revoked',
  // The contact link ceremony (M13 PR3). `contacts.linked_user_id` is an
  // authorization edge — being a linked contact is what makes someone able to
  // open a death case (docs/03 §6b) and what makes an executor resolvable — so
  // every step of acquiring, retiring and removing one is recorded. The claim
  // is audited with the REDEEMER as actor, so "who linked themselves to whose
  // estate" is answerable from either end of the trail.
  'contact.link.invited',
  'contact.link.claimed',
  'contact.link.invitation_revoked',
  'contact.link.removed',
  // The production notifications precondition firing. A control refusing must
  // never read as an outage (the M9 rule).
  'contact.link.notifications_refused',
  // A LINKED CONTACT READING THE NAMES OF THE ESTATES THAT NAME THEM (M22
  // PR4a). This is a DISCLOSURE event, not a navigation one: answering it
  // decrypts another user's `profile.legal_name` for a caller who is not its
  // owner, which is the first read in this service where the DEK subject and
  // the actor are different people. `resourceId` is the READER, because the
  // list has no single subject — the owners disclosed are in `detail.count`
  // and nowhere else, since naming them here would put the very PII the event
  // records the disclosure of into the audit trail.
  'contact.link.estates_read',
  // AN EXECUTOR READING THE ESTATE'S CONTACTS through the staged-access grant
  // (M23 PR4a) — the sibling of `asset.estate.viewed`, and here for the same
  // reason that one exists: the per-name `crypto.field.decrypted` events fire
  // either way, and without this there is no record of WHICH settlement case
  // authorised them, in precisely the docs/03 §5.1 scenario these trails are
  // kept for. `resourceId` is the DECEDENT, whose contacts were disclosed;
  // the contacts themselves appear only as `detail.count`, since naming them
  // would put the PII this event records the disclosure of into the trail.
  'contact.estate.viewed',
  // Asset service (financial cluster).
  'asset.created',
  'asset.updated',
  'asset.valuation.recorded',
  'asset.ownership.changed',
  'asset.beneficiary.designated',
  'asset.beneficiary.removed',
  'asset.retired',
  'asset.projection.rebuilt',
  // Plaid isolating service (financial cluster).
  'plaid.item.linked',
  'plaid.item.synced',
  'plaid.item.revoked',
  'plaid.item.login_required',
  'plaid.webhook.rejected',
  'plaid.sync.anomalous',
  // Document service (documents cluster).
  'document.template.published',
  'document.template.activated',
  'document.generated',
  'document.version.created',
  'document.content.viewed',
  'document.status.changed',
  'document.deleted',
  'document.uploaded',
  'document.scan.rejected',
  'document.ocr.indexed',
  'document.evidence.accessed',
  // The body_sha256 pin failed, or a template body disagreed with its own row
  // (docs/03 TB4 tamper adversary). Emitted where the failure is CAUGHT rather
  // than where it is thrown: the read paths degrade instead of erroring, so
  // without this the one signal that pin exists to produce would leave no
  // trace anywhere (M12 review).
  'document.template.integrity_failed',
  // Vault service (vault cluster, Zone A). These record that something
  // happened and to which entity - never what was in it. The server cannot
  // read vault contents even to log them, which is the point.
  'vault.keyset.created',
  'vault.keyset.updated',
  'vault.opened',
  'vault.open.failed',
  'vault.items.listed',
  'vault.item.created',
  'vault.item.accessed',
  'vault.item.updated',
  'vault.item.deleted',
  'vault.reset',
  'vault.session.revoked',
  // Emergency access (docs/03 §5.2). Every transition is recorded, including
  // requests that were blocked, because the owner's after-the-fact review of
  // who tried to reach their vault is itself one of the controls.
  'vault.recovery_key.published',
  'vault.emergency.configured',
  'vault.emergency.rearmed',
  'vault.emergency.revoked',
  'vault.emergency.requested',
  'vault.emergency.request_blocked',
  'vault.emergency.denied',
  'vault.emergency.released',
  // The docs/03 §6a integration point: a release (or a request) refused
  // because the owner's settlement case has not reached its separately
  // approved vault stage. Zone A is the LAST stage by design.
  'vault.emergency.release_blocked',
  // M27 PR0, and they arrive here A MILESTONE BEFORE THEIR PRODUCERS on
  // purpose: AUDIT_ACTIONS is closed, and a consumer that predates a member
  // treats every instance as `schema_violation` and drops it silently, with no
  // mark on the producer. Deploy order is the only mitigation and nothing
  // enforces it, so the vocabulary ships first and the emitters follow.
  //
  // `vault.emergency.items_read` is the first vault action whose actor is not
  // the subject in the READ direction: a released grantee opening the owner's
  // items. It belongs on the OWNER's trail with the grantee named as actor,
  // which is what `onBehalfOf` exists for. Four vault call sites already set it
  // (`emergency.service.ts` twice, `vault.service.ts` once, and
  // `events.service.ts`'s `emergencyReleased`) — an earlier draft of this
  // comment said `vault.emergency.released` was the only one, which the M27 PR0
  // review measured and refuted. Two of those four emit through
  // `audit.emit` DIRECTLY rather than through `events.service`'s typed helpers,
  // so that union is not the chokepoint it looks like and the reader's emitter
  // must set `onBehalfOf` explicitly rather than inherit it.
  'vault.emergency.items_read',
  // Restoring a soft-deleted or overwritten item. Distinct from
  // `vault.item.updated` because a restore asserts a PRIOR state is now
  // current, and the owner's after-the-fact question is "what came back", not
  // "what changed".
  'vault.item.restored',
  // Settlement service (core cluster; docs/03 §5.1). The case lifecycle is
  // the fraudulent-death-trigger audit trail: every transition is recorded,
  // including rejected and owner-voided cases, because the report itself is
  // evidence (§5.1 control 6 — fraudulent reports are preserved).
  'settlement.case.reported',
  'settlement.case.review_started',
  'settlement.case.evidence_added',
  'settlement.case.approved',
  'settlement.case.rejected',
  'settlement.case.voided',
  'settlement.case.verified',
  'settlement.case.closed',
  'settlement.contact.attempted',
  'settlement.settings.updated',
  // OPERATOR READS (M21 PR3b), and until this milestone there were none.
  //
  // Every one of the settlement actions above is a WRITE. An operator working
  // the review queue, opening a death case, reading its timeline, its access
  // stages or its distributions therefore left NO TRACE THAT THEY HAD LOOKED —
  // in the service whose whole subject is a docs/03 §5.1 investigation, and in
  // the one domain where the question after the fact is usually "who saw
  // this?" rather than "who changed it?". PR3a corrected §4 TB7's claim that
  // these events already existed; PR3b is the change that makes them exist,
  // shipped with the screens that make the reads rather than as a routeless
  // event nothing emits (the M4 legal-hold shape).
  //
  // TWO actions, not six. Loading one case opens four reads (case, timeline,
  // stages, distributions), so one action per route would be four events per
  // screen — noisier without being more informative. The route is carried in
  // `detail.surface`, which SAFE_TOKEN_PATTERN already admits, and the two are
  // split because they answer different questions: a QUEUE read is
  // cross-case reconnaissance with no resource id, while a CASE read names
  // exactly one estate and belongs on that case's own trail.
  //
  // These feed nothing automatic. The M18 decrypt-rate detector counts
  // `crypto.field.decrypted` and only that, so a read action is bounded by no
  // rate limit anywhere — stated rather than implied, because "we now log it"
  // reads like "we now detect it" and does not mean it.
  'settlement.queue.viewed',
  'settlement.case.viewed',
  // The operator allowlist itself (M21 PR1). Until this milestone, granting
  // the authority to approve a death case — the most privileged act in the
  // settlement domain — emitted NOTHING, so the one row that decides who may
  // run §5.1's human review was the only privileged change in the product
  // with no entry in the append-only trail. `actorId` is the human named by
  // the ceremony's `--by`, which is ATTRIBUTION and not authentication:
  // whoever runs the CLI already holds the database. What it buys is that a
  // row arriving through the sanctioned path names somebody, so a
  // `granted_by IS NULL` row is visibly one that did not.
  'settlement.operator.granted',
  'settlement.operator.revoked',
  // The breadth bound firing. NOT a refusal: this slice records and lets the
  // action through, because settlement's human review is mandatory and
  // time-sensitive and the ceiling has no production data behind it yet. The
  // event is the control's whole visible surface, which is why it is a closed
  // vocabulary member rather than a log line — a counter nobody can query is
  // not a control. Carries counts and the window only; never a case list.
  'settlement.operator.breadth_exceeded',
  // Staged executor access (docs/03 §5.1 control 5). Each stage is requested
  // by the executor and separately approved by an operator, so both halves are
  // recorded — a stage that was approved by whom, and when, is the audit
  // question that matters after the fact.
  'settlement.stage.requested',
  'settlement.stage.approved',
  'settlement.stage.denied',
  'settlement.stage.revoked',
  'settlement.task.created',
  'settlement.task.completed',
  // Distribution tracking under dual control (docs/02 §7). Amounts are
  // ciphertext and never appear in a payload; these record WHO moved a
  // distribution and to which state.
  'settlement.distribution.recorded',
  'settlement.distribution.approved',
  'settlement.distribution.completed',
  /*
   * READING A RECORDED AMOUNT (M23 PR4b) — the only event in this group that
   * records a DISCLOSURE rather than a movement.
   *
   * The amount is sealed under the DECEDENT's DEK, so revealing one is an
   * audited decrypt on a dead person's trail exactly like any other Zone B
   * read, and it is the reason the field is worth having at all: until this
   * route existed the figure was write-only, which made the dual-control
   * approval on `settlement.distribution.approved` an approval of a number
   * nobody could see.
   *
   * `resourceId` is the DISTRIBUTION. The amount itself never appears — that
   * is the whole point of the event — and neither does a count, because one
   * event is one amount.
   */
  'settlement.distribution.amount_viewed',
  /*
   * UNTICKING A CHECKLIST ITEM (deferred from M23 PR3, landed here with the
   * consumer change it needs).
   *
   * PR3 shipped the untick with no event: `completeTask` emitted
   * `settlement.task.completed` on the tick and nothing on the reversal, so an
   * executor withdrawing a claim that a step was taken left no trace outside
   * the version table. The reversal matters as much as the claim — it is the
   * half somebody would later be asked about — and the reason it waited is
   * that a new member costs an audit-consumer deployment ahead of its
   * producer, which did not belong in a slice that also shipped a UI.
   */
  'settlement.task.reopened',
  // An executor read the estate inventory through the staged-access grant.
  'asset.estate.viewed',
  // Legal hold set by settlement at verification (the M4 setting surface).
  'document.legal_hold.set',
  // Notifications service (M9). Detail carries kind/channel/outcome enums
  // only — never an address, a subject line, or a body.
  'notification.sent',
  'notification.recipient.updated',
  // M14. Distinct from `.updated` on purpose: that one fires on every login and
  // cannot attribute a change (docs/03 §6c), while this fires once per address
  // and marks the moment three arming gates start trusting it.
  'notification.recipient.verified',
  // M14, identity's half of the ceremony. Ids and enums only — never the code,
  // never its digest, never an address.
  'auth.email_verification.sent',
  'auth.email_verification.verified',
  'auth.email_verification.failed',
  // M14 review: the user presented a CORRECT code and the PLATFORM could not
  // finish (the delivery store had no live row to vouch for, or was
  // unreachable). Kept apart from `.failed` because that action is the trail an
  // investigator reads to decide whether somebody was guessing at a user's
  // codes, and an outage counted there is a false positive in exactly that
  // judgement.
  'auth.email_verification.unavailable',

  // M15, the cross-origin vault handoff. `failed` carries NO reason and NO
  // subject, deliberately: unknown, expired, spent and raced are one answer on
  // the wire, and a trail that separated them would re-create through the audit
  // stream the oracle the uniform refusal removes (the M14 PR1 rule).
  'auth.handoff.minted',
  'auth.handoff.redeemed',
  'auth.handoff.failed',
  // M16, the step-up attempt cap firing. Individual DENIALS are deliberately
  // not audited — they are ordinary noise (a mistyped code, a phone whose clock
  // drifted) and one per attempt would drown the stream. Hitting the CAP is the
  // opposite: it is at most one event per window by construction, and it means
  // somebody is working through a user's codes, which is exactly the burst
  // signal docs/03 §4 TB1 asks for. Distinct from `stepup.denied` in the local
  // ledger AND from any outage token, per the M9 rule — a control firing must
  // never read as either an ordinary failure or a fault.
  'auth.stepup.rate_limited',
  // M17 PR6: the current-password guessing cap firing. One event per window at
  // most, and the burst signal docs/03 §4 TB1 asks for — a stolen session
  // grinding at a password is exactly what an operator wants surfaced.
  'auth.password.change_rate_limited',
  // M17, the credential-guessing bounds on the two UNAUTHENTICATED routes that
  // cost real work. Separate actions rather than one with a `route` enum,
  // because they are different signals with different responses: login means
  // somebody is working through an account's passwords, register means somebody
  // is probing addresses or burning Argon2 on a machine that owes nothing to
  // anyone yet.
  //
  // ATTRIBUTION IS DELIBERATELY UNEVEN, and that is not a leak. `actorId` is the
  // user when the ACCOUNT-keyed half refused (the account resolved, so the trail
  // may as well say whose) and null when the ADDRESS-keyed half did (the address
  // resolved nothing, so there is nobody to name). That distinction already
  // exists in this trail and has since M1: `auth.login.failed` carries a null
  // actor for an unknown identifier. What must stay uniform is THE WIRE — login
  // answers the same 401 either way — and no audit action re-creates through the
  // trail what the status code withholds, because the attacker on an
  // unauthenticated route cannot read the trail at all.
  //
  // Never the address, never the count of attempts against a named address:
  // ids and enums only, as everywhere.
  'auth.login.rate_limited',
  'auth.register.rate_limited',
  // M17 PR2. The account password changed — the first mutation `password_hash`
  // has ever had, and the event an investigator reaches for when an owner says
  // they were locked out of their own account.
  //
  // `detail` carries how many OTHER sessions the change revoked and whether the
  // owner's notice was accepted by the carrier: a count and a boolean, ids and
  // enums only. The notification outcome rides this event rather than being
  // swallowed because it is the single control that tells an owner their
  // credentials moved without them, and a failure has to be visible enough to
  // re-drive (the M13 `ownerNotified` shape).
  //
  // Deliberately NOT paired with an `auth.password.change_failed` action: a
  // wrong current password on an authenticated route is ordinary noise, it is
  // already bounded by the M17 PR1 machinery's sibling ledger row, and one
  // audit event per mistyped password would drown the stream — the same
  // reasoning that keeps individual step-up denials out of the audit trail.
  'auth.password.changed',
  // M17 PR3, the reset ceremony. THREE actions because they are three different
  // facts an investigator needs apart: a code was mailed, a reset completed, and
  // a redemption was refused.
  //
  // `requested` and `completed` carry the subject; `failed` carries NO actor and
  // NO reason, because the redeem route is unauthenticated and resolves a code
  // or nothing — naming which of unknown/expired/spent/revoked/raced applied
  // would tell whoever is guessing that their guess named something real, and
  // would additionally leak account state to a caller with no session (the M14
  // PR1 rule, which binds harder here).
  'auth.password.reset_requested',
  'auth.password.reset_completed',
  'auth.password.reset_failed',
  // M17 PR4 — the address-change ceremony. `denied` is a refused gate at
  // request (wrong password; the step-up refusal is the guard's own event),
  // `failed` a refused redemption with NO reason recorded (the M14 PR1 rule:
  // a trail that named which refusal fired would be a progress meter for
  // whoever is guessing at a pending change), `throttled` the destination
  // bound firing — a control, not an outage.
  'auth.email.change_requested',
  'auth.email.change_completed',
  'auth.email.change_cancelled',
  'auth.email.change_denied',
  'auth.email.change_failed',
  'auth.email.change_throttled',
  // M24 PR2 — the owner read the address on file (docs/03 §6v residual 2's
  // closure). A DISCLOSURE event on the estates_read/amount_viewed pattern:
  // emitted BEFORE the decrypt, so a crash cannot leave plaintext with no
  // record, and carrying the SESSION that authorised it — the automatic
  // `crypto.field.decrypted` says a key was used; this says who asked. The
  // address itself structurally cannot ride here: SAFE_TOKEN_PATTERN rejects
  // '@', so the detail could not carry an email even by mistake.
  'auth.email.viewed',
  // The per-address bound on the REQUEST route refusing. No actor and no
  // subject: the address was never resolved to a user.
  'auth.password.reset_throttled',
  // M16, extension pairing. `paired` names the SESSION the ceremony produced,
  // so an owner reviewing their trail can follow it into the vault events that
  // session later causes. `pairing_failed` carries no actor and no reason —
  // the redeem route is unauthenticated and resolves a code or nothing, so it
  // does not know whose code it was, and naming which of
  // unknown/expired/spent/raced applied would tell whoever is guessing that
  // their guess named something real (the M14 PR1 rule).
  'auth.extension.pairing_minted',
  'auth.extension.paired',
  'auth.extension.pairing_failed',
  // The M6/M7 capability gates firing (503 notifications_unavailable) — a
  // control refusing is a fact the audit stream must carry, or it reads as an
  // outage.
  'vault.emergency.notifications_refused',
  'settlement.notifications_refused',
  // M14, the PROCEED-AND-RECORD half of the gate classification: an owner
  // alert went to an address nobody proved. Not a refusal — the action stood —
  // but evidence a §5.1/§5.2 investigation needs, because a waiting period
  // announced to an unconfirmed mailbox is not one the owner could interrupt.
  'vault.emergency.unverified_recipient',
  'settlement.unverified_recipient',
  'contact.link.unverified_recipient',
  // AI estate assistant service (core cluster; docs/01 §2.8, docs/03 §4 TB5).
  // The firewall is stricter here than anywhere else: these carry IDs and
  // enums only, which in THIS service also excludes prompt text, retrieved
  // estate content, and model output. A refusal is as loudly recorded as a
  // success — every tool the assistant was denied, and every egress the
  // privacy assertion caught, is a control firing, not an absence.
  'assistant.conversation.started',
  'assistant.conversation.deleted',
  'assistant.message.sent',
  'assistant.turn.completed',
  'assistant.tool.invoked',
  'assistant.tool.refused',
  'assistant.consent.granted',
  'assistant.consent.revoked',
  'assistant.egress.refused',
  // The deterministic analysers (M10 PR3). Distinct from the tool actions
  // because they are reachable WITHOUT a conversation — the read routes PR4's
  // UI calls run the same analysis with no model involved, so there is no
  // conversation id to anchor a tool event to, and no `assistant_tool_calls`
  // row (that table binds a retrieval to a conversation). The audit event is
  // therefore the whole record of a route-driven analysis.
  'assistant.analysis.completed',
  // Covers both a failed input read and the reference-data gate refusing an
  // unreviewed tax table in production; the detail's `reason` token separates
  // them, because "a control fired" and "a peer was down" call for different
  // reactions.
  'assistant.analysis.refused',
] as const;
export const AuditActionSchema = z.enum(AUDIT_ACTIONS);
export type AuditAction = z.infer<typeof AuditActionSchema>;

/**
 * The PII firewall for audit payloads (docs/02 §6: "entity IDs and enums
 * only; NEVER plaintext PII"). Detail values must be UUIDs, enum-ish tokens,
 * numbers, or booleans. The token pattern intentionally rejects whitespace
 * and '@' so names, emails, and free text cannot pass.
 */
export const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;

export const AuditDetailValueSchema = z.union([
  z.string().regex(SAFE_TOKEN_PATTERN, { message: 'detail value must be an ID or enum token' }),
  z.number().finite(),
  z.boolean(),
]);

export const AuditEventSchema = z.object({
  eventId: z.string().uuid(),
  occurredAt: z.string().datetime(),
  action: AuditActionSchema,
  actorId: z.string().uuid().nullable(),
  actorType: ActorTypeSchema,
  /** Set for delegated access (trustee acting for an owner, operator support). */
  onBehalfOf: z.string().uuid().nullable(),
  resourceType: z
    .string()
    .regex(SAFE_TOKEN_PATTERN, { message: 'resourceType must be an enum token' }),
  resourceId: z.string().uuid().nullable(),
  sessionId: z.string().uuid().nullable(),
  detail: z.record(
    z.string().regex(SAFE_TOKEN_PATTERN, { message: 'detail key must be an enum token' }),
    AuditDetailValueSchema,
  ),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;
