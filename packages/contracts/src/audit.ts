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
  'crypto.field.decrypted',
  'crypto.dek.destroyed',
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
