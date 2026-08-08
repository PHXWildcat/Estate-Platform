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
