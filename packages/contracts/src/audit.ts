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
