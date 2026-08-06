import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single egress point for audit events (docs/02 §6: entity IDs and enums
 * only — never plaintext PII). Every sensitive profile/contacts action lands
 * here and is mirrored to the append-only audit cluster via the AuditEmitter,
 * which validates each payload against @estate/contracts before the wire so
 * PII cannot leak through developer error.
 *
 * Unlike identity there is no core-cluster domain-event topic yet (a core
 * events contract lands with the asset service that consumes it); until then
 * this service emits audit events only. The `AUDIT_PRODUCER` is still injected
 * (and disconnected on shutdown) so wiring matches identity exactly.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  async profileUpserted(actorId: string, ownerUserId: string): Promise<void> {
    await this.audit.emit({
      action: 'profile.updated',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'profile',
      resourceId: ownerUserId,
      sessionId: null,
    });
  }

  async familyMemberCreated(actorId: string, memberId: string): Promise<void> {
    await this.familyMember('family_member.created', actorId, memberId);
  }

  async familyMemberUpdated(actorId: string, memberId: string): Promise<void> {
    await this.familyMember('family_member.updated', actorId, memberId);
  }

  async familyMemberDeleted(actorId: string, memberId: string): Promise<void> {
    await this.familyMember('family_member.deleted', actorId, memberId);
  }

  private async familyMember(
    action: 'family_member.created' | 'family_member.updated' | 'family_member.deleted',
    actorId: string,
    memberId: string,
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'family_member',
      resourceId: memberId,
      sessionId: null,
    });
  }

  async contactCreated(actorId: string, contactId: string): Promise<void> {
    await this.contact('contact.created', actorId, contactId);
  }

  async contactUpdated(actorId: string, contactId: string): Promise<void> {
    await this.contact('contact.updated', actorId, contactId);
  }

  async contactDeleted(actorId: string, contactId: string): Promise<void> {
    await this.contact('contact.deleted', actorId, contactId);
  }

  private async contact(
    action: 'contact.created' | 'contact.updated' | 'contact.deleted',
    actorId: string,
    contactId: string,
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'contact',
      resourceId: contactId,
      sessionId: null,
    });
  }

  async roleGranted(
    actorId: string,
    roleAssignmentId: string,
    detail: { role: string; scopeType: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'role.granted',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'role_assignment',
      resourceId: roleAssignmentId,
      sessionId: null,
      detail: { role: detail.role, scopeType: detail.scopeType },
    });
  }

  async roleRevoked(actorId: string, roleAssignmentId: string): Promise<void> {
    await this.audit.emit({
      action: 'role.revoked',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'role_assignment',
      resourceId: roleAssignmentId,
      sessionId: null,
    });
  }

  async permissionGranted(
    actorId: string,
    grantId: string,
    detail: { resource: string; action: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'permission.granted',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'permission_grant',
      resourceId: grantId,
      sessionId: null,
      detail: { resource: detail.resource, action: detail.action },
    });
  }

  /**
   * The contact link ceremony (M13 PR3). Four events, because four different
   * things happen to an authorization edge and an investigation of a docs/03
   * §5.1 report needs each of them separately: a code was offered, a code was
   * used, a code was retired unused, a live link was removed.
   *
   * `resourceId` is the CONTACT throughout, so the whole life of one link reads
   * as one thread. The actor differs by event and that difference is the point —
   * the owner invites and removes, the REDEEMER claims.
   */
  async contactLinkInvited(actorId: string, contactId: string): Promise<void> {
    await this.contactLink('contact.link.invited', actorId, contactId);
  }

  /**
   * The claim, with the notification's fate riding along. `ownerNotified` is an
   * enum, never free text (docs/02 §6), and it exists because the M13 review
   * found the delivery outcome recorded NOWHERE when a send failed at the
   * network: the notifications service only logs sends that reach it, and the
   * empty catch at the call site cited "the claim event above" — which carried
   * no such fact. 'failed' is an operator's re-drive signal, the vault
   * delivered_at-NULL precedent.
   */
  async contactLinkClaimed(
    actorId: string,
    contactId: string,
    ownerNotified: 'delivered' | 'failed',
  ): Promise<void> {
    await this.audit.emit({
      action: 'contact.link.claimed',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'contact',
      resourceId: contactId,
      sessionId: null,
      detail: { ownerNotified },
    });
  }

  async contactLinkInvitationRevoked(actorId: string, contactId: string): Promise<void> {
    await this.contactLink('contact.link.invitation_revoked', actorId, contactId);
  }

  async contactLinkRemoved(actorId: string, contactId: string): Promise<void> {
    await this.contactLink('contact.link.removed', actorId, contactId);
  }

  private async contactLink(
    action: 'contact.link.invited' | 'contact.link.invitation_revoked' | 'contact.link.removed',
    actorId: string,
    contactId: string,
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'contact',
      resourceId: contactId,
      sessionId: null,
    });
  }

  /**
   * The production notifications precondition refusing a redemption. Recorded
   * because a control firing must not be indistinguishable from an outage in the
   * very stream operators watch (the M9 rule). No resource: the refusal happens
   * before any invitation is looked up, so there is nothing yet to name — and
   * looking one up first would make the refusal depend on the code.
   */
  async contactLinkNotificationsRefused(actorId: string): Promise<void> {
    await this.audit.emit({
      action: 'contact.link.notifications_refused',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'contact',
      resourceId: null,
      sessionId: null,
    });
  }

  /**
   * A grant withdrawn. No `detail`: the resource/action pair is already on the
   * `permission.granted` event for this same id, and the grant row survives with
   * its `revoked_at` set, so repeating it here would add nothing an
   * investigator does not have and widen what the audit payload carries.
   */
  async permissionRevoked(actorId: string, grantId: string): Promise<void> {
    await this.audit.emit({
      action: 'permission.revoked',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'permission_grant',
      resourceId: grantId,
      sessionId: null,
    });
  }
}
