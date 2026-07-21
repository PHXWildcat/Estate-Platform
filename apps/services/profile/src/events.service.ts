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
}
