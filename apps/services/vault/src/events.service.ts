import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single egress point for this service's audit events.
 *
 * The PII firewall is trivially satisfied here and worth stating plainly: the
 * server cannot read a vault item even if it wanted to log one. What these
 * events carry is that an action happened, to which entity id, by whom - which
 * is exactly what docs/01 §6's vault-access-burst detection consumes.
 *
 * There is deliberately NO domain topic. No consumer exists for vault events
 * (the M3 rationale: topics appear when a consumer needs them), and a vault
 * payload on the bus is a category of risk with no current upside.
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  private async emit(
    action:
      | 'vault.keyset.created'
      | 'vault.keyset.updated'
      | 'vault.opened'
      | 'vault.open.failed'
      | 'vault.items.listed'
      | 'vault.item.created'
      | 'vault.item.accessed'
      | 'vault.item.updated'
      | 'vault.item.deleted'
      | 'vault.reset'
      | 'vault.session.revoked'
      | 'vault.recovery_key.published'
      | 'vault.emergency.configured'
      | 'vault.emergency.rearmed'
      | 'vault.emergency.revoked'
      | 'vault.emergency.requested'
      | 'vault.emergency.request_blocked'
      | 'vault.emergency.denied'
      | 'vault.emergency.released',
    input: {
      actorId: string;
      resourceType: 'vault' | 'vault_item' | 'vault_session' | 'emergency_access_policy';
      resourceId: string | null;
      sessionId?: string | null;
      onBehalfOf?: string | null;
      detail?: Record<string, string | number | boolean>;
    },
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId: input.actorId,
      actorType: 'user',
      onBehalfOf: input.onBehalfOf ?? null,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      sessionId: input.sessionId ?? null,
      detail: input.detail ?? {},
    });
  }

  async keysetCreated(userId: string, sessionId: string): Promise<void> {
    await this.emit('vault.keyset.created', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
    });
  }

  async keysetUpdated(
    userId: string,
    sessionId: string,
    detail: { revokedSessions: number },
  ): Promise<void> {
    await this.emit('vault.keyset.updated', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async opened(userId: string, sessionId: string, vaultSessionId: string): Promise<void> {
    await this.emit('vault.opened', {
      actorId: userId,
      resourceType: 'vault_session',
      resourceId: vaultSessionId,
      sessionId,
    });
  }

  /**
   * A failed unlock. `reason` is an enum token, never anything derived from the
   * attempt: the whole value of this event is that it is safe to emit on every
   * failure, which is what makes burst detection possible.
   */
  async openFailed(
    userId: string,
    sessionId: string,
    reason: 'bad_proof' | 'no_handshake' | 'no_keyset',
  ): Promise<void> {
    await this.emit('vault.open.failed', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail: { reason },
    });
  }

  async itemsListed(userId: string, sessionId: string, count: number): Promise<void> {
    await this.emit('vault.items.listed', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail: { count },
    });
  }

  async itemCreated(
    userId: string,
    sessionId: string,
    itemId: string,
    itemType: string,
  ): Promise<void> {
    await this.emit('vault.item.created', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
      detail: { itemType },
    });
  }

  async itemAccessed(userId: string, sessionId: string, itemId: string): Promise<void> {
    await this.emit('vault.item.accessed', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
    });
  }

  async itemUpdated(
    userId: string,
    sessionId: string,
    itemId: string,
    blobVersion: number,
  ): Promise<void> {
    await this.emit('vault.item.updated', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
      detail: { blobVersion },
    });
  }

  async itemDeleted(userId: string, sessionId: string, itemId: string): Promise<void> {
    await this.emit('vault.item.deleted', {
      actorId: userId,
      resourceType: 'vault_item',
      resourceId: itemId,
      sessionId,
    });
  }

  async reset(
    userId: string,
    sessionId: string,
    detail: { itemsDestroyed: number; revokedSessions: number },
  ): Promise<void> {
    await this.emit('vault.reset', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async sessionRevoked(
    userId: string,
    sessionId: string,
    vaultSessionId: string,
    reason: 'locked' | 'keyset_rotated' | 'vault_reset',
  ): Promise<void> {
    await this.emit('vault.session.revoked', {
      actorId: userId,
      resourceType: 'vault_session',
      resourceId: vaultSessionId,
      sessionId,
      detail: { reason },
    });
  }

  // --- emergency access (docs/03 §5.2) ---
  //
  // Every transition is recorded, including refusals. docs/03 §5.2 promises the
  // owner a "full audit visible to owner afterward", and a grantee who tried
  // repeatedly and was blocked each time is the single most important thing
  // that trail can show.

  async recoveryKeyPublished(userId: string, sessionId: string): Promise<void> {
    await this.emit('vault.recovery_key.published', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
    });
  }

  async emergencyConfigured(
    userId: string,
    sessionId: string,
    detail: { grantees: number; threshold: number },
  ): Promise<void> {
    await this.emit('vault.emergency.configured', {
      actorId: userId,
      resourceType: 'vault',
      resourceId: userId,
      sessionId,
      detail,
    });
  }

  async emergencyRequested(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    detail: { waitingPeriodHours: number },
  ): Promise<void> {
    await this.emit('vault.emergency.requested', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      detail,
    });
  }

  async emergencyRequestBlocked(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    reason: string,
  ): Promise<void> {
    await this.emit('vault.emergency.request_blocked', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      detail: { reason },
    });
  }

  async emergencyDenied(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.denied', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  async emergencyRearmed(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.rearmed', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  async emergencyRevoked(ownerUserId: string, sessionId: string, policyId: string): Promise<void> {
    await this.emit('vault.emergency.revoked', {
      actorId: ownerUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
    });
  }

  async emergencyReleased(
    granteeUserId: string,
    sessionId: string,
    policyId: string,
    ownerUserId: string,
  ): Promise<void> {
    await this.emit('vault.emergency.released', {
      actorId: granteeUserId,
      resourceType: 'emergency_access_policy',
      resourceId: policyId,
      sessionId,
      // onBehalfOf is what makes this event legible: a grantee acted, and the
      // vault it reached belongs to someone else.
      onBehalfOf: ownerUserId,
    });
  }
}
