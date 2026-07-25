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
      | 'vault.session.revoked',
    input: {
      actorId: string;
      resourceType: 'vault' | 'vault_item' | 'vault_session';
      resourceId: string | null;
      sessionId?: string | null;
      detail?: Record<string, string | number | boolean>;
    },
  ): Promise<void> {
    await this.audit.emit({
      action,
      actorId: input.actorId,
      actorType: 'user',
      onBehalfOf: null,
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
}
