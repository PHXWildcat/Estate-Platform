import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import {
  LoginFailedEvent,
  LoginSucceededEvent,
  SessionRevokedEvent,
  StepUpGrantedEvent,
  TOPICS,
  UserRegisteredEvent,
  type MfaLevel,
} from '@estate/contracts';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/** Structural view of a zod schema: runtime validation without `any` leakage. */
interface ParsesEvent {
  parse(input: unknown): unknown;
}

/**
 * The single egress point for domain events + audit events. Every payload is
 * validated against its @estate/contracts schema before hitting the wire, so
 * PII cannot leak into Kafka through developer error (docs/02 §6).
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(
    @Inject(AUDIT_PRODUCER) private readonly producer: AuditProducer,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {
    this.audit = new AuditEmitter(producer, clock);
  }

  private async publish(
    schema: ParsesEvent,
    event: Record<string, unknown>,
    key: string,
  ): Promise<void> {
    const parsed = schema.parse({
      ...event,
      eventId: randomUUID(),
      occurredAt: this.clock().toISOString(),
    });
    await this.producer.send({
      topic: TOPICS.authEvents,
      key,
      value: JSON.stringify(parsed),
    });
  }

  async userRegistered(userId: string): Promise<void> {
    await this.publish(
      UserRegisteredEvent,
      {
        type: 'auth.user.registered',
        version: 1,
        actor: { id: userId, type: 'user' },
        payload: { userId },
      },
      userId,
    );
    await this.audit.emit({
      action: 'auth.user.registered',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
    });
  }

  async loginSucceeded(userId: string, sessionId: string, mfaLevel: MfaLevel): Promise<void> {
    await this.publish(
      LoginSucceededEvent,
      {
        type: 'auth.login.succeeded',
        version: 1,
        actor: { id: userId, type: 'user' },
        payload: { userId, sessionId, mfaLevel },
      },
      userId,
    );
    await this.audit.emit({
      action: 'auth.login.succeeded',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
    });
  }

  async loginFailed(
    userId: string | null,
    reason: 'bad_credentials' | 'account_locked' | 'risk_blocked',
  ): Promise<void> {
    await this.publish(
      LoginFailedEvent,
      {
        type: 'auth.login.failed',
        version: 1,
        actor: { id: userId, type: 'user' },
        payload: { userId, reason },
      },
      userId ?? randomUUID(),
    );
    await this.audit.emit({
      action: 'auth.login.failed',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
      detail: { reason },
    });
  }

  async stepUpGranted(
    userId: string,
    sessionId: string,
    expiresAt: Date,
    method: 'totp' | 'webauthn' = 'totp',
  ): Promise<void> {
    await this.publish(
      StepUpGrantedEvent,
      {
        type: 'auth.stepup.granted',
        version: 1,
        actor: { id: userId, type: 'user' },
        payload: { userId, sessionId, method, expiresAt: expiresAt.toISOString() },
      },
      userId,
    );
    await this.audit.emit({
      action: 'auth.stepup.granted',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
      detail: { method },
    });
  }

  async sessionRevoked(
    userId: string,
    sessionId: string,
    reason: 'logout' | 'expired' | 'admin' | 'risk' | 'rotation_reuse_detected',
  ): Promise<void> {
    await this.publish(
      SessionRevokedEvent,
      {
        type: 'auth.session.revoked',
        version: 1,
        actor: { id: userId, type: 'user' },
        payload: { userId, sessionId, reason },
      },
      userId,
    );
    await this.audit.emit({
      action: 'auth.session.revoked',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
      detail: { reason },
    });
  }
}
