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
    reason: 'bad_credentials' | 'account_locked' | 'risk_blocked' | 'account_settled',
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

  /**
   * The step-up attempt cap firing (M16).
   *
   * AUDIT ONLY, with no domain event: nothing consumes "someone is guessing" on
   * the bus, and adding a topic for it would be the dormant-schema shape. The
   * audit stream is where a burst signal belongs (docs/03 §4 TB1).
   *
   * Its own action, deliberately NOT reusing anything that means "a step-up
   * failed" — a control firing must not read as an ordinary failure (M9), and
   * an investigator reading this trail needs to tell "this user mistyped" from
   * "this account is being worked through". IDS AND ENUMS ONLY, as everywhere:
   * the count is a fact about volume, never the codes and never the address.
   */
  async stepUpRateLimited(userId: string, sessionId: string, denials: number): Promise<void> {
    await this.audit.emit({
      action: 'auth.stepup.rate_limited',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
      detail: { denials: String(denials) },
    });
  }

  /**
   * The LOGIN bound firing (M17). Audit only, on `stepUpRateLimited`'s terms —
   * nothing consumes "somebody is guessing" on the bus.
   *
   * THE WIRE SAYS NOTHING AND THIS SAYS WHAT IT CAN. Login answers the same 401
   * whichever half refused, because a distinct status would be an
   * account-existence oracle; the trail is where the control becomes visible to
   * the people entitled to see it. `actorId` is the user when the ACCOUNT half
   * refused and null when the ADDRESS half did — which resolves nobody, so
   * there is nobody to name. That unevenness is not a leak: this trail has
   * carried exactly the same distinction since M1, where `auth.login.failed`
   * takes a null actor for an unknown identifier, and an unauthenticated
   * attacker cannot read any of it.
   *
   * NEVER THE ADDRESS. `scope` says which half fired, `attempts` is a volume
   * number for the account half and null for the other — the address half's
   * count lives only in a process's memory and putting it here would be a
   * number about somebody who may have no account at all.
   */
  async loginRateLimited(
    userId: string | null,
    scope: 'address' | 'account',
    attempts: number | null,
  ): Promise<void> {
    await this.audit.emit({
      action: 'auth.login.rate_limited',
      actorId: userId,
      actorType: userId === null ? 'system' : 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
      detail: attempts === null ? { scope } : { scope, attempts: String(attempts) },
    });
  }

  /**
   * The REGISTER bound firing (M17). No actor and no subject, on
   * `handoffFailed`'s terms: this route deliberately never resolves a user, and
   * the whole point of its identical-response contract is that the platform does
   * not say whether the address it was handed belongs to anyone. An audit row
   * naming one would answer through the trail the question the route refuses to
   * answer on the wire.
   */
  /**
   * The account password changed (M17 PR2). Audit only — nothing consumes a
   * password change on the bus, and a topic for it would be the dormant-schema
   * shape.
   *
   * `revokedSessions` and `notified` are both here rather than in separate
   * events because they are facts ABOUT this change: how much credential
   * material it invalidated, and whether the owner could be told. The second is
   * the M13 `ownerNotified` shape — the notice is the only thing that surfaces
   * a change the owner did not make, so a delivery failure must be visible
   * enough to re-drive rather than swallowed by a catch.
   */
  async passwordChanged(
    userId: string,
    sessionId: string,
    revokedSessions: number,
    notified: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: 'auth.password.changed',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId,
      detail: {
        revokedSessions: String(revokedSessions),
        notified: notified ? 'delivered' : 'failed',
      },
    });
  }

  async registerRateLimited(): Promise<void> {
    await this.audit.emit({
      action: 'auth.register.rate_limited',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: null,
      sessionId: null,
      detail: {},
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

  /**
   * M16, extension pairing. Ids and enums only, and — as with the handoff —
   * NEVER the code and never its digest. No domain event on the bus: nothing
   * consumes one, and the M9/M13 rule is that a topic gets a payload when a
   * consumer needs it.
   */
  async extensionPairingMinted(userId: string, sessionId: string, retired: boolean): Promise<void> {
    await this.audit.emit({
      action: 'auth.extension.pairing_minted',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
      // `retired` is how an owner sees a second code minted while one was
      // outstanding — the receipt for a button pressed twice, and the signal
      // if it was pressed by someone else.
      detail: { retired: String(retired) },
    });
  }

  async extensionPaired(userId: string, sessionId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.extension.paired',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      // The session the pairing PRODUCED — the long-lived credential itself,
      // and the row the paired-devices surface will offer to revoke.
      resourceId: sessionId,
      sessionId,
      detail: { audience: 'extension' },
    });
  }

  /** A refused redemption. No actor, no subject, no reason — see the action. */
  async extensionPairingFailed(): Promise<void> {
    await this.audit.emit({
      action: 'auth.extension.pairing_failed',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: null,
      sessionId: null,
      detail: {},
    });
  }

  /**
   * M15, the vault handoff. Ids and enums only — never the code and never its
   * digest. No domain event on the bus: nothing consumes one, and the M9/M13
   * rule is that a topic gets a payload when a consumer needs it.
   */
  async handoffMinted(
    userId: string,
    sessionId: string,
    detail: { audience: string; retired: number },
  ): Promise<void> {
    await this.audit.emit({
      action: 'auth.handoff.minted',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: sessionId,
      sessionId,
      // `retired` is how an owner sees that a second code was minted while one
      // was outstanding — the receipt for a button pressed twice, and the
      // signal if it was pressed by someone else.
      detail,
    });
  }

  async handoffRedeemed(
    userId: string,
    sessionId: string,
    detail: { audience: string },
  ): Promise<void> {
    await this.audit.emit({
      action: 'auth.handoff.redeemed',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'session',
      // The session the handoff PRODUCED, which is the thing an owner reviewing
      // their trail would want to follow into the vault events.
      resourceId: sessionId,
      sessionId,
      detail,
    });
  }

  /**
   * A refused redemption. NO actor, NO subject, NO reason, and that is the
   * whole design: the redeem route resolves a code and nothing else, so it does
   * not know whose code it was — an unknown code has no row — and saying which
   * of unknown/expired/spent/raced applied would tell whoever is guessing that
   * their guess named something real.
   */
  async handoffFailed(): Promise<void> {
    await this.audit.emit({
      action: 'auth.handoff.failed',
      actorId: null,
      actorType: 'system',
      onBehalfOf: null,
      resourceType: 'session',
      resourceId: null,
      sessionId: null,
      detail: {},
    });
  }

  /**
   * M14 address verification. Ids and enums ONLY — never the code, never its
   * digest, never the address it was mailed to. `delivered` is the same
   * outcome-riding-the-event shape M13 uses for `ownerNotified`: a send that
   * failed is a fact somebody may need to act on, and recording it here is what
   * keeps a silent failure from looking like a user who never bothered.
   */
  async emailVerificationSent(userId: string, delivered: boolean): Promise<void> {
    await this.audit.emit({
      action: 'auth.email_verification.sent',
      actorId: null,
      actorType: 'service',
      onBehalfOf: userId,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
      detail: { delivered: delivered ? 'delivered' : 'failed' },
    });
  }

  async emailVerified(userId: string, sessionId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.email_verification.verified',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId,
    });
  }

  /**
   * A redemption was refused. Deliberately carries NO reason: the route answers
   * one uniform `invalid_code` for unknown/expired/spent/revoked/exhausted/
   * mismatched, and an audit detail naming which one would re-create through
   * the trail exactly the oracle the uniform answer removes from the wire.
   */
  async emailVerificationFailed(userId: string, sessionId: string | null): Promise<void> {
    await this.audit.emit({
      action: 'auth.email_verification.failed',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId,
      detail: {},
    });
  }

  /**
   * A verification the platform could not complete (M14 review). Distinct from
   * `emailVerificationFailed`: the code was right and was spent, and what
   * failed was the delivery store. Counting this as a failed verification would
   * corrupt the one signal that says somebody is guessing at a user's codes.
   */
  async emailVerificationUnavailable(userId: string, sessionId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.email_verification.unavailable',
      actorId: null,
      actorType: 'service',
      onBehalfOf: userId,
      resourceType: 'user',
      resourceId: userId,
      sessionId,
      detail: {},
    });
  }

  async webauthnRegistered(userId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.webauthn.registered',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'webauthn_credential',
      resourceId: userId,
      sessionId: null,
    });
  }

  /** A non-incrementing signature counter — the credential may be cloned. */
  async webauthnCloneDetected(userId: string, sessionId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.webauthn.clone_detected',
      actorId: userId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'webauthn_credential',
      resourceId: userId,
      sessionId,
    });
  }

  /**
   * M7 settlement lock: a status transition performed FOR the settlement
   * service (actorType 'service', no user session). The case id ties the
   * transition to its settlement audit trail; from/to are enum tokens.
   */
  async userStatusChanged(userId: string, from: string, to: string, caseId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.user.status_changed',
      actorId: null,
      actorType: 'service',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
      detail: { from, to, caseId },
    });
  }

  /** M7: bulk revocation at settlement verification (no decedent credential survives). */
  async sessionsRevokedAll(userId: string, count: number, caseId: string): Promise<void> {
    await this.audit.emit({
      action: 'auth.sessions.revoked_all',
      actorId: null,
      actorType: 'service',
      onBehalfOf: null,
      resourceType: 'user',
      resourceId: userId,
      sessionId: null,
      detail: { count, caseId, reason: 'settlement_verified' },
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
