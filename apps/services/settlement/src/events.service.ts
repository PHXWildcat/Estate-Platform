import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The single audit egress point (docs/02 §6 PII firewall: entity IDs and enum
 * tokens only). In THIS service the audit trail is itself a docs/03 §5.1
 * control — fraudulent reports are preserved as evidence — so every case
 * transition, including rejections and owner voids, is recorded.
 *
 * No domain topic: nothing consumes settlement events yet, and topics appear
 * when a consumer needs them (the M3 rule).
 */
@Injectable()
export class EventsService {
  readonly audit: AuditEmitter;

  constructor(@Inject(AUDIT_PRODUCER) producer: AuditProducer, @Inject(CLOCK) clock: Clock) {
    this.audit = new AuditEmitter(producer, clock);
  }

  /** A reporter (or an operator filing provider signals) opened a case. */
  async caseReported(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    source: 'trusted_contact' | 'data_provider' | 'death_certificate_upload',
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.reported',
      actorId,
      actorType: 'user',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { source, decedent: decedentUserId },
    });
  }

  async reviewStarted(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.review_started',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: {},
    });
  }

  /**
   * An operator listed a worklist (M21 PR3b).
   *
   * NO `resourceId`, deliberately: a queue read is about no single case, and
   * naming one would put an arbitrary member of the list on that estate's
   * trail. The count is the useful fact — it distinguishes an operator glancing
   * at an empty queue from one enumerating every open estate — and it is a
   * stringified integer, which SAFE_TOKEN_PATTERN admits, never a list of ids.
   *
   * `onBehalfOf` is likewise absent: there is no single subject.
   */
  async worklistViewed(
    operatorId: string,
    sessionId: string,
    worklist: 'queue' | 'administrable',
    count: number,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.queue.viewed',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'settlement_case',
      resourceId: null,
      sessionId,
      detail: { worklist, count: String(count) },
    });
  }

  /**
   * Somebody read one case (M21 PR3b), on the case's own trail.
   *
   * Emitted for OPERATOR reads only, and that narrowness is the decision
   * rather than an omission. `assertCaseVisible` and the Cedar `read` permit
   * both admit the decedent, the reporter and the estate's executor — people
   * reading their own case, which the rest of the product does not audit as a
   * disclosure either. What TB7 asks for is a record of PLATFORM STAFF looking
   * at somebody's death case, so `actorType` here is always `operator` and the
   * caller decides by asking the gate, exactly as it already must to
   * authorize the read.
   *
   * `surface` names which of the four reads this was, so one screen produces
   * four attributable rows rather than four indistinguishable ones.
   */
  async caseViewed(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    surface: 'case' | 'timeline' | 'stages' | 'tasks' | 'distributions',
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.viewed',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { surface },
    });
  }

  async evidenceAdded(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    kind: 'document' | 'provider_match',
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.evidence_added',
      actorId,
      actorType: asOperator ? 'operator' : 'user',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { kind },
    });
  }

  /** Review approved: the waiting period begins and the account locks. */
  async caseApproved(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    waitingPeriodEnds: Date,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.approved',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: {
        waitingPeriodEnds: waitingPeriodEnds.toISOString(),
        lock: 'deceased_pending',
      },
    });
  }

  async caseRejected(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    reason: 'insufficient_evidence' | 'fraud_suspected' | 'duplicate_report' | 'other',
    reporterId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.rejected',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      // The reporter id is preserved in the trail (docs/03 §5.1 control 6).
      detail: { reason, reporter: reporterId },
    });
  }

  /**
   * The case died because the owner is alive — either they hit the void route
   * or the verification-time liveness re-check caught a step-up sign-in.
   * The reporter is flagged in the same event.
   */
  async caseVoided(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    via: 'owner_route' | 'liveness_check',
    reporterId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.voided',
      actorId,
      actorType: via === 'owner_route' ? 'user' : 'operator',
      onBehalfOf: via === 'owner_route' ? null : decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { via, reporter: reporterId, reporterFlagged: true },
    });
  }

  async caseVerified(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.verified',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { lock: 'settlement' },
    });
  }

  /** One owner-contact attempt (docs/03 §5.1 control 3), driver-performed. */
  async contactAttempted(
    caseId: string,
    decedentUserId: string,
    seq: number,
    channel: 'push' | 'email' | 'sms' | 'voice',
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.contact.attempted',
      actorId: null,
      actorType: 'system',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId: null,
      detail: { seq, channel },
    });
  }

  // ------------------------------------------- PR2: staged access + tracking

  async stageRequested(
    executorId: string,
    sessionId: string,
    caseId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.requested',
      actorId: executorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'settlement_access_stage',
      resourceId: stageId,
      sessionId,
      detail: { stage, caseId },
    });
  }

  async stageApproved(
    operatorId: string,
    sessionId: string,
    caseId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.approved',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'settlement_access_stage',
      resourceId: stageId,
      sessionId,
      detail: { stage, caseId },
    });
  }

  async stageDenied(
    operatorId: string,
    sessionId: string,
    caseId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.denied',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'settlement_access_stage',
      resourceId: stageId,
      sessionId,
      detail: { stage, caseId },
    });
  }

  async stageRevoked(
    operatorId: string,
    sessionId: string,
    caseId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.revoked',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'settlement_access_stage',
      resourceId: stageId,
      sessionId,
      detail: { stage, caseId },
    });
  }

  async tasksGenerated(caseId: string, decedentUserId: string, count: number): Promise<void> {
    await this.audit.emit({
      action: 'settlement.task.created',
      actorId: null,
      actorType: 'system',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId: null,
      detail: { count },
    });
  }

  async taskCompleted(
    executorId: string,
    sessionId: string,
    caseId: string,
    taskId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.task.completed',
      actorId: executorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'settlement_task',
      resourceId: taskId,
      sessionId,
      detail: { caseId },
    });
  }

  /** Amounts are ciphertext and NEVER appear here — only who and which. */
  async distributionRecorded(
    executorId: string,
    sessionId: string,
    caseId: string,
    distributionId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.recorded',
      actorId: executorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      detail: { caseId },
    });
  }

  async distributionApproved(
    operatorId: string,
    sessionId: string,
    caseId: string,
    distributionId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.approved',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: null,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      detail: { caseId },
    });
  }

  async distributionCompleted(
    actorId: string,
    sessionId: string,
    caseId: string,
    distributionId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.completed',
      actorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      detail: { caseId },
    });
  }

  async caseClosed(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.closed',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: {},
    });
  }

  async settingsUpdated(
    ownerId: string,
    sessionId: string,
    waitingPeriodDays: number,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.settings.updated',
      actorId: ownerId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'settlement_settings',
      resourceId: ownerId,
      sessionId,
      detail: { waitingPeriodDays },
    });
  }
}
