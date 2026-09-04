import { Inject, Injectable } from '@nestjs/common';
import { AuditEmitter, type AuditProducer } from '@estate/audit-emitter';
import type { AuditAction } from '@estate/contracts';
import type { CaseStatus } from './cases.repo';
import type { DistributionStatus } from './distributions.repo';
import { AUDIT_PRODUCER, CLOCK, type Clock } from './di-tokens';

/**
 * The distribution targets `setDistributionStatus` accepts, and the action each
 * one writes (M49 PR1).
 *
 * DATA, NOT A CONDITIONAL. The emitter reads this map, so the three targets
 * cannot drift into three differently-shaped envelopes, and a target added to
 * `DistributionStatusTarget` is a compile error here rather than a silent
 * fall-through into an `else`.
 *
 * THAT IS A TYPE-LEVEL GUARANTEE AND NOT A DDL ONE, which an earlier draft of
 * this sentence claimed. `Extract` narrows a hand-written union, so a sixth
 * status added to the migration and to `DistributionStatus` leaves this map
 * total over the same three members and compiles clean. What catches THAT is
 * the fence, which derives the key set from the migration — including from an
 * `ALTER TABLE`, the only way this repo can add one — and compares it against
 * `DistributionStatusTarget`.
 *
 * `planned` and `approved` are absent deliberately: they are not targets of
 * this verb. `planned` is the DDL default written by `recordDistribution`
 * (`settlement.distribution.recorded`) and `approved` is written by
 * `approveDistribution` (`settlement.distribution.approved`) — both already
 * audited, both reached by a different method.
 */
export type DistributionStatusTarget = Extract<
  DistributionStatus,
  'in_progress' | 'completed' | 'disputed'
>;

export const DISTRIBUTION_STATUS_ACTIONS: Readonly<Record<DistributionStatusTarget, AuditAction>> =
  {
    in_progress: 'settlement.distribution.in_progress',
    completed: 'settlement.distribution.completed',
    disputed: 'settlement.distribution.disputed',
  };

/**
 * The case rungs `advanceStatus` climbs as a SIDE EFFECT of another act, and
 * the action each one writes (M49 PR1).
 *
 * `closed` is absent deliberately, and its absence is the interesting one:
 * `closeCase` also advances through this repo method, but it is a verb in its
 * own right with its own event (`settlement.case.closed`) and its own operator
 * gate, so routing it through here would give one movement two rows. The two
 * members are exactly the rungs that had no verb of their own — which is why
 * they had no event either.
 */
export type CaseStatusAdvanceTarget = Extract<CaseStatus, 'active' | 'distributing'>;

export const CASE_ADVANCE_ACTIONS: Readonly<Record<CaseStatusAdvanceTarget, AuditAction>> = {
  active: 'settlement.case.activated',
  distributing: 'settlement.case.distributing',
};

/**
 * Which case read produced a `settlement.case.viewed` row.
 *
 * ONE SPELLING (M48 PR2). This union existed twice — here, and again as
 * `recordOperatorRead`'s narrower `surface` parameter in `admin.service.ts` —
 * with nothing tying them together (the wrapper was `recordOperatorRead` until
 * this change renamed it `recordCaseRead`). The copies agreed by hand until they
 * did not: `distributionAmount` joined `assertCaseVisible` in M23 PR4b and
 * joined neither union, so the fifth gated read produced no case-trail row.
 *
 * A union cannot derive itself from "the methods that call the gate", so the
 * derivation is a FENCE rather than a type, and its CORPUS IS TWO FILES because
 * the reads live behind two gates. `admin.service.spec.ts` scans
 * `admin.service.ts` for `assertCaseVisible` callers — five today — and
 * `settlement.service.ts` for direct `events.caseViewed` calls — one, `getCase`,
 * on the Cedar gate — and compares the union of what they record against this
 * type. A SIXTH caller of either gate that records no surface reddens it by
 * name instead of joining silently.
 *
 * A case read added on neither gate is outside that scan and needs its own
 * fence. That is not hypothetical: `listMyCases` reads cases through raw SQL on
 * a third gate, and its absence from every union is why it went unnoticed.
 */
export type CaseReadSurface = 'case' | 'timeline' | 'stages' | 'tasks' | 'distributions' | 'amount';

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

  /**
   * A reporter (or an operator filing provider signals) opened a case.
   *
   * `asOperator` is EXPLICIT rather than inferred from `source`. The source
   * token is a reliable proxy only while `data_provider` has exactly one
   * writer — a POSITIONAL dependency, which is the shape §6aa criticised in
   * Cedar's literal `true` and the reason `assertIn` now returns its answer.
   * The docstring above already said an operator files provider signals while
   * the code below hardcoded `'user'`; this makes the code agree with it.
   */
  async caseReported(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    source: 'trusted_contact' | 'data_provider' | 'death_certificate_upload',
    asOperator = false,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.reported',
      actorId,
      actorType: asOperator ? 'operator' : 'user',
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
   * Somebody listed a worklist (M21 PR3b).
   *
   * NO `resourceId`, deliberately: a worklist read is about no single case, and
   * naming one would put an arbitrary member of the list on that estate's
   * trail. The count is the useful fact — it distinguishes an operator glancing
   * at an empty queue from one enumerating every open estate — and it is a
   * stringified integer, which SAFE_TOKEN_PATTERN admits, never a list of ids.
   *
   * `onBehalfOf` is likewise absent: there is no single subject.
   *
   * `'executor'` IS NOT AN OPERATOR WORKLIST (M48 PR2), so `actorType` is
   * derived here rather than hardcoded. `executorCases` lists the estates one
   * person administers for OTHER people — the disclosure the assets service has
   * recorded as `asset.estate.viewed` with `actorType: 'user'` since M7 PR2 —
   * and the ONLY stated reason it had no event of its own was that this emitter
   * asserted `actorType: 'operator'`. Deriving the class spends that reason, so
   * the omission had to be re-decided rather than inherited.
   *
   * It reuses `settlement.queue.viewed` rather than adding a vocabulary member:
   * `AUDIT_ACTIONS` is closed and an older consumer silently drops what it does
   * not know, so widening `worklist` costs no consumer deployment ahead of this
   * producer while a new action would.
   *
   * NOT `listMyCases`, and the reason is VOLUME rather than principle. That
   * route answers `OpenSettlementCaseBanner`, mounted in `AppShell` with its
   * effect keyed on `pathname`, so auditing it would write one permanent row
   * per page navigation for every authenticated user — the
   * audited-volume-is-a-UI-constraint rule (docs/03 §6cc) that already stops the
   * operator console polling, and an append-only trail cannot be pruned later.
   * It is also the weaker purchase of the two: a self-read of one's own cases,
   * where this one is a read of somebody else's estates.
   */
  async worklistViewed(
    actorId: string,
    sessionId: string,
    worklist: 'queue' | 'administrable' | 'executor',
    count: number,
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.queue.viewed',
      actorId,
      actorType: asOperator ? 'operator' : 'user',
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
   * EVERY read is emitted now, with the actor class DERIVED (M48 PR2). The
   * old narrowness rested on a premise this repo does not hold: that the
   * non-operator readers are "people reading their own case, which the rest of
   * the product does not audit as a disclosure either". The decedent is, and a
   * still-linked reporter arguably is. The EXECUTOR is not — they administer
   * somebody else's estate, and the assets service has audited exactly that
   * read as `asset.estate.viewed` with `actorType: 'user'` since M7 PR2.
   * Settlement was the outlier: `admin.service.ts`'s `executorCases` cited that
   * very event as the reason it needed none of its own, and this change gives
   * it one instead.
   *
   * The old argument's other half — that a false actor class on an append-only
   * trail is worse than no row — is SPENT once the class is derived from the
   * gate instead of asserted by the emitter.
   *
   * `asOperator` is REQUIRED, not defaulted like `caseReported`'s: BOTH callers
   * already hold it, on their two different gates. `recordCaseRead` takes the
   * flag `assertCaseVisible` computed to authorize the read; `getCase` binds the
   * same `OperatorGate.is` answer to hand its Cedar decision. A default would
   * let a new caller record an operator as a user by omission, which is the
   * defect this fixes.
   *
   * KNOWN LIMIT, stated rather than hidden: `actorType` cannot tell the
   * decedent, a linked reporter and an executor apart — all three are `user`.
   * The distinction lives in `onBehalfOf` (the decedent) and in the case row,
   * not in this vocabulary.
   *
   * `surface` names which read this was, so one screen produces
   * four attributable rows rather than four indistinguishable ones.
   */
  async caseViewed(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    surface: CaseReadSurface,
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.case.viewed',
      actorId,
      actorType: asOperator ? 'operator' : 'user',
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
    decedentUserId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.requested',
      actorId: executorId,
      actorType: 'user',
      // NAMED HERE TOO (M49 PR1), and this one is the reason the property
      // below it is asserted over the RESOURCE rather than over one action.
      // The three DECISIONS on this resource — approved, denied, revoked —
      // all named the decedent and the REQUEST did not, so "who asked for
      // access to this estate" was the one question on the stage ladder that
      // could not be answered from the dead person's side. Found by the same
      // sweep that found `distributionRecorded`, and fixed for the same
      // reason: a rule applied to one member of a category is half-applied.
      onBehalfOf: decedentUserId,
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
    decedentUserId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.approved',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_access_stage',
      resourceId: stageId,
      sessionId,
      detail: { stage, caseId },
    });
  }

  /**
   * The breadth bound fired for this operator.
   *
   * `onBehalfOf` is deliberately absent: the event is about the OPERATOR's
   * pattern across estates, not about any one decedent, and naming a single
   * estate here would both mislead a reader and pick one family arbitrarily out
   * of a set. The counts and the window are the payload — entity counts and a
   * number, never a list of the cases touched, which would put a map of who is
   * being administered into the trail.
   */
  async operatorBreadthExceeded(
    operatorId: string,
    sessionId: string,
    distinctCases: number,
    ceiling: number,
    windowMs: number,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.operator.breadth_exceeded',
      actorId: operatorId,
      actorType: 'operator',
      // NULL, not a case id. The event is about the OPERATOR's pattern across
      // estates; naming one would both mislead the reader and pick one family
      // arbitrarily out of a set. The field is nullable for exactly this.
      onBehalfOf: null,
      resourceType: 'settlement_operator',
      resourceId: operatorId,
      sessionId,
      detail: { distinctCases, ceiling, windowMs },
    });
  }

  async stageDenied(
    operatorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.denied',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
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
    decedentUserId: string,
    stageId: string,
    stage: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.stage.revoked',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
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

  /**
   * An executor UNTICKED a checklist item (M23 PR4b, deferred from PR3).
   *
   * THE SAME SHAPE AS `taskCompleted`, deliberately: an investigator asking
   * "what did this executor claim, and did they take it back" reads two events
   * of one form rather than one event plus an inference from its absence.
   *
   * PR3 shipped the untick with no event at all. The reversal was not lost —
   * `settlement_tasks_versions` is trigger-maintained and append-only and
   * records both transitions with the actor — but the version table is a
   * database artifact and the audit chain is the record somebody is answerable
   * to. The delay was the closed vocabulary: a new member costs an
   * audit-consumer deployment ahead of its producer, so it waited for a change
   * that was already paying that cost.
   */
  async taskReopened(
    executorId: string,
    sessionId: string,
    caseId: string,
    taskId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.task.reopened',
      actorId: executorId,
      actorType: 'user',
      onBehalfOf: null,
      resourceType: 'settlement_task',
      resourceId: taskId,
      sessionId,
      detail: { caseId },
    });
  }

  /**
   * An executor or operator REVEALED a recorded amount (M23 PR4b).
   *
   * The one event in this group that records a DISCLOSURE rather than a
   * movement, and the reason the amount is worth recording at all: until the
   * read route existed the figure was write-only, which made the dual-control
   * approval an approval of a number nobody could see.
   *
   * The amount does not appear, which is the point. `onBehalfOf` names the
   * DECEDENT — the DEK subject whose trail this decrypt belongs on — so the
   * read is findable from the side of the person whose estate it was.
   *
   * The first line said "an executor OR OPERATOR" while the code below
   * hardcoded `'user'`, so every operator who opened an amount was recorded as
   * the estate's own reader (M48 PR2). This is the same disagreement between a
   * docstring and its literal that `caseReported` fixed, and this route is where
   * it survived: it is the one read behind `assertCaseVisible` whose emitter
   * hardcoded `'user'`, the other four having reached the trail through
   * `recordOperatorRead` (renamed `recordCaseRead` by this change), which
   * hardcoded `'operator'` instead. Console reachability is not the
   * discriminant — `AUDIENCE_ROUTE_ADMITTERS.operator` admits four of the five.
   */
  async distributionAmountViewed(
    actorId: string,
    sessionId: string,
    decedentUserId: string,
    caseId: string,
    distributionId: string,
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.amount_viewed',
      actorId,
      actorType: asOperator ? 'operator' : 'user',
      onBehalfOf: decedentUserId,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      detail: { caseId },
    });
  }

  /**
   * Amounts are ciphertext and NEVER appear here — only who and which.
   *
   * THE FOURTH SIBLING, BROUGHT INTO LINE (M49 PR1). This emitted
   * `onBehalfOf: null` while `distributionApproved` and
   * `distributionAmountViewed` on the same resource named the decedent, and it
   * was found by DRIVING the browser rather than by reading: the trail for one
   * estate showed FIVE distribution rows, four naming it and the row that
   * CREATED the distribution naming nobody. There was no argument for the difference — the
   * method simply never took the decedent, though every caller has it in
   * scope. A rule applied to one member of a category is a rule half-applied,
   * and this file was the category.
   *
   * `actorType` stays a literal `'user'` — as `distributionApproved`'s stays a
   * literal `'operator'`; only the two emitters with both arms derive it — and
   * that is measured rather than left alone: `recordDistribution` authorises through
   * `requireAdministeredDecedentFor` and `administrableCaseFor`, both of which
   * admit on `isExecutorOf` alone with no operator disjunct. There is no
   * operator arm to discriminate.
   */
  async distributionRecorded(
    executorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    distributionId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.recorded',
      actorId: executorId,
      actorType: 'user',
      onBehalfOf: decedentUserId,
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
    decedentUserId: string,
    distributionId: string,
  ): Promise<void> {
    await this.audit.emit({
      action: 'settlement.distribution.approved',
      actorId: operatorId,
      actorType: 'operator',
      onBehalfOf: decedentUserId,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      detail: { caseId },
    });
  }

  /**
   * Either an executor or an OPERATOR may move a distribution, and this is the
   * only record of which — `distributions` has `created_by` and `approved_by`
   * and no `completed_by`. The caller already computes the flag to authorize
   * the call and used to discard it; `evidenceAdded` in this same file has
   * taken an explicit `asOperator` since M7 for exactly this reason.
   *
   * ONE EMITTER, THREE TOKENS, CHOSEN BY A MAP (M49 PR1). This was
   * `distributionCompleted`, called under `if (to === 'completed')`, and the
   * other two targets emitted nothing. Three hand-written call sites would
   * have been three chances to spell the envelope differently and one place
   * for a fourth target to land in an unguarded arm and emit the WRONG
   * action — a mislabelled row on an append-only store being worse than the
   * missing one. `DISTRIBUTION_STATUS_ACTIONS` is total over the targets this
   * verb accepts, so a new target is a COMPILE ERROR here rather than a
   * silent fall-through, and it is DATA a fence imports rather than prose a
   * fence parses.
   *
   * `onBehalfOf` NAMES THE ESTATE ON BOTH ARMS, and that is a change rather
   * than a copy. The old ternary nulled it for a user actor, so the ordinary
   * case — an executor moving their own estate's money — wrote the one row
   * that could not be found from the dead person's side, which is the query an
   * investigator actually runs. Two siblings on this trail —
   * `distributionApproved` and `distributionAmountViewed` — already named the
   * decedent unconditionally, and `distributionRecorded` did not until this
   * same PR brought it into line; all four agree now. The estate is a fact
   * about the ROW, and `actorType` still says in what capacity.
   *
   * NOT because the operator arm is unreachable — the tempting version of this
   * argument, and it does not hold. The console genuinely cannot reach the
   * verb (`session-audience.spec.ts` lists `setDistributionStatus` among the
   * routes that must never admit an operator session, and the operator edge
   * carries no `/status` path), but `asOperator` is `gate.is`, a question
   * about the ACTOR rather than the audience, so an operator on an ordinary
   * account session still takes that arm.
   */
  async distributionStatusChanged(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    distributionId: string,
    from: DistributionStatus,
    to: DistributionStatusTarget,
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: DISTRIBUTION_STATUS_ACTIONS[to],
      actorId,
      actorType: asOperator ? 'operator' : 'user',
      onBehalfOf: decedentUserId,
      resourceType: 'distribution',
      resourceId: distributionId,
      sessionId,
      // THE EDGE, not just the target. `completed → disputed` undoes a payout;
      // `approved → disputed` disputes one that never happened. Only the prior
      // status tells them apart, and §6dd's own measurement says a target-only
      // record hides that.
      detail: { caseId, from, to },
    });
  }

  /**
   * A CASE MOVED ITSELF WHILE SOMETHING ELSE WAS BEING RECORDED (M49 PR1).
   *
   * The two post-verification rungs — `verified → active` inside `decideStage`
   * and `verified|active → distributing` inside `recordDistribution` — are the
   * only `settlement_cases.status` transitions that emitted nothing. Both are
   * side effects of a DIFFERENT audited act, so "the case entered
   * administration" was answerable only by inferring it from a stage approval
   * standing nearby. They answer different questions, which is the same reason
   * `queue.viewed` and `case.viewed` are two actions rather than one.
   *
   * The caller emits only when the compare-and-set actually MOVED the row.
   * Both sites used to discard that boolean, so a lost race changed nothing
   * and said nothing; now a race that loses stays silent because there was no
   * movement, and one that wins is on the record.
   */
  async caseStatusAdvanced(
    actorId: string,
    sessionId: string,
    caseId: string,
    decedentUserId: string,
    from: CaseStatus,
    to: CaseStatusAdvanceTarget,
    asOperator: boolean,
  ): Promise<void> {
    await this.audit.emit({
      action: CASE_ADVANCE_ACTIONS[to],
      actorId,
      actorType: asOperator ? 'operator' : 'user',
      onBehalfOf: decedentUserId,
      resourceType: 'settlement_case',
      resourceId: caseId,
      sessionId,
      detail: { from, to },
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
