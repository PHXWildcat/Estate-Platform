import {
  ConflictException,
  ForbiddenException,
  GoneException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { DekDestroyedError, type FieldCrypto } from '@estate/crypto';
import { ADMINISTRABLE_STATUSES, CasesRepo, type CaseRow, type CaseStatus } from './cases.repo';
import { OperatorBreadthMonitor } from './operator-breadth.monitor';
import { OPERATOR_BREADTH_MAX_CASES, OPERATOR_BREADTH_WINDOW_MS } from './operator-breadth';
import { CoreReadsRepo } from './core-reads.repo';
import { CLOCK, FIELD_CRYPTO, type Clock } from './di-tokens';
import { Db, isCheckViolation, type Queryable } from './db';
import {
  DistributionsRepo,
  type DistributionRow,
  type DistributionStatus,
} from './distributions.repo';
import { EventsService } from './events.service';
import { OperatorGate } from './operator-gate';
import { ACCESS_STAGES, StagesRepo, type AccessStage, type StageRow } from './stages.repo';
import { TasksRepo, type TaskRow } from './tasks.repo';
import { generateTasks } from './task-template';

export interface StageDto {
  stageId: string;
  caseId: string;
  stage: AccessStage;
  status: string;
  requestedBy: string;
  requestedAt: string;
  decidedBy: string | null;
  decidedAt: string | null;
}

/**
 * One estate the caller has been designated executor of, on a case an operator
 * has already verified (M23 PR2).
 *
 * `contactId` is here so the BFF can name the estate to a browser without a
 * raw user id; `decedentUserId` is here because the BFF has to reach assets
 * and profile with it. Both come from the same row, so the pair cannot
 * disagree the way two lookups could.
 */
export interface ExecutorCaseDto {
  caseId: string;
  contactId: string;
  decedentUserId: string;
  status: string;
  verifiedAt: string | null;
  createdAt: string;
}

export interface TaskDto {
  taskId: string;
  title: string;
  category: string | null;
  assignedRole: string | null;
  dueAt: string | null;
  completedAt: string | null;
  completedBy: string | null;
  courtDocVersionId: string | null;
}

export interface DistributionDto {
  distributionId: string;
  caseId: string;
  assetId: string | null;
  beneficiaryContactId: string;
  status: string;
  createdBy: string;
  approvedBy: string | null;
  approvedAt: string | null;
  /**
   * Whether an encrypted amount is recorded — never the amount itself.
   *
   * A LIST FIELD CANNOT CARRY IT, and that is a decrypt-budget decision rather
   * than a secrecy one (docs/03 §6f): revealing an amount is one audited
   * decrypt on the DECEDENT's trail, so it is a deliberate per-row act on
   * `GET /distributions/:id/amount` and never something a page load spends N
   * of.
   *
   * THIS COMMENT ONCE SAID the amount was "sealed at write under settlement's
   * own KEK" and that "settlement has NO amount read route". The first half was
   * false when written — `recordDistribution` calls
   * `encryptField(decedent, ...)`, so it is the DECEDENT's DEK and shredding
   * the estate retires every amount recorded against it — and the second was
   * true until M23 PR4b, which added the route because a write-only figure made
   * the dual-control approval an approval of a number nobody could see.
   */
  hasAmount: boolean;
  createdAt: string;
}

export interface TimelineEntry {
  at: string;
  kind: string;
  detail: Record<string, string | number | boolean>;
}

/** AAD field label for an encrypted distribution amount (docs/02 conventions). */
const DISTRIBUTION_AMOUNT_FIELD = 'distributions.amount';

/**
 * The case id used when a distribution id names nothing.
 *
 * A CONSTANT, not a skipped check: `assertCaseVisible` must run before the
 * missing-row branch or an unknown id would refuse differently from one on
 * somebody else's case — the M23 PR1 defect, in the shape it takes when the
 * lookup cannot move. This value names no case, so it takes the same
 * uniform-404 path every unauthorised caller does.
 */
const MISSING_CASE = '00000000-0000-0000-0000-000000000000';

/**
 * Case statuses at which post-verification administration is permitted.
 *
 * Re-exported from the repo rather than declared here (M21 PR3b): the same set
 * now also selects the operator worklist that makes these verbs reachable, and
 * a second copy would let the screen list cases the verbs refuse — or hide
 * cases they accept.
 */
const ADMINISTRABLE: readonly CaseStatus[] = ADMINISTRABLE_STATUSES;
/** Statuses that mean "this estate is still contested/pending" for the vault gate. */
const NON_TERMINAL: readonly CaseStatus[] = [
  'reported',
  'verifying',
  'waiting_period',
  'verified',
  'active',
  'distributing',
];

function stageDto(row: StageRow): StageDto {
  return {
    stageId: row.id,
    caseId: row.case_id,
    stage: row.stage,
    status: row.status,
    requestedBy: row.requested_by,
    requestedAt: row.requested_at.toISOString(),
    decidedBy: row.decided_by,
    decidedAt: row.decided_at?.toISOString() ?? null,
  };
}

function taskDto(row: TaskRow): TaskDto {
  return {
    taskId: row.id,
    title: row.title,
    category: row.category,
    assignedRole: row.assigned_role,
    dueAt: row.due_at ? new Date(row.due_at).toISOString() : null,
    completedAt: row.completed_at?.toISOString() ?? null,
    completedBy: row.completed_by,
    courtDocVersionId: row.court_doc_version_id,
  };
}

function distributionDto(row: DistributionRow): DistributionDto {
  return {
    distributionId: row.id,
    caseId: row.case_id,
    assetId: row.asset_id,
    beneficiaryContactId: row.beneficiary_contact_id,
    status: row.status,
    createdBy: row.created_by,
    approvedBy: row.approved_by,
    approvedAt: row.approved_at?.toISOString() ?? null,
    hasAmount: row.amount_ct !== null,
    createdAt: row.created_at.toISOString(),
  };
}

/**
 * Post-verification administration (docs/03 §5.1 control 5, docs/02 §7).
 *
 * The rules that make this safe, each of which is a control rather than a
 * convenience:
 *
 *  - **Staged, ordered, separately approved.** An executor may request only
 *    the NEXT stage; inventory must be approved before documents, documents
 *    before vault. Zone A is last by construction, so the most dangerous grant
 *    is the one furthest from a fresh death report.
 *  - **Two people per stage.** The executor requests; an operator approves;
 *    a DDL CHECK forbids them being the same person. Designation as executor
 *    grants NOTHING on its own.
 *  - **Two people per distribution.** The recorder is stamped at insert and
 *    the approver must differ — enforced by CHECK, so a service bug cannot
 *    produce a self-approved distribution.
 *  - **This service holds no data-read power.** It answers authority
 *    questions; assets/documents/vault do their own reads and their own
 *    audit. A compromise here cannot exfiltrate an estate, only mis-answer.
 */
@Injectable()
export class SettlementAdminService {
  constructor(
    private readonly db: Db,
    private readonly cases: CasesRepo,
    private readonly stages: StagesRepo,
    private readonly tasks: TasksRepo,
    private readonly distributions: DistributionsRepo,
    private readonly gate: OperatorGate,
    private readonly breadth: OperatorBreadthMonitor,
    private readonly coreReads: CoreReadsRepo,
    private readonly events: EventsService,
    @Inject(FIELD_CRYPTO) private readonly fieldCrypto: FieldCrypto,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  // ------------------------------------------------------------ staged access

  /**
   * THE EXECUTOR'S FRONT DOOR (M23 PR2).
   *
   * Until this route existed, a designated executor could reach every verb in
   * this file only by holding a case id from somewhere else — the same gap
   * M21 PR3b closed for operators, whose three post-verification verbs had no
   * listing that could return a case to use them on.
   *
   * NOT A WIDENED `listMyCases`: see `CasesRepo.listAdministeredBy`. That list
   * is "cases about me, and cases I filed", and the web renders it as two
   * panels off one boolean.
   *
   * NO AUDIT EVENT, and the omission is argued rather than overlooked. It
   * would have to be a new `AUDIT_ACTIONS` member — `settlement.queue.viewed`
   * hardcodes `actorType: 'operator'` and an executor is not one, so reusing it
   * would put a false actor type on the trail, which is worse than no event.
   * A new member costs a consumer deployment ahead of this producer, and buys
   * a record that somebody read their OWN worklist. The reads that disclose
   * anything are audited where they happen: `asset.estate.viewed` names the
   * case that authorised an inventory read, and `settlement.case.viewed`
   * covers operator reads of a single case.
   */
  async executorCases(actor: string): Promise<ExecutorCaseDto[]> {
    const rows = await this.cases.listAdministeredBy(this.db, actor);
    return rows.map((row) => ({
      caseId: row.id,
      contactId: row.contact_id,
      decedentUserId: row.decedent_user_id,
      status: row.status,
      verifiedAt: row.verified_at?.toISOString() ?? null,
      createdAt: row.created_at.toISOString(),
    }));
  }

  /**
   * The executor requests the next stage. Refuses a stage whose predecessor is
   * not yet approved — the ladder cannot be climbed out of order or skipped.
   */
  async requestStage(
    actor: string,
    sessionId: string,
    caseId: string,
    stage: AccessStage,
  ): Promise<StageDto> {
    const now = this.clock();
    const row = await this.db.withTransaction(actor, async (tx) => {
      // Authority and location in one step, answering a uniform 404 to anyone
      // without it — see `administrableCaseFor`. The 403 that used to live here
      // was the last of three distinguishable answers this route gave.
      await this.administrableCaseFor(tx, caseId, actor);
      const existing = await this.stages.findLive(tx, caseId, stage);
      if (existing) {
        throw new ConflictException({ error: 'stage_exists' });
      }
      await this.assertPredecessorApproved(tx, caseId, stage);
      return this.stages.insertRequest(tx, {
        caseId,
        stage,
        requestedBy: actor,
        requestedAt: now,
      });
    });
    await this.events.stageRequested(actor, sessionId, caseId, row.id, stage);
    return stageDto(row);
  }

  /**
   * An operator approves or denies. Never the requester (DDL CHECK + the
   * readable refusal here), and approval re-checks the ladder under the lock
   * so a concurrently revoked predecessor cannot leave a hole.
   */
  async decideStage(
    operator: string,
    sessionId: string,
    stageId: string,
    decision: 'approve' | 'deny',
  ): Promise<StageDto> {
    const now = this.clock();
    const outcome = await this.db.withTransaction(operator, async (tx) => {
      // First, and on `tx`: refused before the stage is looked up (so a
      // non-operator learns nothing about the id) and on the same handle as
      // the write it authorizes — see OperatorGate.is.
      await this.gate.assertIn(tx, operator);
      const locked = await this.stages.lockById(tx, stageId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      if (locked.requested_by === operator) {
        throw new ForbiddenException({ error: 'approver_is_requester' });
      }
      if (locked.status !== 'requested') {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      const kase = await this.requireAdministrableCase(tx, locked.case_id);
      if (decision === 'approve') {
        await this.assertPredecessorApproved(tx, locked.case_id, locked.stage);
      }
      if (
        !(await this.stages.decide(
          tx,
          stageId,
          decision === 'approve' ? 'approved' : 'denied',
          operator,
          now,
        ))
      ) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      // First approved stage moves the case from verified into active
      // administration (docs/02 §7's status ladder).
      if (decision === 'approve' && kase.status === 'verified') {
        await this.cases.advanceStatus(tx, locked.case_id, ['verified'], 'active');
      }
      // Recorded inside the transaction so the ledger row commits with the
      // approval it describes. ONLY the approve arm: a denial is the
      // protective action and counting it would make withdrawing access the
      // thing that runs out first.
      const breadth =
        decision === 'approve'
          ? await this.breadth.record(tx, operator, locked.case_id, 'stage.approved', now)
          : 0;
      return {
        stage: (await this.stages.lockById(tx, stageId)) as StageRow,
        decedentUserId: kase.decedent_user_id,
        breadth,
      };
    });
    const { stage: outcomeStage, decedentUserId } = outcome;
    if (decision === 'approve') {
      await this.events.stageApproved(
        operator,
        sessionId,
        outcomeStage.case_id,
        decedentUserId,
        stageId,
        outcomeStage.stage,
      );
      if (this.breadth.exceeded(outcome.breadth)) {
        // WARN, never refuse. Settlement's human review is mandatory and
        // time-sensitive; the ceiling has no production data behind it yet.
        await this.events.operatorBreadthExceeded(
          operator,
          sessionId,
          outcome.breadth,
          OPERATOR_BREADTH_MAX_CASES,
          OPERATOR_BREADTH_WINDOW_MS,
        );
      }
    } else {
      await this.events.stageDenied(
        operator,
        sessionId,
        outcomeStage.case_id,
        decedentUserId,
        stageId,
        outcomeStage.stage,
      );
    }
    return stageDto(outcomeStage);
  }

  /**
   * Revoke an approved stage (operator). Access is a grant, not a fact.
   *
   * Revocation records the revoker in `decided_by`, so it lands under the same
   * `decided_by <> requested_by` CHECK as approval: an operator who is ALSO the
   * executor that requested this stage cannot revoke it, and another operator
   * must. That is a real constraint, not a formality — but it used to surface
   * as an unhandled 23514 (a 500) with the access left standing, so the caller
   * could not tell "get a second operator" from "the service is broken". The
   * M7 security review flagged the unused `isCheckViolation` helper as exactly
   * this gap. Refused up front, with the DDL as the backstop it is meant to be.
   */
  async revokeStage(operator: string, sessionId: string, stageId: string): Promise<StageDto> {
    const now = this.clock();
    const row = await this.db
      .withTransaction(operator, async (tx) => {
        await this.gate.assertIn(tx, operator);
        const locked = await this.stages.lockById(tx, stageId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        if (locked.requested_by === operator) {
          throw new ForbiddenException({ error: 'approver_is_requester' });
        }
        if (!(await this.stages.revoke(tx, stageId, operator, now))) {
          throw new ConflictException({ error: 'invalid_transition' });
        }
        return (await this.stages.lockById(tx, stageId)) as StageRow;
      })
      .catch((err: unknown) => {
        // Backstop for any dual-control CHECK the pre-check above missed: a
        // clean refusal, never a 500 that reads as an outage.
        if (isCheckViolation(err)) {
          throw new ForbiddenException({ error: 'approver_is_requester' });
        }
        throw err;
      });
    await this.events.stageRevoked(
      operator,
      sessionId,
      row.case_id,
      await this.requireDecedentFor(row.case_id),
      stageId,
      row.stage,
    );
    return stageDto(row);
  }

  async listStages(actor: string, sessionId: string, caseId: string): Promise<StageDto[]> {
    const { kase, isOperator } = await this.assertCaseVisible(actor, caseId);
    const rows = await this.stages.listByCase(this.db, caseId);
    await this.recordOperatorRead(actor, sessionId, kase, isOperator, 'stages');
    return rows.map(stageDto);
  }

  // ------------------------------------------------------------------- tasks

  async listTasks(actor: string, sessionId: string, caseId: string): Promise<TaskDto[]> {
    const { kase, isOperator } = await this.assertCaseVisible(actor, caseId);
    const rows = await this.tasks.listByCase(this.db, caseId);
    await this.recordOperatorRead(actor, sessionId, kase, isOperator, 'tasks');
    return rows.map(taskDto);
  }

  /**
   * Complete (or reopen) a checklist item. The executor owns the checklist, so
   * this needs no stage: a task is procedural state about the estate's
   * administration, not access to the decedent's data.
   */
  async completeTask(
    actor: string,
    sessionId: string,
    taskId: string,
    input: { completed: boolean; courtDocVersionId?: string | undefined },
  ): Promise<TaskDto> {
    const now = this.clock();
    const row = await this.db.withTransaction(actor, async (tx) => {
      const locked = await this.tasks.lockById(tx, taskId);
      // A missing task and a task on somebody else's estate answer the SAME
      // 404 — `administrableCaseFor` handles the null, so there is no early
      // return here that would answer before authority is established.
      await this.administrableCaseFor(tx, locked?.case_id ?? null, actor);
      if (locked === null) {
        throw new NotFoundException({ error: 'not_found' });
      }
      await this.tasks.setCompletion(
        tx,
        taskId,
        input.completed ? { at: now, by: actor } : null,
        input.courtDocVersionId ?? null,
      );
      return (await this.tasks.lockById(tx, taskId)) as TaskRow;
    });
    /*
     * BOTH DIRECTIONS ARE RECORDED (M23 PR4b). PR3 emitted on the tick and
     * nothing on the untick, so an executor withdrawing a claim that a step
     * was taken left no trace outside the version table. Two events of one
     * shape, so the trail answers "what did they claim, and did they take it
     * back" without inferring anything from an absence.
     */
    if (input.completed) {
      await this.events.taskCompleted(actor, sessionId, row.case_id, taskId);
    } else {
      await this.events.taskReopened(actor, sessionId, row.case_id, taskId);
    }
    return taskDto(row);
  }

  // ----------------------------------------------------------- distributions

  /**
   * Record a planned distribution. The recorder is stamped from the verified
   * session — never from the payload — which is what makes the dual-control
   * CHECK meaningful.
   */
  async recordDistribution(
    actor: string,
    sessionId: string,
    caseId: string,
    input: {
      beneficiaryContactId: string;
      assetId?: string;
      /** Decimal string; encrypted here and never stored or logged in clear. */
      amount: string | null;
    },
  ): Promise<DistributionDto> {
    // Resolve the estate BEFORE the transaction so the KMS round trip for the
    // DEK does not sit inside an open one — and AUTHORISE before that round
    // trip happens at all (M23 PR1). `requireDecedentFor` answered 404-or-not
    // to anyone, and then this method sealed a caller-supplied plaintext under
    // the DECEDENT's DEK before ever asking whether the caller was the estate's
    // executor: a stranger holding a case id could spend a KMS operation on
    // somebody else's estate key. Measured, not inferred — the harness recorded
    // `{userId: <decedent>, field: 'distributions.amount', plaintext: '1000.00'}`
    // sealed on behalf of an account that was refused a moment later.
    //
    // This pre-check gates the SEAL and nothing else. The authority that gates
    // the WRITE is re-established under the row lock below, because a
    // pre-transaction read and the transaction it guards are separated by every
    // commit that lands between them.
    const decedent = await this.requireAdministeredDecedentFor(caseId, actor);
    let amountCt: Buffer | null = null;
    let dekId: string | null = null;
    if (input.amount !== null) {
      // Keyed by the DECEDENT: shredding the estate's DEK retires every amount
      // recorded against it. The AAD field label binds the ciphertext to this
      // purpose, so an amount cannot be replayed as another encrypted field.
      const sealed = await this.fieldCrypto.encryptField(
        decedent,
        DISTRIBUTION_AMOUNT_FIELD,
        input.amount,
      );
      amountCt = sealed.ciphertext;
      dekId = sealed.dekId;
    }

    const row = await this.db.withTransaction(actor, async (tx) => {
      const kase = await this.administrableCaseFor(tx, caseId, actor);
      const created = await this.distributions.insert(tx, {
        caseId,
        assetId: input.assetId ?? null,
        beneficiaryContactId: input.beneficiaryContactId,
        amountCt,
        dekId,
        createdBy: actor,
      });
      if (kase.status !== 'distributing') {
        await this.cases.advanceStatus(tx, caseId, ['verified', 'active'], 'distributing');
      }
      return created;
    });
    await this.events.distributionRecorded(actor, sessionId, caseId, row.id);
    return distributionDto(row);
  }

  /**
   * Approve a distribution — the second half of dual control. An operator
   * approves; the DDL CHECK guarantees they are not the recorder even if this
   * check were bypassed.
   */
  async approveDistribution(
    operator: string,
    sessionId: string,
    distributionId: string,
  ): Promise<DistributionDto> {
    const now = this.clock();
    const row = await this.db.withTransaction(operator, async (tx) => {
      await this.gate.assertIn(tx, operator);
      const locked = await this.distributions.lockById(tx, distributionId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      if (locked.created_by === operator) {
        throw new ForbiddenException({ error: 'approver_is_recorder' });
      }
      const kase = await this.requireAdministrableCase(tx, locked.case_id);
      if (!(await this.distributions.approve(tx, distributionId, operator, now))) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      return {
        distribution: (await this.distributions.lockById(tx, distributionId)) as DistributionRow,
        decedentUserId: kase.decedent_user_id,
        breadth: await this.breadth.record(tx, operator, kase.id, 'distribution.approved', now),
      };
    });
    await this.events.distributionApproved(
      operator,
      sessionId,
      row.distribution.case_id,
      row.decedentUserId,
      distributionId,
    );
    if (this.breadth.exceeded(row.breadth)) {
      // WARN, never refuse. Settlement's human review is mandatory and
      // time-sensitive; the ceiling has no production data behind it yet.
      await this.events.operatorBreadthExceeded(
        operator,
        sessionId,
        row.breadth,
        OPERATOR_BREADTH_MAX_CASES,
        OPERATOR_BREADTH_WINDOW_MS,
      );
    }
    return distributionDto(row.distribution);
  }

  /** Post-approval movement: in_progress → completed, or disputed. */
  /**
   * REVEAL ONE RECORDED AMOUNT (M23 PR4b) — one audited decrypt, one act.
   *
   * WHY IT EXISTS. Until this route the amount was write-only: sealed at
   * `recordDistribution` under the DECEDENT's DEK and readable by nobody. That
   * made `settlement.distribution.approved` — dual-control AND step-up gated,
   * and named in docs/03 §5.4 as a control — an approval of a number the
   * approver could not see. A control whose subject is invisible to the person
   * exercising it is a ceremony, not a control.
   *
   * `assertCaseVisible`, NOT the narrower executor test. The same four parties
   * `listDistributions` admits — the decedent's own reader, the reporter, the
   * executor and an operator — because this route reveals a field of a row
   * that route already returns, and a reader who may see that a distribution
   * exists and carries an amount is the reader who may see which amount. A
   * narrower gate here would mean the operator approving still could not look.
   *
   * ONE AT A TIME, never a list field. Every reveal is an audited decrypt on a
   * dead person's trail, so the cost is per row and the caller has to ask for
   * each one (docs/03 §6f — no content field on a list type, no prefetch).
   *
   * THE RECORD GOES FIRST, because it records a disclosure — the rule
   * `ContactLinksService.estatesNaming` states and this service now shares
   * (docs/06, 2026-08-20). An event written after the decrypt is an event a
   * crash can lose while the plaintext already exists, and here that would
   * leave an actor-attributed `crypto.field.decrypted` on a dead person's
   * trail with nothing saying what authorised it. The ordering costs a
   * false positive in the shred arm below — a recorded view of a value that
   * turned out to be unreadable — and an over-record is the safe direction:
   * the failure it prevents is a disclosure with no record at all.
   *
   * NULL FOR A ROW WITH NO AMOUNT, which is not a refusal: `amount_ct` is
   * nullable by design (a distribution may name an asset rather than a sum), so
   * "nothing was recorded" is an answer and must not read as one of the two
   * failures around it. A CRYPTO-SHREDDED estate is the THIRD fact and gets
   * its own answer — `content_erased`, the spelling `DocumentsService` already
   * uses for exactly this, because "never recorded" and "erased under a legal
   * request" are different truths and 500 is neither.
   */
  async distributionAmount(
    actor: string,
    sessionId: string,
    distributionId: string,
  ): Promise<{ amount: string | null }> {
    const row = await this.distributions.findById(this.db, distributionId);
    // Authority BEFORE anything is said about this row (M23 PR1): a missing
    // distribution and one on a case this caller cannot see leave through the
    // same line, so holding an id proves nothing about whether it names
    // anything.
    const { kase } = await this.assertCaseVisible(actor, row?.case_id ?? MISSING_CASE);
    if (row === null) {
      throw new NotFoundException({ error: 'not_found' });
    }
    if (row.amount_ct === null || row.dek_id === null) {
      return { amount: null };
    }
    await this.events.distributionAmountViewed(
      actor,
      sessionId,
      kase.decedent_user_id,
      kase.id,
      distributionId,
    );
    let plaintext: Buffer;
    try {
      plaintext = await this.fieldCrypto.decryptField({
        userId: kase.decedent_user_id,
        dekId: row.dek_id,
        field: DISTRIBUTION_AMOUNT_FIELD,
        ciphertext: row.amount_ct,
        actorId: actor,
        actorType: 'user',
        purpose: 'distribution_amount',
      });
    } catch (err) {
      if (err instanceof DekDestroyedError) {
        // Crypto-shredded: the ledger row survives, the sum does not.
        throw new GoneException({ error: 'content_erased' });
      }
      throw err;
    }
    // A decimal STRING end to end — never parsed to a number at any layer.
    return { amount: plaintext.toString('utf8') };
  }

  async setDistributionStatus(
    actor: string,
    sessionId: string,
    distributionId: string,
    to: Extract<DistributionStatus, 'in_progress' | 'completed' | 'disputed'>,
  ): Promise<DistributionDto> {
    const row = await this.db.withTransaction(actor, async (tx) => {
      // AUTHORISE BEFORE ANSWERING ANYTHING ABOUT THIS ROW.
      //
      // This was the one operator-reachable write verb that refused in three
      // distinguishable ways: 404 for an unknown id, 409 `case_not_verified`
      // for a case that exists but is not administrable, and 403 for a real
      // administrable case the caller had no authority over. Holding a
      // distribution UUID was therefore enough to track an estate's settlement
      // progress after losing authority over it — a former or replaced executor
      // is the concrete holder, and the id is a v4 UUID so this was never blind
      // enumeration.
      //
      // THIS COMMENT ONCE CLAIMED "every sibling verb gates first". It was
      // false when written: `requestStage`, `completeTask` and
      // `recordDistribution` all looked the row up first too, by way of
      // `requireAdministrableCase`, and went on leaking for two milestones
      // behind a sentence asserting they did not. M23 PR1 fixed all three
      // through `administrableCaseFor`. A rule applied to one member of a
      // category is a rule half-applied — and prose that asserts a fact about
      // the rest of the file is a test nobody runs.
      //
      // The lookup CANNOT move: the executor arm of the authority test needs
      // the case to know whose estate it is. So the refusals are what get
      // fixed, not the order — every one of them is now the same 404 an unknown
      // id gets, which is the rule `assertCaseVisible` already states in this
      // file. Only a caller with authority may learn that the case is real but
      // not yet administrable.
      //
      // NOT `assertCaseVisible`, deliberately: that admits the decedent and the
      // reporter as well, and neither of them may move money. Same refusal
      // shape, narrower authority.
      const locked = await this.distributions.lockById(tx, distributionId);
      const kase = locked ? await this.cases.lockById(tx, locked.case_id) : null;
      // Asked unconditionally so the work done before a refusal does not itself
      // vary with whether the id was real.
      const isOperator = await this.gate.is(tx, actor);
      const authorised =
        kase !== null &&
        (isOperator || (await this.coreReads.isExecutorOf(kase.decedent_user_id, actor)));
      if (locked === null || kase === null || !authorised) {
        throw new NotFoundException({ error: 'not_found' });
      }
      if (!ADMINISTRABLE.includes(kase.status)) {
        // Reachable only by someone with authority over this case, so it is
        // safe to be specific — and useful, because their remedy differs.
        throw new ConflictException({ error: 'case_not_verified' });
      }
      // Nothing moves until dual control has been satisfied.
      const from: DistributionStatus[] =
        to === 'disputed'
          ? ['approved', 'in_progress', 'completed']
          : to === 'in_progress'
            ? ['approved']
            : ['in_progress'];
      if (!(await this.distributions.setStatus(tx, distributionId, from, to))) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      return {
        distribution: (await this.distributions.lockById(tx, distributionId)) as DistributionRow,
        decedentUserId: kase.decedent_user_id,
        asOperator: isOperator,
      };
    });
    if (to === 'completed') {
      await this.events.distributionCompleted(
        actor,
        sessionId,
        row.distribution.case_id,
        row.decedentUserId,
        distributionId,
        row.asOperator,
      );
    }
    return distributionDto(row.distribution);
  }

  async listDistributions(
    actor: string,
    sessionId: string,
    caseId: string,
  ): Promise<DistributionDto[]> {
    const { kase, isOperator } = await this.assertCaseVisible(actor, caseId);
    const rows = await this.distributions.listByCase(this.db, caseId);
    await this.recordOperatorRead(actor, sessionId, kase, isOperator, 'distributions');
    return rows.map(distributionDto);
  }

  // -------------------------------------------------------------- case close

  /** Close a fully administered case (operator). Refuses while work is open. */
  async closeCase(
    operator: string,
    sessionId: string,
    caseId: string,
  ): Promise<{ status: string }> {
    const closed = await this.db.withTransaction(operator, async (tx) => {
      await this.gate.assertIn(tx, operator);
      const locked = await this.cases.lockById(tx, caseId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      if (!ADMINISTRABLE.includes(locked.status)) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      if ((await this.distributions.countOpen(tx, caseId)) > 0) {
        throw new ConflictException({ error: 'distributions_open' });
      }
      if (!(await this.cases.advanceStatus(tx, caseId, ADMINISTRABLE, 'closed'))) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      return {
        decedentUserId: locked.decedent_user_id,
        breadth: await this.breadth.record(tx, operator, caseId, 'case.closed', this.clock()),
      };
    });
    await this.events.caseClosed(operator, sessionId, caseId, closed.decedentUserId);
    if (this.breadth.exceeded(closed.breadth)) {
      await this.events.operatorBreadthExceeded(
        operator,
        sessionId,
        closed.breadth,
        OPERATOR_BREADTH_MAX_CASES,
        OPERATOR_BREADTH_WINDOW_MS,
      );
    }
    return { status: 'closed' };
  }

  // --------------------------------------------------------------- authority

  /**
   * "May this caller act on this estate at this stage?" — asked by assets (and
   * any later data service). Three conjuncts, all required: an administrable
   * case exists, the caller is its executor, and the stage is approved.
   */
  async stageAccessAuthority(
    actor: string,
    ownerUserId: string,
    stage: AccessStage,
  ): Promise<{ allowed: boolean; caseId: string | null }> {
    const refused = { allowed: false, caseId: null };
    const kase = await this.cases.findNonTerminalByDecedent(this.db, ownerUserId);
    if (!kase || !ADMINISTRABLE.includes(kase.status)) {
      return refused;
    }
    if (!(await this.coreReads.isExecutorOf(ownerUserId, actor))) {
      return refused;
    }
    if (!(await this.stages.isApproved(this.db, kase.id, stage))) {
      return refused;
    }
    return { allowed: true, caseId: kase.id };
  }

  /**
   * "May vault emergency access proceed for this owner?" (docs/03 §6a).
   *
   * Permitted when the owner has no non-terminal case, or has one whose
   * `vault` stage is approved. A case that is merely REPORTED blocks: stages
   * only exist after verification, so a pending death report necessarily
   * freezes Zone A emergency release.
   *
   * That is the deliberate direction. §5.1's whole design is that a death
   * report must make access harder while the claim is unproven; the
   * availability cost — a malicious or mistaken report suspends emergency
   * access until an operator rejects it — falls on the side of the owner who
   * may still be alive, and the owner's own step-up void clears it instantly.
   */
  async vaultReleaseAuthority(
    ownerUserId: string,
  ): Promise<{ permitted: boolean; caseId: string | null }> {
    const kase = await this.cases.findNonTerminalByDecedent(this.db, ownerUserId);
    if (!kase || !NON_TERMINAL.includes(kase.status)) {
      return { permitted: true, caseId: null };
    }
    const approved = await this.stages.isApproved(this.db, kase.id, 'vault');
    return { permitted: approved, caseId: kase.id };
  }

  // ---------------------------------------------------------------- timeline

  /** The estate timeline: case milestones + stage decisions, oldest first. */
  async timeline(actor: string, sessionId: string, caseId: string): Promise<TimelineEntry[]> {
    const { kase, isOperator } = await this.assertCaseVisible(actor, caseId);
    const entries: TimelineEntry[] = [
      {
        at: kase.created_at.toISOString(),
        kind: 'case.reported',
        detail: { source: kase.report_source },
      },
    ];
    if (kase.human_review_at) {
      entries.push({
        at: kase.human_review_at.toISOString(),
        kind: 'case.reviewed',
        detail: {},
      });
    }
    if (kase.waiting_period_ends) {
      entries.push({
        at: kase.waiting_period_ends.toISOString(),
        kind: 'case.waiting_period_ends',
        detail: {},
      });
    }
    if (kase.verified_at) {
      entries.push({ at: kase.verified_at.toISOString(), kind: 'case.verified', detail: {} });
    }
    if (kase.resolved_at) {
      entries.push({
        at: kase.resolved_at.toISOString(),
        kind: 'case.resolved',
        detail: { resolution: kase.resolution ?? 'unknown' },
      });
    }
    for (const stage of await this.stages.listByCase(this.db, caseId)) {
      entries.push({
        at: stage.requested_at.toISOString(),
        kind: 'stage.requested',
        detail: { stage: stage.stage },
      });
      if (stage.decided_at) {
        entries.push({
          at: stage.decided_at.toISOString(),
          kind: `stage.${stage.status}`,
          detail: { stage: stage.stage },
        });
      }
    }
    const sorted = entries.sort((a, b) => a.at.localeCompare(b.at));
    // After the rows are gathered, before they are returned — see
    // `recordOperatorRead`. This site emitted BEFORE reading the stage rows
    // until the PR3b review; it was the only one of the four that did.
    await this.recordOperatorRead(actor, sessionId, kase, isOperator, 'timeline');
    return sorted;
  }

  // ----------------------------------------------------------------- helpers

  /** Generate the checklist for a freshly verified case (same transaction). */
  async generateChecklist(tx: Queryable, caseId: string, verifiedAt: Date): Promise<number> {
    return this.tasks.insertMany(tx, caseId, generateTasks(verifiedAt));
  }

  /** The estate a case belongs to, for key selection outside a transaction. */
  /**
   * Whose estate this case settles, for an ALREADY-AUTHORISED operator path.
   *
   * `revokeStage` is its only caller and reaches it after `gate.assertIn`, at a
   * point where the case id came from a row it just locked rather than from the
   * caller. The executor-facing variant below is the one that authorises.
   */
  private async requireDecedentFor(caseId: string): Promise<string> {
    const kase = await this.cases.findById(this.db, caseId);
    if (!kase) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return kase.decedent_user_id;
  }

  /**
   * Whose estate this case settles — answered ONLY to its executor.
   *
   * Was `requireDecedentFor`, which answered to anybody and existed purely to
   * name the DEK subject for an encrypt that happens outside the transaction.
   * That made an unauthorised caller's refusal cost a KMS operation on the
   * decedent's key. Same uniform 404 as everywhere else in this file.
   */
  private async requireAdministeredDecedentFor(caseId: string, actor: string): Promise<string> {
    const kase = await this.cases.findById(this.db, caseId);
    const authorised =
      kase !== null && (await this.coreReads.isExecutorOf(kase.decedent_user_id, actor));
    if (kase === null || !authorised) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return kase.decedent_user_id;
  }

  /**
   * Check a case is administrable, for a caller whose authority is ALREADY
   * ESTABLISHED.
   *
   * Every remaining caller is an operator path that has passed
   * `OperatorGate.assertIn` before reaching this line, so answering
   * `case_not_verified` here tells them nothing they were not entitled to
   * know. THAT PRECONDITION IS THE WHOLE CONTRACT: this helper looks safe and
   * is not, which is how `requestStage`, `completeTask` and
   * `recordDistribution` came to leak — they called it FIRST and tested
   * authority afterwards. An executor-facing caller wants
   * `administrableCaseFor`, which establishes authority itself.
   */
  private async requireAdministrableCase(tx: Queryable, caseId: string): Promise<CaseRow> {
    const locked = await this.cases.lockById(tx, caseId);
    if (!locked) {
      throw new NotFoundException({ error: 'not_found' });
    }
    if (!ADMINISTRABLE.includes(locked.status)) {
      throw new ConflictException({ error: 'case_not_verified' });
    }
    return locked;
  }

  /**
   * Locate a case, ESTABLISH AUTHORITY OVER IT, and only then say anything
   * about it (M23 PR1).
   *
   * This used to be `requireAdministrableCase`, which answered 404 for an
   * unknown id and 409 `case_not_verified` for a real pre-verification case
   * BEFORE its callers tested whether the caller was the estate's executor —
   * so `requestStage` refused three distinguishable ways and a caller holding
   * a case UUID with no authority over it learned both that the case was real
   * and roughly what state it was in. Case ids are v4 UUIDs, so this was never
   * blind enumeration: the concrete holder is a former or replaced executor,
   * or the reporter, and what they could track is an estate's settlement
   * progress after losing any right to it.
   *
   * M21 PR4d fixed exactly this on `setDistributionStatus` and said in a
   * comment that "every sibling verb gates first". That was not true —
   * `requestStage`, `completeTask` and `recordDistribution` all looked the row
   * up first — and the prose has been corrected where it sits. Fixing one
   * member of a category is fixing it half.
   *
   * WHAT IS DELIBERATELY STILL SPECIFIC: `case_not_verified`, once authority
   * is established. It is reachable only by this estate's executor, their
   * remedy genuinely differs from a 404's, and fail-closed means DE-ESCALATE
   * rather than withhold the answer from the person entitled to it.
   *
   * NOT `assertCaseVisible`: that admits the decedent and the reporter too, and
   * neither of them may administer an estate. Same refusal shape, narrower
   * authority — PR4d's own distinction.
   */
  private async administrableCaseFor(
    tx: Queryable,
    caseId: string | null,
    actor: string,
  ): Promise<CaseRow> {
    const locked = caseId === null ? null : await this.cases.lockById(tx, caseId);
    const authorised =
      locked !== null && (await this.coreReads.isExecutorOf(locked.decedent_user_id, actor));
    if (locked === null || !authorised) {
      // The SAME answer an unknown id gets. A caller without authority learns
      // nothing about whether the id names anything.
      throw new NotFoundException({ error: 'not_found' });
    }
    if (!ADMINISTRABLE.includes(locked.status)) {
      // Pre-verification (or terminal) cases have no administration surface at
      // all — this is what keeps a fresh report from granting anything.
      throw new ConflictException({ error: 'case_not_verified' });
    }
    return locked;
  }

  /** The ladder: every earlier stage must already be approved. */
  private async assertPredecessorApproved(
    tx: Queryable,
    caseId: string,
    stage: AccessStage,
  ): Promise<void> {
    const index = ACCESS_STAGES.indexOf(stage);
    for (const earlier of ACCESS_STAGES.slice(0, index)) {
      if (!(await this.stages.isApproved(tx, caseId, earlier))) {
        throw new ConflictException({ error: 'stage_out_of_order' });
      }
    }
  }

  /**
   * Record a case read that the OPERATOR ALLOWLIST is behind (M21 PR3b).
   *
   * A no-op for everyone else by construction: the decedent, the reporter and
   * the estate's executor are reading their own case, which the rest of the
   * product does not audit as a disclosure either. What docs/03 §4 TB7 asks
   * for is a record of platform staff looking at somebody's death case, and
   * that is exactly the set this admits.
   *
   * EMITTED AFTER THE ROWS ARE GATHERED AND BEFORE THEY ARE RETURNED, at all
   * four call sites — `timeline` was the odd one out until the PR3b review and
   * has been moved. The emit is awaited, and the audit path is fail-closed, so
   * on this ordering nothing is disclosed without a record either way; what it
   * additionally buys is that a read which THREW leaves no record claiming it
   * completed.
   *
   * THIS IS THE OPPOSITE OF M19's `estate.viewed` ORDERING AND DELIBERATELY SO,
   * because the two situations differ in the one way that decides it. There the
   * work being recorded was a DECRYPT LOOP that released plaintext row by row,
   * so a failure half way had already disclosed — the record had to precede it.
   * Here the rows are gathered by one query and released only after the emit has
   * succeeded, so there is no partial disclosure for a record to be late for.
   * The rule is not "always before" or "always after": it is that the record
   * must exist before anything leaves, and where release is incremental that
   * means before the work.
   */
  private async recordOperatorRead(
    actor: string,
    sessionId: string,
    kase: CaseRow,
    isOperator: boolean,
    surface: 'timeline' | 'stages' | 'tasks' | 'distributions',
  ): Promise<void> {
    if (!isOperator) return;
    await this.events.caseViewed(actor, sessionId, kase.id, kase.decedent_user_id, surface);
  }

  /**
   * Case reads: the subject, the reporter, its executor, or an operator.
   *
   * Returns the operator flag as well as the row, because M21 PR3b audits
   * OPERATOR reads and the answer must not depend on which clause admitted
   * the caller. The gate is therefore consulted UNCONDITIONALLY and up front,
   * rather than as the second arm of the chain it used to be: an operator who
   * is also the reporter of a case is still platform staff reading a death
   * case, and if the subject/reporter clause short-circuited first their read
   * would go unrecorded — an audit claim whose truth turned on the order of an
   * `if`. One extra indexed lookup on the caller's own reads is the price, and
   * `settlement.case.viewed` is worth more than it.
   */
  private async assertCaseVisible(
    actor: string,
    caseId: string,
  ): Promise<{ kase: CaseRow; isOperator: boolean }> {
    const kase = await this.cases.findById(this.db, caseId);
    if (!kase) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const isOperator = await this.gate.is(this.db, actor);
    if (
      kase.decedent_user_id === actor ||
      kase.reported_by === actor ||
      isOperator ||
      (await this.coreReads.isExecutorOf(kase.decedent_user_id, actor))
    ) {
      return { kase, isOperator };
    }
    // The SAME answer the missing case above gives. Every read that funnels
    // through here is scoped by a case id, so a 403 would tell an unrelated
    // caller that the id names a real case (see SettlementAuthz.assertCanOrNotFound).
    throw new NotFoundException({ error: 'not_found' });
  }
}
