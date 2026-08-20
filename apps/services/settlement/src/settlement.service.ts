import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { SettlementAuthz, caseResource, settingsResource } from './authz.service';
import { OperatorBreadthMonitor } from './operator-breadth.monitor';
import { OPERATOR_BREADTH_MAX_CASES, OPERATOR_BREADTH_WINDOW_MS } from './operator-breadth';
import { CasesRepo, type CaseRow, type EvidenceEntry } from './cases.repo';
import type { SettlementConfig } from './config';
import { ContactAttemptsRepo, type ContactChannel } from './contact-attempts.repo';
import { CoreReadsRepo, type ReportableEstate } from './core-reads.repo';
import {
  CLOCK,
  CONFIG,
  DOCUMENTS_HOLD,
  IDENTITY_LOCK,
  NOTIFIER,
  SYSTEM_ACTOR_ID,
  type Clock,
} from './di-tokens';
import { Db, isUniqueViolation } from './db';
import { DocumentsHoldError, type DocumentsHoldPort } from './documents-hold';
import { EventsService } from './events.service';
import { IdentityLockError, OwnerAliveError, type IdentityLockPort } from './identity-lock';
import type { NotificationPort, NotifyOutcome } from './notifications';
import { OperatorGate } from './operator-gate';
import { SettingsRepo, DEFAULT_WAITING_PERIOD_DAYS } from './settings.repo';
import { TasksRepo } from './tasks.repo';
import { generateTasks } from './task-template';
import type {
  EvidenceInput,
  ProviderReportInput,
  ReportCaseInput,
  ReviewDecisionInput,
  SettingsInput,
} from './schemas';

export interface CaseDto {
  caseId: string;
  decedentUserId: string;
  status: string;
  reportSource: string;
  reportedBy: string;
  evidence: EvidenceEntry[];
  humanReviewBy: string | null;
  humanReviewAt: string | null;
  /**
   * Who picked this case up, and when (M21 PR3b). Distinct from
   * humanReviewBy — which records who APPROVED the review and is written at
   * the decision — because a shared queue needs to say "taken" before anyone
   * has decided anything, and the two can legitimately be different people.
   */
  claimedBy: string | null;
  claimedAt: string | null;
  waitingPeriodEnds: string | null;
  verifiedAt: string | null;
  resolution: string | null;
  resolvedAt: string | null;
  createdAt: string;
  updatedAt: string;
  /** waiting_period whose deadline has lapsed — confirmable, never auto-advanced. */
  eligibleForVerification: boolean;
}

export interface EvidenceReadAnswer {
  allowed: boolean;
  caseId: string | null;
  ownerUserId: string | null;
}

/** Owner-contact schedule: one attempt per slot, channels cycling (docs/03
 * §5.1 control 3 "through every channel"). seq 0 is the report-time
 * notification; waiting-period slots (seq >= 1) open every 12h from review
 * approval. */
export const CONTACT_INTERVAL_HOURS = 12;
export const CONTACT_CHANNELS: readonly ContactChannel[] = ['push', 'email', 'sms', 'voice'];

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

function toDto(row: CaseRow, now: Date): CaseDto {
  return {
    caseId: row.id,
    decedentUserId: row.decedent_user_id,
    status: row.status,
    reportSource: row.report_source,
    reportedBy: row.reported_by,
    evidence: row.verification_evidence,
    humanReviewBy: row.human_review_by,
    humanReviewAt: row.human_review_at?.toISOString() ?? null,
    claimedBy: row.claimed_by,
    claimedAt: row.claimed_at?.toISOString() ?? null,
    waitingPeriodEnds: row.waiting_period_ends?.toISOString() ?? null,
    verifiedAt: row.verified_at?.toISOString() ?? null,
    resolution: row.resolution,
    resolvedAt: row.resolved_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
    eligibleForVerification:
      row.status === 'waiting_period' &&
      row.waiting_period_ends !== null &&
      row.waiting_period_ends.getTime() <= now.getTime(),
  };
}

/**
 * The docs/03 §5.1 case state machine. Structural rules, restated because
 * every one of them is a control, not a convenience:
 *
 *  - No single source and no single actor advances a case: intake only OPENS
 *    a case; an operator (never the reporter — CHECK + row check) moves it
 *    through review; a lapsed waiting period makes it ELIGIBLE; a second
 *    explicit operator action confirms verification, and that confirmation
 *    re-checks owner liveness against identity.
 *  - The workflow driver holds no transition power. Its only write is the
 *    contact-attempt trail.
 *  - Every identity-lock effect happens INSIDE the case transaction, before
 *    COMMIT: a transition whose account-lock effect cannot be confirmed rolls
 *    back (fail closed). The cost — an HTTP call inside an open transaction —
 *    is accepted and bounded by the lock routes' triviality; the identity
 *    side is idempotent, so a commit failure after a successful lock is
 *    healed by retry.
 *  - The estate-wide legal hold (M9 PR2) is paired with the lock at every
 *    site: set with deceased_pending at review-approve, re-asserted with the
 *    terminal lock at verification (catching documents uploaded during the
 *    wait), cleared with every restore to active. Same fail-closed rollback,
 *    same idempotent re-drive on the documents side.
 *  - ORDER WITHIN A TRANSITION IS ITSELF A CONTROL, and it differs by site.
 *    Where the identity state is REVERSIBLE (approve), the lock goes first, so
 *    a failed hold cannot strand a hold on a living owner whose reject path
 *    would not clear it. Where it is IRREVERSIBLE (verification's terminal
 *    `settlement`), the hold goes first, so a failed hold cannot leave an
 *    account terminally locked under a case that rolled back. The rule is:
 *    the step that cannot be undone runs LAST. The M9 security review found
 *    verification had it backwards.
 *  - Intake and review-approve REFUSE in production while only the stub
 *    notifier is wired (M6 precedent): a waiting period nobody can be told
 *    about is not a control.
 */
@Injectable()
export class SettlementService {
  constructor(
    private readonly db: Db,
    private readonly cases: CasesRepo,
    private readonly attempts: ContactAttemptsRepo,
    private readonly gate: OperatorGate,
    private readonly breadth: OperatorBreadthMonitor,
    private readonly settings: SettingsRepo,
    private readonly tasks: TasksRepo,
    private readonly coreReads: CoreReadsRepo,
    private readonly authz: SettlementAuthz,
    private readonly events: EventsService,
    @Inject(NOTIFIER) private readonly notifier: NotificationPort,
    @Inject(IDENTITY_LOCK) private readonly identity: IdentityLockPort,
    @Inject(DOCUMENTS_HOLD) private readonly documentsHold: DocumentsHoldPort,
    @Inject(CONFIG) private readonly config: SettlementConfig,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  // ------------------------------------------------------------------- intake

  async reportableEstates(actor: string): Promise<ReportableEstate[]> {
    return this.coreReads.reportableEstates(actor);
  }

  /**
   * Reporter intake (trusted_contact / death_certificate_upload). The caller
   * must be the linked platform user of a live contact of the decedent —
   * resolved in SQL, uniform not_found otherwise, no lookup by email or
   * arbitrary id (the anti-enumeration boundary).
   */
  async report(actor: string, sessionId: string, input: ReportCaseInput): Promise<CaseDto> {
    await this.assertNotificationsUsable();
    if (input.decedentUserId === actor) {
      // Reporting yourself dead is never a legitimate flow.
      throw new BadRequestException({ error: 'invalid_request' });
    }
    const linked = await this.coreReads.isLinkedContact(input.decedentUserId, actor);
    if (!linked) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const now = this.clock();
    const evidence: EvidenceEntry[] = input.evidence.map((e) => this.toEntry(e, actor, now));
    const row = await this.insertCase({
      decedentUserId: input.decedentUserId,
      reportedBy: actor,
      source: input.source,
      evidence,
      now,
    });
    await this.events.caseReported(actor, sessionId, row.id, row.decedent_user_id, input.source);
    await this.notifyOwner('case_opened', row);
    return toDto(row, now);
  }

  /**
   * Operator-filed provider-signal intake (docs/01 §2.7: death-data providers
   * are SIGNALS, never triggers — a match opens a case for human review like
   * any other report). No contact-link requirement: the operator files on the
   * provider's behalf, and the operator allowlist is the gate.
   */
  async reportProviderSignal(
    operator: string,
    sessionId: string,
    input: ProviderReportInput,
  ): Promise<CaseDto> {
    await this.assertNotificationsUsable();
    // On the POOL, and that is the correct handle here: this route owns no
    // transaction — `insertCase` opens its own, and it is shared with the
    // trusted-contact path, whose gate is the linked-contact check rather than
    // the allowlist. A caller that owns a transaction asks inside it; one that
    // does not asks the pool (OperatorGate.is).
    await this.gate.assertIn(this.db, operator);
    if (input.decedentUserId === operator) {
      throw new BadRequestException({ error: 'invalid_request' });
    }
    const now = this.clock();
    const evidence: EvidenceEntry[] = input.providerMatchIds.map((matchId) => ({
      type: 'provider_match',
      matchId,
      addedBy: operator,
      addedAt: now.toISOString(),
    }));
    const row = await this.insertCase({
      decedentUserId: input.decedentUserId,
      reportedBy: operator,
      source: 'data_provider',
      evidence,
      now,
    });
    await this.events.caseReported(
      operator,
      sessionId,
      row.id,
      row.decedent_user_id,
      'data_provider',
      // This route is operator-gated (`gate.assertIn` above) and is the only
      // intake path that needs no linked contact, so the actor class is the
      // one fact the trail must not get wrong.
      true,
    );
    await this.notifyOwner('case_opened', row);
    return toDto(row, now);
  }

  async addEvidence(
    actor: string,
    sessionId: string,
    caseId: string,
    input: EvidenceInput,
  ): Promise<CaseDto> {
    const now = this.clock();
    let isOperator = false;
    const row = await this.db.withTransaction(actor, async (tx) => {
      // Resolved on `tx`, not the pool: the answer that authorizes this write
      // belongs to the transaction that performs it (OperatorGate.is). It is
      // hoisted out because the audit event below reports the capacity the
      // caller acted in.
      isOperator = await this.gate.is(tx, actor);
      const locked = await this.cases.lockById(tx, caseId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      this.authz.assertCan(
        actor,
        isOperator,
        'evidence_add',
        caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
      );
      if (locked.status !== 'reported' && locked.status !== 'verifying') {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      await this.cases.appendEvidence(tx, caseId, this.toEntry(input, actor, now));
      return (await this.cases.findById(tx, caseId)) as CaseRow;
    });
    await this.events.evidenceAdded(
      actor,
      sessionId,
      caseId,
      row.decedent_user_id,
      input.type,
      isOperator,
    );
    return toDto(row, now);
  }

  // ------------------------------------------------------------------- review

  async startReview(operator: string, sessionId: string, caseId: string): Promise<CaseDto> {
    const now = this.clock();
    const started = await this.db.withTransaction(operator, async (tx) => {
      // BEFORE lockById, deliberately: a non-operator must be refused without
      // learning whether the case id names anything (the uniform-404 rule).
      // INSIDE the transaction, so the allowlist answer and the row it
      // authorizes come from one handle — see OperatorGate.is.
      const isOperator = await this.gate.assertIn(tx, operator);
      const locked = await this.cases.lockById(tx, caseId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      this.authz.assertCan(
        operator,
        isOperator,
        'review',
        caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
      );
      if (locked.reported_by === operator) {
        // Dual control, refused at the CLAIM rather than only at the decision
        // (M21 PR3b). decideReview and confirmVerification have always thrown
        // this, and the DDL has always backstopped it — but nothing stopped a
        // reporter-operator claiming the case first, which moved it to
        // `verifying` and put their name on a review they could never
        // discharge. Now that the claim is recorded and shown on a shared
        // queue, a claim has to mean "I may decide this".
        throw new ForbiddenException({ error: 'reviewer_is_reporter' });
      }
      if (!(await this.cases.markReviewStarted(tx, caseId, operator, now))) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      return {
        kase: (await this.cases.findById(tx, caseId)) as CaseRow,
        breadth: await this.breadth.record(tx, operator, caseId, 'review.started', now),
      };
    });
    const { kase: row } = started;
    await this.events.reviewStarted(operator, sessionId, caseId, row.decedent_user_id);
    if (this.breadth.exceeded(started.breadth)) {
      await this.events.operatorBreadthExceeded(
        operator,
        sessionId,
        started.breadth,
        OPERATOR_BREADTH_MAX_CASES,
        OPERATOR_BREADTH_WINDOW_MS,
      );
    }
    return toDto(row, now);
  }

  /**
   * The mandatory human review (docs/03 §5.1 control 2). Approve starts the
   * waiting period and locks the account to deceased_pending; reject
   * terminates the case (restoring the account if it was already locked —
   * reject is allowed from waiting_period too, for evidence that falls apart
   * during the wait).
   */
  async decideReview(
    operator: string,
    sessionId: string,
    caseId: string,
    input: ReviewDecisionInput,
  ): Promise<CaseDto> {
    const now = this.clock();
    let outcome: {
      row: CaseRow;
      waitingPeriodEnds: Date | null;
      restored: boolean;
      breadth: number;
    };
    try {
      outcome = await this.db.withTransaction(operator, async (tx) => {
        const isOperator = await this.gate.assertIn(tx, operator);
        const locked = await this.cases.lockById(tx, caseId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        this.authz.assertCan(
          operator,
          isOperator,
          'review',
          caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
        );
        if (locked.reported_by === operator) {
          // Dual control: the DDL CHECK is the backstop; this is the readable
          // refusal (docs/02 §7's approver-≠-recorder rule, applied to review).
          throw new ForbiddenException({ error: 'reviewer_is_reporter' });
        }

        if (input.decision === 'approve') {
          await this.assertNotificationsUsable();
          if (locked.status !== 'verifying') {
            throw new ConflictException({ error: 'invalid_transition' });
          }
          const days = Math.max(
            DEFAULT_WAITING_PERIOD_DAYS,
            await this.settings.waitingPeriodDays(tx, locked.decedent_user_id),
          );
          const ends = new Date(now.getTime() + days * DAY_MS);
          await this.cases.markApproved(tx, caseId, operator, now, ends);
          // Account lock INSIDE the transaction: an unconfirmed lock rolls
          // the approval back (docs/03 §5.1 control 4, fail closed).
          await this.identity.setState(locked.decedent_user_id, 'deceased_pending', caseId);
          // Legal hold rides the lock (M9 PR2): from this instant the estate
          // is under administration and its documents must not be deletable.
          await this.documentsHold.setHold(locked.decedent_user_id, true, caseId);
          const row = (await this.cases.findById(tx, caseId)) as CaseRow;
          return {
            row,
            waitingPeriodEnds: ends,
            restored: false,
            breadth: await this.breadth.record(tx, operator, caseId, 'review.approved', now),
          };
        }

        if (locked.status !== 'verifying' && locked.status !== 'waiting_period') {
          throw new ConflictException({ error: 'invalid_transition' });
        }
        const wasLocked = locked.status === 'waiting_period';
        await this.cases.markResolved(
          tx,
          caseId,
          ['verifying', 'waiting_period'],
          'operator_rejected',
          now,
          locked.status === 'verifying' ? { id: operator, at: now } : null,
        );
        if (wasLocked) {
          await this.identity.setState(locked.decedent_user_id, 'active', caseId);
          // The claim fell apart, so the hold set at approval lifts with the
          // lock — a rejected case must not leave documents frozen.
          await this.documentsHold.setHold(locked.decedent_user_id, false, caseId);
        }
        const row = (await this.cases.findById(tx, caseId)) as CaseRow;
        // The REJECT arm records nothing. Rejecting terminates the case and
        // restores the account: it is the protective decision, and an operator
        // must never approach a ceiling by refusing things.
        return { row, waitingPeriodEnds: null, restored: wasLocked, breadth: 0 };
      });
    } catch (err) {
      throw this.mapIdentityFailure(err);
    }

    const { row, waitingPeriodEnds } = outcome;
    if (input.decision === 'approve') {
      await this.events.caseApproved(
        operator,
        sessionId,
        caseId,
        row.decedent_user_id,
        waitingPeriodEnds as Date,
      );
    } else {
      await this.events.caseRejected(
        operator,
        sessionId,
        caseId,
        row.decedent_user_id,
        input.reason ?? 'other',
        row.reported_by,
      );
    }
    if (this.breadth.exceeded(outcome.breadth)) {
      await this.events.operatorBreadthExceeded(
        operator,
        sessionId,
        outcome.breadth,
        OPERATOR_BREADTH_MAX_CASES,
        OPERATOR_BREADTH_WINDOW_MS,
      );
    }
    return toDto(row, now);
  }

  // ----------------------------------------------------------- owner controls

  /**
   * The owner's kill switch (docs/03 §5.1 control 3): step-up-gated at the
   * controller, valid at any pre-verification stage, restores the account and
   * flags the reporter. Post-verification rescue is deliberately NOT
   * self-serve — that is an operator ceremony which does not exist yet.
   */
  async void(owner: string, sessionId: string, caseId: string): Promise<CaseDto> {
    const now = this.clock();
    let row: CaseRow;
    try {
      row = await this.db.withTransaction(owner, async (tx) => {
        const locked = await this.cases.lockById(tx, caseId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        // `false` is DELIBERATE and is not the literal M21 PR2 removed. This
        // is the OWNER's kill switch, and the owner is evaluated purely as the
        // decedent: measuring the allowlist here would WIDEN the decision for
        // an owner who happens also to be an operator, which is the wrong
        // direction on the one route a subject uses against their own case.
        this.authz.assertCan(
          owner,
          false,
          'void',
          caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
        );
        if (
          locked.status !== 'reported' &&
          locked.status !== 'verifying' &&
          locked.status !== 'waiting_period'
        ) {
          throw new ConflictException({ error: 'invalid_transition' });
        }
        await this.cases.markResolved(
          tx,
          caseId,
          ['reported', 'verifying', 'waiting_period'],
          'owner_voided',
          now,
          null,
        );
        // Always restore: a no-op when the case never reached the lock stage
        // (identity's transition table treats same-state as idempotent), and
        // the hold-clear below is idempotent the same way.
        await this.identity.setState(locked.decedent_user_id, 'active', caseId);
        await this.documentsHold.setHold(locked.decedent_user_id, false, caseId);
        return (await this.cases.findById(tx, caseId)) as CaseRow;
      });
    } catch (err) {
      throw this.mapIdentityFailure(err);
    }
    await this.events.caseVoided(
      owner,
      sessionId,
      caseId,
      row.decedent_user_id,
      'owner_route',
      row.reported_by,
    );
    return toDto(row, now);
  }

  // ------------------------------------------------------------- verification

  /**
   * Post-waiting-period confirmation. Timer expiry is necessary, never
   * sufficient: verification is an explicit operator action, and it re-checks
   * owner liveness against identity's append-only step-up ledger. A step-up
   * newer than the case voids the case on the spot (docs/03 §5.1: "any owner
   * sign-in with step-up MFA instantly voids the case") — the operator's
   * confirmation attempt becomes the void, audited as such.
   */
  async confirmVerification(operator: string, sessionId: string, caseId: string): Promise<CaseDto> {
    const now = this.clock();
    let outcome: { row: CaseRow; voided: boolean; breadth: number };
    let taskCount = 0;
    try {
      outcome = await this.db.withTransaction(operator, async (tx) => {
        const isOperator = await this.gate.assertIn(tx, operator);
        const locked = await this.cases.lockById(tx, caseId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        this.authz.assertCan(
          operator,
          isOperator,
          'verify',
          caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
        );
        if (locked.reported_by === operator) {
          throw new ForbiddenException({ error: 'reviewer_is_reporter' });
        }
        if (locked.status !== 'waiting_period' || !locked.waiting_period_ends) {
          throw new ConflictException({ error: 'invalid_transition' });
        }
        if (locked.waiting_period_ends.getTime() > now.getTime()) {
          throw new ForbiddenException({ error: 'waiting_period_active' });
        }

        // Owner-liveness re-check, fail closed: unreachable identity means no
        // verification, never a default-dead answer.
        const liveness = await this.identity.liveness(locked.decedent_user_id);
        const aliveSinceCase =
          liveness.lastStepUpAt !== null &&
          liveness.lastStepUpAt.getTime() > locked.created_at.getTime();

        if (!aliveSinceCase) {
          await this.cases.markVerified(tx, caseId, now);
          // The checklist is generated in the SAME transaction as verification,
          // so a verified case always has one (and a rolled-back verification
          // leaves none behind). Anchored on the verification instant — the
          // platform does not record a date of death.
          taskCount = await this.tasks.insertMany(tx, caseId, generateTasks(now));
          try {
            // ORDER IS A CONTROL HERE, and it is the opposite of the approve
            // site's. The identity call below is the one IRREVERSIBLE step in
            // the whole machine — `settlement` has no transition back to
            // `active` (identity's ALLOWED_TRANSITIONS), and it revokes every
            // session. So the fallible-but-reversible call goes FIRST: if the
            // hold cannot be confirmed we roll back having changed nothing
            // durable, and the operator retries. Were it the other way round,
            // a documents blip after a successful lock would leave the case
            // rolled back to waiting_period while the account sat terminally
            // in `settlement` — and every restore path (reject, owner void,
            // liveness void) calls setState('active'), which from `settlement`
            // is an invalid transition surfacing as a transient-looking 503.
            // A LIVING owner would be locked out permanently, with the only
            // unblocked move being to finish settling their estate: docs/03
            // §5.1's Critical outcome reached by a third service hiccuping.
            // (Found by the M9 security review; the M9 PR2 claim that the hold
            // "rides the SAME rule" as the lock was derived when setState was
            // the last statement before COMMIT.)
            //
            // Re-asserting the hold set at approval is idempotent, and it
            // catches documents the owner uploaded DURING the waiting period
            // (their login stays alive in deceased_pending — the rescue path),
            // so the invariant at verification is "every live document of a
            // verified estate is held", not "every document that existed at
            // approval".
            await this.documentsHold.setHold(locked.decedent_user_id, true, caseId);
            // The watermark restates the liveness predicate INSIDE identity's
            // status write, closing the window between the read above and this
            // commit: a step-up landing in between refuses the lock rather
            // than silently entombing an owner who just proved they are alive.
            await this.identity.setState(
              locked.decedent_user_id,
              'settlement',
              caseId,
              locked.created_at,
            );
            const row = (await this.cases.findById(tx, caseId)) as CaseRow;
            return {
              row,
              voided: false,
              breadth: await this.breadth.record(
                tx,
                operator,
                caseId,
                'verification.confirmed',
                now,
              ),
            };
          } catch (err) {
            if (!(err instanceof OwnerAliveError)) {
              throw err;
            }
            // Fall through to the void path. markVerified above is undone by
            // markResolved below — both are inside this open transaction.
          }
        }

        await this.cases.markResolved(
          tx,
          caseId,
          ['waiting_period', 'verified'],
          'owner_voided',
          now,
          null,
        );
        await this.identity.setState(locked.decedent_user_id, 'active', caseId);
        await this.documentsHold.setHold(locked.decedent_user_id, false, caseId);
        const row = (await this.cases.findById(tx, caseId)) as CaseRow;
        // The VOID arm records nothing: the owner is alive, and the operator's
        // attempt became a restoration. Counting it would charge them for the
        // outcome that protects the subject.
        return { row, voided: true, breadth: 0 };
      });
    } catch (err) {
      throw this.mapIdentityFailure(err);
    }

    if (outcome.voided) {
      await this.events.caseVoided(
        operator,
        sessionId,
        caseId,
        outcome.row.decedent_user_id,
        'liveness_check',
        outcome.row.reported_by,
      );
      throw new ConflictException({ error: 'owner_alive' });
    }
    await this.events.caseVerified(operator, sessionId, caseId, outcome.row.decedent_user_id);
    if (taskCount > 0) {
      await this.events.tasksGenerated(caseId, outcome.row.decedent_user_id, taskCount);
    }
    if (this.breadth.exceeded(outcome.breadth)) {
      await this.events.operatorBreadthExceeded(
        operator,
        sessionId,
        outcome.breadth,
        OPERATOR_BREADTH_MAX_CASES,
        OPERATOR_BREADTH_WINDOW_MS,
      );
    }
    return toDto(outcome.row, now);
  }

  // ------------------------------------------------------------------ queries

  async getCase(actor: string, sessionId: string, caseId: string): Promise<CaseDto> {
    const row = await this.cases.findById(this.db, caseId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const isOperator = await this.gate.is(this.db, actor);
    // NOT-FOUND on a deny: the row was located BY the id under authorization,
    // so a 403 here would confirm that a guessed case id names a real death
    // case while an unknown one answered 404 (see assertCanOrNotFound).
    this.authz.assertCanOrNotFound(
      actor,
      isOperator,
      'read',
      caseResource(row.id, row.decedent_user_id, row.reported_by),
    );
    // Operator reads only — the decedent and the reporter are reading their
    // own case. See SettlementAdminService.recordOperatorRead for why the
    // distinction is drawn on the ALLOWLIST rather than on the Cedar clause
    // that admitted them.
    if (isOperator) {
      await this.events.caseViewed(actor, sessionId, row.id, row.decedent_user_id, 'case');
    }
    return toDto(row, this.clock());
  }

  /** The caller's own cases (as subject or reporter); SQL-scoped. */
  async listMyCases(actor: string): Promise<CaseDto[]> {
    const now = this.clock();
    const rows = await this.cases.listForUser(this.db, actor);
    return rows.map((r) => toDto(r, now));
  }

  /** The operator review queue (documented row check: allowlist is the gate). */
  async queue(operator: string, sessionId: string): Promise<CaseDto[]> {
    await this.gate.assertIn(this.db, operator);
    const now = this.clock();
    const rows = await this.cases.listOpenForReview(this.db);
    await this.events.worklistViewed(operator, sessionId, 'queue', rows.length);
    return rows.map((r) => toDto(r, now));
  }

  /**
   * The post-verification worklist (M21 PR3b).
   *
   * Same gate, same shape, a disjoint status set — see
   * `ADMINISTRABLE_STATUSES`. It exists because `close`, stage decisions and
   * distribution approvals all require a case in one of those statuses, and
   * the only listing that existed could not return one: an operator could
   * reach three of their six verbs only by holding an id from somewhere else.
   */
  async administrable(operator: string, sessionId: string): Promise<CaseDto[]> {
    // On the POOL, and declared as such in operator-gate-fence.spec.ts: a
    // listing owns no transaction, so there is no row for the answer to be
    // consistent with (the `queue` argument verbatim).
    await this.gate.assertIn(this.db, operator);
    const now = this.clock();
    const rows = await this.cases.listAdministrable(this.db);
    await this.events.worklistViewed(operator, sessionId, 'administrable', rows.length);
    return rows.map((r) => toDto(r, now));
  }

  // ----------------------------------------------------------------- settings

  async getSettings(owner: string): Promise<{ waitingPeriodDays: number }> {
    return { waitingPeriodDays: await this.settings.waitingPeriodDays(this.db, owner) };
  }

  /**
   * Owner-configurable waiting period, UP only (floor in DDL + zod + here).
   * Refused while the owner has a non-terminal case: a pending case's
   * parameters are frozen — otherwise a step-up-fresh stolen session could
   * shorten the very window designed to catch it.
   */
  async updateSettings(
    owner: string,
    sessionId: string,
    input: SettingsInput,
  ): Promise<{ waitingPeriodDays: number }> {
    // `false` deliberately, on the owner's own settings — see voidCase.
    this.authz.assertCan(owner, false, 'manage', settingsResource(owner));
    const days = await this.db.withTransaction(owner, async (tx) => {
      const open = await this.cases.findNonTerminalByDecedent(tx, owner);
      if (open) {
        throw new ConflictException({ error: 'case_open' });
      }
      await this.settings.upsert(tx, owner, input.waitingPeriodDays);
      return input.waitingPeriodDays;
    });
    await this.events.settingsUpdated(owner, sessionId, days);
    return { waitingPeriodDays: days };
  }

  // ---------------------------------------------------------------- authority

  /**
   * Answers documents' evidence-read authority question. The ownerUserId in
   * the answer is the recorded ATTACHER of the evidence — the documents
   * service cross-checks it against the document's real owner before
   * decrypting, which is what stops a reporter registering someone else's
   * document id as "evidence". Cases in ANY status answer: a rejected case's
   * evidence is preserved for exactly this kind of after-the-fact review.
   * The read itself is audited on the documents side (document.evidence.accessed).
   */
  async evidenceReadAuthority(
    actor: string,
    documentId: string,
    version: number,
  ): Promise<EvidenceReadAnswer> {
    const refused: EvidenceReadAnswer = { allowed: false, caseId: null, ownerUserId: null };
    if (!(await this.gate.is(this.db, actor))) {
      return refused;
    }
    const row = await this.cases.findByDocumentEvidence(this.db, documentId, version);
    if (!row) {
      return refused;
    }
    const entry = row.verification_evidence.find(
      (e) => e.type === 'document' && e.documentId === documentId && e.version === version,
    );
    if (!entry) {
      return refused;
    }
    return { allowed: true, caseId: row.id, ownerUserId: entry.addedBy };
  }

  // -------------------------------------------------------- the contact sweep

  /**
   * The workflow driver's ONLY entry point. Records and sends due owner-contact
   * attempts for every waiting-period case; never transitions state. Attempts
   * are idempotent per (case, seq): a concurrent sweep loses the insert race
   * and skips. Deterministic given (cases, clock) — the Temporal adoption
   * swaps the scheduler around this method, not the method.
   */
  async runContactSweep(now: Date): Promise<{ attempts: number }> {
    const due = await this.cases.listWaitingPeriod(this.db);
    let attempts = 0;
    for (const c of due) {
      if (!c.human_review_at || !c.waiting_period_ends) {
        continue; // unreachable behind the DDL CHECKs; belt for bad fixtures
      }
      const start = c.human_review_at.getTime();
      const horizon = Math.min(now.getTime(), c.waiting_period_ends.getTime());
      if (horizon < start) {
        continue;
      }
      // seq n (n >= 1) opens at start + (n-1) * 12h.
      const maxSeq = Math.floor((horizon - start) / (CONTACT_INTERVAL_HOURS * HOUR_MS)) + 1;
      const recorded = (await this.attempts.maxSeq(this.db, c.id)) ?? -1;
      for (let seq = Math.max(1, recorded + 1); seq <= maxSeq; seq++) {
        const channel = CONTACT_CHANNELS[(seq - 1) % CONTACT_CHANNELS.length] as ContactChannel;
        const inserted = await this.db.withTransaction(SYSTEM_ACTOR_ID, async (tx) => {
          // Re-read under the row lock: the snapshot above may be stale, and a
          // case the owner voided (or an operator rejected) mid-sweep must not
          // collect further contact attempts on its permanent trail.
          const current = await this.cases.lockById(tx, c.id);
          if (!current || current.status !== 'waiting_period') {
            return false;
          }
          return this.attempts.insert(tx, { caseId: c.id, seq, channel, attemptedAt: now });
        });
        if (!inserted) {
          continue; // resolved mid-sweep, or another sweep recorded this slot
        }
        attempts += 1;
        await this.notifyOwner('owner_contact', c);
        await this.events.contactAttempted(c.id, c.decedent_user_id, seq, channel);
      }
    }
    return { attempts };
  }

  // ------------------------------------------------------------------ helpers

  private toEntry(input: EvidenceInput, addedBy: string, now: Date): EvidenceEntry {
    return input.type === 'document'
      ? {
          type: 'document',
          documentId: input.documentId,
          version: input.version,
          addedBy,
          addedAt: now.toISOString(),
        }
      : { type: 'provider_match', matchId: input.matchId, addedBy, addedAt: now.toISOString() };
  }

  private async insertCase(input: {
    decedentUserId: string;
    reportedBy: string;
    source: 'trusted_contact' | 'data_provider' | 'death_certificate_upload';
    evidence: EvidenceEntry[];
    now: Date;
  }): Promise<CaseRow> {
    try {
      return await this.db.withTransaction(input.reportedBy, async (tx) => {
        const row = await this.cases.insert(tx, input);
        // seq 0: the report-time owner notification, part of the same commit
        // so a recorded case always has its first contact on the trail.
        await this.attempts.insert(tx, {
          caseId: row.id,
          seq: 0,
          channel: 'push',
          attemptedAt: input.now,
        });
        return row;
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        // One open case per decedent. Existence is revealed only to callers
        // who passed the linked-contact (or operator) gate above.
        throw new ConflictException({ error: 'case_exists' });
      }
      throw err;
    }
  }

  private async assertNotificationsUsable(): Promise<void> {
    if (this.config.nodeEnv === 'production' && !this.notifier.deliversToRealChannels) {
      // The refusal is a control firing, and as of M9 it is VISIBLE in the
      // audit stream rather than indistinguishable from an outage.
      await this.events.audit.emit({
        action: 'settlement.notifications_refused',
        actorId: null,
        actorType: 'system',
        onBehalfOf: null,
        resourceType: 'settlement_case',
        resourceId: null,
        sessionId: null,
        detail: {},
      });
      throw new ServiceUnavailableException({ error: 'notifications_unavailable' });
    }
  }

  private async notifyOwner(kind: 'case_opened' | 'owner_contact', row: CaseRow): Promise<void> {
    let outcome: NotifyOutcome = { delivered: false, recipientVerified: false };
    try {
      outcome = await this.notifier.notify({
        kind,
        ownerUserId: row.decedent_user_id,
        caseId: row.id,
        ...(row.waiting_period_ends ? { waitingPeriodEnds: row.waiting_period_ends } : {}),
      });
    } catch {
      // Delivery failure is non-fatal: the attempt row + audit event record
      // that contact was attempted, and (M9) the notifications service's own
      // send log records the outcome. Contact liveness degrades; safety never.
    }
    // M14, PROCEED-AND-RECORD. This is the case the classification exists
    // for: the actor is a reporter or an operator and the recipient is the
    // DECEDENT, so refusing on an unverified address would deny a legitimate
    // reporter the §5.1 chain — hardest for the dormant owner a fraudulent
    // report actually targets, whose address is stalest because the only
    // self-heal was a login and whose account cannot log in once verified.
    //
    // The case still opens. What must not happen is that it opens LOOKING
    // like the owner had a chance to interrupt it. §5.1's control 3 is a
    // waiting period the owner can void; announcing it to an address nobody
    // proved is not that control, and an operator reviewing this case — or
    // an investigation reading it afterwards — has to be able to see the
    // difference.
    // OUTSIDE the delivery catch, deliberately. M14 first put this emit inside
    // it, where a broker failure on the EVIDENCE would be swallowed by a catch
    // written for a CARRIER failure — two different faults sharing one silence.
    // The M14 review judged the loss narrow (the notifications service's own
    // send log records `sent_unverified` durably, and a broker outage would
    // usually have failed the unwrapped `caseReported` emit moments earlier),
    // but the vault sibling propagates and the M13 rule is that an audit emit
    // is loud. Consistency with those is worth more than the swallow.
    if (outcome.delivered && !outcome.recipientVerified) {
      await this.events.audit.emit({
        action: 'settlement.unverified_recipient',
        actorId: null,
        actorType: 'system',
        onBehalfOf: row.decedent_user_id,
        resourceType: 'settlement_case',
        resourceId: row.id,
        sessionId: null,
        detail: { kind },
      });
    }
  }

  private mapIdentityFailure(err: unknown): unknown {
    if (err instanceof IdentityLockError) {
      return new ServiceUnavailableException({ error: 'identity_unavailable' });
    }
    if (err instanceof DocumentsHoldError) {
      // Same fail-closed contract as identity: the transaction has rolled
      // back, so the case did not move — the caller retries when documents
      // is reachable rather than committing a transition whose legal-hold
      // effect is unconfirmed.
      return new ServiceUnavailableException({ error: 'documents_unavailable' });
    }
    return err;
  }
}
