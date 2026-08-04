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
import { CasesRepo, type CaseRow, type EvidenceEntry } from './cases.repo';
import type { SettlementConfig } from './config';
import { ContactAttemptsRepo, type ContactChannel } from './contact-attempts.repo';
import { CoreReadsRepo, type ReportableEstate } from './core-reads.repo';
import { CLOCK, CONFIG, IDENTITY_LOCK, NOTIFIER, SYSTEM_ACTOR_ID, type Clock } from './di-tokens';
import { Db, isUniqueViolation } from './db';
import { EventsService } from './events.service';
import { IdentityLockError, OwnerAliveError, type IdentityLockPort } from './identity-lock';
import type { NotificationPort } from './notifications';
import { OperatorsRepo } from './operators.repo';
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
    private readonly operators: OperatorsRepo,
    private readonly settings: SettingsRepo,
    private readonly tasks: TasksRepo,
    private readonly coreReads: CoreReadsRepo,
    private readonly authz: SettlementAuthz,
    private readonly events: EventsService,
    @Inject(NOTIFIER) private readonly notifier: NotificationPort,
    @Inject(IDENTITY_LOCK) private readonly identity: IdentityLockPort,
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
    await this.assertOperator(operator);
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
    const isOperator = await this.operators.isOperator(this.db, actor);
    const now = this.clock();
    const row = await this.db.withTransaction(actor, async (tx) => {
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
    await this.assertOperator(operator);
    const now = this.clock();
    const row = await this.db.withTransaction(operator, async (tx) => {
      const locked = await this.cases.lockById(tx, caseId);
      if (!locked) {
        throw new NotFoundException({ error: 'not_found' });
      }
      this.authz.assertCan(
        operator,
        true,
        'review',
        caseResource(locked.id, locked.decedent_user_id, locked.reported_by),
      );
      if (!(await this.cases.markReviewStarted(tx, caseId))) {
        throw new ConflictException({ error: 'invalid_transition' });
      }
      return (await this.cases.findById(tx, caseId)) as CaseRow;
    });
    await this.events.reviewStarted(operator, sessionId, caseId, row.decedent_user_id);
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
    await this.assertOperator(operator);
    const now = this.clock();
    let outcome: { row: CaseRow; waitingPeriodEnds: Date | null; restored: boolean };
    try {
      outcome = await this.db.withTransaction(operator, async (tx) => {
        const locked = await this.cases.lockById(tx, caseId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        this.authz.assertCan(
          operator,
          true,
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
          const row = (await this.cases.findById(tx, caseId)) as CaseRow;
          return { row, waitingPeriodEnds: ends, restored: false };
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
        }
        const row = (await this.cases.findById(tx, caseId)) as CaseRow;
        return { row, waitingPeriodEnds: null, restored: wasLocked };
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
        // (identity's transition table treats same-state as idempotent).
        await this.identity.setState(locked.decedent_user_id, 'active', caseId);
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
    await this.assertOperator(operator);
    const now = this.clock();
    let outcome: { row: CaseRow; voided: boolean };
    let taskCount = 0;
    try {
      outcome = await this.db.withTransaction(operator, async (tx) => {
        const locked = await this.cases.lockById(tx, caseId);
        if (!locked) {
          throw new NotFoundException({ error: 'not_found' });
        }
        this.authz.assertCan(
          operator,
          true,
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
            return { row, voided: false };
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
        const row = (await this.cases.findById(tx, caseId)) as CaseRow;
        return { row, voided: true };
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
    return toDto(outcome.row, now);
  }

  // ------------------------------------------------------------------ queries

  async getCase(actor: string, caseId: string): Promise<CaseDto> {
    const row = await this.cases.findById(this.db, caseId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    const isOperator = await this.operators.isOperator(this.db, actor);
    this.authz.assertCan(
      actor,
      isOperator,
      'read',
      caseResource(row.id, row.decedent_user_id, row.reported_by),
    );
    return toDto(row, this.clock());
  }

  /** The caller's own cases (as subject or reporter); SQL-scoped. */
  async listMyCases(actor: string): Promise<CaseDto[]> {
    const now = this.clock();
    const rows = await this.cases.listForUser(this.db, actor);
    return rows.map((r) => toDto(r, now));
  }

  /** The operator review queue (documented row check: allowlist is the gate). */
  async queue(operator: string): Promise<CaseDto[]> {
    await this.assertOperator(operator);
    const now = this.clock();
    const rows = await this.cases.listOpenForReview(this.db);
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
    if (!(await this.operators.isOperator(this.db, actor))) {
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

  private async assertOperator(userId: string): Promise<void> {
    if (!(await this.operators.isOperator(this.db, userId))) {
      throw new ForbiddenException({ error: 'forbidden' });
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
    try {
      await this.notifier.notify({
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
  }

  private mapIdentityFailure(err: unknown): unknown {
    return err instanceof IdentityLockError
      ? new ServiceUnavailableException({ error: 'identity_unavailable' })
      : err;
  }
}
