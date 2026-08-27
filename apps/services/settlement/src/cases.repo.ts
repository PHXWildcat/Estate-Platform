import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export type CaseStatus =
  | 'reported'
  | 'verifying'
  | 'waiting_period'
  | 'verified'
  | 'active'
  | 'distributing'
  | 'closed'
  | 'rejected_fraud';

/**
 * THE TWO WORKLISTS, declared as data because their DISJOINTNESS is a
 * product invariant rather than a coincidence (M21 PR3b decision 2).
 *
 * `/queue` is pre-verification: work an operator claims, reviews and either
 * approves or rejects. `administrable` is post-verification: estates under
 * settlement, where the remaining operator verbs are closing the case,
 * deciding a stage and approving a distribution. A case is in exactly one of
 * them or in neither (`closed` and `rejected_fraud` are terminal and appear on
 * no worklist at all).
 *
 * Kept next to each other, and pinned against the MIGRATION's own status
 * CHECK by `test/operator-worklists.spec.ts`, so a ninth status has to be placed deliberately rather
 * than defaulting into invisibility — the failure this pair exists to prevent
 * is a status nobody can reach a screen for, which is what
 * `close`/stage-decision/distribution-approval were before PR3b.
 */
export const QUEUE_STATUSES: readonly CaseStatus[] = ['reported', 'verifying', 'waiting_period'];
export const ADMINISTRABLE_STATUSES: readonly CaseStatus[] = ['verified', 'active', 'distributing'];

/**
 * Render a status set as a SQL literal list.
 *
 * Interpolated rather than parameterised, which is safe HERE and only here:
 * both inputs are module constants typed as `CaseStatus`, a closed union whose
 * members are also enforced by the table's own CHECK — no value on this path
 * has ever been near a request. A parameterised `= ANY($1)` would work too and
 * is what a caller-supplied filter must use; this stays literal so the two
 * queries read as the status sets they are.
 */
function statusList(statuses: readonly CaseStatus[]): string {
  return statuses.map((s) => `'${s}'`).join(',');
}

/** An evidence entry as stored in verification_evidence (ids only, never content). */
export type EvidenceEntry =
  | {
      type: 'document';
      documentId: string;
      version: number;
      addedBy: string;
      addedAt: string;
    }
  | { type: 'provider_match'; matchId: string; addedBy: string; addedAt: string };

export interface CaseRow {
  id: string;
  decedent_user_id: string;
  status: CaseStatus;
  reported_by: string;
  report_source: string;
  verification_evidence: EvidenceEntry[];
  human_review_by: string | null;
  human_review_at: Date | null;
  claimed_by: string | null;
  claimed_at: Date | null;
  waiting_period_ends: Date | null;
  verified_at: Date | null;
  resolution: string | null;
  resolved_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * A case joined to the contact row that names the caller its executor
 * (M23 PR2). `contact_id` is the handle the BFF gives the browser — a raw
 * `decedent_user_id` never leaves the BFF.
 */
export interface ExecutorCaseRow extends CaseRow {
  contact_id: string;
}

const COLUMNS = `id, decedent_user_id, status, reported_by, report_source,
       verification_evidence, human_review_by, human_review_at,
       claimed_by, claimed_at,
       waiting_period_ends, verified_at, resolution, resolved_at,
       created_at, updated_at`;

/**
 * settlement_cases persistence. Transition writes carry the expected FROM
 * status in the WHERE clause (compare-and-set) on top of the caller's row
 * lock, so a lost race surfaces as zero rows updated, never as a silently
 * overwritten transition — and the DDL CHECKs backstop every invariant the
 * schema can carry.
 */
@Injectable()
export class CasesRepo {
  async insert(
    tx: Queryable,
    input: {
      decedentUserId: string;
      reportedBy: string;
      source: 'trusted_contact' | 'data_provider' | 'death_certificate_upload';
      evidence: EvidenceEntry[];
    },
  ): Promise<CaseRow> {
    const rows = await tx.query<CaseRow>(
      `INSERT INTO settlement_cases (decedent_user_id, reported_by, report_source, verification_evidence)
       VALUES ($1, $2, $3, $4::jsonb)
       RETURNING ${COLUMNS}`,
      [input.decedentUserId, input.reportedBy, input.source, JSON.stringify(input.evidence)],
    );
    return rows[0] as CaseRow;
  }

  async findById(q: Queryable | Db, caseId: string): Promise<CaseRow | null> {
    const rows = await q.query<CaseRow>(`SELECT ${COLUMNS} FROM settlement_cases WHERE id = $1`, [
      caseId,
    ]);
    return rows[0] ?? null;
  }

  /** Row-lock a case for a transition. */
  async lockById(tx: Queryable, caseId: string): Promise<CaseRow | null> {
    const rows = await tx.query<CaseRow>(
      `SELECT ${COLUMNS} FROM settlement_cases WHERE id = $1 FOR UPDATE`,
      [caseId],
    );
    return rows[0] ?? null;
  }

  /**
   * Cases where the caller is subject or reporter (their own view).
   *
   * THE `reported_by` MATCH HERE STAYS UNQUALIFIED, AND THAT IS A DECISION
   * (M48). `assertCaseVisible` now re-derives the reporter's link at read time,
   * because the administration reads behind it answer questions about the
   * estate. This route answers a different question — "which reports have I
   * filed?" — and docs/03 §6g's acceptance rests on it: a case is evidence, and
   * revoking the author's sight of their own report would leave a case with no
   * visible author. So an unlinked reporter still sees THAT the case exists and
   * that they filed it, and no longer sees how the estate is being settled.
   *
   * This is the THIRD gate admitting on the frozen column — Cedar's
   * `caseResource` snapshot and `assertCaseVisible` are the other two — and it
   * is deliberately the one that keeps it.
   */
  async listForUser(q: Queryable | Db, userId: string): Promise<CaseRow[]> {
    return q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE decedent_user_id = $1 OR reported_by = $1
        ORDER BY created_at DESC, id`,
      [userId],
    );
  }

  /** The operator queue: everything pre-verification, oldest first. */
  async listOpenForReview(q: Queryable | Db): Promise<CaseRow[]> {
    return q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE status IN (${statusList(QUEUE_STATUSES)})
        ORDER BY created_at, id`,
    );
  }

  /**
   * The post-verification worklist, newest verification first.
   *
   * A SECOND route rather than a widened `/queue`, and the disjointness is the
   * reason (M21 PR3b decision 2). `/queue` is pre-verification work an
   * operator picks up and puts down within days; an administrable case is an
   * estate under settlement, which lingers for months. Merging them would grow
   * the review queue without bound and change what the word means for the one
   * route the audience table, the route↔consumer fence, the stack e2e and
   * docs/04 all name by it. Before this existed, `close`, stage decisions and
   * distribution approvals were reachable only by an operator who already held
   * an id from somewhere else — the three verbs had a surface that could not
   * reach them.
   *
   * `test/operator-worklists.spec.ts` asserts the two sets are disjoint and
   * that every status the DDL admits is in at most one of them, so a ninth
   * status cannot silently land in both or in neither unnoticed.
   */
  async listAdministrable(q: Queryable | Db): Promise<CaseRow[]> {
    return q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE status IN (${statusList(ADMINISTRABLE_STATUSES)})
        ORDER BY verified_at DESC, id`,
    );
  }

  /**
   * THE EXECUTOR'S OWN WORKLIST (M23 PR2).
   *
   * A THIRD listing rather than a widened `listForUser`, for the reason M21
   * PR3b gave when it split `administrable` off `queue`: the two answer
   * different questions for different people. `listForUser` is
   * `decedent_user_id = $1 OR reported_by = $1` — cases ABOUT you and cases you
   * FILED — and the web splits its result on `aboutMe` to render two panels of
   * one list. Adding a third OR arm would have put somebody else's estate into
   * both panels, under a heading that says it is yours.
   *
   * The status filter is `ADMINISTRABLE_STATUSES`, the same constant
   * `listAdministrable` uses and the same one every executor verb tests, so a
   * ninth case status cannot appear on this list without appearing on the
   * operator's too. A pre-verification case is deliberately invisible here:
   * until an operator verifies a death, a designated executor is a living
   * person's nominee with nothing to administer, and listing the case would
   * tell them a report exists about somebody who may well be alive.
   *
   * The join is the M2 dormant role model — `role = 'executor'` with
   * `effective_condition = 'on_death_verified'` — and it is the SAME predicate
   * `isExecutorOf` tests one case at a time. `contacts.id` comes back with each
   * row because the BFF names an estate to the browser by contact id and never
   * by user id; returning it here saves a second lookup that could disagree.
   */
  async listAdministeredBy(q: Queryable | Db, userId: string): Promise<ExecutorCaseRow[]> {
    return q.query<ExecutorCaseRow>(
      `SELECT ${COLUMNS.split(',')
        .map((c) => `sc.${c.trim()}`)
        .join(', ')},
              c.id AS contact_id
         FROM settlement_cases sc
         JOIN contacts c
           ON c.owner_user_id = sc.decedent_user_id
          AND c.linked_user_id = $1
          AND c.deleted_at IS NULL
         JOIN role_assignments ra
           ON ra.contact_id = c.id
          AND ra.owner_user_id = sc.decedent_user_id
          AND ra.role = 'executor'
          AND ra.effective_condition = 'on_death_verified'
          AND ra.deleted_at IS NULL
        WHERE sc.status IN (${statusList(ADMINISTRABLE_STATUSES)})
        ORDER BY sc.verified_at DESC, sc.id`,
      [userId],
    );
  }

  /** Waiting-period cases due a contact-attempt sweep. */
  async listWaitingPeriod(q: Queryable | Db): Promise<CaseRow[]> {
    return q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE status = 'waiting_period'
        ORDER BY created_at, id`,
    );
  }

  /** Any case blocking a settings change / holding the open-case slot. */
  async findNonTerminalByDecedent(
    q: Queryable | Db,
    decedentUserId: string,
  ): Promise<CaseRow | null> {
    const rows = await q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE decedent_user_id = $1
          AND status NOT IN ('closed','rejected_fraud')
        LIMIT 1`,
      [decedentUserId],
    );
    return rows[0] ?? null;
  }

  /**
   * Evidence-read authority lookup: the case (any status — a rejected case's
   * evidence stays reviewable, it is preserved for law enforcement) holding a
   * document evidence entry for exactly (documentId, version).
   */
  async findByDocumentEvidence(
    q: Queryable | Db,
    documentId: string,
    version: number,
  ): Promise<CaseRow | null> {
    const probe = JSON.stringify([{ type: 'document', documentId, version }]);
    const rows = await q.query<CaseRow>(
      `SELECT ${COLUMNS}
         FROM settlement_cases
        WHERE verification_evidence @> $1::jsonb
        ORDER BY created_at
        LIMIT 1`,
      [probe],
    );
    return rows[0] ?? null;
  }

  async appendEvidence(tx: Queryable, caseId: string, entry: EvidenceEntry): Promise<void> {
    await tx.query(
      `UPDATE settlement_cases
          SET verification_evidence = verification_evidence || $2::jsonb
        WHERE id = $1`,
      [caseId, JSON.stringify([entry])],
    );
  }

  /**
   * reported → verifying (an operator claimed the review), RECORDING THE
   * CLAIMER. The claim is written in the same statement as the transition, so
   * a case can never be `verifying` with no owner — which is the state that
   * let two operators pick up one docs/03 §5.1 review (migration 003).
   *
   * The reporter is refused above this by the readable `reviewer_is_reporter`
   * 403; `settlement_cases_claimer_not_reporter` is the backstop, and it is a
   * backstop rather than the gate for the same reason the review pair's is.
   */
  async markReviewStarted(
    tx: Queryable,
    caseId: string,
    claimedBy: string,
    claimedAt: Date,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_cases
          SET status = 'verifying', claimed_by = $2, claimed_at = $3
        WHERE id = $1 AND status = 'reported'
        RETURNING id`,
      [caseId, claimedBy, claimedAt],
    );
    return rows.length > 0;
  }

  /** verifying → waiting_period (review approved; the DDL CHECKs enforce the pairs). */
  async markApproved(
    tx: Queryable,
    caseId: string,
    reviewerId: string,
    reviewedAt: Date,
    waitingPeriodEnds: Date,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_cases
          SET status = 'waiting_period',
              human_review_by = $2,
              human_review_at = $3,
              waiting_period_ends = $4
        WHERE id = $1 AND status = 'verifying'
        RETURNING id`,
      [caseId, reviewerId, reviewedAt, waitingPeriodEnds],
    );
    return rows.length > 0;
  }

  /**
   * → rejected_fraud. From 'verifying' the rejecting operator becomes the
   * recorded reviewer; from 'waiting_period' the approving reviewer stands and
   * the rejecter lives in the version trigger's actor + the audit event. From
   * 'reported' (owner void before any review) no reviewer is recorded.
   */
  async markResolved(
    tx: Queryable,
    caseId: string,
    fromStatuses: readonly CaseStatus[],
    resolution: 'operator_rejected' | 'owner_voided',
    resolvedAt: Date,
    reviewer: { id: string; at: Date } | null,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      // verified_at is cleared too: a resolved case was never verified, and the
      // settlement_cases_verified_at_matches CHECK forbids the combination.
      // (Reachable when a liveness-interlock refusal unwinds an in-transaction
      // markVerified — see SettlementService.confirmVerification.)
      `UPDATE settlement_cases
          SET status = 'rejected_fraud',
              resolution = $2,
              resolved_at = $3,
              human_review_by = COALESCE($4, human_review_by),
              human_review_at = COALESCE($5, human_review_at),
              waiting_period_ends = NULL,
              verified_at = NULL
        WHERE id = $1 AND status = ANY($6)
        RETURNING id`,
      [
        caseId,
        resolution,
        resolvedAt,
        reviewer?.id ?? null,
        reviewer?.at ?? null,
        [...fromStatuses],
      ],
    );
    return rows.length > 0;
  }

  /**
   * Post-verification status movement (verified → active → distributing →
   * closed). Compare-and-set on the allowed `from` set, like every other
   * transition here.
   */
  async advanceStatus(
    tx: Queryable,
    caseId: string,
    from: readonly CaseStatus[],
    to: CaseStatus,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_cases
          SET status = $3
        WHERE id = $1 AND status = ANY($2)
        RETURNING id`,
      [caseId, [...from], to],
    );
    return rows.length > 0;
  }

  /** waiting_period → verified (operator confirmation after the period lapses). */
  async markVerified(tx: Queryable, caseId: string, verifiedAt: Date): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_cases
          SET status = 'verified',
              verified_at = $2
        WHERE id = $1 AND status = 'waiting_period'
        RETURNING id`,
      [caseId, verifiedAt],
    );
    return rows.length > 0;
  }
}
