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
  waiting_period_ends: Date | null;
  verified_at: Date | null;
  resolution: string | null;
  resolved_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, decedent_user_id, status, reported_by, report_source,
       verification_evidence, human_review_by, human_review_at,
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

  /** Cases where the caller is subject or reporter (their own view). */
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
        WHERE status IN ('reported','verifying','waiting_period')
        ORDER BY created_at, id`,
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

  /** reported → verifying (an operator claimed the review). */
  async markReviewStarted(tx: Queryable, caseId: string): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_cases
          SET status = 'verifying'
        WHERE id = $1 AND status = 'reported'
        RETURNING id`,
      [caseId],
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
