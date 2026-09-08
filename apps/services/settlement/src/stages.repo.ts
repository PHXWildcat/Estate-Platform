import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/** The staged-access ladder (docs/03 §5.1 control 5). Vault is LAST by design. */
export const ACCESS_STAGES = ['inventory', 'documents', 'vault'] as const;
export type AccessStage = (typeof ACCESS_STAGES)[number];

export type StageStatus = 'requested' | 'approved' | 'denied' | 'revoked';

/**
 * The statuses a stage grant is LIVE in — and therefore exactly the statuses it
 * can be revoked FROM. One set, one spelling: it was two identical literal
 * lists in two statements, and `revoke`'s own doc comment described half of one
 * of them ("an already-approved stage"), which is the sentence that sent M49
 * PR3 looking (docs/03 §6mmm).
 */
export const LIVE_STAGE_STATUSES = [
  'requested',
  'approved',
] as const satisfies readonly StageStatus[];
export type LiveStageStatus = (typeof LIVE_STAGE_STATUSES)[number];

/**
 * Rendered as a SQL literal list, interpolated rather than parameterised for
 * the same reason `CasesRepo`'s `statusList` is: a module constant of a closed
 * union whose members the table's own CHECK enforces, never near a request.
 */
const LIVE_LIST = LIVE_STAGE_STATUSES.map((s) => `'${s}'`).join(',');

export interface StageRow {
  id: string;
  case_id: string;
  stage: AccessStage;
  status: StageStatus;
  requested_by: string;
  requested_at: Date;
  decided_by: string | null;
  decided_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, case_id, stage, status, requested_by, requested_at,
       decided_by, decided_at, created_at, updated_at`;

/**
 * settlement_access_stages persistence. The stage ORDER invariant
 * (inventory → documents → vault, no skipping) is a predicate over sibling
 * rows, so it is enforced by the service under the case row lock rather than
 * by a constraint; approver ≠ requester IS row-local and lives in the DDL.
 */
@Injectable()
export class StagesRepo {
  async insertRequest(
    tx: Queryable,
    input: { caseId: string; stage: AccessStage; requestedBy: string; requestedAt: Date },
  ): Promise<StageRow> {
    const rows = await tx.query<StageRow>(
      `INSERT INTO settlement_access_stages (case_id, stage, requested_by, requested_at)
       VALUES ($1, $2, $3, $4)
       RETURNING ${COLUMNS}`,
      [input.caseId, input.stage, input.requestedBy, input.requestedAt],
    );
    return rows[0] as StageRow;
  }

  async listByCase(q: Queryable | Db, caseId: string): Promise<StageRow[]> {
    return q.query<StageRow>(
      `SELECT ${COLUMNS} FROM settlement_access_stages
        WHERE case_id = $1
        ORDER BY created_at, id`,
      [caseId],
    );
  }

  async lockById(tx: Queryable, stageId: string): Promise<StageRow | null> {
    const rows = await tx.query<StageRow>(
      `SELECT ${COLUMNS} FROM settlement_access_stages WHERE id = $1 FOR UPDATE`,
      [stageId],
    );
    return rows[0] ?? null;
  }

  /** The live (requested or approved) record for a stage, if any. */
  async findLive(q: Queryable | Db, caseId: string, stage: AccessStage): Promise<StageRow | null> {
    const rows = await q.query<StageRow>(
      `SELECT ${COLUMNS} FROM settlement_access_stages
        WHERE case_id = $1 AND stage = $2 AND status IN (${LIVE_LIST})`,
      [caseId, stage],
    );
    return rows[0] ?? null;
  }

  /** Is `stage` approved on this case? The question every consuming service asks. */
  async isApproved(q: Queryable | Db, caseId: string, stage: AccessStage): Promise<boolean> {
    const rows = await q.query<{ ok: number }>(
      `SELECT 1 AS ok FROM settlement_access_stages
        WHERE case_id = $1 AND stage = $2 AND status = 'approved'
        LIMIT 1`,
      [caseId, stage],
    );
    return rows.length > 0;
  }

  async decide(
    tx: Queryable,
    stageId: string,
    status: Extract<StageStatus, 'approved' | 'denied'>,
    decidedBy: string,
    decidedAt: Date,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_access_stages
          SET status = $2, decided_by = $3, decided_at = $4
        WHERE id = $1 AND status = 'requested'
        RETURNING id`,
      [stageId, status, decidedBy, decidedAt],
    );
    return rows.length > 0;
  }

  /**
   * Owner/operator revocation of a LIVE stage — `requested` OR `approved`.
   *
   * WITHDRAWING A PENDING REQUEST IS NOT THE SAME ACT as withdrawing a granted
   * one, and until M49 PR3 the trail could not tell them apart: this statement
   * has always accepted both, and the event it produces recorded only the stage
   * name. So it answers with THE STATUS IT MOVED, which the caller puts on the
   * audit event.
   *
   * READ AT THE WRITE, not at the top of the caller. AFTER is wrong on its
   * face — the row is already `revoked`. A `SELECT` on the line above this
   * UPDATE would be as right as the CTE, under the row lock both rely on; what
   * is wrong is the caller's EARLIER read, because its sibling
   * `CasesRepo.markResolved` has a call site that mutates the very status such
   * a read would be reporting, inside the same transaction. The CTE is the
   * spelling that cannot drift back up the method. One spelling for both.
   *
   * The CTE is evaluated against the statement's snapshot, so `prior.status` is
   * the value from before this UPDATE — that is what makes it the answer rather
   * than a second copy of it. The row lock above is the precondition for that,
   * and `CasesRepo.markResolved` states why in full: without it, a statement
   * that waits on a concurrent writer proceeds against the NEW row version and
   * still returns the OLD snapshot's status.
   */
  async revoke(
    tx: Queryable,
    stageId: string,
    revokedBy: string,
    at: Date,
  ): Promise<LiveStageStatus | null> {
    const rows = await tx.query<{ from_status: LiveStageStatus }>(
      `WITH prior AS (
         SELECT id, status FROM settlement_access_stages WHERE id = $1
       )
       UPDATE settlement_access_stages
          SET status = 'revoked', decided_by = $2, decided_at = $3
         FROM prior
        WHERE settlement_access_stages.id = prior.id
          AND settlement_access_stages.status IN (${LIVE_LIST})
        RETURNING prior.status AS from_status`,
      [stageId, revokedBy, at],
    );
    return rows[0]?.from_status ?? null;
  }
}
