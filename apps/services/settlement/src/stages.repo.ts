import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/** The staged-access ladder (docs/03 §5.1 control 5). Vault is LAST by design. */
export const ACCESS_STAGES = ['inventory', 'documents', 'vault'] as const;
export type AccessStage = (typeof ACCESS_STAGES)[number];

export type StageStatus = 'requested' | 'approved' | 'denied' | 'revoked';

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
        WHERE case_id = $1 AND stage = $2 AND status IN ('requested','approved')`,
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

  /** Owner/operator revocation of an already-approved stage. */
  async revoke(tx: Queryable, stageId: string, revokedBy: string, at: Date): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE settlement_access_stages
          SET status = 'revoked', decided_by = $2, decided_at = $3
        WHERE id = $1 AND status IN ('requested','approved')
        RETURNING id`,
      [stageId, revokedBy, at],
    );
    return rows.length > 0;
  }
}
