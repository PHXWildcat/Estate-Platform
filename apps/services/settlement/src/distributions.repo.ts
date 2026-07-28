import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export type DistributionStatus = 'planned' | 'approved' | 'in_progress' | 'completed' | 'disputed';

export interface DistributionRow {
  id: string;
  case_id: string;
  asset_id: string | null;
  beneficiary_contact_id: string;
  amount_ct: Buffer | null;
  dek_id: string | null;
  status: DistributionStatus;
  created_by: string;
  approved_by: string | null;
  approved_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, case_id, asset_id, beneficiary_contact_id, amount_ct, dek_id,
       status, created_by, approved_by, approved_at, created_at, updated_at`;

/**
 * distributions (docs/02 §7) under DUAL CONTROL. `created_by` is the recorder
 * and `approved_by` the approver; the DDL CHECK forbids them being the same
 * person, so the two-person rule cannot be defeated by a service-layer bug.
 * `amount_ct` is envelope ciphertext — the plaintext amount never appears in a
 * column, a log, or an audit event.
 */
@Injectable()
export class DistributionsRepo {
  async insert(
    tx: Queryable,
    input: {
      caseId: string;
      assetId: string | null;
      beneficiaryContactId: string;
      amountCt: Buffer | null;
      dekId: string | null;
      createdBy: string;
    },
  ): Promise<DistributionRow> {
    const rows = await tx.query<DistributionRow>(
      `INSERT INTO distributions
         (case_id, asset_id, beneficiary_contact_id, amount_ct, dek_id, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING ${COLUMNS}`,
      [
        input.caseId,
        input.assetId,
        input.beneficiaryContactId,
        input.amountCt,
        input.dekId,
        input.createdBy,
      ],
    );
    return rows[0] as DistributionRow;
  }

  async listByCase(q: Queryable | Db, caseId: string): Promise<DistributionRow[]> {
    return q.query<DistributionRow>(
      `SELECT ${COLUMNS} FROM distributions
        WHERE case_id = $1
        ORDER BY created_at, id`,
      [caseId],
    );
  }

  async lockById(tx: Queryable, distributionId: string): Promise<DistributionRow | null> {
    const rows = await tx.query<DistributionRow>(
      `SELECT ${COLUMNS} FROM distributions WHERE id = $1 FOR UPDATE`,
      [distributionId],
    );
    return rows[0] ?? null;
  }

  /**
   * Record the approval. The `approved_by <> created_by` DDL CHECK is the real
   * gate; the service refuses first with a readable error, and this statement
   * is scoped to `status = 'planned'` so an approval cannot be replayed.
   */
  async approve(
    tx: Queryable,
    distributionId: string,
    approvedBy: string,
    approvedAt: Date,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE distributions
          SET status = 'approved', approved_by = $2, approved_at = $3
        WHERE id = $1 AND status = 'planned'
        RETURNING id`,
      [distributionId, approvedBy, approvedAt],
    );
    return rows.length > 0;
  }

  /** Post-approval status movement (in_progress → completed, or disputed). */
  async setStatus(
    tx: Queryable,
    distributionId: string,
    from: readonly DistributionStatus[],
    to: DistributionStatus,
  ): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE distributions
          SET status = $3
        WHERE id = $1 AND status = ANY($2)
        RETURNING id`,
      [distributionId, [...from], to],
    );
    return rows.length > 0;
  }

  /** Are all distributions on this case terminal? Gates case close. */
  async countOpen(q: Queryable | Db, caseId: string): Promise<number> {
    const rows = await q.query<{ n: string }>(
      `SELECT COUNT(*) AS n FROM distributions
        WHERE case_id = $1 AND status NOT IN ('completed','disputed')`,
      [caseId],
    );
    return Number(rows[0]?.n ?? 0);
  }
}
