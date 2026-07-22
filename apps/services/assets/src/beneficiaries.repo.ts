import { Injectable } from '@nestjs/common';
import { pctToSql } from './money';
import type { Queryable } from './db';

/**
 * The `asset_beneficiaries` projection of Beneficiary* ledger events. Rows
 * are only ever written inside a command transaction (or rebuild repair) as
 * reducer output: designate = revive-or-insert, remove = soft delete.
 */

export interface BeneficiaryRow {
  id: string;
  asset_id: string;
  contact_id: string;
  designation: string;
  share_pct: string; // NUMERIC arrives as string
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
}

const COLUMNS =
  'id, asset_id, contact_id, designation, share_pct, created_at, updated_at, deleted_at';

@Injectable()
export class BeneficiariesRepo {
  async listLive(q: Queryable, assetId: string): Promise<BeneficiaryRow[]> {
    return q.query<BeneficiaryRow>(
      `SELECT ${COLUMNS} FROM asset_beneficiaries
        WHERE asset_id = $1 AND deleted_at IS NULL
        ORDER BY designation ASC, contact_id ASC`,
      [assetId],
    );
  }

  /** All live designations — the rebuild diff's live side. */
  async listAllLive(q: Queryable): Promise<BeneficiaryRow[]> {
    return q.query<BeneficiaryRow>(
      `SELECT ${COLUMNS} FROM asset_beneficiaries WHERE deleted_at IS NULL
        ORDER BY asset_id ASC, designation ASC, contact_id ASC`,
    );
  }

  /**
   * Project a BeneficiaryDesignated event: update the live row's share if one
   * exists, otherwise insert a fresh row (a previously removed designation
   * stays soft-deleted as history; re-designation is a new row).
   */
  async upsertDesignation(
    q: Queryable,
    input: { assetId: string; contactId: string; designation: string; sharePct: number },
  ): Promise<void> {
    const updated = await q.query<{ id: string }>(
      `UPDATE asset_beneficiaries
          SET share_pct = $4
        WHERE asset_id = $1 AND contact_id = $2 AND designation = $3 AND deleted_at IS NULL
        RETURNING id`,
      [input.assetId, input.contactId, input.designation, pctToSql(input.sharePct)],
    );
    if (updated.length === 0) {
      await q.query(
        `INSERT INTO asset_beneficiaries (asset_id, contact_id, designation, share_pct)
         VALUES ($1, $2, $3, $4)`,
        [input.assetId, input.contactId, input.designation, pctToSql(input.sharePct)],
      );
    }
  }

  /** Project a BeneficiaryRemoved event. Returns false if no live row existed. */
  async softRemove(
    q: Queryable,
    input: { assetId: string; contactId: string; designation: string },
  ): Promise<boolean> {
    const rows = await q.query<{ id: string }>(
      `UPDATE asset_beneficiaries
          SET deleted_at = now()
        WHERE asset_id = $1 AND contact_id = $2 AND designation = $3 AND deleted_at IS NULL
        RETURNING id`,
      [input.assetId, input.contactId, input.designation],
    );
    return rows.length > 0;
  }
}
