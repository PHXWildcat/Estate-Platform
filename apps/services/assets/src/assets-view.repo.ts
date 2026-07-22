import { Injectable } from '@nestjs/common';
import type { AssetState } from './projection';
import { pctToSql } from './money';
import type { Queryable } from './db';

/**
 * The `assets_view` projection. Writes happen ONLY through
 * `upsertFromState`, whose input is reducer output — there is no ad-hoc
 * column-update surface, so "never write to the projection directly" is a
 * type-level property of this repo, not a convention.
 */

export interface AssetViewRow {
  asset_id: string;
  user_id: string;
  category: string;
  title: string;
  est_value_ct: Buffer | null;
  valuation_as_of: string | null;
  valuation_source: string | null;
  ownership_pct: string; // NUMERIC arrives as string
  cost_basis_ct: Buffer | null;
  location_ct: Buffer | null;
  notes_ct: Buffer | null;
  in_trust: boolean;
  funding_status: string | null;
  dek_id: string;
  updated_at: Date;
  deleted_at: Date | null;
}

const COLUMNS =
  'asset_id, user_id, category, title, est_value_ct, valuation_as_of::text, valuation_source, ' +
  'ownership_pct, cost_basis_ct, location_ct, notes_ct, in_trust, funding_status, dek_id, ' +
  'updated_at, deleted_at';

@Injectable()
export class AssetsViewRepo {
  /**
   * Load and row-lock an asset inside the command transaction — the per-asset
   * write serialization point. Returns retired rows too: commands against a
   * retired asset must see it (and be rejected), not treat it as missing.
   */
  async lockById(tx: Queryable, assetId: string): Promise<AssetViewRow | null> {
    const rows = await tx.query<AssetViewRow>(
      `SELECT ${COLUMNS} FROM assets_view WHERE asset_id = $1 FOR UPDATE`,
      [assetId],
    );
    return rows[0] ?? null;
  }

  /** Read regardless of retirement — history/beneficiaries stay readable. */
  async getAny(q: Queryable, assetId: string): Promise<AssetViewRow | null> {
    const rows = await q.query<AssetViewRow>(
      `SELECT ${COLUMNS} FROM assets_view WHERE asset_id = $1`,
      [assetId],
    );
    return rows[0] ?? null;
  }

  async getLive(q: Queryable, assetId: string): Promise<AssetViewRow | null> {
    const rows = await q.query<AssetViewRow>(
      `SELECT ${COLUMNS} FROM assets_view WHERE asset_id = $1 AND deleted_at IS NULL`,
      [assetId],
    );
    return rows[0] ?? null;
  }

  async listLiveByUser(q: Queryable, userId: string): Promise<AssetViewRow[]> {
    return q.query<AssetViewRow>(
      `SELECT ${COLUMNS} FROM assets_view WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY title ASC, asset_id ASC`,
      [userId],
    );
  }

  /** All rows including retired — the rebuild diff's live side. */
  async listAll(q: Queryable): Promise<AssetViewRow[]> {
    return q.query<AssetViewRow>(`SELECT ${COLUMNS} FROM assets_view ORDER BY asset_id ASC`);
  }

  /** Write reducer output. The single projection write path. */
  async upsertFromState(
    q: Queryable,
    state: AssetState<Buffer | null>,
    dekId: string,
    updatedAt: Date,
  ): Promise<void> {
    await q.query(
      `INSERT INTO assets_view (asset_id, user_id, category, title, est_value_ct, valuation_as_of,
                                valuation_source, ownership_pct, cost_basis_ct, location_ct,
                                notes_ct, in_trust, funding_status, dek_id, updated_at, deleted_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       ON CONFLICT (asset_id) DO UPDATE SET
         category = EXCLUDED.category,
         title = EXCLUDED.title,
         est_value_ct = EXCLUDED.est_value_ct,
         valuation_as_of = EXCLUDED.valuation_as_of,
         valuation_source = EXCLUDED.valuation_source,
         ownership_pct = EXCLUDED.ownership_pct,
         cost_basis_ct = EXCLUDED.cost_basis_ct,
         location_ct = EXCLUDED.location_ct,
         notes_ct = EXCLUDED.notes_ct,
         in_trust = EXCLUDED.in_trust,
         funding_status = EXCLUDED.funding_status,
         dek_id = EXCLUDED.dek_id,
         updated_at = EXCLUDED.updated_at,
         deleted_at = EXCLUDED.deleted_at`,
      [
        state.assetId,
        state.userId,
        state.category,
        state.title,
        state.estValue,
        state.valuationAsOf,
        state.valuationSource,
        pctToSql(state.ownershipPct),
        state.costBasis,
        state.location,
        state.notes,
        state.inTrust,
        state.fundingStatus,
        dekId,
        updatedAt,
        state.retiredAt,
      ],
    );
  }
}
