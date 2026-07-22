import { Injectable } from '@nestjs/common';
import { CryptoError } from '@estate/crypto';
import { deserializePayload } from './asset-events';
import { AssetsViewRepo, type AssetViewRow } from './assets-view.repo';
import { BeneficiariesRepo, type BeneficiaryRow } from './beneficiaries.repo';
import { payloadField, viewField } from './assets.service';
import { Db } from './db';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { LedgerRepo, type LedgerRow } from './ledger.repo';
import { sqlToPct } from './money';
import {
  applyAssetEvent,
  applyBeneficiaryEvent,
  type AssetState,
  type BeneficiaryState,
  type EncryptedField,
} from './projection';

/**
 * Projection rebuild — the docs/02 §8 disaster-recovery integrity check:
 * `assets_view` and `asset_beneficiaries` must be derivable from
 * `asset_events` at any time. Folds the full ledger through the SAME pure
 * reducer the command path uses, diffs the result against the live
 * projection, and (with `repair`) rewrites diverged rows from the ledger.
 *
 * Rebuilds are LOUD by design: every payload/field decryption is audited as
 * actorType 'system' with purpose 'projection_rebuild', and the run emits an
 * `asset.projection.rebuilt` summary. Diff output carries entity IDs and
 * column names only — never values.
 */

/** Fixed system-actor id for rebuild decrypt audits (nil UUID). */
export const SYSTEM_ACTOR_ID = '00000000-0000-0000-0000-000000000000';
const PURPOSE = 'projection_rebuild';

export interface RebuildDiff {
  assetId: string;
  kind:
    | 'view_missing' // ledger says the asset exists; projection has no row
    | 'view_extra' // projection row with no ledger events (not repairable from the ledger)
    | 'view_field' // a column diverges from replay
    | 'beneficiary_missing'
    | 'beneficiary_extra'
    | 'beneficiary_share';
  field?: string;
  contactId?: string;
  designation?: string;
}

export interface RebuildReport {
  assets: number;
  events: number;
  /** Assets skipped because their DEK is destroyed/undecryptable (crypto-shred). */
  skippedAssets: number;
  diffs: RebuildDiff[];
  repaired: boolean;
}

interface ExpectedAsset {
  state: AssetState<string>;
  beneficiaries: BeneficiaryState[];
}

@Injectable()
export class RebuildService {
  constructor(
    private readonly db: Db,
    private readonly ledger: LedgerRepo,
    private readonly views: AssetsViewRepo,
    private readonly beneficiaries: BeneficiariesRepo,
    private readonly cipher: FieldCipher,
    private readonly events: EventsService,
  ) {}

  async rebuild(options: { repair: boolean }): Promise<RebuildReport> {
    const rows = await this.ledger.listAll(this.db);
    const { expected, skippedAssets } = await this.replayAll(rows);

    const liveViews = new Map<string, AssetViewRow>(
      (await this.views.listAll(this.db)).map((r) => [r.asset_id, r]),
    );
    const liveBens = new Map<string, BeneficiaryRow[]>();
    for (const b of await this.beneficiaries.listAllLive(this.db)) {
      const list = liveBens.get(b.asset_id) ?? [];
      list.push(b);
      liveBens.set(b.asset_id, list);
    }

    const diffs: RebuildDiff[] = [];
    for (const [assetId, exp] of expected) {
      const live = liveViews.get(assetId);
      if (!live) {
        diffs.push({ assetId, kind: 'view_missing' });
      } else {
        diffs.push(...(await this.diffView(assetId, exp.state, live)));
      }
      diffs.push(...diffBeneficiaries(assetId, exp.beneficiaries, liveBens.get(assetId) ?? []));
    }
    for (const assetId of liveViews.keys()) {
      if (!expected.has(assetId) && !isSkipped(assetId, skippedAssets)) {
        diffs.push({ assetId, kind: 'view_extra' });
      }
    }

    let repaired = false;
    if (options.repair && diffs.length > 0) {
      await this.repair(expected, diffs);
      repaired = true;
    }

    await this.events.projectionRebuilt({
      assets: expected.size,
      events: rows.length,
      diffs: diffs.length,
      repaired,
    });
    return {
      assets: expected.size,
      events: rows.length,
      skippedAssets: skippedAssets.size,
      diffs,
      repaired,
    };
  }

  /** Fold the whole ledger to expected plaintext states, per asset. */
  private async replayAll(rows: LedgerRow[]): Promise<{
    expected: Map<string, ExpectedAsset>;
    skippedAssets: Set<string>;
  }> {
    const expected = new Map<string, ExpectedAsset>();
    const skippedAssets = new Set<string>();
    let currentAssetId: string | null = null;
    let state: AssetState<string> | null = null;
    let bens: BeneficiaryState[] = [];
    let skipCurrent = false;
    const flush = (): void => {
      if (currentAssetId && state && !skipCurrent) {
        expected.set(currentAssetId, { state, beneficiaries: bens });
      }
      state = null;
      bens = [];
      skipCurrent = false;
    };
    for (const row of rows) {
      if (row.asset_id !== currentAssetId) {
        flush();
        currentAssetId = row.asset_id;
      }
      if (skipCurrent) {
        continue;
      }
      try {
        const json = await this.cipher.decrypt({
          ownerUserId: row.user_id,
          dekId: await this.cipher.getOrCreateDek(row.user_id),
          field: payloadField(row.event_id),
          ciphertext: row.payload_ct,
          actorId: SYSTEM_ACTOR_ID,
          actorType: 'system',
          purpose: PURPOSE,
        });
        const payload = deserializePayload(json!);
        const evt = {
          assetId: row.asset_id,
          userId: row.user_id,
          occurredAt: row.occurred_at,
          payload,
        };
        state = applyAssetEvent<string>(state, evt, (_f, plaintext) => plaintext);
        bens = applyBeneficiaryEvent(bens, evt);
      } catch (err) {
        if (err instanceof CryptoError) {
          // Crypto-shredded (or otherwise undecryptable) owner: this asset's
          // history is unrecoverable by design; report it as skipped rather
          // than failing the whole DR check.
          skipCurrent = true;
          skippedAssets.add(row.asset_id);
          continue;
        }
        throw err;
      }
    }
    flush();
    return { expected, skippedAssets };
  }

  /** Column-by-column comparison; ciphertext columns compare by decrypted value. */
  private async diffView(
    assetId: string,
    exp: AssetState<string>,
    live: AssetViewRow,
  ): Promise<RebuildDiff[]> {
    const diffs: RebuildDiff[] = [];
    const push = (field: string): number => diffs.push({ assetId, kind: 'view_field', field });
    if (live.category !== exp.category) push('category');
    if (live.title !== exp.title) push('title');
    if ((live.valuation_as_of ?? null) !== exp.valuationAsOf) push('valuation_as_of');
    if ((live.valuation_source ?? null) !== exp.valuationSource) push('valuation_source');
    if (sqlToPct(live.ownership_pct) !== exp.ownershipPct) push('ownership_pct');
    if (live.in_trust !== exp.inTrust) push('in_trust');
    if ((live.funding_status ?? null) !== exp.fundingStatus) push('funding_status');
    if (live.user_id !== exp.userId) push('user_id');
    const liveRetired = live.deleted_at ? live.deleted_at.getTime() : null;
    const expRetired = exp.retiredAt ? exp.retiredAt.getTime() : null;
    if (liveRetired !== expRetired) push('deleted_at');
    const encrypted: Array<[EncryptedField, Buffer | null, string | null]> = [
      ['est_value', live.est_value_ct, exp.estValue],
      ['cost_basis', live.cost_basis_ct, exp.costBasis],
      ['location', live.location_ct, exp.location],
      ['notes', live.notes_ct, exp.notes],
    ];
    for (const [field, ciphertext, expectedValue] of encrypted) {
      if (ciphertext === null) {
        if (expectedValue !== null) push(field);
        continue;
      }
      try {
        const liveValue = await this.cipher.decrypt({
          ownerUserId: live.user_id,
          dekId: live.dek_id,
          field: viewField(live.asset_id, field),
          ciphertext,
          actorId: SYSTEM_ACTOR_ID,
          actorType: 'system',
          purpose: PURPOSE,
        });
        if (liveValue !== expectedValue) push(field);
      } catch (err) {
        if (err instanceof CryptoError) {
          push(field); // undecryptable live value while the ledger replays fine
        } else {
          throw err;
        }
      }
    }
    return diffs;
  }

  /** Rewrite diverged projections from replayed state, in one transaction. */
  private async repair(expected: Map<string, ExpectedAsset>, diffs: RebuildDiff[]): Promise<void> {
    const assetIds = [...new Set(diffs.map((d) => d.assetId))];
    await this.db.withTransaction(SYSTEM_ACTOR_ID, async (tx) => {
      for (const assetId of assetIds) {
        const exp = expected.get(assetId);
        if (!exp) {
          continue; // view_extra rows are not derivable from the ledger; report-only
        }
        // Re-encrypt replayed plaintext under the owner's active DEK.
        const dekId = await this.cipher.getOrCreateDek(exp.state.userId);
        const enc = async (field: EncryptedField, value: string | null): Promise<Buffer | null> =>
          value === null
            ? null
            : (await this.cipher.encrypt(exp.state.userId, viewField(assetId, field), value))
                .ciphertext;
        const state: AssetState<Buffer | null> = {
          ...exp.state,
          estValue: await enc('est_value', exp.state.estValue),
          costBasis: await enc('cost_basis', exp.state.costBasis),
          location: await enc('location', exp.state.location),
          notes: await enc('notes', exp.state.notes),
        };
        await this.views.upsertFromState(tx, state, dekId, new Date());
        // Make live designations match the replayed set exactly.
        const live = await this.beneficiaries.listLive(tx, assetId);
        const want = new Map<string, BeneficiaryState>(
          exp.beneficiaries.map((b) => [`${b.contactId}|${b.designation}`, b]),
        );
        for (const row of live) {
          const key = `${row.contact_id}|${row.designation}`;
          const target = want.get(key);
          if (!target) {
            await this.beneficiaries.softRemove(tx, {
              assetId,
              contactId: row.contact_id,
              designation: row.designation,
            });
          } else if (sqlToPct(row.share_pct) !== target.sharePct) {
            await this.beneficiaries.upsertDesignation(tx, {
              assetId,
              contactId: target.contactId,
              designation: target.designation,
              sharePct: target.sharePct,
            });
          }
          want.delete(key);
        }
        for (const target of want.values()) {
          await this.beneficiaries.upsertDesignation(tx, {
            assetId,
            contactId: target.contactId,
            designation: target.designation,
            sharePct: target.sharePct,
          });
        }
      }
    });
  }
}

function diffBeneficiaries(
  assetId: string,
  expected: readonly BeneficiaryState[],
  live: readonly BeneficiaryRow[],
): RebuildDiff[] {
  const diffs: RebuildDiff[] = [];
  const liveByKey = new Map<string, BeneficiaryRow>(
    live.map((r) => [`${r.contact_id}|${r.designation}`, r]),
  );
  for (const exp of expected) {
    const key = `${exp.contactId}|${exp.designation}`;
    const row = liveByKey.get(key);
    if (!row) {
      diffs.push({
        assetId,
        kind: 'beneficiary_missing',
        contactId: exp.contactId,
        designation: exp.designation,
      });
    } else {
      if (sqlToPct(row.share_pct) !== exp.sharePct) {
        diffs.push({
          assetId,
          kind: 'beneficiary_share',
          contactId: exp.contactId,
          designation: exp.designation,
        });
      }
      liveByKey.delete(key);
    }
  }
  for (const row of liveByKey.values()) {
    diffs.push({
      assetId,
      kind: 'beneficiary_extra',
      contactId: row.contact_id,
      designation: row.designation,
    });
  }
  return diffs;
}

function isSkipped(assetId: string, skipped: Set<string>): boolean {
  return skipped.has(assetId);
}
