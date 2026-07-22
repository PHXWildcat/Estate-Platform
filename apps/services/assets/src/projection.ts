import type { z } from 'zod';
import type { AssetCategory } from '@estate/contracts';
import type { AssetEventPayload, FundingStatusSchema, ValuationSourceSchema } from './asset-events';

type ValuationSource = z.infer<typeof ValuationSourceSchema>;
type FundingStatus = z.infer<typeof FundingStatusSchema>;

/**
 * The pure projection reducer — the ONLY way `assets_view` and
 * `asset_beneficiaries` content is ever derived (CLAUDE.md: never write to
 * the projection directly). Three consumers fold with it:
 *  - the command transaction (V = ciphertext Buffer: payload values are
 *    pre-encrypted, `lift` looks them up);
 *  - the rebuild CLI and as-of queries (V = plaintext string).
 * No I/O, no clock, no randomness — replay determinism is the contract.
 */

/** Encrypted-capable projection fields (the *_ct columns of assets_view). */
export type EncryptedField = 'est_value' | 'cost_basis' | 'location' | 'notes';

/**
 * Maps a plaintext payload value for an encrypted-capable field into the
 * fold's value representation (identity for plaintext folds; a lookup into
 * this event's pre-encrypted ciphertexts for the command fold).
 */
export type LiftFn<V> = (field: EncryptedField, plaintext: string) => V;

export interface AssetState<V> {
  assetId: string;
  userId: string;
  category: AssetCategory;
  title: string;
  estValue: V | null;
  valuationAsOf: string | null;
  valuationSource: ValuationSource | null;
  ownershipPct: number;
  costBasis: V | null;
  location: V | null;
  notes: V | null;
  inTrust: boolean;
  fundingStatus: FundingStatus | null;
  /** Non-null ⇒ retired (projects to assets_view.deleted_at). */
  retiredAt: Date | null;
}

/** A live beneficiary designation (soft-deleted rows are not state). */
export interface BeneficiaryState {
  contactId: string;
  designation: 'primary' | 'contingent';
  sharePct: number;
}

/**
 * The ledger contains an event sequence this reducer cannot lawfully apply.
 * During command handling this is prevented by validation; during replay it
 * means corrupted or incompatible history and must fail the rebuild loudly.
 */
export class ProjectionError extends Error {
  constructor(message: string) {
    // Event types and invariant names only — never payload values.
    super(message);
    this.name = 'ProjectionError';
  }
}

export interface LedgerEventInput {
  assetId: string;
  userId: string;
  occurredAt: Date;
  payload: AssetEventPayload;
}

/** Fold one ledger event into the asset's view state. */
export function applyAssetEvent<V>(
  state: AssetState<V> | null,
  evt: LedgerEventInput,
  lift: LiftFn<V>,
): AssetState<V> {
  const p = evt.payload;
  if (p.type === 'AssetCreated') {
    if (state !== null) {
      throw new ProjectionError('AssetCreated on existing asset');
    }
    return {
      assetId: evt.assetId,
      userId: evt.userId,
      category: p.category,
      title: p.title,
      estValue: p.estValue !== undefined ? lift('est_value', p.estValue) : null,
      valuationAsOf: p.valuationAsOf ?? null,
      valuationSource: p.valuationSource ?? null,
      ownershipPct: p.ownershipPct,
      costBasis: p.costBasis !== undefined ? lift('cost_basis', p.costBasis) : null,
      location: p.location !== undefined ? lift('location', p.location) : null,
      notes: p.notes !== undefined ? lift('notes', p.notes) : null,
      inTrust: p.inTrust,
      fundingStatus: p.fundingStatus ?? null,
      retiredAt: null,
    };
  }
  if (state === null) {
    throw new ProjectionError(`${p.type} before AssetCreated`);
  }
  if (state.retiredAt !== null) {
    throw new ProjectionError(`${p.type} after AssetRetired`);
  }
  switch (p.type) {
    case 'AssetDetailsUpdated':
      return {
        ...state,
        title: p.title ?? state.title,
        location:
          p.location === undefined
            ? state.location
            : p.location === null
              ? null
              : lift('location', p.location),
        notes:
          p.notes === undefined ? state.notes : p.notes === null ? null : lift('notes', p.notes),
        inTrust: p.inTrust ?? state.inTrust,
        fundingStatus: p.fundingStatus === undefined ? state.fundingStatus : p.fundingStatus,
      };
    case 'ValuationRecorded':
      return {
        ...state,
        estValue: lift('est_value', p.estValue),
        valuationAsOf: p.valuationAsOf,
        valuationSource: p.valuationSource,
      };
    case 'OwnershipChanged':
      return {
        ...state,
        ownershipPct: p.ownershipPct,
        costBasis:
          p.costBasis === undefined
            ? state.costBasis
            : p.costBasis === null
              ? null
              : lift('cost_basis', p.costBasis),
      };
    case 'BeneficiaryDesignated':
    case 'BeneficiaryRemoved':
      // Beneficiary events change the designations projection, not the view.
      return state;
    case 'AssetRetired':
      return { ...state, retiredAt: evt.occurredAt };
  }
}

/** Fold one ledger event into the asset's live beneficiary designations. */
export function applyBeneficiaryEvent(
  rows: readonly BeneficiaryState[],
  evt: LedgerEventInput,
): BeneficiaryState[] {
  const p = evt.payload;
  if (p.type === 'BeneficiaryDesignated') {
    const rest = rows.filter(
      (r) => !(r.contactId === p.contactId && r.designation === p.designation),
    );
    return [...rest, { contactId: p.contactId, designation: p.designation, sharePct: p.sharePct }];
  }
  if (p.type === 'BeneficiaryRemoved') {
    const next = rows.filter(
      (r) => !(r.contactId === p.contactId && r.designation === p.designation),
    );
    if (next.length === rows.length) {
      throw new ProjectionError('BeneficiaryRemoved without live designation');
    }
    return next;
  }
  return [...rows];
}

/** Live share sum per designation class after folding (invariant: ≤ 100). */
export function shareSum(rows: readonly BeneficiaryState[], designation: string): number {
  // Sum in milli-percent to avoid float accumulation.
  const milli = rows
    .filter((r) => r.designation === designation)
    .reduce((acc, r) => acc + Math.round(r.sharePct * 1000), 0);
  return milli / 1000;
}
