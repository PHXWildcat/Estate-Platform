import { randomUUID } from 'node:crypto';
import type { AssetEventPayload } from '../src/asset-events';
import {
  applyAssetEvent,
  applyBeneficiaryEvent,
  ProjectionError,
  shareSum,
  type AssetState,
  type BeneficiaryState,
  type LedgerEventInput,
} from '../src/projection';

const ASSET = randomUUID();
const OWNER = randomUUID();
const CONTACT = randomUUID();

function evt(
  payload: AssetEventPayload,
  occurredAt = new Date('2026-07-21T12:00:00Z'),
): LedgerEventInput {
  return { assetId: ASSET, userId: OWNER, occurredAt, payload };
}

const identity = (_f: string, v: string): string => v;

function created(): AssetState<string> {
  return applyAssetEvent<string>(
    null,
    evt({
      v: 1,
      type: 'AssetCreated',
      category: 'real_estate',
      title: 'Lake house',
      ownershipPct: 100,
      inTrust: false,
      estValue: '850000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
      location: '123 Shore Rd',
    }),
    identity,
  );
}

describe('projection reducer', () => {
  it('folds a full lifecycle deterministically', () => {
    let state = created();
    expect(state.title).toBe('Lake house');
    expect(state.estValue).toBe('850000.00');
    expect(state.retiredAt).toBeNull();

    state = applyAssetEvent(
      state,
      evt({ v: 1, type: 'AssetDetailsUpdated', title: 'Lake house (deeded)', inTrust: true }),
      identity,
    );
    expect(state.title).toBe('Lake house (deeded)');
    expect(state.inTrust).toBe(true);
    expect(state.location).toBe('123 Shore Rd'); // untouched fields carried

    state = applyAssetEvent(
      state,
      evt({
        v: 1,
        type: 'ValuationRecorded',
        estValue: '900000.00',
        valuationAsOf: '2026-07-15',
        valuationSource: 'market',
      }),
      identity,
    );
    expect(state.estValue).toBe('900000.00');
    expect(state.valuationSource).toBe('market');

    state = applyAssetEvent(
      state,
      evt({ v: 1, type: 'OwnershipChanged', ownershipPct: 50, costBasis: '400000.00' }),
      identity,
    );
    expect(state.ownershipPct).toBe(50);
    expect(state.costBasis).toBe('400000.00');

    const retiredAt = new Date('2026-07-20T00:00:00Z');
    state = applyAssetEvent(
      state,
      evt({ v: 1, type: 'AssetRetired', reason: 'sold' }, retiredAt),
      identity,
    );
    expect(state.retiredAt).toEqual(retiredAt);
  });

  it('null clears an optional field; absent leaves it', () => {
    let state = created();
    state = applyAssetEvent(
      state,
      evt({ v: 1, type: 'AssetDetailsUpdated', location: null }),
      identity,
    );
    expect(state.location).toBeNull();
    expect(state.title).toBe('Lake house');
  });

  it('is order-sensitive (later valuations win)', () => {
    let state = created();
    state = applyAssetEvent(
      state,
      evt({
        v: 1,
        type: 'ValuationRecorded',
        estValue: '1.00',
        valuationAsOf: '2026-01-01',
        valuationSource: 'owner_estimate',
      }),
      identity,
    );
    state = applyAssetEvent(
      state,
      evt({
        v: 1,
        type: 'ValuationRecorded',
        estValue: '2.00',
        valuationAsOf: '2026-02-01',
        valuationSource: 'owner_estimate',
      }),
      identity,
    );
    expect(state.estValue).toBe('2.00');
  });

  it('rejects unlawful sequences (replay integrity)', () => {
    expect(() =>
      applyAssetEvent<string>(null, evt({ v: 1, type: 'AssetRetired' }), identity),
    ).toThrow(ProjectionError);
    expect(() =>
      applyAssetEvent(
        created(),
        evt({
          v: 1,
          type: 'AssetCreated',
          category: 'cash',
          title: 'x',
          ownershipPct: 100,
          inTrust: false,
        }),
        identity,
      ),
    ).toThrow(ProjectionError);
    const retired = applyAssetEvent(created(), evt({ v: 1, type: 'AssetRetired' }), identity);
    expect(() =>
      applyAssetEvent(
        retired,
        evt({ v: 1, type: 'AssetDetailsUpdated', title: 'zombie' }),
        identity,
      ),
    ).toThrow(ProjectionError);
  });

  it('folds beneficiary designations with replace + remove semantics', () => {
    let rows: BeneficiaryState[] = [];
    rows = applyBeneficiaryEvent(
      rows,
      evt({
        v: 1,
        type: 'BeneficiaryDesignated',
        contactId: CONTACT,
        designation: 'primary',
        sharePct: 60,
      }),
    );
    rows = applyBeneficiaryEvent(
      rows,
      evt({
        v: 1,
        type: 'BeneficiaryDesignated',
        contactId: CONTACT,
        designation: 'primary',
        sharePct: 40,
      }),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.sharePct).toBe(40);
    expect(shareSum(rows, 'primary')).toBe(40);

    rows = applyBeneficiaryEvent(
      rows,
      evt({
        v: 1,
        type: 'BeneficiaryRemoved',
        contactId: CONTACT,
        designation: 'primary',
      }),
    );
    expect(rows).toHaveLength(0);
    expect(() =>
      applyBeneficiaryEvent(
        rows,
        evt({
          v: 1,
          type: 'BeneficiaryRemoved',
          contactId: CONTACT,
          designation: 'primary',
        }),
      ),
    ).toThrow(ProjectionError);
  });

  it('sums shares without float drift', () => {
    const rows: BeneficiaryState[] = [
      { contactId: randomUUID(), designation: 'primary', sharePct: 33.333 },
      { contactId: randomUUID(), designation: 'primary', sharePct: 33.333 },
      { contactId: randomUUID(), designation: 'primary', sharePct: 33.334 },
    ];
    expect(shareSum(rows, 'primary')).toBe(100);
  });
});
