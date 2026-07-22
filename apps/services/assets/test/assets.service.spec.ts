import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { AssetsService } from '../src/assets.service';
import { AssetsAuthz } from '../src/authz.service';
import { buildCipher, fakeDb, FakeBens, FakeLedger, FakeViews, noopEvents } from './support';

const OWNER = randomUUID();
const STRANGER = randomUUID();

function build(): {
  service: AssetsService;
  ledger: FakeLedger;
  views: FakeViews;
  bens: FakeBens;
} {
  const ledger = new FakeLedger();
  const views = new FakeViews();
  const bens = new FakeBens();
  // The fakes are structurally compatible with the repo classes (stateless,
  // public-method-only), so no casts are needed.
  const service = new AssetsService(
    fakeDb(),
    ledger,
    views,
    bens,
    buildCipher(),
    new AssetsAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
    noopEvents,
  );
  return { service, ledger, views, bens };
}

describe('AssetsService commands', () => {
  it('creates an asset: appends, projects ciphertext, acks with version', async () => {
    const { service, ledger, views } = build();
    const ack = await service.createAsset(OWNER, {
      category: 'real_estate',
      title: 'Lake house',
      estValue: '850000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
      notes: 'deed in safe',
    });
    expect(ack.version).toBe('1');
    expect(ack.replayed).toBe(false);
    expect(ledger.rows).toHaveLength(1);
    const row = views.rows.get(ack.assetId)!;
    expect(row.title).toBe('Lake house');
    // Sensitive columns are ciphertext at rest — never the plaintext bytes.
    expect(row.est_value_ct).toBeInstanceOf(Buffer);
    expect(row.est_value_ct!.includes(Buffer.from('850000.00'))).toBe(false);
    expect(row.notes_ct!.includes(Buffer.from('deed'))).toBe(false);
    expect(ledger.rows[0]!.payload_ct.includes(Buffer.from('Lake house'))).toBe(false);
  });

  it('reads back decrypted state and bumps the version per command', async () => {
    const { service } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'cash', title: 'Checking' });
    await service.recordValuation(OWNER, assetId, {
      estValue: '12000.00',
      valuationAsOf: '2026-07-20',
      valuationSource: 'owner_estimate',
    });
    const dto = await service.getAsset(OWNER, assetId);
    expect(dto.estValue).toBe('12000.00');
    expect(dto.version).toBe('2');
  });

  it('404s commands on missing or retired assets; history survives retirement', async () => {
    const { service } = build();
    await expect(
      service.recordValuation(OWNER, randomUUID(), {
        estValue: '1.00',
        valuationAsOf: '2026-07-01',
        valuationSource: 'market',
      }),
    ).rejects.toThrow(NotFoundException);

    const { assetId } = await service.createAsset(OWNER, { category: 'vehicle', title: 'Truck' });
    await service.retireAsset(OWNER, assetId, { reason: 'sold' });
    await expect(service.getAsset(OWNER, assetId)).rejects.toThrow(NotFoundException);
    await expect(service.updateDetails(OWNER, assetId, { title: 'Zombie truck' })).rejects.toThrow(
      NotFoundException,
    );
    const history = await service.getHistory(OWNER, assetId);
    expect(history.map((h) => h.eventType)).toEqual(['AssetCreated', 'AssetRetired']);
    expect(history[0]!.payload.type).toBe('AssetCreated');
  });

  it('denies non-owners (deny-by-default PEP)', async () => {
    const { service } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'art', title: 'Painting' });
    await expect(service.getAsset(STRANGER, assetId)).rejects.toThrow(ForbiddenException);
    await expect(service.updateDetails(STRANGER, assetId, { title: 'Mine now' })).rejects.toThrow(
      ForbiddenException,
    );
    expect(await service.listAssets(STRANGER)).toEqual([]);
  });

  it('enforces optimistic concurrency via If-Match', async () => {
    const { service } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'cash', title: 'Savings' });
    await service.recordValuation(OWNER, assetId, {
      estValue: '5.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'owner_estimate',
    });
    await expect(
      service.updateDetails(OWNER, assetId, { title: 'stale write' }, 1n),
    ).rejects.toThrow(ConflictException);
    const ack = await service.updateDetails(OWNER, assetId, { title: 'fresh write' }, 2n);
    expect(ack.version).toBe('3');
  });

  it('is idempotent per client eventId', async () => {
    const { service, ledger } = build();
    const eventId = randomUUID();
    const first = await service.createAsset(OWNER, { category: 'cash', title: 'Once', eventId });
    const retry = await service.createAsset(OWNER, { category: 'cash', title: 'Once', eventId });
    expect(retry.replayed).toBe(true);
    expect(retry.assetId).toBe(first.assetId);
    expect(retry.version).toBe(first.version);
    expect(ledger.rows).toHaveLength(1);
    // Another user must not be able to probe someone else's eventId.
    await expect(
      service.createAsset(STRANGER, { category: 'cash', title: 'Steal', eventId }),
    ).rejects.toThrow(ConflictException);
  });

  it('enforces the beneficiary share-sum invariant (≤ 100 per designation)', async () => {
    const { service, bens } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'llc', title: 'Family LLC' });
    const alice = randomUUID();
    const bob = randomUUID();
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: alice,
      designation: 'primary',
      sharePct: 60,
    });
    await expect(
      service.designateBeneficiary(OWNER, assetId, {
        contactId: bob,
        designation: 'primary',
        sharePct: 50,
      }),
    ).rejects.toThrow(UnprocessableEntityException);
    // Re-designating the same contact REPLACES their share (60→50), no double count.
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: alice,
      designation: 'primary',
      sharePct: 50,
    });
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: bob,
      designation: 'primary',
      sharePct: 50,
    });
    // Contingent class sums independently.
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: bob,
      designation: 'contingent',
      sharePct: 100,
    });
    const dto = await service.getBeneficiaries(OWNER, assetId);
    expect(dto.totals).toEqual([
      { designation: 'primary', sharePct: 100, designationComplete: true },
      { designation: 'contingent', sharePct: 100, designationComplete: true },
    ]);
    expect(bens.rows.filter((r) => r.deleted_at === null)).toHaveLength(3);

    await service.removeBeneficiary(OWNER, assetId, bob, { designation: 'primary' });
    await expect(
      service.removeBeneficiary(OWNER, assetId, bob, { designation: 'primary' }),
    ).rejects.toThrow(NotFoundException);
  });
});

describe('AssetsService queries', () => {
  it('answers "what did the estate hold on date X" by ledger replay', async () => {
    const { service, ledger } = build();
    ledger.nextOccurredAt = new Date('2026-01-10T12:00:00Z');
    const early = await service.createAsset(OWNER, { category: 'gold', title: 'Coins' });
    ledger.nextOccurredAt = new Date('2026-03-05T12:00:00Z');
    await service.recordValuation(OWNER, early.assetId, {
      estValue: '9000.00',
      valuationAsOf: '2026-03-05',
      valuationSource: 'market',
    });
    ledger.nextOccurredAt = new Date('2026-06-01T12:00:00Z');
    const late = await service.createAsset(OWNER, { category: 'vehicle', title: 'Truck' });
    ledger.nextOccurredAt = new Date('2026-07-01T12:00:00Z');
    await service.retireAsset(OWNER, early.assetId, { reason: 'sold' });

    // Before anything existed.
    expect(await service.listAssets(OWNER, '2025-12-31')).toEqual([]);
    // After creation, before the valuation: held, unvalued.
    const feb = await service.listAssets(OWNER, '2026-02-01');
    expect(feb.map((a) => a.title)).toEqual(['Coins']);
    expect(feb[0]!.estValue).toBeNull();
    // After valuation, before the truck.
    const april = await service.listAssets(OWNER, '2026-04-01');
    expect(april[0]!.estValue).toBe('9000.00');
    // Between truck purchase and gold sale: both held.
    const june = await service.listAssets(OWNER, '2026-06-15');
    expect(june.map((a) => a.title).sort()).toEqual(['Coins', 'Truck']);
    // Today: gold retired, only the truck remains.
    const today = await service.listAssets(OWNER);
    expect(today.map((a) => a.title)).toEqual(['Truck']);
    expect(late.assetId).toBe(today[0]!.assetId);
  });

  it('computes net worth with exact ownership-weighted math', async () => {
    const { service } = build();
    await service.createAsset(OWNER, {
      category: 'real_estate',
      title: 'House',
      estValue: '800000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
      inTrust: true,
    });
    const duplex = await service.createAsset(OWNER, {
      category: 'real_estate',
      title: 'Duplex',
      estValue: '500000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
    });
    await service.changeOwnership(OWNER, duplex.assetId, { ownershipPct: 50 });
    await service.createAsset(OWNER, { category: 'jewelry', title: 'Ring' }); // unvalued

    const nw = await service.getNetWorth(OWNER);
    expect(nw.totalValue).toBe('1050000.00'); // 800k + 50% × 500k
    expect(nw.assetCount).toBe(3);
    expect(nw.valuedAssetCount).toBe(2);
    expect(nw.inTrustValue).toBe('800000.00');
    expect(nw.inTrustPct).toBeCloseTo(76.2, 1); // value-weighted funding %
    expect(nw.byCategory).toEqual([
      { category: 'jewelry', count: 1, value: '0.00' },
      { category: 'real_estate', count: 2, value: '1050000.00' },
    ]);
  });
});
