import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import type { SettlementStageAuthority, StageAccessAuthority } from '@estate/settlement-client';
import { AssetsService, viewField } from '../src/assets.service';
import { AssetsAuthz } from '../src/authz.service';
import type { FieldCipher } from '../src/field-cipher';
import { buildCipher, fakeDb, FakeBens, FakeLedger, FakeViews, noopEvents } from './support';

const OWNER = randomUUID();
const STRANGER = randomUUID();

function build(options?: { settlement?: SettlementStageAuthority }): {
  service: AssetsService;
  ledger: FakeLedger;
  views: FakeViews;
  bens: FakeBens;
  cipher: FieldCipher;
} {
  const ledger = new FakeLedger();
  const views = new FakeViews();
  const bens = new FakeBens();
  const cipher = buildCipher();
  // The fakes are structurally compatible with the repo classes (stateless,
  // public-method-only), so no casts are needed.
  const service = new AssetsService(
    fakeDb(),
    ledger,
    views,
    bens,
    cipher,
    new AssetsAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
    noopEvents,
    // Settlement refuses by default: these suites cover the OWNER paths, and a
    // refusing gate keeps the executor route from accidentally passing here.
    options?.settlement ?? {
      checkStageAccess: () => Promise.resolve({ allowed: false as const }),
    },
  );
  return { service, ledger, views, bens, cipher };
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

  it('404s commands on missing or retired assets; the RECORD survives retirement', async () => {
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
    // The detail stays READABLE with an explicit status (M19 PR2): a disposal
    // is a record, not a deletion. Commands still refuse.
    const retired = await service.getAsset(OWNER, assetId);
    expect(retired.status).toBe('retired');
    expect(retired.retiredAt).not.toBeNull();
    await expect(service.updateDetails(OWNER, assetId, { title: 'Zombie truck' })).rejects.toThrow(
      NotFoundException,
    );
    // Default list excludes it; includeRetired serves it with its status.
    expect(await service.listAssets(OWNER)).toEqual([]);
    const withRetired = await service.listAssets(OWNER, undefined, true);
    expect(withRetired).toHaveLength(1);
    expect(withRetired[0]!.status).toBe('retired');
    const history = await service.getHistory(OWNER, assetId);
    expect(history.map((h) => h.eventType)).toEqual(['AssetCreated', 'AssetRetired']);
    expect(history[0]!.payload.type).toBe('AssetCreated');
  });

  it('denies non-owners with the SAME 404 a missing asset gets (no existence oracle)', async () => {
    const { service } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'art', title: 'Painting' });
    // Deny-by-default PEP still decides; the ANSWER is the missing-row 404,
    // so a guessed id that names a real asset is indistinguishable from one
    // that names nothing (assertCanOrNotFound).
    await expect(service.getAsset(STRANGER, assetId)).rejects.toThrow(NotFoundException);
    await expect(service.updateDetails(STRANGER, assetId, { title: 'Mine now' })).rejects.toThrow(
      NotFoundException,
    );
    await expect(service.getHistory(STRANGER, assetId)).rejects.toThrow(NotFoundException);
    await expect(service.getBeneficiaries(STRANGER, assetId)).rejects.toThrow(NotFoundException);
    expect(await service.listAssets(STRANGER)).toEqual([]);
  });

  it('the list decrypts EXACTLY est_value and carries no detail fields', async () => {
    const { service, cipher } = build();
    await service.createAsset(OWNER, {
      category: 'real_estate',
      title: 'Lake house',
      estValue: '850000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
      costBasis: '400000.00',
      location: 'safe behind the painting',
      notes: 'combination is 12-34-56',
    });
    const decryptSpy = jest.spyOn(cipher, 'decrypt');
    const list = await service.listAssets(OWNER);
    expect(list).toHaveLength(1);
    expect(list[0]!.estValue).toBe('850000.00');
    // The wire shape has NO keys for the detail fields — not null values,
    // absent keys (AssetSummaryDto is deliberately not Omit<AssetDto,…>).
    expect(list[0]).not.toHaveProperty('costBasis');
    expect(list[0]).not.toHaveProperty('location');
    expect(list[0]).not.toHaveProperty('notes');
    // Every decrypt the list performed was an est_value decrypt: each other
    // ciphertext field would be one audited crypto.field.decrypted PER ROW
    // on the hottest read (docs/03 §4 TB4 — the M18 decrypt-rate baseline).
    const fields = decryptSpy.mock.calls.map(([input]) => input.field);
    expect(fields.length).toBeGreaterThan(0);
    for (const field of fields) {
      expect(field).toMatch(/\.est_value$/);
    }
    // Control: the DETAIL read still decrypts the full row.
    decryptSpy.mockClear();
    const dto = await service.getAsset(OWNER, list[0]!.assetId);
    expect(dto.notes).toBe('combination is 12-34-56');
    expect(dto.costBasis).toBe('400000.00');
    decryptSpy.mockRestore();
  });

  it('getHistory resolves the owner DEK once, not once per event', async () => {
    const { service, cipher } = build();
    const { assetId } = await service.createAsset(OWNER, { category: 'cash', title: 'Checking' });
    await service.recordValuation(OWNER, assetId, {
      estValue: '12000.00',
      valuationAsOf: '2026-07-20',
      valuationSource: 'owner_estimate',
    });
    await service.updateDetails(OWNER, assetId, { inTrust: true });
    const dekSpy = jest.spyOn(cipher, 'getOrCreateDek');
    const history = await service.getHistory(OWNER, assetId);
    expect(history).toHaveLength(3);
    // Three events, one owner, one DEK lookup for the whole request.
    expect(dekSpy).toHaveBeenCalledTimes(1);
    dekSpy.mockRestore();
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

describe('AssetsService executor estate reads (docs/03 §5.1 control 5)', () => {
  const EXECUTOR = randomUUID();
  const CASE_ID = randomUUID();

  function buildWithGate(): {
    service: AssetsService;
    gate: { answer: StageAccessAuthority; calls: Array<Record<string, string>> };
  } {
    const gate = {
      answer: { allowed: false } as StageAccessAuthority,
      calls: [] as Array<Record<string, string>>,
      checkStageAccess(input: {
        bearerToken: string;
        ownerUserId: string;
        stage: string;
      }): Promise<StageAccessAuthority> {
        gate.calls.push({ ...input });
        return Promise.resolve(gate.answer);
      },
    };
    const settlement: SettlementStageAuthority = gate;
    const { service } = build({ settlement });
    return { service, gate };
  }

  it('refuses with a uniform 403 when settlement grants nothing', async () => {
    const { service, gate } = buildWithGate();
    await expect(service.listEstateAssets(EXECUTOR, 'bearer-token', OWNER)).rejects.toThrow(
      ForbiddenException,
    );
    // The refusal asked settlement exactly the staged-access question, on the
    // CALLER's own bearer — assets never invents authority of its own.
    expect(gate.calls).toEqual([
      { bearerToken: 'bearer-token', ownerUserId: OWNER, stage: 'inventory' },
    ]);
  });

  it('serves the FULL inventory on an approved inventory stage', async () => {
    const { service, gate } = buildWithGate();
    await service.createAsset(OWNER, {
      category: 'real_estate',
      title: 'Lake house',
      estValue: '850000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
      location: 'safe behind the painting',
      notes: 'deed in safe',
    });
    gate.answer = { allowed: true, caseId: CASE_ID };
    const inventory = await service.listEstateAssets(EXECUTOR, 'executor-bearer', OWNER);
    expect(inventory).toHaveLength(1);
    // Full DTOs, deliberately unlike the owner LIST: inventory is the
    // executor's ONLY read surface (there is no executor detail route), and
    // §5.1's inventory rung exists so an executor can FIND assets — every
    // decrypt is executor-attributed and audited.
    expect(inventory[0]!.estValue).toBe('850000.00');
    expect(inventory[0]!.location).toBe('safe behind the painting');
    expect(inventory[0]!.notes).toBe('deed in safe');
  });

  it('an approved stage for one estate grants nothing about another', async () => {
    const { service, gate } = buildWithGate();
    const otherOwner = randomUUID();
    await service.createAsset(otherOwner, { category: 'cash', title: 'Checking' });
    gate.answer = { allowed: true, caseId: CASE_ID };
    // The grant is scoped by the ownerUserId settlement was ASKED about; the
    // service reads exactly that owner's rows and no one else's.
    const inventory = await service.listEstateAssets(EXECUTOR, 'executor-bearer', OWNER);
    expect(inventory).toEqual([]);
    expect(gate.calls[0]!['ownerUserId']).toBe(OWNER);
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
    // The as-of path shares the LIST wire shape (no detail fields), even
    // though the replay necessarily decrypted whole payloads to fold.
    expect(feb[0]).not.toHaveProperty('notes');
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

describe('assets_view column AAD binds asset_id (docs/03 TB4 splice resistance)', () => {
  it('a projection ciphertext cannot be decrypted under a different asset of the same owner', async () => {
    const cipher = buildCipher();
    const owner = randomUUID();
    const assetA = randomUUID();
    const assetB = randomUUID();

    const { ciphertext, dekId } = await cipher.encrypt(
      owner,
      viewField(assetA, 'est_value'),
      '325000.00',
    );
    expect(ciphertext).not.toBeNull();

    // The exact splice a DB-tamper adversary would attempt: move asset A's
    // est_value blob onto asset B's row (same owner, same DEK, same field).
    // AAD now carries the asset_id, so GCM authentication must fail.
    await expect(
      cipher.decrypt({
        ownerUserId: owner,
        dekId,
        field: viewField(assetB, 'est_value'),
        ciphertext,
        actorId: owner,
        purpose: 'test',
      }),
    ).rejects.toThrow();

    // Control: under the correct asset id the same ciphertext decrypts.
    await expect(
      cipher.decrypt({
        ownerUserId: owner,
        dekId,
        field: viewField(assetA, 'est_value'),
        ciphertext,
        actorId: owner,
        purpose: 'test',
      }),
    ).resolves.toBe('325000.00');
  });
});
