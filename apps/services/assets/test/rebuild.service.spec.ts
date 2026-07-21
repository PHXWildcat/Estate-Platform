import { randomUUID } from 'node:crypto';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import { AssetsService } from '../src/assets.service';
import { AssetsAuthz } from '../src/authz.service';
import { RebuildService } from '../src/rebuild.service';
import { buildCipher, fakeDb, FakeBens, FakeLedger, FakeViews, noopEvents } from './support';

const OWNER = randomUUID();

describe('RebuildService (projection = fold(ledger))', () => {
  function build(): {
    service: AssetsService;
    rebuild: RebuildService;
    views: FakeViews;
    bens: FakeBens;
  } {
    const ledger = new FakeLedger();
    const views = new FakeViews();
    const bens = new FakeBens();
    const db = fakeDb();
    const cipher = buildCipher(); // shared DEK store: service + rebuild see the same keys
    const service = new AssetsService(
      db,
      ledger,
      views,
      bens,
      cipher,
      new AssetsAuthz(new PolicyDecisionPoint(loadBundledPolicies())),
      noopEvents,
    );
    const rebuild = new RebuildService(db, ledger, views, bens, cipher, noopEvents);
    return { service, rebuild, views, bens };
  }

  it('reports zero diffs on an untampered projection', async () => {
    const { service, rebuild } = build();
    const { assetId } = await service.createAsset(OWNER, {
      category: 'crypto',
      title: 'Cold wallet',
      estValue: '25000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'market',
      notes: 'seed phrase is in the vault',
    });
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: randomUUID(),
      designation: 'primary',
      sharePct: 100,
    });
    const report = await rebuild.rebuild({ repair: false });
    expect(report.assets).toBe(1);
    expect(report.events).toBe(2);
    expect(report.diffs).toEqual([]);
    expect(report.repaired).toBe(false);
  });

  it('detects tampering — plaintext, ciphertext, and beneficiary rows — and repairs from the ledger', async () => {
    const { service, rebuild, views, bens } = build();
    const { assetId } = await service.createAsset(OWNER, {
      category: 'art',
      title: 'Original title',
      estValue: '10000.00',
      valuationAsOf: '2026-07-01',
      valuationSource: 'appraisal',
    });
    const contact = randomUUID();
    await service.designateBeneficiary(OWNER, assetId, {
      contactId: contact,
      designation: 'primary',
      sharePct: 100,
    });

    // Simulate projection corruption (the class of drift the DR check exists for):
    const row = views.rows.get(assetId)!;
    row.title = 'TAMPERED';
    row.in_trust = true;
    row.est_value_ct = Buffer.from('garbage-not-aead'); // undecryptable live value
    bens.rows.find((r) => r.contact_id === contact)!.deleted_at = new Date(); // designation vanished

    const detect = await rebuild.rebuild({ repair: false });
    const kinds = detect.diffs.map((d) => `${d.kind}:${d.field ?? d.designation ?? ''}`).sort();
    expect(kinds).toEqual([
      'beneficiary_missing:primary',
      'view_field:est_value',
      'view_field:in_trust',
      'view_field:title',
    ]);
    // Diff output carries IDs and column names only — never values.
    expect(JSON.stringify(detect.diffs)).not.toContain('10000.00');
    expect(JSON.stringify(detect.diffs)).not.toContain('Original title');

    const repaired = await rebuild.rebuild({ repair: true });
    expect(repaired.repaired).toBe(true);

    const clean = await rebuild.rebuild({ repair: false });
    expect(clean.diffs).toEqual([]);
    const dto = await service.getAsset(OWNER, assetId);
    expect(dto.title).toBe('Original title');
    expect(dto.estValue).toBe('10000.00');
    expect(dto.inTrust).toBe(false);
  });
});
