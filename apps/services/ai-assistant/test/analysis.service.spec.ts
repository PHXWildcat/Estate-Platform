import { randomUUID } from 'node:crypto';
import { AnalysisService, DESIGNATION_FETCH_CAP } from '../src/analysis.service';
import type { AiAssistantConfig } from '../src/config';
import type {
  AssetsClient,
  AssetView,
  BeneficiariesView,
  DocumentsClient,
  DocumentView,
  ProfileClient,
} from '../src/clients';

/**
 * The service is the only part of the analysis stack that does I/O, so these
 * tests are about exactly two things: that a failed read can never be rendered
 * as an empty estate, and that every read rides the CALLER'S OWN bearer.
 */

const BEARER = 'the-callers-own-access-token';

interface Answers {
  listAssets: AssetView[] | null;
  beneficiaries: BeneficiariesView | null | ((assetId: string) => BeneficiariesView | null);
  list: DocumentView[] | null;
  facts: { stateOfResidence: string | null; maritalStatus: string | null } | null;
  family: { id: string; relation: string; isMinor: boolean | null }[] | null;
}

function asset(over: Partial<AssetView> = {}): AssetView {
  return {
    assetId: randomUUID(),
    category: 'real_estate',
    title: 'A house',
    estValue: '100.00',
    valuationAsOf: null,
    ownershipPct: 100,
    inTrust: false,
    fundingStatus: 'unfunded',
    ...over,
  };
}

function harness(over: Partial<Answers> = {}, nodeEnv: 'test' | 'production' = 'test') {
  const bearers: string[] = [];
  const answer = <T>(bearer: string, value: T): Promise<T> => {
    bearers.push(bearer);
    return Promise.resolve(value);
  };
  const assets = {
    listAssets: (bearer: string) => answer(bearer, over.listAssets ?? null),
    beneficiaries: (bearer: string, assetId: string) =>
      answer(
        bearer,
        typeof over.beneficiaries === 'function'
          ? over.beneficiaries(assetId)
          : (over.beneficiaries ?? null),
      ),
  } as unknown as AssetsClient;
  const documents = {
    list: (bearer: string) => answer(bearer, over.list ?? null),
  } as unknown as DocumentsClient;
  const profile = {
    facts: (bearer: string) => answer(bearer, over.facts ?? null),
    family: (bearer: string) => answer(bearer, over.family ?? null),
  } as unknown as ProfileClient;
  const config = { nodeEnv } as AiAssistantConfig;
  return { service: new AnalysisService(assets, documents, profile, config), bearers };
}

/** Every input present, so an analyser can actually run. */
const COMPLETE: Partial<Answers> = {
  listAssets: [],
  list: [],
  facts: { stateOfResidence: 'TX', maritalStatus: 'single' },
  family: [],
  beneficiaries: null,
};

describe('a failed read is never an empty estate', () => {
  // The single most consequential rule in this file. "No beneficiary conflicts"
  // is the sentence a user is most likely to act on by doing nothing, and every
  // client answers `null` for every failure it can have.
  it.each([
    ['funding: assets down', { ...COMPLETE, listAssets: null }, 'funding'],
    ['funding: documents down', { ...COMPLETE, list: null }, 'funding'],
    ['missing documents: documents down', { ...COMPLETE, list: null }, 'missingDocuments'],
    ['missing documents: profile down', { ...COMPLETE, facts: null }, 'missingDocuments'],
    ['missing documents: family down', { ...COMPLETE, family: null }, 'missingDocuments'],
    ['missing documents: assets down', { ...COMPLETE, listAssets: null }, 'missingDocuments'],
    ['beneficiaries: assets down', { ...COMPLETE, listAssets: null }, 'beneficiaryConflicts'],
    ['estate tax: assets down', { ...COMPLETE, listAssets: null }, 'estateTax'],
    ['estate tax: profile down', { ...COMPLETE, facts: null }, 'estateTax'],
  ] as const)('%s', async (_name, answers, method) => {
    const h = harness(answers);
    const result = await (h.service[method] as (b: string) => Promise<{ status: string }>)(BEARER);
    expect(result.status).toBe('unavailable');
  });

  it('fails the whole beneficiary run when ONE asset’s designations are unreadable', async () => {
    // Not "this asset has no beneficiaries" — that is the same sentence with a
    // completely different meaning, and the safe one is to report nothing.
    const one = asset();
    const h = harness({ ...COMPLETE, listAssets: [one], beneficiaries: () => null });
    await expect(h.service.beneficiaryConflicts(BEARER)).resolves.toMatchObject({
      status: 'unavailable',
      reason: 'upstream_unavailable',
    });
  });
});

describe('bearer forwarding', () => {
  it('presents the caller own bearer on every peer read', async () => {
    // The service holds no credential in either direction: an analysis can only
    // ever be computed from data this caller could already read.
    const h = harness(COMPLETE);
    await h.service.missingDocuments(BEARER);
    expect(h.bearers.length).toBeGreaterThan(0);
    expect(new Set(h.bearers)).toEqual(new Set([BEARER]));
  });
});

describe('designation fetching is capped, and says so', () => {
  it('examines up to the cap and reports the truncation', async () => {
    const many = Array.from({ length: DESIGNATION_FETCH_CAP + 5 }, () => asset());
    const h = harness({
      ...COMPLETE,
      listAssets: many,
      beneficiaries: (assetId) => ({ assetId, beneficiaries: [], totals: [] }),
    });
    const result = await h.service.beneficiaryConflicts(BEARER);
    expect(result.status).toBe('ok');
    if (result.status !== 'ok') {
      return;
    }
    const truncation = result.findings.find((f) => f.code === 'assets_not_examined');
    expect(truncation?.detail).toMatchObject({
      examined: DESIGNATION_FETCH_CAP,
      total: many.length,
    });
    // A capped run must never also claim the designations are consistent.
    expect(result.findings.map((f) => f.code)).not.toContain('designations_consistent');
  });

  it('does not report truncation when everything was examined', async () => {
    const h = harness({
      ...COMPLETE,
      listAssets: [asset()],
      beneficiaries: (assetId) => ({ assetId, beneficiaries: [], totals: [] }),
    });
    const result = await h.service.beneficiaryConflicts(BEARER);
    expect(result.status === 'ok' && result.findings.map((f) => f.code)).not.toContain(
      'assets_not_examined',
    );
  });
});

describe('the estate-tax gate comes from config, so both surfaces inherit it', () => {
  it('refuses in production and runs elsewhere', async () => {
    await expect(harness(COMPLETE, 'production').service.estateTax(BEARER)).resolves.toMatchObject({
      status: 'refused',
      reason: 'reference_unreviewed',
    });
    await expect(harness(COMPLETE, 'test').service.estateTax(BEARER)).resolves.toMatchObject({
      status: 'ok',
    });
  });

  it('passes an explicit tax year through', async () => {
    const result = await harness(COMPLETE).service.estateTax(BEARER, 1999);
    expect(result.status === 'ok' && result.findings.map((f) => f.code)).toContain(
      'tax_year_unavailable',
    );
  });
});
