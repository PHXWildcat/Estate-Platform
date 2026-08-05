import {
  analyseBeneficiaryConflicts,
  analyseEstateTax,
  analyseFunding,
  analyseMissingDocuments,
  ANALYSIS_DISCLAIMER,
  isReviewed,
  referenceUsable,
  UNREVIEWED_EXEMPLAR,
  type AnalysisResult,
} from '../src/analysis';
import {
  ESTATE_TAX_REVIEW,
  federalFor,
  LATEST_TAX_YEAR,
} from '../src/analysis/reference/estate-tax';
import type {
  AssetView,
  BeneficiariesView,
  DocumentView,
  FamilyMemberView,
  ProfileFactsView,
} from '../src/clients';

/**
 * The analysers are pure functions, so these are the cheapest tests in the
 * service and the ones that carry the most product meaning: every assertion
 * here is a sentence the platform will one day say to somebody about their
 * estate.
 */

const ASSET_A = 'a55e0000-0000-4000-8000-0000000000a1';
const ASSET_B = 'a55e0000-0000-4000-8000-0000000000a2';
const DOC_A = 'd0c00000-0000-4000-8000-0000000000d1';

function asset(over: Partial<AssetView> = {}): AssetView {
  return {
    assetId: ASSET_A,
    category: 'real_estate',
    title: 'Elm Street house',
    estValue: '500000.00',
    valuationAsOf: '2026-01-01',
    ownershipPct: 100,
    inTrust: false,
    fundingStatus: 'unfunded',
    ...over,
  };
}

function doc(over: Partial<DocumentView> = {}): DocumentView {
  return {
    documentId: DOC_A,
    docType: 'revocable_trust',
    title: 'Family trust',
    currentVersion: 1,
    executionStatus: 'executed',
    executedAt: '2026-01-01T00:00:00.000Z',
    sealed: false,
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...over,
  };
}

function facts(over: Partial<ProfileFactsView> = {}): ProfileFactsView {
  return { stateOfResidence: 'TX', maritalStatus: 'married', ...over };
}

/** Codes present in a result, or a failure that says what the status was instead. */
function codes(result: AnalysisResult<string, unknown>): string[] {
  if (result.status !== 'ok') {
    throw new Error(`expected an ok analysis, got ${result.status}: ${result.reason}`);
  }
  return result.findings.map((finding) => finding.code);
}

function finding(result: AnalysisResult<string, unknown>, code: string) {
  if (result.status !== 'ok') {
    throw new Error(`expected an ok analysis, got ${result.status}`);
  }
  const match = result.findings.find((f) => f.code === code);
  if (match === undefined) {
    throw new Error(`no ${code} finding in [${codes(result).join(', ')}]`);
  }
  return match;
}

describe('every analyser carries the non-advice watermark', () => {
  // docs/01 §2.8: assistant outputs are "education/analysis only and are
  // watermarked in-product as non-legal-advice". A disclaimer a caller must
  // remember to attach is not a disclaimer, so it is a required field and this
  // is the assertion that keeps it one.
  const results: AnalysisResult<string, unknown>[] = [
    analyseFunding([], []),
    analyseMissingDocuments([], facts(), [], []),
    analyseBeneficiaryConflicts([], new Map()),
    analyseEstateTax([], facts(), { nodeEnv: 'test' }),
    // Including the refusal path: a user told "unavailable" is still being told
    // something about their estate.
    analyseEstateTax([], facts(), { nodeEnv: 'production' }),
  ];

  it.each(results.map((r, i) => [i, r] as const))('result %i is watermarked', (_i, result) => {
    expect(result.disclaimer).toBe(ANALYSIS_DISCLAIMER);
    expect(result.disclaimer).toMatch(/not legal or tax advice/i);
  });
});

describe('analyseFunding', () => {
  it('does not treat "no trust" as a funding gap', () => {
    // Telling a user with no trust that their assets are not in one is a product
    // opinion about how they should plan, not a finding about their estate.
    const result = analyseFunding([asset()], [doc({ docType: 'will' })]);
    expect(codes(result)).toEqual(['no_trust_on_file']);
    expect(result.status === 'ok' && result.summary).toMatchObject({ trustOnFile: false });
  });

  it('finds an asset titled outside an existing trust', () => {
    const result = analyseFunding([asset()], [doc()]);
    expect(codes(result)).toEqual(['asset_not_titled_in_trust', 'value_outside_trust']);
    expect(finding(result, 'asset_not_titled_in_trust')).toMatchObject({
      severity: 'high',
      subject: { kind: 'asset', ref: ASSET_A, label: 'Elm Street house' },
    });
  });

  it('respects the owner marking an asset not applicable', () => {
    // `na` is the owner's own decision. An analyser that nagged anyway teaches
    // people to ignore it, which costs more than the finding is worth.
    const result = analyseFunding([asset({ fundingStatus: 'na' })], [doc()]);
    expect(codes(result)).toEqual(['value_outside_trust']);
    expect(finding(result, 'value_outside_trust').detail).toMatchObject({
      assetsOutsideTrust: 0,
      excludedByOwner: 1,
    });
  });

  it('softens a reminder for funding already under way', () => {
    const result = analyseFunding([asset({ fundingStatus: 'in_progress' })], [doc()]);
    expect(finding(result, 'asset_funding_in_progress').severity).toBe('medium');
  });

  it('reports the two ledger fields disagreeing rather than believing either', () => {
    const result = analyseFunding([asset({ fundingStatus: 'funded', inTrust: false })], [doc()]);
    expect(codes(result)).toContain('funding_status_contradicts_title');
  });

  it('sums the owner share of value outside the trust, never a float', () => {
    const result = analyseFunding(
      [
        asset({ estValue: '1000000000000.00', ownershipPct: 33.333 }),
        asset({ assetId: ASSET_B, estValue: '0.01', ownershipPct: 100 }),
      ],
      [doc()],
    );
    expect(finding(result, 'value_outside_trust').detail).toMatchObject({
      valueOutsideTrust: '333330000000.01',
    });
  });

  it('counts unvalued assets so the total reads as a floor', () => {
    const result = analyseFunding([asset({ estValue: null })], [doc()]);
    expect(finding(result, 'value_outside_trust').detail).toMatchObject({
      valueOutsideTrust: '0.00',
      unvaluedAssetsOutsideTrust: 1,
    });
  });

  it('ignores a revoked trust — a retired document is absent, not present', () => {
    const result = analyseFunding([asset()], [doc({ executionStatus: 'revoked' })]);
    expect(codes(result)).toEqual(['no_trust_on_file']);
  });
});

describe('analyseMissingDocuments', () => {
  it('reports an empty document set as the high-severity gaps it is', () => {
    const result = analyseMissingDocuments([], facts(), [], []);
    expect(codes(result)).toEqual([
      'instrument_missing',
      'instrument_missing',
      'instrument_missing',
      'instrument_missing',
      'instrument_missing',
    ]);
    // Ordered by consequence: no will comes before no HIPAA authorization.
    expect(finding(result, 'instrument_missing').detail).toMatchObject({ expectedKind: 'will' });
  });

  it('accepts a trust-based plan as satisfying the will expectation', () => {
    const result = analyseMissingDocuments([doc()], facts(), [], []);
    const missing =
      result.status === 'ok' ? result.findings.map((f) => f.detail['expectedKind']) : [];
    expect(missing).not.toContain('will');
  });

  it('separates present-but-unexecuted from absent', () => {
    // The dangerous case: a document the user can see in their vault that
    // directs nothing.
    const result = analyseMissingDocuments(
      [doc({ docType: 'will', executionStatus: 'generated', executedAt: null })],
      facts(),
      [],
      [],
    );
    expect(codes(result)).toContain('instrument_not_executed');
    expect(finding(result, 'instrument_not_executed')).toMatchObject({
      severity: 'high',
      subject: { kind: 'document', ref: DOC_A },
      detail: { expectedKind: 'will', executionStatus: 'generated' },
    });
  });

  it('expects a guardian designation only when a minor child is on record', () => {
    const family: FamilyMemberView[] = [{ id: 'f1', relation: 'child', isMinor: true }];
    const withMinor = analyseMissingDocuments([], facts(), family, []);
    const withoutMinor = analyseMissingDocuments([], facts(), [], []);
    const kinds = (result: AnalysisResult<string, unknown>) =>
      result.status === 'ok' ? result.findings.map((f) => f.detail['expectedKind']) : [];
    expect(kinds(withMinor)).toContain('guardian_designation');
    expect(kinds(withoutMinor)).not.toContain('guardian_designation');
  });

  it('says so when it cannot tell whether a member is a minor', () => {
    // "I cannot tell whether you need a guardian designation" and "you do not
    // need one" are completely different answers.
    const family: FamilyMemberView[] = [{ id: 'f1', relation: 'child', isMinor: null }];
    const result = analyseMissingDocuments([], facts(), family, []);
    expect(codes(result)).toContain('minor_status_unknown');
  });

  it('expects funding paperwork only while something is left to move', () => {
    const complete = analyseMissingDocuments([doc()], facts(), [], [asset({ inTrust: true })]);
    const incomplete = analyseMissingDocuments([doc()], facts(), [], [asset()]);
    const kinds = (result: AnalysisResult<string, unknown>) =>
      result.status === 'ok' ? result.findings.map((f) => f.detail['expectedKind']) : [];
    expect(kinds(complete)).not.toContain('funding_letter');
    expect(kinds(incomplete)).toContain('funding_letter');
  });

  it('reports a complete set as a finding of its own', () => {
    const executed = (docType: string, documentId: string): DocumentView =>
      doc({ docType, documentId });
    const result = analyseMissingDocuments(
      [
        executed('will', 'd1'),
        executed('durable_poa', 'd2'),
        executed('medical_poa', 'd3'),
        executed('living_will', 'd4'),
        executed('hipaa_auth', 'd5'),
      ],
      facts(),
      [],
      [],
    );
    expect(codes(result)).toEqual(['document_set_complete']);
  });
});

describe('analyseBeneficiaryConflicts', () => {
  function designations(over: Partial<BeneficiariesView> = {}): BeneficiariesView {
    return {
      assetId: ASSET_A,
      beneficiaries: [{ contactId: 'c1', designation: 'primary', sharePct: 100 }],
      totals: [{ designation: 'primary', sharePct: 100, designationComplete: true }],
      ...over,
    };
  }

  it('finds the designation that quietly overrides the trust', () => {
    // The finding the whole feature is named for: the asset is in the trust AND
    // names a beneficiary directly, so it passes outside the instrument the
    // owner believes controls it.
    const result = analyseBeneficiaryConflicts(
      [asset({ inTrust: true })],
      new Map([[ASSET_A, designations()]]),
    );
    expect(codes(result)).toContain('designation_overrides_trust');
    expect(finding(result, 'designation_overrides_trust').severity).toBe('high');
  });

  it('reports shares that do not total 100%', () => {
    const result = analyseBeneficiaryConflicts(
      [asset()],
      new Map([
        [
          ASSET_A,
          designations({
            beneficiaries: [{ contactId: 'c1', designation: 'primary', sharePct: 60 }],
            totals: [{ designation: 'primary', sharePct: 60, designationComplete: false }],
          }),
        ],
      ]),
    );
    expect(finding(result, 'designation_incomplete').detail).toMatchObject({ sharePct: 60 });
  });

  it('separates over-allocation from under-allocation', () => {
    const result = analyseBeneficiaryConflicts(
      [asset()],
      new Map([
        [
          ASSET_A,
          designations({
            totals: [{ designation: 'primary', sharePct: 120, designationComplete: false }],
          }),
        ],
      ]),
    );
    expect(codes(result)).toContain('designation_over_allocated');
    expect(codes(result)).not.toContain('designation_incomplete');
  });

  it('flags a contact named twice in one class, without naming them', () => {
    const result = analyseBeneficiaryConflicts(
      [asset()],
      new Map([
        [
          ASSET_A,
          designations({
            beneficiaries: [
              { contactId: 'c1', designation: 'primary', sharePct: 50 },
              { contactId: 'c1', designation: 'primary', sharePct: 50 },
            ],
          }),
        ],
      ]),
    );
    expect(codes(result)).toContain('duplicate_designation');
    // A third party's id is not the owner's answer to give a model provider.
    expect(JSON.stringify(result)).not.toContain('c1');
  });

  it('expects a designation on insurance and annuities, and nowhere else', () => {
    const insurance = analyseBeneficiaryConflicts(
      [asset({ category: 'life_insurance' })],
      new Map(),
    );
    const house = analyseBeneficiaryConflicts([asset({ category: 'real_estate' })], new Map());
    expect(codes(insurance)).toContain('no_beneficiary_designated');
    expect(codes(house)).toEqual(['designations_consistent']);
  });

  it('never reports "consistent" from a partial examination', () => {
    // A capped run that said "no conflicts" would be the most misleading answer
    // this analyser could give.
    // One asset examined out of nine: the truncation is derived from the count.
    const result = analyseBeneficiaryConflicts([asset()], new Map(), 9);
    expect(codes(result)).toContain('assets_not_examined');
    expect(codes(result)).not.toContain('designations_consistent');
  });

  it('says designations are consistent when they are', () => {
    const result = analyseBeneficiaryConflicts([asset()], new Map([[ASSET_A, designations()]]));
    expect(codes(result)).toEqual(['designations_consistent']);
  });
});

describe('analyseEstateTax', () => {
  const options = { nodeEnv: 'test' } as const;

  it('REFUSES in production while the reference data is unreviewed', () => {
    // The control this analyser is gated by (analysis/reference/review.ts): the
    // figures are exemplars, and production must not state a threshold nobody
    // qualified has checked.
    const result = analyseEstateTax([asset()], facts(), { nodeEnv: 'production' });
    expect(result.status).toBe('refused');
    expect(result.status === 'refused' && result.reason).toBe('reference_unreviewed');
  });

  it('runs outside production, which is what makes it testable', () => {
    expect(analyseEstateTax([asset()], facts(), options).status).toBe('ok');
  });

  it('reports headroom when the estate is under the federal exemption', () => {
    const result = analyseEstateTax([asset({ estValue: '1000000.00' })], facts(), options);
    expect(finding(result, 'federal_within_exemption').detail).toMatchObject({
      grossEstate: '1000000.00',
      headroom: '14000000.00',
    });
  });

  it('computes the excess and labels the tax figure an upper bound', () => {
    const result = analyseEstateTax([asset({ estValue: '20000000.00' })], facts(), options);
    expect(finding(result, 'federal_exposure')).toMatchObject({
      severity: 'high',
      detail: {
        amountOverExemption: '5000000.00',
        topRatePct: 40,
        estimatedTaxUpperBound: '2000000.00',
      },
    });
  });

  it('counts only the owner share of a jointly held asset', () => {
    const result = analyseEstateTax(
      [asset({ estValue: '100000.00', ownershipPct: 50 })],
      facts(),
      options,
    );
    expect(result.status === 'ok' && result.summary).toMatchObject({ grossEstate: '50000.00' });
  });

  it('says an estate with no valued assets is exactly that', () => {
    const result = analyseEstateTax([asset({ estValue: null })], facts(), options);
    expect(codes(result)).toContain('unvalued_assets_excluded');
    expect(result.status === 'ok' && result.summary).toMatchObject({
      grossEstate: '0.00',
      unvaluedAssetCount: 1,
      valuedAssetCount: 0,
    });
  });

  it('reports a state estate tax against its own, lower threshold', () => {
    // The case that matters in practice: far under the federal exemption and
    // over the state's.
    const result = analyseEstateTax(
      [asset({ estValue: '5000000.00' })],
      facts({ stateOfResidence: 'OR' }),
      options,
    );
    expect(codes(result)).toContain('state_estate_exposure');
    expect(finding(result, 'state_estate_exposure').detail).toMatchObject({
      stateOfResidence: 'OR',
      amountOverExemption: '4000000.00',
    });
  });

  it('reports inheritance-tax exposure WITHOUT inventing a rate', () => {
    // The rate depends on each recipient's relationship to the decedent, and
    // the platform holds beneficiaries as contact ids with no relationship.
    const result = analyseEstateTax([asset()], facts({ stateOfResidence: 'PA' }), options);
    expect(finding(result, 'state_inheritance_tax_applies').detail).toMatchObject({
      dependsOnRecipientRelationship: true,
    });
    expect(codes(result)).not.toContain('state_estate_exposure');
  });

  it('reports both halves for the one state that levies both', () => {
    const result = analyseEstateTax(
      [asset({ estValue: '9000000.00' })],
      facts({ stateOfResidence: 'MD' }),
      options,
    );
    expect(codes(result)).toEqual(
      expect.arrayContaining(['state_estate_exposure', 'state_inheritance_tax_applies']),
    );
  });

  it('states positively that a state levies no death tax', () => {
    const result = analyseEstateTax([asset()], facts({ stateOfResidence: 'TX' }), options);
    expect(codes(result)).toContain('no_state_death_tax');
  });

  it('says when it does not know the state rather than assuming none', () => {
    const result = analyseEstateTax([asset()], facts({ stateOfResidence: null }), options);
    expect(codes(result)).toContain('state_of_residence_unknown');
    expect(codes(result)).not.toContain('no_state_death_tax');
  });

  it('falls back to the latest year on file and says it did', () => {
    const result = analyseEstateTax([asset()], facts(), { ...options, taxYear: 1999 });
    expect(finding(result, 'tax_year_unavailable').detail).toMatchObject({
      requestedYear: 1999,
      usedYear: LATEST_TAX_YEAR,
    });
  });

  it('always states what the estimate leaves out', () => {
    // Gross, not net: no debts, no prior gifts, no DSUE, no trust structures.
    expect(codes(analyseEstateTax([], facts(), options))).toContain(
      'estimate_excludes_liabilities',
    );
  });
});

describe('the reference-data review gate', () => {
  it('ships unreviewed, which is why production refuses', () => {
    // Pinned deliberately: when a tax professional signs off, this assertion is
    // what a reviewer must consciously flip, alongside the figures.
    expect(ESTATE_TAX_REVIEW.reviewedBy).toBe(UNREVIEWED_EXEMPLAR);
    expect(isReviewed(ESTATE_TAX_REVIEW)).toBe(false);
  });

  it('treats a half-filled review block as unreviewed', () => {
    // The failure to defend against is a well-meaning edit that clears the
    // sentinel without adding a reviewer, a date or a source.
    expect(
      isReviewed({ reviewedBy: '', reviewedAt: '2026-01-01', source: 'x', effectiveYear: 2026 }),
    ).toBe(false);
    expect(
      isReviewed({ reviewedBy: 'A CPA', reviewedAt: '', source: 'x', effectiveYear: 2026 }),
    ).toBe(false);
    expect(
      isReviewed({
        reviewedBy: 'A CPA',
        reviewedAt: '2026-01-01',
        source: '',
        effectiveYear: 2026,
      }),
    ).toBe(false);
    expect(
      isReviewed({
        reviewedBy: 'A CPA',
        reviewedAt: '2026-01-01',
        source: 'IRC §2010',
        effectiveYear: 2026,
      }),
    ).toBe(true);
  });

  it('blocks only production', () => {
    for (const env of ['development', 'test'] as const) {
      expect(referenceUsable(ESTATE_TAX_REVIEW, env)).toBe(true);
    }
    expect(referenceUsable(ESTATE_TAX_REVIEW, 'production')).toBe(false);
  });

  it('has figures for the year it calls latest', () => {
    // The analyser falls back to LATEST_TAX_YEAR, so a table that does not
    // contain it would turn every unknown year into a refusal.
    expect(federalFor(LATEST_TAX_YEAR)).not.toBeNull();
  });
});
