import type { FindingInfo } from '../graphql/client';
import { findingCopy, sortFindings, STATUS_COPY, type FindingCode } from './findings';

/**
 * The copy table is the only thing standing between an analyser's enum code and
 * a sentence a person reads about their own estate, so it is tested like code
 * rather than eyeballed like copy.
 */

/** Every code the four analysers emit (M10 PR3), kept in one list here too. */
const ALL_CODES: readonly FindingCode[] = [
  'no_trust_on_file',
  'asset_not_titled_in_trust',
  'asset_funding_in_progress',
  'funding_status_contradicts_title',
  'value_outside_trust',
  'instrument_missing',
  'instrument_not_executed',
  'minor_status_unknown',
  'document_set_complete',
  'designation_incomplete',
  'designation_over_allocated',
  'duplicate_designation',
  'designation_overrides_trust',
  'no_beneficiary_designated',
  'designations_consistent',
  'assets_not_examined',
  'federal_exposure',
  'federal_within_exemption',
  'state_estate_exposure',
  'state_within_exemption',
  'state_inheritance_tax_applies',
  'no_state_death_tax',
  'state_of_residence_unknown',
  'unvalued_assets_excluded',
  'estimate_excludes_liabilities',
  'tax_year_unavailable',
];

function finding(over: Partial<FindingInfo> = {}): FindingInfo {
  return {
    code: 'asset_not_titled_in_trust',
    severity: 'high',
    subject: { kind: 'asset', ref: 'a1', label: 'The lake house' },
    detail: {},
    ...over,
  };
}

describe('every analyser code has copy', () => {
  it.each(ALL_CODES)('%s renders a title and a body, never the raw token', (code) => {
    const copy = findingCopy(finding({ code }));
    expect(copy.title.length).toBeGreaterThan(0);
    expect(copy.body.length).toBeGreaterThan(0);
    expect(`${copy.title} ${copy.body}`).not.toContain(code);
  });

  it('survives a finding whose detail map is empty', () => {
    // Defence against a peer that trims a detail key: the sentence degrades,
    // the page does not throw.
    for (const code of ALL_CODES) {
      expect(() => findingCopy(finding({ code, detail: {} }))).not.toThrow();
    }
  });

  it('falls back safely for a code this app has never heard of', () => {
    const copy = findingCopy(finding({ code: 'invented_by_a_newer_service' }));
    expect(copy.title).toBe('A finding we cannot describe yet');
    expect(copy.body).not.toContain('invented_by_a_newer_service');
  });
});

describe('the sentences state facts about the account, not legal requirements', () => {
  // The line that lets this surface ship without a lawyer's sign-off (the same
  // line the analysers' own reference data holds): the platform reports what is
  // on file, and never what the law obliges anyone to do.
  it.each(ALL_CODES)('%s makes no legal demand', (code) => {
    const copy = findingCopy(finding({ code }));
    const text = `${copy.title} ${copy.body}`.toLowerCase();
    expect(text).not.toMatch(/you must|required by law|the law requires|you are required/);
  });
});

describe('numbers come from detail, through the string formatter', () => {
  it('formats money digit-perfectly past MAX_SAFE_INTEGER', () => {
    const copy = findingCopy(
      finding({
        code: 'federal_exposure',
        detail: {
          grossEstate: '90071992547409.91',
          exemption: '15000000.00',
          amountOverExemption: '75071992547409.91',
          estimatedTaxUpperBound: '30028797018963.96',
          topRatePct: 40,
        },
      }),
    );
    expect(copy.body).toContain('$90,071,992,547,409.91');
  });

  it('renders a missing money value as an em dash rather than NaN or 0', () => {
    const copy = findingCopy(finding({ code: 'value_outside_trust', detail: {} }));
    expect(copy.body).toContain('—');
    expect(copy.body).not.toMatch(/NaN|undefined|null/);
  });

  it('pluralizes counts', () => {
    const one = findingCopy(
      finding({ code: 'unvalued_assets_excluded', detail: { unvaluedAssetCount: 1 } }),
    );
    const many = findingCopy(
      finding({ code: 'unvalued_assets_excluded', detail: { unvaluedAssetCount: 3 } }),
    );
    expect(one.body).toContain('1 asset was');
    expect(many.body).toContain('3 assets were');
  });

  it('names the instrument in words, not in enum spelling', () => {
    const copy = findingCopy(
      finding({ code: 'instrument_missing', detail: { expectedKind: 'hipaa_auth' } }),
    );
    expect(copy.title).toContain('HIPAA authorization');
    expect(copy.title).not.toContain('hipaa_auth');
  });
});

describe('STATUS_COPY', () => {
  it('explains each non-OK status without implying the estate is fine', () => {
    for (const status of ['UNAVAILABLE', 'REFUSED', 'DISABLED'] as const) {
      const copy = STATUS_COPY[status];
      expect(copy.title.length).toBeGreaterThan(0);
      expect(copy.body.length).toBeGreaterThan(0);
      expect(`${copy.title} ${copy.body}`.toLowerCase()).not.toMatch(/no (issues|problems) found/);
    }
  });
});

describe('sortFindings', () => {
  it('puts high first, then medium, then info, without mutating the input', () => {
    const input = [
      finding({ code: 'no_trust_on_file', severity: 'info' }),
      finding({ code: 'asset_funding_in_progress', severity: 'medium' }),
      finding({ code: 'asset_not_titled_in_trust', severity: 'high' }),
    ];
    expect(sortFindings(input).map((f) => f.severity)).toEqual(['high', 'medium', 'info']);
    expect(input.map((f) => f.severity)).toEqual(['info', 'medium', 'high']);
  });
});
