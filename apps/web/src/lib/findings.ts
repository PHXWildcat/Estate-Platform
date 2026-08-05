import type { AnalysisStatus, FindingInfo } from '../graphql/client';
import { formatMoney } from './money';

/**
 * Where a finding CODE becomes a sentence (M10 PR4).
 *
 * The analysers deliberately emit closed enum codes with structured detail
 * rather than prose (M10 PR3: the analyser computes, the model explains), so
 * SOMETHING has to write the words. On this surface it is not a model — it is
 * this file, reviewed like any other code, identical for every user, and
 * incapable of inventing a finding that the analyser did not compute.
 *
 * Two rules hold the copy honest:
 *
 * 1. EVERY SENTENCE IS A FACT ABOUT THE USER'S OWN ACCOUNT, never a legal
 *    claim. "No will is on file" — not "you are required to have a will". The
 *    analysers were written to the same line (see the service's
 *    reference/required-documents.ts), and it is what lets this surface run
 *    without a lawyer's sign-off while the estate-tax table cannot.
 * 2. NUMBERS COME FROM `detail`, never from the copy. Money arrives as a
 *    decimal string and goes through `formatMoney`, which groups digits by
 *    string manipulation — no parse, no float, at any point.
 *
 * `COPY` is typed as a total map over the union, so adding an analyser finding
 * without writing its sentence is a COMPILE ERROR rather than a raw token on
 * someone's screen. Unknown codes still get a safe fallback, because a peer
 * that ships a new code before this app redeploys must not blank the page.
 */

/** Every code the four analysers can emit (M10 PR3). */
export type FindingCode =
  // funding
  | 'no_trust_on_file'
  | 'asset_not_titled_in_trust'
  | 'asset_funding_in_progress'
  | 'funding_status_contradicts_title'
  | 'value_outside_trust'
  // missing documents
  | 'instrument_missing'
  | 'instrument_not_executed'
  | 'minor_status_unknown'
  | 'document_set_complete'
  // beneficiary conflicts
  | 'designation_incomplete'
  | 'designation_over_allocated'
  | 'duplicate_designation'
  | 'designation_overrides_trust'
  | 'no_beneficiary_designated'
  | 'designations_consistent'
  | 'assets_not_examined'
  // estate tax
  | 'federal_exposure'
  | 'federal_within_exemption'
  | 'state_estate_exposure'
  | 'state_within_exemption'
  | 'state_inheritance_tax_applies'
  | 'no_state_death_tax'
  | 'state_of_residence_unknown'
  | 'unvalued_assets_excluded'
  | 'estimate_excludes_liabilities'
  | 'tax_year_unavailable';

type Detail = FindingInfo['detail'];

/** A detail value as text, or '' when the analyser did not supply it. */
function text(detail: Detail, key: string): string {
  const value = detail[key];
  return value === undefined || value === null ? '' : String(value);
}

/** A money detail, formatted. Never parsed — see `formatMoney`. */
function money(detail: Detail, key: string): string {
  const value = detail[key];
  return typeof value === 'string' ? formatMoney(value) : '—';
}

function count(detail: Detail, key: string): number {
  const value = detail[key];
  return typeof value === 'number' ? value : 0;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Instrument kinds as a person would name them, not as the enum spells them. */
const INSTRUMENTS: Record<string, string> = {
  will: 'a will',
  revocable_trust: 'a revocable trust',
  irrevocable_trust: 'an irrevocable trust',
  pour_over_will: 'a pour-over will',
  durable_poa: 'a durable power of attorney',
  financial_poa: 'a financial power of attorney',
  medical_poa: 'a medical power of attorney',
  mental_health_poa: 'a mental-health power of attorney',
  living_will: 'a living will',
  hipaa_auth: 'a HIPAA authorization',
  guardian_designation: 'a guardian designation',
  certification_of_trust: 'a certification of trust',
  property_assignment: 'a property assignment',
  funding_letter: 'a funding letter',
  beneficiary_letter: 'a beneficiary letter',
};

function instrument(detail: Detail, key = 'expectedKind'): string {
  const kind = text(detail, key);
  return INSTRUMENTS[kind] ?? kind.replace(/_/g, ' ');
}

/** What the finding is about, for the headline. */
function subjectName(finding: FindingInfo): string {
  const label = finding.subject.label;
  return label !== null && label.trim().length > 0 ? label : 'This item';
}

export interface FindingCopy {
  /** Short headline; the subject's own title when it has one. */
  readonly title: string;
  /** One sentence of explanation, drawing its numbers from `detail`. */
  readonly body: string;
}

const COPY: Record<FindingCode, (finding: FindingInfo) => FindingCopy> = {
  // ---- funding ---------------------------------------------------------
  no_trust_on_file: (f) => ({
    title: 'No trust on file',
    body: `You have no trust recorded, so nothing here needs to be titled into one. ${plural(
      count(f.detail, 'assetCount'),
      'asset is',
      'assets are',
    )} recorded.`,
  }),
  asset_not_titled_in_trust: (f) => ({
    title: `${subjectName(f)} is outside your trust`,
    body: 'It is not titled in the trust, so it would pass outside it — which is usually the opposite of what a trust was set up to do.',
  }),
  asset_funding_in_progress: (f) => ({
    title: `${subjectName(f)} is being moved into your trust`,
    body: 'You have marked this transfer as under way. Nothing to do unless it has stalled.',
  }),
  funding_status_contradicts_title: (f) => ({
    title: `${subjectName(f)} says two different things`,
    body: 'It is marked as funded, but the ledger does not show it held in trust. One of the two is out of date.',
  }),
  value_outside_trust: (f) => ({
    title: 'Value held outside your trust',
    body: `${money(f.detail, 'valueOutsideTrust')} across ${plural(
      count(f.detail, 'assetsOutsideTrust'),
      'asset',
      'assets',
    )}. ${
      count(f.detail, 'unvaluedAssetsOutsideTrust') > 0
        ? `${plural(count(f.detail, 'unvaluedAssetsOutsideTrust'), 'asset has', 'assets have')} no value recorded, so the real figure is higher.`
        : ''
    }`.trim(),
  }),

  // ---- missing documents ----------------------------------------------
  instrument_missing: (f) => ({
    title: `No ${instrument(f.detail).replace(/^an? /, '')} on file`,
    body: `You have no ${instrument(f.detail).replace(/^an? /, '')} recorded here. Generating one takes a few minutes.`,
  }),
  instrument_not_executed: (f) => ({
    title: `${subjectName(f)} has not been executed`,
    body: 'It exists but has not been signed, witnessed or notarized as required — so it directs nothing yet.',
  }),
  minor_status_unknown: (f) => ({
    title: 'We cannot tell whether you need a guardian designation',
    body: `${plural(
      count(f.detail, 'membersWithUnknownAge'),
      'person in your household has',
      'people in your household have',
    )} no date of birth on record.`,
  }),
  document_set_complete: () => ({
    title: 'Your core documents are all on file',
    body: 'Every instrument we would expect for an estate like yours is recorded and in force.',
  }),

  // ---- beneficiary conflicts -------------------------------------------
  designation_incomplete: (f) => ({
    title: `${subjectName(f)}: beneficiary shares do not add up`,
    body: `The ${text(f.detail, 'designation')} designations total ${text(f.detail, 'sharePct')}%, not 100%. The remainder would fall back to your estate.`,
  }),
  designation_over_allocated: (f) => ({
    title: `${subjectName(f)}: beneficiary shares total more than 100%`,
    body: `The ${text(f.detail, 'designation')} designations add up to ${text(f.detail, 'sharePct')}%, so every share on this asset is wrong.`,
  }),
  duplicate_designation: (f) => ({
    title: `${subjectName(f)}: one person is named twice`,
    body: `The same contact appears ${text(f.detail, 'entries')} times in the ${text(f.detail, 'designation')} designations.`,
  }),
  designation_overrides_trust: (f) => ({
    title: `${subjectName(f)} names beneficiaries AND sits in your trust`,
    body: 'A beneficiary designation passes the asset outside the trust, so the trust does not control it — whatever the trust document says.',
  }),
  no_beneficiary_designated: (f) => ({
    title: `${subjectName(f)} names no beneficiary`,
    body: 'Policies and annuities pass by designation. With none recorded, the proceeds fall back to your estate and into probate.',
  }),
  designations_consistent: () => ({
    title: 'Beneficiary designations look consistent',
    body: 'Every asset we examined adds up to 100% and none conflicts with your trust.',
  }),
  assets_not_examined: (f) => ({
    title: 'Not every asset was examined',
    body: `We checked ${count(f.detail, 'examined')} of ${count(f.detail, 'total')} assets in this pass, so treat the result as partial.`,
  }),

  // ---- estate tax -------------------------------------------------------
  federal_exposure: (f) => ({
    title: 'Your estate may be over the federal exemption',
    body: `A gross estate of ${money(f.detail, 'grossEstate')} against a ${money(
      f.detail,
      'exemption',
    )} exemption — ${money(f.detail, 'amountOverExemption')} over. At the top rate that is at most ${money(
      f.detail,
      'estimatedTaxUpperBound',
    )}; the real figure is lower, because the schedule is graduated.`,
  }),
  federal_within_exemption: (f) => ({
    title: 'Under the federal exemption',
    body: `A gross estate of ${money(f.detail, 'grossEstate')} leaves ${money(
      f.detail,
      'headroom',
    )} of headroom against the ${text(f.detail, 'taxYear')} exemption.`,
  }),
  state_estate_exposure: (f) => ({
    title: `${text(f.detail, 'stateOfResidence')} may tax this estate`,
    body: `Your state's exemption is ${money(f.detail, 'exemption')} — lower than the federal one — and the estate is ${money(
      f.detail,
      'amountOverExemption',
    )} above it.`,
  }),
  state_within_exemption: (f) => ({
    title: `Under the ${text(f.detail, 'stateOfResidence')} exemption`,
    body: `${money(f.detail, 'headroom')} of headroom against your state's ${money(f.detail, 'exemption')} threshold.`,
  }),
  state_inheritance_tax_applies: (f) => ({
    title: `${text(f.detail, 'stateOfResidence')} levies an inheritance tax`,
    body: 'What it costs depends on each recipient’s relationship to you, which this platform does not record — so there is exposure here, but no number we can honestly put on it.',
  }),
  no_state_death_tax: (f) => ({
    title: `${text(f.detail, 'stateOfResidence')} has no estate or inheritance tax`,
    body: 'Only the federal figures above apply where you live.',
  }),
  state_of_residence_unknown: () => ({
    title: 'No state of residence on file',
    body: 'State thresholds are often far lower than the federal one, so adding your state may change this answer materially.',
  }),
  unvalued_assets_excluded: (f) => ({
    title: 'Some assets have no value recorded',
    body: `${plural(count(f.detail, 'unvaluedAssetCount'), 'asset was', 'assets were')} left out of the total, so the estate is worth at least what is shown — probably more.`,
  }),
  estimate_excludes_liabilities: () => ({
    title: 'This is a gross estimate',
    body: 'It counts what you own, not what you owe: debts, prior taxable gifts, a spouse’s unused exemption and trust structures are all excluded.',
  }),
  tax_year_unavailable: (f) => ({
    title: `No figures on file for ${text(f.detail, 'requestedYear')}`,
    body: `The ${text(f.detail, 'usedYear')} figures were used instead.`,
  }),
};

const KNOWN: ReadonlySet<string> = new Set(Object.keys(COPY));

/**
 * A finding as words. An unrecognized code — a service deployed ahead of this
 * app — gets a neutral placeholder rather than a raw token or a blank card.
 */
export function findingCopy(finding: FindingInfo): FindingCopy {
  if (!KNOWN.has(finding.code)) {
    return {
      title: 'A finding we cannot describe yet',
      body: 'Your estate data produced a result this version of the app does not have wording for.',
    };
  }
  return COPY[finding.code as FindingCode](finding);
}

/** What an analysis says when it produced no findings at all. */
export const STATUS_COPY: Record<Exclude<AnalysisStatus, 'OK'>, FindingCopy> = {
  UNAVAILABLE: {
    title: 'We could not run this check',
    body: 'Some of the information it needs could not be read just now. This is not a statement about your estate — try again in a moment.',
  },
  REFUSED: {
    title: 'We do not publish this check here',
    body: 'The reference figures it relies on have not been reviewed by a tax professional, so we will not state them.',
  },
  DISABLED: {
    title: 'The assistant is switched off',
    body: 'Turn it on below to see this check. Nothing is analysed while it is off.',
  },
};

/** High first: the order a person should read them in. */
export const SEVERITY_ORDER: Record<FindingInfo['severity'], number> = {
  high: 0,
  medium: 1,
  info: 2,
};

export function sortFindings(findings: readonly FindingInfo[]): FindingInfo[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}
