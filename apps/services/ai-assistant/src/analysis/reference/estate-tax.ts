import type { UsState } from '@estate/contracts';
import { UNREVIEWED_EXEMPLAR, type ReferenceReview } from './review';

/**
 * Estate and inheritance tax reference data (M10 PR3).
 *
 * ===========================================================================
 * THESE FIGURES ARE EXEMPLARS. THEY HAVE NOT BEEN REVIEWED BY A TAX
 * PROFESSIONAL, AND THE ANALYSER BUILT ON THEM REFUSES TO RUN IN PRODUCTION.
 * ===========================================================================
 *
 * See `review.ts` for why that is the design rather than a disclaimer. Replacing
 * this file's contents with reviewed figures — and its `review` block with a
 * real reviewer, date and source — is what turns the estate-tax analyser on in
 * production. Nothing else has to change, which is the point of keeping the data
 * separate from the arithmetic.
 *
 * WHAT THE ANALYSER CAN AND CANNOT SEE, because it shapes what belongs here:
 *
 *   * It sees the owner's asset ledger and ownership percentages, so it can
 *     estimate a GROSS estate. It does not see debts, liabilities, prior taxable
 *     gifts, life-insurance ownership structures, or which assets sit in an
 *     irrevocable trust outside the estate — so what it computes is an upper
 *     bound on the taxable base, and every finding says so.
 *   * It sees beneficiaries as CONTACT IDS with no relationship attached
 *     (assets returns ids, never names — and that is the right shape for
 *     everything else). Inheritance tax depends entirely on the beneficiary's
 *     relationship to the decedent, so in an inheritance-tax state the analyser
 *     can only say the exposure exists and what drives it. Guessing a rate from
 *     a relationship nobody recorded would be inventing the input.
 *   * Portability, the marital deduction and state QTIP elections all turn on
 *     facts (a deceased spouse's DSUE, how a trust is drafted) the platform does
 *     not hold. Marital status alone does not let anyone compute them, so the
 *     analyser flags them as questions rather than folding them into a number.
 */

/** Federal figures for one tax year. Money is a decimal STRING, as everywhere. */
export interface FederalEstateTax {
  readonly taxYear: number;
  /** The basic exclusion amount for one decedent. */
  readonly exemption: string;
  /** Top marginal rate as a percentage (40 = 40%). */
  readonly topRatePct: number;
}

/**
 * What kind of death tax a state levies.
 *
 * `estate` is charged to the estate and turns on its size; `inheritance` is
 * charged to each recipient and turns on their relationship to the decedent;
 * `both` is Maryland. `none` is the majority and is represented by ABSENCE from
 * the table rather than by rows of nulls — a state missing from the map means
 * "no state-level death tax on file", which the analyser states positively.
 */
export type StateDeathTaxKind = 'estate' | 'inheritance' | 'both';

export interface StateDeathTax {
  readonly kind: StateDeathTaxKind;
  /** Estate-tax exclusion, or null for a pure inheritance-tax state. */
  readonly exemption: string | null;
  /** Top marginal rate as a percentage, or null when it varies by recipient class. */
  readonly topRatePct: number | null;
  /**
   * True when the rate depends on the beneficiary's relationship to the
   * decedent — the fact this platform deliberately does not hold. It is what
   * makes the analyser report the exposure rather than estimate it.
   */
  readonly dependsOnRelationship: boolean;
}

/** Federal figures by tax year. Extend by adding a year, never by editing one. */
const FEDERAL: ReadonlyMap<number, FederalEstateTax> = new Map([
  [2026, { taxYear: 2026, exemption: '15000000.00', topRatePct: 40 }],
]);

/** The most recent year this file states figures for. */
export const LATEST_TAX_YEAR = 2026;

/**
 * States with a death tax. Absence means none — see `StateDeathTaxKind`.
 * `US_STATES` in @estate/contracts includes DC, which levies an estate tax.
 */
const STATES: ReadonlyMap<UsState, StateDeathTax> = new Map<UsState, StateDeathTax>([
  [
    'CT',
    { kind: 'estate', exemption: '15000000.00', topRatePct: 12, dependsOnRelationship: false },
  ],
  ['DC', { kind: 'estate', exemption: '4873200.00', topRatePct: 16, dependsOnRelationship: false }],
  ['HI', { kind: 'estate', exemption: '5490000.00', topRatePct: 20, dependsOnRelationship: false }],
  ['IL', { kind: 'estate', exemption: '4000000.00', topRatePct: 16, dependsOnRelationship: false }],
  ['KY', { kind: 'inheritance', exemption: null, topRatePct: null, dependsOnRelationship: true }],
  ['MA', { kind: 'estate', exemption: '2000000.00', topRatePct: 16, dependsOnRelationship: false }],
  // Maryland is the only state levying both, and the inheritance half turns on
  // the recipient — so the analyser reports a threshold AND a relationship
  // question for the same state.
  ['MD', { kind: 'both', exemption: '5000000.00', topRatePct: 16, dependsOnRelationship: true }],
  ['ME', { kind: 'estate', exemption: '7000000.00', topRatePct: 12, dependsOnRelationship: false }],
  ['MN', { kind: 'estate', exemption: '3000000.00', topRatePct: 16, dependsOnRelationship: false }],
  ['NE', { kind: 'inheritance', exemption: null, topRatePct: null, dependsOnRelationship: true }],
  ['NJ', { kind: 'inheritance', exemption: null, topRatePct: null, dependsOnRelationship: true }],
  ['NY', { kind: 'estate', exemption: '7160000.00', topRatePct: 16, dependsOnRelationship: false }],
  ['OR', { kind: 'estate', exemption: '1000000.00', topRatePct: 16, dependsOnRelationship: false }],
  ['PA', { kind: 'inheritance', exemption: null, topRatePct: null, dependsOnRelationship: true }],
  ['RI', { kind: 'estate', exemption: '1802431.00', topRatePct: 16, dependsOnRelationship: false }],
  ['VT', { kind: 'estate', exemption: '5000000.00', topRatePct: 16, dependsOnRelationship: false }],
  ['WA', { kind: 'estate', exemption: '3000000.00', topRatePct: 35, dependsOnRelationship: false }],
]);

/**
 * Sign-off for this file. Replacing the sentinel is what lets the estate-tax
 * analyser run in production; until then it refuses there and runs everywhere
 * else (`review.ts`).
 */
export const ESTATE_TAX_REVIEW: ReferenceReview = {
  reviewedBy: UNREVIEWED_EXEMPLAR,
  reviewedAt: '',
  source: '',
  effectiveYear: LATEST_TAX_YEAR,
};

/** Federal figures for a year, or null when this file states none for it. */
export function federalFor(taxYear: number): FederalEstateTax | null {
  return FEDERAL.get(taxYear) ?? null;
}

/**
 * A state's death tax, or null for "no state-level death tax on file".
 *
 * Takes the caller's string rather than a `UsState` because it comes from a
 * profile field that is nullable and free-form at the type level: an unknown
 * value must answer "nothing on file for this state", which the Map lookup does
 * without a cast that would claim more than we know.
 */
export function stateDeathTaxFor(state: string | null): StateDeathTax | null {
  if (state === null) {
    return null;
  }
  return STATES.get(state.toUpperCase() as UsState) ?? null;
}
