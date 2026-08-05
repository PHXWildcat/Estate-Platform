import { centsToMoney, moneyToCents, ownedShareCents } from '@estate/money';
import type { AssetView, ProfileFactsView } from '../clients';
import {
  analysisOk,
  analysisRefused,
  ESTATE_SUBJECT,
  type AnalysisResult,
  type Finding,
} from './findings';
import {
  ESTATE_TAX_REVIEW,
  federalFor,
  LATEST_TAX_YEAR,
  stateDeathTaxFor,
} from './reference/estate-tax';
import { referenceUsable } from './reference/review';

/**
 * Estate-tax estimation (docs/00 feature 6).
 *
 * THIS ANALYSER REFUSES IN PRODUCTION while its reference data is unreviewed
 * (`reference/review.ts`). Everything below runs and is tested; what production
 * will not do is state a threshold nobody qualified has checked. It is the M6/M7
 * pattern — a capability that cannot be exercised safely answers with a control
 * firing rather than with a plausible number — and the reason it applies here
 * and not to the other three analysers is that this one makes a claim about the
 * law rather than about the user's own account.
 *
 * WHAT IT COMPUTES IS AN UPPER BOUND ON THE TAXABLE BASE, and every result says
 * so. The platform holds an asset ledger, not a balance sheet: there are no
 * liabilities, no prior taxable gifts, no DSUE from a deceased spouse, no view
 * of which assets sit in an irrevocable trust outside the estate, and no way to
 * know how a trust is drafted. A number that looked like a tax bill would be
 * false precision on the finding most likely to change what someone actually
 * does, so the findings report the gross estate, the exemption, the excess, and
 * the top rate — and name what was left out.
 *
 * Inheritance-tax states get a different answer on purpose. The rate turns on
 * each recipient's relationship to the decedent, and this platform holds
 * beneficiaries as contact ids with no relationship attached. So the analyser
 * reports that exposure exists and what drives it, rather than inventing the
 * input it would need.
 */

export type EstateTaxFindingCode =
  /** Gross estate exceeds the federal exemption for the year. */
  | 'federal_exposure'
  /** Gross estate is under the federal exemption. Headroom is in the detail. */
  | 'federal_within_exemption'
  /** The state levies an estate tax and the estate is over its threshold. */
  | 'state_estate_exposure'
  /** The state levies an estate tax and the estate is under its threshold. */
  | 'state_within_exemption'
  /** The state levies an inheritance tax, which depends on facts we do not hold. */
  | 'state_inheritance_tax_applies'
  /** No state-level death tax on file for the state of residence. */
  | 'no_state_death_tax'
  /** No state on the profile, so the state half could not run. */
  | 'state_of_residence_unknown'
  /** Assets with no valuation contribute nothing, so the estimate understates. */
  | 'unvalued_assets_excluded'
  /** The standing caveat: gross, not net; excludes debts, gifts and structures. */
  | 'estimate_excludes_liabilities'
  /** No figures on file for the requested year; the latest were used instead. */
  | 'tax_year_unavailable';

export interface EstateTaxSummary {
  readonly taxYear: number;
  /** Owner's share of every valued asset, as a decimal string. */
  readonly grossEstate: string;
  readonly federalExemption: string;
  readonly valuedAssetCount: number;
  readonly unvaluedAssetCount: number;
  readonly stateOfResidence: string | null;
}

export type EstateTaxAnalysis = AnalysisResult<EstateTaxFindingCode, EstateTaxSummary>;

/** Excess over a threshold, never negative. */
function excessCents(grossCents: bigint, thresholdCents: bigint): bigint {
  return grossCents > thresholdCents ? grossCents - thresholdCents : 0n;
}

export function analyseEstateTax(
  assets: readonly AssetView[],
  profile: ProfileFactsView | null,
  options: {
    readonly taxYear?: number;
    readonly nodeEnv: 'development' | 'test' | 'production';
  },
): EstateTaxAnalysis {
  if (!referenceUsable(ESTATE_TAX_REVIEW, options.nodeEnv)) {
    return analysisRefused<EstateTaxFindingCode, EstateTaxSummary>();
  }

  const findings: Finding<EstateTaxFindingCode>[] = [];
  const requestedYear = options.taxYear ?? LATEST_TAX_YEAR;
  let federal = federalFor(requestedYear);
  if (federal === null) {
    // Fall back rather than fail: the arithmetic is still worth doing, and a
    // year the table does not cover is a fact about the table, reported as one.
    findings.push({
      code: 'tax_year_unavailable',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: { requestedYear, usedYear: LATEST_TAX_YEAR },
    });
    federal = federalFor(LATEST_TAX_YEAR);
  }
  // Unreachable: LATEST_TAX_YEAR indexes the table this module owns, and a
  // reference spec pins that. Handled rather than asserted because a missing
  // year must not be a thrown turn.
  if (federal === null) {
    return analysisRefused<EstateTaxFindingCode, EstateTaxSummary>();
  }

  let grossCents = 0n;
  let valued = 0;
  let unvalued = 0;
  for (const asset of assets) {
    if (asset.estValue === null) {
      unvalued += 1;
      continue;
    }
    valued += 1;
    grossCents += ownedShareCents(moneyToCents(asset.estValue), asset.ownershipPct);
  }
  const grossEstate = centsToMoney(grossCents);

  const federalExemptionCents = moneyToCents(federal.exemption);
  const federalExcess = excessCents(grossCents, federalExemptionCents);
  if (federalExcess > 0n) {
    findings.push({
      code: 'federal_exposure',
      severity: 'high',
      subject: ESTATE_SUBJECT,
      detail: {
        taxYear: federal.taxYear,
        grossEstate,
        exemption: federal.exemption,
        amountOverExemption: centsToMoney(federalExcess),
        topRatePct: federal.topRatePct,
        // The top rate applied to the whole excess. An UPPER BOUND, named as
        // one: the federal schedule is graduated, so the real figure is lower —
        // and a single rounded number would be read as a bill.
        estimatedTaxUpperBound: centsToMoney(
          (federalExcess * BigInt(Math.round(federal.topRatePct * 100))) / 10_000n,
        ),
      },
    });
  } else {
    findings.push({
      code: 'federal_within_exemption',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: {
        taxYear: federal.taxYear,
        grossEstate,
        exemption: federal.exemption,
        headroom: centsToMoney(federalExemptionCents - grossCents),
      },
    });
  }

  const state = profile?.stateOfResidence ?? null;
  const stateTax = stateDeathTaxFor(state);
  if (state === null) {
    findings.push({
      code: 'state_of_residence_unknown',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: {},
    });
  } else if (stateTax === null) {
    findings.push({
      code: 'no_state_death_tax',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: { stateOfResidence: state },
    });
  } else {
    if (stateTax.exemption !== null) {
      const stateExemptionCents = moneyToCents(stateTax.exemption);
      const stateExcess = excessCents(grossCents, stateExemptionCents);
      findings.push(
        stateExcess > 0n
          ? {
              code: 'state_estate_exposure',
              severity: 'high',
              subject: ESTATE_SUBJECT,
              detail: {
                stateOfResidence: state,
                exemption: stateTax.exemption,
                amountOverExemption: centsToMoney(stateExcess),
                topRatePct: stateTax.topRatePct,
              },
            }
          : {
              code: 'state_within_exemption',
              severity: 'info',
              subject: ESTATE_SUBJECT,
              detail: {
                stateOfResidence: state,
                exemption: stateTax.exemption,
                headroom: centsToMoney(stateExemptionCents - grossCents),
              },
            },
      );
    }
    if (stateTax.dependsOnRelationship) {
      findings.push({
        code: 'state_inheritance_tax_applies',
        severity: 'medium',
        subject: ESTATE_SUBJECT,
        detail: {
          stateOfResidence: state,
          kind: stateTax.kind,
          // Why no number: the platform holds beneficiaries as contact ids with
          // no relationship, and the rate is a function of exactly that.
          dependsOnRecipientRelationship: true,
        },
      });
    }
  }

  if (unvalued > 0) {
    findings.push({
      code: 'unvalued_assets_excluded',
      severity: 'medium',
      subject: ESTATE_SUBJECT,
      detail: { unvaluedAssetCount: unvalued, valuedAssetCount: valued },
    });
  }

  findings.push({
    code: 'estimate_excludes_liabilities',
    severity: 'info',
    subject: ESTATE_SUBJECT,
    detail: { basis: 'gross', excludes: 'debts,prior_gifts,dsue,irrevocable_trust_structures' },
  });

  return analysisOk<EstateTaxFindingCode, EstateTaxSummary>(findings, {
    taxYear: federal.taxYear,
    grossEstate,
    federalExemption: federal.exemption,
    valuedAssetCount: valued,
    unvaluedAssetCount: unvalued,
    stateOfResidence: state,
  });
}
