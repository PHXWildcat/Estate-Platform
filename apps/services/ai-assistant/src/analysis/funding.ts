import { centsToMoney, moneyToCents, ownedShareCents } from '@estate/money';
import type { AssetView, DocumentView } from '../clients';
import { analysisOk, ESTATE_SUBJECT, type AnalysisResult, type Finding } from './findings';
import { RETIRED_STATUSES, TRUST_KINDS } from './reference/required-documents';

/**
 * Trust-funding analysis (docs/00 feature 6, "funding recommendations").
 *
 * THE GAP THIS FINDS IS THE MOST COMMON FAILURE IN ESTATE PLANNING: a trust that
 * was drafted, signed, and never funded. An unfunded revocable trust controls
 * nothing — the assets it was meant to hold pass through probate exactly as if
 * it had never been written, which is the outcome the client paid a lawyer to
 * avoid. It is a structural question the platform can answer precisely, because
 * `assets_view.in_trust` and `funding_status` are already ledger facts.
 *
 * The analysis is deliberately CONDITIONAL ON A TRUST EXISTING. Telling a user
 * with no trust that their assets are not in one is not a finding, it is a
 * product opinion about how they should plan — so that case reports as an
 * explicit non-finding instead, and the estate is described rather than graded.
 *
 * `funding_status` is the owner's own statement of progress and is respected as
 * such: `na` means they have decided this asset does not belong in the trust,
 * and an analyser that nagged anyway would train them to ignore it.
 */

export type FundingFindingCode =
  /** No trust on file, so "not funded" is not a gap. Informational, by design. */
  | 'no_trust_on_file'
  /** Titled outside the trust, with funding not started. */
  | 'asset_not_titled_in_trust'
  /** The owner has said funding is under way; a reminder, not a gap. */
  | 'asset_funding_in_progress'
  /** Marked funded, yet the ledger says it is not held in trust. */
  | 'funding_status_contradicts_title'
  /** Estate-level totals: how much sits outside the trust. */
  | 'value_outside_trust';

export interface FundingSummary {
  readonly trustOnFile: boolean;
  readonly assetsOutsideTrust: number;
  /** Owner's share of value held outside the trust, as a decimal string. */
  readonly valueOutsideTrust: string;
  /** Assets excluded because the owner marked them not applicable. */
  readonly excludedByOwner: number;
}

export type FundingAnalysis = AnalysisResult<FundingFindingCode, FundingSummary>;

/** A document that is on file AND still in force. */
function inForce(doc: DocumentView): boolean {
  return !RETIRED_STATUSES.has(doc.executionStatus);
}

/** Owner's share of one asset's value, in cents. Unvalued assets contribute 0. */
function ownedCents(asset: AssetView): bigint {
  if (asset.estValue === null) {
    return 0n;
  }
  return ownedShareCents(moneyToCents(asset.estValue), asset.ownershipPct);
}

export function analyseFunding(
  assets: readonly AssetView[],
  documents: readonly DocumentView[],
): FundingAnalysis {
  const trustOnFile = documents.some((doc) => inForce(doc) && TRUST_KINDS.has(doc.docType));

  if (!trustOnFile) {
    return analysisOk<FundingFindingCode, FundingSummary>(
      [
        {
          code: 'no_trust_on_file',
          severity: 'info',
          subject: ESTATE_SUBJECT,
          detail: { assetCount: assets.length },
        },
      ],
      {
        trustOnFile: false,
        assetsOutsideTrust: 0,
        valueOutsideTrust: '0.00',
        excludedByOwner: 0,
      },
    );
  }

  const findings: Finding<FundingFindingCode>[] = [];
  let outsideCents = 0n;
  let outsideCount = 0;
  let excludedByOwner = 0;

  for (const asset of assets) {
    const subject = { kind: 'asset' as const, ref: asset.assetId, label: asset.title };

    if (asset.inTrust) {
      // Held in trust but flagged unfunded is NOT a contradiction worth
      // reporting: retitling can complete before anyone updates the status, and
      // the ledger's `in_trust` is the fact that matters.
      continue;
    }
    if (asset.fundingStatus === 'na') {
      excludedByOwner += 1;
      continue;
    }

    outsideCount += 1;
    outsideCents += ownedCents(asset);

    if (asset.fundingStatus === 'funded') {
      // The two ledger fields disagree. Reported rather than resolved: which
      // one is true is a question for the owner, and quietly believing either
      // would make the estate look better or worse than it is.
      findings.push({
        code: 'funding_status_contradicts_title',
        severity: 'medium',
        subject,
        detail: { category: asset.category, fundingStatus: asset.fundingStatus, inTrust: false },
      });
      continue;
    }
    findings.push({
      code:
        asset.fundingStatus === 'in_progress'
          ? 'asset_funding_in_progress'
          : 'asset_not_titled_in_trust',
      severity: asset.fundingStatus === 'in_progress' ? 'medium' : 'high',
      subject,
      detail: {
        category: asset.category,
        fundingStatus: asset.fundingStatus,
        estValue: asset.estValue,
        ownershipPct: asset.ownershipPct,
      },
    });
  }

  const valueOutsideTrust = centsToMoney(outsideCents);
  findings.push({
    code: 'value_outside_trust',
    severity: 'info',
    subject: ESTATE_SUBJECT,
    detail: {
      assetsOutsideTrust: outsideCount,
      valueOutsideTrust,
      excludedByOwner,
      // Stated because the total is a floor, not a measurement: an asset with
      // no valuation on record contributes nothing to it.
      unvaluedAssetsOutsideTrust: assets.filter(
        (a) => !a.inTrust && a.fundingStatus !== 'na' && a.estValue === null,
      ).length,
    },
  });

  return analysisOk<FundingFindingCode, FundingSummary>(findings, {
    trustOnFile: true,
    assetsOutsideTrust: outsideCount,
    valueOutsideTrust,
    excludedByOwner,
  });
}
