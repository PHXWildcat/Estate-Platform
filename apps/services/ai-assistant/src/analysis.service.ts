import { Inject, Injectable } from '@nestjs/common';
import {
  analyseBeneficiaryConflicts,
  analyseEstateTax,
  analyseFunding,
  analyseMissingDocuments,
  analysisUnavailable,
  type BeneficiaryConflictAnalysis,
  type EstateTaxAnalysis,
  type FundingAnalysis,
  type MissingDocumentAnalysis,
} from './analysis';
import { AssetsClient, DocumentsClient, ProfileClient, type BeneficiariesView } from './clients';
import type { AiAssistantConfig } from './config';
import { CONFIG } from './di-tokens';

/**
 * The one place the analysers get their inputs (M10 PR3).
 *
 * Everything here reads through the peer clients on THE CALLER'S OWN FORWARDED
 * BEARER, so an analysis can only ever be computed from data that caller could
 * already read. The service holds no credential of its own in either direction,
 * which is why an analysis route needs no authorization beyond the caller's
 * session: there is no widening for it to authorize.
 *
 * A NULL FROM A CLIENT IS NEVER AN EMPTY ESTATE. Every client answers `null` for
 * every failure it can have — network, non-2xx, non-JSON, schema drift — and an
 * analyser fed an empty list would happily report that nothing is wrong. So a
 * failed input read becomes `status: 'unavailable'`, never a finding-free `ok`.
 * That is the same rule the tools follow, applied where it matters most: "no
 * beneficiary conflicts" is the sentence a user is most likely to act on by
 * doing nothing.
 */

/**
 * How many assets' designations one beneficiary analysis will fetch.
 *
 * Designations are a per-asset read, so an estate with 400 assets would mean 400
 * peer calls inside one request. The cap bounds that, and the analyser is TOLD
 * it was capped so it can say so — a truncated examination reporting "no
 * conflicts found" is the most misleading answer this feature could give, and
 * the M8 rule is that a workflow which bounds coverage says what it dropped.
 */
export const DESIGNATION_FETCH_CAP = 100;

@Injectable()
export class AnalysisService {
  constructor(
    private readonly assets: AssetsClient,
    private readonly documents: DocumentsClient,
    private readonly profile: ProfileClient,
    @Inject(CONFIG) private readonly config: AiAssistantConfig,
  ) {}

  /** Trust funding: which assets sit outside an existing trust. */
  async funding(bearer: string): Promise<FundingAnalysis> {
    const [assets, documents] = await Promise.all([
      this.assets.listAssets(bearer),
      this.documents.list(bearer),
    ]);
    if (assets === null || documents === null) {
      return analysisUnavailable();
    }
    return analyseFunding(assets, documents);
  }

  /** Which expected instruments are absent or not in force. */
  async missingDocuments(bearer: string): Promise<MissingDocumentAnalysis> {
    const [documents, facts, family, assets] = await Promise.all([
      this.documents.list(bearer),
      this.profile.facts(bearer),
      this.profile.family(bearer),
      this.assets.listAssets(bearer),
    ]);
    // `facts` is required as well: the analyser reports the state of residence,
    // and a null profile read must not be rendered as "no state on file".
    if (documents === null || facts === null || family === null || assets === null) {
      return analysisUnavailable();
    }
    return analyseMissingDocuments(documents, facts, family, assets);
  }

  /** Designation gaps and the trust-versus-designation conflict. */
  async beneficiaryConflicts(bearer: string): Promise<BeneficiaryConflictAnalysis> {
    const assets = await this.assets.listAssets(bearer);
    if (assets === null) {
      return analysisUnavailable();
    }
    const examined = assets.slice(0, DESIGNATION_FETCH_CAP);
    const designations = new Map<string, BeneficiariesView>();
    for (const asset of examined) {
      const view = await this.assets.beneficiaries(bearer, asset.assetId);
      if (view === null) {
        // One asset's designations being unreadable means this analysis cannot
        // be completed — not that this asset has none. Failing the whole run is
        // the only answer that cannot be mistaken for a clean bill of health.
        return analysisUnavailable();
      }
      designations.set(asset.assetId, view);
    }
    // The TRUE total, not the examined count: the analyser derives truncation
    // from the difference and says what it did not look at.
    return analyseBeneficiaryConflicts(examined, designations, assets.length);
  }

  /**
   * Federal and state exposure. Refuses in production while the reference data
   * is unreviewed — the analyser decides that, from config, so both the tool and
   * the route inherit the same gate.
   */
  async estateTax(bearer: string, taxYear?: number): Promise<EstateTaxAnalysis> {
    const [assets, facts] = await Promise.all([
      this.assets.listAssets(bearer),
      this.profile.facts(bearer),
    ]);
    if (assets === null || facts === null) {
      return analysisUnavailable();
    }
    return analyseEstateTax(assets, facts, {
      ...(taxYear === undefined ? {} : { taxYear }),
      nodeEnv: this.config.nodeEnv,
    });
  }
}
