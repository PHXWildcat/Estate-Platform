/**
 * The deterministic analysers (M10 PR3). Pure functions over already-fetched
 * peer views: no I/O, no Nest, no clock, no randomness — the same estate always
 * produces the same findings, which is what lets the UI render them without a
 * model and lets a spec assert them exactly.
 *
 * `analysis.service.ts` is the one place that fetches; everything here computes.
 */

export {
  analysisOk,
  analysisRefused,
  analysisUnavailable,
  ANALYSIS_DISCLAIMER,
  ESTATE_SUBJECT,
  type AnalysisResult,
  type Finding,
  type FindingSeverity,
  type FindingSubject,
} from './findings';

export {
  analyseFunding,
  type FundingAnalysis,
  type FundingFindingCode,
  type FundingSummary,
} from './funding';

export {
  analyseMissingDocuments,
  type MissingDocumentAnalysis,
  type MissingDocumentFindingCode,
  type MissingDocumentSummary,
} from './missing-documents';

export {
  analyseBeneficiaryConflicts,
  type BeneficiaryConflictAnalysis,
  type BeneficiaryConflictSummary,
  type BeneficiaryFindingCode,
} from './beneficiary-conflicts';

export {
  analyseEstateTax,
  type EstateTaxAnalysis,
  type EstateTaxFindingCode,
  type EstateTaxSummary,
} from './estate-tax';

export { ESTATE_TAX_REVIEW, LATEST_TAX_YEAR } from './reference/estate-tax';
export { isReviewed, referenceUsable, UNREVIEWED_EXEMPLAR } from './reference/review';
