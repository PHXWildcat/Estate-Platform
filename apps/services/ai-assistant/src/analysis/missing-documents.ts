import type { AssetView, DocumentView, FamilyMemberView, ProfileFactsView } from '../clients';
import { analysisOk, ESTATE_SUBJECT, type AnalysisResult, type Finding } from './findings';
import {
  DOCUMENT_EXPECTATIONS,
  RETIRED_STATUSES,
  TRUST_KINDS,
  UNEXECUTED_STATUSES,
  type DocumentExpectation,
  type ExpectationTrigger,
} from './reference/required-documents';

/**
 * Missing-document detection (docs/00 feature 6).
 *
 * The distinction that makes this useful rather than nagging is between an
 * instrument that is ABSENT and one that is PRESENT BUT NOT IN FORCE. A
 * generated, unsigned will is the more dangerous of the two: the user has a
 * document, sees it in their vault, believes they have a plan, and has an
 * instrument that directs nothing. So both are findings, with different codes,
 * and a revoked or superseded document counts as absent — which is exactly what
 * it is.
 *
 * Every finding is phrased as a fact about the account ("no guardian designation
 * is on file"), never as a legal requirement, and the expectations themselves
 * carry no state-specific claims — see `reference/required-documents.ts` for why
 * that is what lets this analyser run in production while the estate-tax one
 * refuses.
 *
 * WHAT IT CANNOT SEE, and says so rather than assuming: a family member whose
 * date of birth is unknown has `isMinor === null`, so the guardian rule can
 * neither fire nor be dismissed. Reporting that as its own informational finding
 * is the difference between "you need no guardian designation" and "I cannot
 * tell whether you do".
 */

export type MissingDocumentFindingCode =
  /** No document of this kind (or an accepted equivalent) is on file. */
  | 'instrument_missing'
  /** On file, but not executed — it exists and directs nothing. */
  | 'instrument_not_executed'
  /** A household member's age is unknown, so a minor-child rule could not run. */
  | 'minor_status_unknown'
  /** Nothing expected is missing. Saying so is the useful answer. */
  | 'document_set_complete';

export interface MissingDocumentSummary {
  readonly expected: number;
  readonly missing: number;
  readonly unexecuted: number;
  /** Null when the profile has no state on file. Carried for the UI, not used in a rule. */
  readonly stateOfResidence: string | null;
}

export type MissingDocumentAnalysis = AnalysisResult<
  MissingDocumentFindingCode,
  MissingDocumentSummary
>;

/** In force = on file and not revoked or superseded. */
function inForce(doc: DocumentView): boolean {
  return !RETIRED_STATUSES.has(doc.executionStatus);
}

/** Which triggers this estate satisfies, computed once. */
function activeTriggers(
  documents: readonly DocumentView[],
  family: readonly FamilyMemberView[],
  assets: readonly AssetView[],
): ReadonlySet<ExpectationTrigger> {
  const triggers = new Set<ExpectationTrigger>(['always']);
  if (family.some((member) => member.isMinor === true)) {
    triggers.add('minor_child');
  }
  const trustOnFile = documents.some((doc) => inForce(doc) && TRUST_KINDS.has(doc.docType));
  if (trustOnFile) {
    triggers.add('trust_exists');
    // Only when something is left to move. `na` is the owner's decision that an
    // asset does not belong in the trust, and it is respected here as in the
    // funding analyser.
    if (assets.some((asset) => !asset.inTrust && asset.fundingStatus !== 'na')) {
      triggers.add('trust_with_unfunded_assets');
    }
  }
  return triggers;
}

/** Every kind that satisfies one expectation: the instrument or an equivalent. */
function satisfyingKinds(expectation: DocumentExpectation): ReadonlySet<string> {
  return new Set<string>([expectation.kind, ...expectation.satisfiedAlsoBy]);
}

export function analyseMissingDocuments(
  documents: readonly DocumentView[],
  profile: ProfileFactsView | null,
  family: readonly FamilyMemberView[],
  assets: readonly AssetView[],
): MissingDocumentAnalysis {
  const triggers = activeTriggers(documents, family, assets);
  const live = documents.filter(inForce);
  const findings: Finding<MissingDocumentFindingCode>[] = [];

  let expected = 0;
  let missing = 0;
  let unexecuted = 0;

  for (const expectation of DOCUMENT_EXPECTATIONS) {
    if (!triggers.has(expectation.trigger)) {
      continue;
    }
    expected += 1;
    const kinds = satisfyingKinds(expectation);
    const candidates = live.filter((doc) => kinds.has(doc.docType));
    const executed = candidates.find((doc) => !UNEXECUTED_STATUSES.has(doc.executionStatus));
    if (executed !== undefined) {
      continue;
    }
    // Present but not in force. The FIRST candidate is named as the subject so
    // the UI can link to it — there is normally one, and naming any of several
    // drafts is more useful than naming none.
    const draft = candidates[0];
    if (draft !== undefined) {
      unexecuted += 1;
      findings.push({
        code: 'instrument_not_executed',
        severity: expectation.severity,
        subject: { kind: 'document', ref: draft.documentId, label: draft.title },
        detail: {
          expectedKind: expectation.kind,
          docType: draft.docType,
          executionStatus: draft.executionStatus,
          trigger: expectation.trigger,
        },
      });
      continue;
    }
    missing += 1;
    findings.push({
      code: 'instrument_missing',
      severity: expectation.severity,
      // No document to point at, so the subject is the estate. `expectedKind`
      // in the detail is what the UI and the model render.
      subject: ESTATE_SUBJECT,
      detail: { expectedKind: expectation.kind, trigger: expectation.trigger },
    });
  }

  // Stated whether or not the guardian rule fired: if some member's minority is
  // unknown, neither the presence nor the absence of a guardian finding above is
  // the whole truth.
  const unknownMinority = family.filter((member) => member.isMinor === null).length;
  if (unknownMinority > 0) {
    findings.push({
      code: 'minor_status_unknown',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: { membersWithUnknownAge: unknownMinority },
    });
  }

  if (missing === 0 && unexecuted === 0) {
    findings.push({
      code: 'document_set_complete',
      severity: 'info',
      subject: ESTATE_SUBJECT,
      detail: { expected },
    });
  }

  return analysisOk<MissingDocumentFindingCode, MissingDocumentSummary>(findings, {
    expected,
    missing,
    unexecuted,
    stateOfResidence: profile?.stateOfResidence ?? null,
  });
}
