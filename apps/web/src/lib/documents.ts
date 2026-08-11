import type { DocumentInfo, ExecutionRequirementsInfo } from '../graphql/client';

/**
 * Where a document service ENUM becomes a sentence (M12) — the `lib/findings.ts`
 * shape, and for the same reason: the service emits closed tokens, and the words
 * a person reads are written here, in reviewed code, identical for every user.
 *
 * Two rules, inherited from that file and equally load-bearing here:
 *
 * 1. EVERY SENTENCE IS A FACT ABOUT THE USER'S OWN ACCOUNT, never a legal
 *    claim. "Two witnesses are required for this document in this state" is
 *    what the reviewed template declares; "you must have a will" is not ours to
 *    say. The execution-requirements copy is a readback of the template's own
 *    `execution_requirements`, which is the attorney-signed-off column — so it
 *    states what the template says rather than what the law is.
 * 2. THE MAPS ARE TOTAL over their unions, so a status or a document kind
 *    arriving without wording is a compile error rather than a raw token on
 *    someone's screen. An UNKNOWN token still renders a safe fallback, because
 *    a service deployed ahead of this app must not blank the page.
 */

/** docs/02 §4 `documents.execution_status`. */
export type ExecutionStatus =
  | 'draft'
  | 'generated'
  | 'signed'
  | 'witnessed'
  | 'notarized'
  | 'executed'
  | 'revoked'
  | 'superseded';

const EXECUTION_STATUS_LABEL: Record<ExecutionStatus, string> = {
  draft: 'Draft',
  generated: 'Generated',
  signed: 'Signed',
  witnessed: 'Witnessed',
  notarized: 'Notarized',
  executed: 'Executed',
  revoked: 'Revoked',
  superseded: 'Superseded',
};

/**
 * What each status means for whether the document actually DOES anything.
 *
 * This distinction is the whole point of the surface: a generated, unsigned
 * will looks like a plan and directs nothing, which is exactly what the
 * readiness page's `instrument_not_executed` finding is about. The status chip
 * says so rather than leaving "Generated" to be read as "done".
 */
const EXECUTION_STATUS_MEANING: Record<ExecutionStatus, string> = {
  draft: 'Not yet in force.',
  generated: 'Created but not signed — it does not direct anything yet.',
  signed: 'Signed, with the remaining formalities still to complete.',
  witnessed: 'Witnessed, with the remaining formalities still to complete.',
  notarized: 'Notarized, with the remaining formalities still to complete.',
  executed: 'In force.',
  revoked: 'Revoked — it no longer has effect.',
  superseded: 'Replaced by a later document.',
};

/** Instrument types (docs/02 §4) plus the upload categories (docs/00 §8). */
export type DocumentKind =
  | 'will'
  | 'revocable_trust'
  | 'irrevocable_trust'
  | 'pour_over_will'
  | 'durable_poa'
  | 'financial_poa'
  | 'medical_poa'
  | 'mental_health_poa'
  | 'living_will'
  | 'hipaa_auth'
  | 'guardian_designation'
  | 'certification_of_trust'
  | 'property_assignment'
  | 'funding_letter'
  | 'beneficiary_letter'
  | 'legal'
  | 'tax'
  | 'identity'
  | 'insurance'
  | 'property'
  | 'military'
  | 'medical'
  | 'financial'
  | 'other'
  | 'death_certificate'
  | 'court_document';

const DOCUMENT_KIND_LABEL: Record<DocumentKind, string> = {
  will: 'Will',
  revocable_trust: 'Revocable trust',
  irrevocable_trust: 'Irrevocable trust',
  pour_over_will: 'Pour-over will',
  durable_poa: 'Durable power of attorney',
  financial_poa: 'Financial power of attorney',
  medical_poa: 'Medical power of attorney',
  mental_health_poa: 'Mental-health power of attorney',
  living_will: 'Living will',
  hipaa_auth: 'HIPAA authorization',
  guardian_designation: 'Guardian designation',
  certification_of_trust: 'Certification of trust',
  property_assignment: 'Property assignment',
  funding_letter: 'Funding letter',
  beneficiary_letter: 'Beneficiary letter',
  legal: 'Legal',
  tax: 'Tax',
  identity: 'Identity',
  insurance: 'Insurance',
  property: 'Property',
  military: 'Military',
  medical: 'Medical',
  financial: 'Financial',
  other: 'Other',
  death_certificate: 'Death certificate',
  court_document: 'Court document',
};

/**
 * Turn an unknown token into something readable rather than blanking the row.
 * `will` → "Will", `some_new_kind` → "Some new kind".
 */
function humanize(token: string): string {
  const spaced = token.replace(/_/g, ' ').trim();
  return spaced.length === 0 ? 'Document' : spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function documentKindLabel(kind: string): string {
  return DOCUMENT_KIND_LABEL[kind as DocumentKind] ?? humanize(kind);
}

export function executionStatusLabel(status: string): string {
  return EXECUTION_STATUS_LABEL[status as ExecutionStatus] ?? humanize(status);
}

export function executionStatusMeaning(status: string): string {
  return EXECUTION_STATUS_MEANING[status as ExecutionStatus] ?? '';
}

/**
 * The chip class for a status. `executed` is the only one that reads as
 * finished; the pre-execution statuses deliberately carry the warn tone,
 * because "you have a will" and "you have a will that is in force" are
 * different facts and only one of them protects anyone.
 */
export function executionStatusTone(status: string): string {
  if (status === 'executed') return 'chip chip-success';
  if (status === 'revoked' || status === 'superseded') return 'chip';
  return 'chip chip-warn';
}

/**
 * The verb for attesting a rung. Phrased as something the OWNER DID, because
 * that is what the platform is recording: it does not witness a signing, it
 * notes that one happened.
 */
const TRANSITION_LABEL: Record<ExecutionStatus, string> = {
  draft: 'Return to draft',
  generated: 'Mark as generated',
  signed: 'I signed it',
  witnessed: 'It was witnessed',
  notarized: 'It was notarized',
  executed: 'Record it as executed',
  revoked: 'Revoke it',
  superseded: 'Mark it superseded',
};

export function transitionLabel(status: string): string {
  return TRANSITION_LABEL[status as ExecutionStatus] ?? humanize(status);
}

export function documentSourceLabel(source: string): string {
  return source === 'generated' ? 'Generated here' : source === 'uploaded' ? 'Uploaded' : '';
}

/**
 * A readback of the template's own execution requirements — what THIS
 * instrument in THIS state needs before it is in force, as the attorney-signed
 * off template declares it. Never phrased as a statement of law.
 */
export function executionRequirementsSummary(requirements: ExecutionRequirementsInfo): string {
  const parts: string[] = [];
  if (requirements.witnesses > 0) {
    parts.push(`${requirements.witnesses} witness${requirements.witnesses === 1 ? '' : 'es'}`);
  }
  if (requirements.notarization) {
    parts.push('notarization');
  }
  if (requirements.selfProvingAffidavit) {
    parts.push('a self-proving affidavit');
  }
  return parts.length === 0
    ? 'This template records no additional signing formalities.'
    : `This template records that signing needs ${listOf(parts)}.`;
}

function listOf(parts: readonly string[]): string {
  if (parts.length === 1) return parts[0] as string;
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1] as string}`;
}

/** Newest activity first, matching how someone actually looks for a document. */
export function sortDocuments(documents: readonly DocumentInfo[]): DocumentInfo[] {
  return [...documents].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

// Moved to lib/datetime.ts when the paired-devices list (M16) became its second
// consumer. Re-exported rather than copied, and rather than churning every
// import site: one implementation, whichever path a caller reaches it by.
export { formatDateTime } from './datetime';

/** Byte sizes as they appear on a version row. No parsing of anything. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
