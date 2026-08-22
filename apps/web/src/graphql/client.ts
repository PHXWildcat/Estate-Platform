/**
 * Minimal typed GraphQL client for the BFF.
 *
 * Security posture:
 * - Auth lives in httpOnly cookies set by the BFF; this module never reads,
 *   stores, or forwards any token.
 * - `x-estate-csrf` is a custom header the BFF requires so simple-form CSRF
 *   cannot reach the endpoint.
 * - Requests are persisted-query calls (hash from the checked-in manifest);
 *   the full document is included only outside production.
 * - Server error text is never surfaced: failures narrow to a closed code set
 *   and the UI maps codes to its own copy.
 */
import manifest from '../../persisted-manifest.json';
import { notifyOperationSuccess } from './operation-events';
import { operations, type OperationName } from './operations';

export const GQL_ERROR_CODES = [
  'UNAUTHENTICATED',
  'STEPUP_REQUIRED',
  'INVALID_REQUEST',
  'INVALID_CREDENTIALS',
  /** The assistant's uniform not-found — never distinguishes whose it was. */
  'NOT_FOUND',
  /** The `assistant.enabled` master switch is off, and the user can fix it. */
  'ASSISTANT_DISABLED',
  /** No reviewed template exists for that instrument in that state (M12). */
  'TEMPLATE_NOT_FOUND',
  /** The content DEK was destroyed. Permanent — never offer a retry (M12). */
  'CONTENT_ERASED',
  /**
   * Erasure refused because a death report is open on the account (M25 PR4).
   * A CONTROL FIRING with a remedy the owner can take, which is why it is not
   * folded into the refusal below — copy must send them to the case, not to
   * support.
   */
  'OPEN_DEATH_REPORT',
  /** Erasure refused for any other account status (M25 PR4). */
  'ERASURE_NOT_PERMITTED',
  /** The document moved on between read and write. Reload, then retry (M12). */
  'VERSION_CONFLICT',
  /** Beneficiary shares for one class would pass 100% (M19 PR3). */
  'SHARE_SUM_EXCEEDED',
  /** Signing has started, so the content is a legal record now (M12). */
  'DOCUMENT_NOT_EDITABLE',
  /** Preserved for an estate matter — the one refusal step-up cannot fix (M12). */
  'LEGAL_HOLD',
  /** Not the next rung of THIS document's ladder (M12). */
  'INVALID_TRANSITION',
  /** A real scanner matched a signature. Nothing was stored (M12). */
  'MALWARE_DETECTED',
  /** Not an accepted format, or the bytes contradicted the declared type (M12). */
  'UNSUPPORTED_CONTENT',
  /** The scanner was unreachable, so nothing was stored — fail closed (M12). */
  'SCAN_UNAVAILABLE',
  /** A live role assignment still names this contact. Revoke it first (M13). */
  'CONTACT_IN_USE',
  /** The contact already has an account linked (M13). */
  'ALREADY_LINKED',
  /** A link code was refused — one code for every reason, by design (M13). */
  'INVALID_LINK_CODE',
  /** Redemption refused because the owner could not be told (M13). */
  'NOTIFICATIONS_UNAVAILABLE',
  /** That designation is already live on that contact (M13). */
  'ROLE_ALREADY_GRANTED',
  /** That permission is already live on that role (M13). */
  'PERMISSION_ALREADY_GRANTED',
  /**
   * A permission over something nothing enforces. The people surface offers
   * only what is enforced, so reaching this means the app is running ahead of
   * the service — and it must read as "not built yet", never as an outage.
   */
  'GRANT_NOT_ENFORCED',
  /**
   * A verification code was refused — one answer for unknown, expired, spent,
   * revoked and attempt-exhausted, by design (M14). Kept apart from
   * INVALID_CREDENTIALS because that token means "email and password" on the
   * login surface, and the M12 review found exactly that collision producing
   * copy about a password on a form that has none.
   */
  'INVALID_VERIFICATION_CODE',
  /** The code was fine but the platform could not complete it (M14). */
  'VERIFICATION_UNAVAILABLE',
  /**
   * The vault handoff could not be minted (M15). Its own code because the
   * remedy is "try again in a moment" — and because the vault is the one
   * surface where a bounced user needs to know it was the platform rather than
   * their credentials.
   */
  'VAULT_UNAVAILABLE',
  /**
   * The extension pairing code could not be minted (M16). Kept apart from
   * VAULT_UNAVAILABLE, whose copy reassures the reader about their vault — a
   * sentence with nothing to do with the screen this refusal appears on.
   */
  'PAIRING_UNAVAILABLE',
  'OPERATOR_UNAVAILABLE',
  'WEBAUTHN_FAILED',
  /**
   * A rate bound refused it — identity's step-up cap today (M17 PR6). The one
   * refusal on this list whose remedy is to WAIT rather than to do something
   * differently, which is why it is not folded into INVALID_CREDENTIALS: on a
   * step-up prompt that code renders "enter the current code", and after the
   * cap the current code will not be accepted either (M19 PR4 review).
   */
  'TOO_MANY_ATTEMPTS',
  /**
   * An address change was requested again inside identity's re-issue floor, or
   * too many were aimed at one destination (M20 PR2). Named for the REQUEST
   * rather than for a send: a destination that already belongs to somebody else
   * stages nothing and mails nothing, so a caller can meet this refusal having
   * never been sent anything, and copy telling them to use the code they were
   * sent would send them looking for a mail that will never arrive.
   */
  'CODE_REQUESTED_RECENTLY',
  /** A case about this owner is open, so the waiting period is frozen (M22 PR3). */
  'CASE_OPEN',
  /** The case passed verification — self-rescue is now an operator ceremony. */
  'CASE_NOT_VOIDABLE',
  /** A settlement transition rolled back. NOTHING happened; retry is the remedy. */
  'SETTLEMENT_UNAVAILABLE',
  /** Somebody already reported this estate (M22 PR4c). Not the caller's OWN open case. */
  'CASE_ALREADY_REPORTED',
  /** The case moved past the point where more evidence can be attached (M22 PR4c). */
  'EVIDENCE_WINDOW_CLOSED',
  /** An earlier rung of the staged-access ladder is not approved yet (M23 PR2). */
  'STAGE_OUT_OF_ORDER',
  'STAGE_NOT_APPROVED',
  /** A live request for this stage already exists. A control firing, not an outage. */
  'STAGE_ALREADY_REQUESTED',
  /** A real case, really this caller's to administer, not yet at a status that has one. */
  'CASE_NOT_VERIFIED',
  /**
   * A distribution cannot move until an OPERATOR approves it (M23 PR4b) — the
   * dual-control gate in docs/02 §7. The remedy is a second PERSON, so it is
   * kept apart from every refusal whose remedy is another attempt.
   */
  'DISTRIBUTION_NOT_APPROVED',
] as const;

/** Error codes the BFF contract defines. */
/**
 * One settlement case, as this app receives it (M22 PR3).
 *
 * `status` is a STRING, not a union, and deliberately so: the DDL owns that
 * vocabulary and the BFF declines to make it a GraphQL enum, so an app-side
 * union would be a third copy of a list neither of the other two derives.
 * Render from `resolution` for an ENDED case — the DDL forces an owner-voided
 * case to carry `status: 'rejected_fraud'`.
 */
export interface SettlementCaseInfo {
  caseId: string;
  status: string;
  reportSource: string;
  evidenceCount: number;
  waitingPeriodEnds: string | null;
  resolution: string | null;
  resolvedAt: string | null;
  createdAt: string;
  aboutMe: boolean;
  voidable: boolean;
}

/**
 * An estate that names the caller (M22 PR4a).
 *
 * `ownerName` is null when that owner has never saved a profile. It is not a
 * missing value to paper over — it is the server saying there is no name.
 */
/**
 * One estate this caller is settling as executor (M23 PR2).
 *
 * NO USER ID, the rule `ReportableEstateInfo` already holds: the estate is
 * named by `caseId`, every executor query takes the same handle, and the BFF
 * resolves it against settlement's own list. A case id names something only to
 * a caller with authority over it, so it is safe here in a way a
 * `decedentUserId` never would be.
 */
export interface ExecutorCaseInfo {
  caseId: string;
  ownerName: string | null;
  status: string;
  verifiedAt: string | null;
}

/**
 * One rung of the staged-access ladder.
 *
 * DERIVED FROM THE SDL's `AccessStage` enum by `enum-parity.test.ts` — GraphQL
 * serialises an enum as its member NAME, so these are UPPERCASE and a
 * lowercase union here would compare permanently false (the M20 PR1 defect).
 */
export type AccessStage = 'INVENTORY' | 'DOCUMENTS' | 'VAULT';

/**
 * The ladder IN ORDER — the one thing the union above cannot carry.
 *
 * `enum-parity.test.ts` checks the MEMBERS of the union against the SDL and is
 * order-blind by design (it sorts, so declaration order is free). Order is
 * load-bearing here: it decides which rung is offered next, and vault being
 * last is a security property rather than a layout choice. So this array is
 * checked separately, against the SDL's own declaration order, in
 * `EstateSettlement.test.tsx`.
 */
export const ACCESS_STAGES: readonly AccessStage[] = ['INVENTORY', 'DOCUMENTS', 'VAULT'];

export interface EstateAccessStageInfo {
  stage: AccessStage;
  /** 'requested' | 'approved' | 'denied' | 'revoked' — the service's vocabulary. */
  status: string;
  requestedAt: string;
  decidedAt: string | null;
}

/**
 * One item on the estate's administration checklist (M23 PR3).
 *
 * NO `completedBy`, because the BFF has no such field: settlement answers it
 * with a raw user UUID, which tells a reader nothing they can act on.
 *
 * `completedAt` is the WHOLE of "done" — there is no separate boolean, so a
 * row cannot be marked complete with no time on it, or timed with no mark.
 */
export interface EstateTaskInfo {
  taskId: string;
  title: string;
  /** 'legal' | 'financial' | 'administrative' | 'notification', or null. */
  category: string | null;
  /** 'executor' | 'attorney' | 'cpa', or null. A step aimed elsewhere is still shown. */
  assignedRole: string | null;
  dueAt: string | null;
  completedAt: string | null;
}

/**
 * The status moves an executor may make on a distribution (M23 PR4b).
 *
 * DERIVED FROM THE SDL's `EstateDistributionStatusChange` enum by
 * `enum-parity.test.ts` — UPPERCASE because GraphQL serialises an enum as its
 * member NAME, and a lowercase union here would compare permanently false.
 *
 * IT IS NOT THE WHOLE VOCABULARY, and that is the point. 'planned' is where a
 * distribution starts and 'approved' is an OPERATOR's act under dual control
 * (docs/02 §7); neither is here, so this app has no way to spell an action the
 * server would refuse. `EstateDistributionInfo.status` below is a plain string
 * because it must be able to REPORT all five.
 */
export type EstateDistributionStatusChange = 'IN_PROGRESS' | 'COMPLETED' | 'DISPUTED';

/**
 * One planned or completed distribution from an estate (M23 PR4b).
 *
 * NO ACTOR IDS, because the BFF has no such fields: settlement answers with
 * `createdBy` and `approvedBy`, and the second is a member of staff.
 *
 * NO AMOUNT. `hasAmount` says whether there is a figure to ask for; the figure
 * itself is a separate query, because each read is an audited decrypt on the
 * decedent's own key. Never fetch one while rendering a list.
 */
export interface EstateDistributionInfo {
  distributionId: string;
  /** The CONTACT handle, resolvable against `estateContacts` — not a user id. */
  beneficiaryContactId: string;
  assetId: string | null;
  /**
   * 'planned' | 'approved' | 'in_progress' | 'completed' | 'disputed' — a
   * STRING and not a union, because the DDL owns this vocabulary and an
   * app-side copy would be a third list neither of the other two derives.
   */
  status: string;
  approvedAt: string | null;
  hasAmount: boolean;
  createdAt: string;
}

/** One revealed amount — a decimal STRING, or null where none was recorded. */
export interface EstateDistributionAmountInfo {
  distributionId: string;
  amount: string | null;
}

export interface LinkedEstateInfo {
  ownerUserId: string;
  contactId: string;
  ownerName: string | null;
  roles: string[];
}

/**
 * One estate this caller may file a death report on (M22 PR4c).
 *
 * NO USER ID — the estate is named by `contactId`, and the reporting mutation
 * takes the same handle. The BFF resolves it against settlement's own list, so
 * this app never holds and never sends another person's user id.
 */
export interface ReportableEstateInfo {
  contactId: string;
  ownerName: string | null;
  roles: string[];
}

export interface SettlementSettingsInfo {
  waitingPeriodDays: number;
}

export type GqlErrorCode = (typeof GQL_ERROR_CODES)[number];

/** Every way a request can fail, as seen by the UI. */
/**
 * Client-only failure codes — deliberately OUTSIDE `GQL_ERROR_CODES`, which
 * `error-codes.test.ts` fences against the BFF's own union. These are facts
 * about this transport, never about a server answer.
 *
 * `SESSION_RENEWED` (M20 PR4) is the one a caller must not read as an outage:
 * the session was expired and has just been renewed, the request was NOT
 * performed, and trying again will work.
 */
export type GqlFailureCode = GqlErrorCode | 'NETWORK' | 'UNKNOWN' | 'SESSION_RENEWED';

export type GqlResult<T> = { ok: true; data: T } | { ok: false; code: GqlFailureCode };

/**
 * How strongly the session is authenticated — the BFF enum verbatim.
 *
 * UPPERCASE, AND THE CASE IS THE WHOLE POINT. GraphQL serialises an enum as its
 * NAME, so the wire carries `"NONE"`; this union said `'none' | 'mfa' |
 * 'stepup'` from M2 until M20, which made `session.mfaLevel === 'none'`
 * PERMANENTLY FALSE at all three of its call sites. Measured on the running
 * stack: an account with no `mfa_methods` row and `sessions.mfa_level = 'none'`
 * was shown "MFA enrolled" and offered "Re-enroll authenticator app". The
 * compiler could not object — it compares values against this DECLARATION, and
 * the declaration was the thing that was wrong — and no test could either,
 * because every fixture used the same invented lowercase vocabulary (the M15
 * "a fixture that invents an enum tests the fixture" lesson). `enum-parity.test.ts`
 * now derives all five of these unions from the BFF's SDL.
 */
export type MfaLevel = 'NONE' | 'MFA' | 'STEPUP';

/**
 * A live account-erasure request (M25 PR4).
 *
 * `status` is deliberately a plain string. Identity owns the vocabulary and it
 * grows; a union here would make a state this build has not met a PARSE
 * FAILURE, when the honest degradation is "something is in progress, and this
 * build does not know enough to offer you a button".
 */
export interface ErasureRequestInfo {
  status: string;
  requestedAt: string;
}

export interface SessionInfo {
  userId: string;
  mfaLevel: MfaLevel;
  stepUpFresh: boolean;
}

/** What a session may be spent on — the BFF enum verbatim (M15's audience, listed in M16). */
export type SessionAudience = 'ACCOUNT' | 'VAULT' | 'EXTENSION' | 'OPERATOR' | 'UNKNOWN';

/**
 * One live credential on the caller's account (M16).
 *
 * Deliberately narrow, and the narrowness is identity's rather than this app's:
 * `sessions` returns ids, the audience and two timestamps, with no IP and no
 * device name, because those columns exist and nothing writes them. The
 * audience is what lets a row say "browser extension" instead of "a session".
 */
export interface LiveSessionInfo {
  sessionId: string;
  audience: SessionAudience;
  createdAt: string;
  expiresAt: string;
  /** The session this browser is using — revoking it is a sign-out. */
  current: boolean;
}

/** M17 PR5. */
export interface PasskeyInfo {
  id: string;
  nickname: string | null;
  isHardwareKey: boolean;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface AssetInfo {
  assetId: string;
  category: string;
  title: string;
  /** Decimal string — money is never a Float. */
  estValue: string | null;
  valuationAsOf: string | null;
  valuationSource: string | null;
  ownershipPct: number;
  inTrust: boolean;
  fundingStatus: string | null;
  /** 'live' | 'retired' — a retired asset is a record, not a deletion. */
  status: string;
  retiredAt: string | null;
  version: string;
}

/**
 * The full record. A SEPARATE type from AssetInfo on purpose: the list
 * deliberately cannot carry costBasis/location/notes (the service decrypts
 * exactly est_value per list row), and folding the shapes together would
 * make "not carried" indistinguishable from "not set".
 */
export interface AssetDetailInfo extends AssetInfo {
  costBasis: string | null;
  location: string | null;
  notes: string | null;
}

export interface AssetHistoryEntryInfo {
  version: string;
  eventId: string;
  eventType: string;
  occurredAt: string;
  /** The service's own validated event body — rendered defensively, never parsed as instructions. */
  payload: Record<string, unknown>;
}

/**
 * One designation. `name` is composed by the BFF from the caller's own
 * contacts; NULL means the contact is no longer on file — a fact the row
 * states while staying removable, never a value to guess at.
 */
export interface AssetBeneficiaryInfo {
  contactId: string;
  name: string | null;
  designation: string;
  sharePct: number;
}

export interface DesignationTotalInfo {
  designation: string;
  sharePct: number;
  designationComplete: boolean;
}

export interface AssetBeneficiariesInfo {
  assetId: string;
  beneficiaries: AssetBeneficiaryInfo[];
  totals: DesignationTotalInfo[];
}

export interface AssetCommandAckInfo {
  assetId: string;
  eventId: string;
  version: string;
  /** True when this call was an idempotent retry answered with the original ack. */
  replayed: boolean;
}

/** The full create input (M19 PR2). A valuation is all-or-nothing. */
export interface CreateAssetInputInfo {
  category: string;
  title: string;
  ownershipPct?: number;
  inTrust?: boolean;
  fundingStatus?: string;
  estValue?: string;
  valuationAsOf?: string;
  valuationSource?: string;
  costBasis?: string;
  location?: string;
  notes?: string;
  /** Idempotency key: mint per payload, hold across retries of the SAME payload. */
  clientEventId?: string;
}

export interface NetWorthInfo {
  totalValue: string;
  assetCount: number;
  valuedAssetCount: number;
  inTrustValue: string;
}

/**
 * Four statuses, and the UI must keep them apart (M10 PR4). `OK` with no
 * findings is a real answer — "nothing found"; `UNAVAILABLE` is a read that did
 * not happen; `REFUSED` is a control firing (the estate-tax reference data has
 * no professional sign-off, so production will not state it); `DISABLED` is the
 * one the user can act on. Rendering any of the last three as "no findings"
 * would tell someone their estate is in order on the strength of a failure.
 */
export type AnalysisStatus = 'OK' | 'UNAVAILABLE' | 'REFUSED' | 'DISABLED';

/**
 * M14. `UNAVAILABLE` is a fact about the platform, not about the user, and
 * collapsing it into `UNVERIFIED` would send somebody to complete a ceremony
 * that cannot run.
 */
export type EmailVerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'UNAVAILABLE';

/**
 * M14. `TOO_SOON` is the re-issue floor — the only rate limit on that path — and
 * a user told "sent" who receives nothing keeps pressing.
 */
export type ResendVerificationOutcome = 'SENT' | 'TOO_SOON' | 'ALREADY_VERIFIED' | 'UNAVAILABLE';

export interface FindingInfo {
  /** Closed token from the analyser. `lib/findings.ts` turns it into a sentence. */
  code: string;
  severity: 'high' | 'medium' | 'info';
  subject: { kind: 'asset' | 'document' | 'estate'; ref: string | null; label: string | null };
  /** Counts, enum tokens, and money as decimal STRINGS — never parsed to a float. */
  detail: Record<string, string | number | boolean | null>;
}

export interface AnalysisInfo {
  status: AnalysisStatus;
  reason: string | null;
  findings: FindingInfo[];
  /** docs/01 §2.8's non-legal-advice watermark. Present on every status. */
  disclaimer: string;
}

export interface ConversationInfo {
  conversationId: string;
  createdAt: string;
  updatedAt: string;
}

export interface TranscriptMessageInfo {
  messageId: string;
  seq: number;
  role: 'user' | 'assistant';
  /**
   * MODEL-AUTHORED on the assistant side, and untrusted markup either way. It
   * is rendered ONLY through `MessageText`, which builds text nodes and nothing
   * else — no component may interpret this string (docs/03 §6d).
   */
  text: string;
  createdAt: string;
}

export interface TranscriptInfo {
  conversationId: string;
  messages: TranscriptMessageInfo[];
}

export interface TurnInfo {
  conversationId: string;
  messageId: string;
  text: string;
  toolCalls: number;
}

/**
 * One declared intake variable of a template (M12). The QUESTIONNAIRE IS THE
 * TEMPLATE'S, not this app's: a state-specific instrument asks for what its
 * reviewed source declares, so the form is built from these rather than from a
 * hand-written field list that would drift from the legal document.
 */
export interface TemplateVariableInfo {
  name: string;
  kind: 'text' | 'boolean' | 'date' | 'enum';
  label: string | null;
  required: boolean;
  /** Text variables only. */
  maxLength: number | null;
  /** Enum variables only. */
  options: string[] | null;
}

export interface ExecutionRequirementsInfo {
  witnesses: number;
  notarization: boolean;
  selfProvingAffidavit: boolean;
}

export interface DocumentTemplateInfo {
  templateId: string;
  docType: string;
  state: string;
  version: number;
  legalReviewAt: string;
  executionRequirements: ExecutionRequirementsInfo;
  variables: TemplateVariableInfo[];
}

export interface DocumentInfo {
  documentId: string;
  docType: string;
  source: 'generated' | 'uploaded';
  /**
   * The one plaintext, user-authored label in the documents cluster (accepted
   * low-sensitivity metadata). Rendered as data, never as markup.
   */
  title: string;
  currentVersion: number;
  executionStatus: string;
  executedAt: string | null;
  legalHold: boolean;
  sealed: boolean;
  templateId: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * One document plus the transitions IT may take next (M12 PR2).
 *
 * The ladder is the SERVICE's computation from the template's own
 * sha256-verified `execution_requirements`, so this app renders the
 * attestations this instrument in this state requires and derives nothing. An
 * empty list is a real answer — the service's fail-closed one when it cannot
 * read the ladder from a verified template.
 */
export interface DocumentDetailInfo extends DocumentInfo {
  allowedTransitions: string[];
}

export interface UploadedDocumentInfo {
  documentId: string;
  version: number;
  contentSha256: string;
  executionStatus: string;
  /** Best-effort: OCR failing is never a reason to refuse a clean upload. */
  ocrIndexed: boolean;
}

export interface DocumentVersionInfo {
  version: number;
  contentSha256: string;
  sizeBytes: number;
  mime: string;
  createdAt: string;
}

/**
 * One version's decrypted content. ASKING FOR THIS IS AN AUDITED DECRYPT on the
 * user's own trail, so it is fetched on an explicit action and never as part of
 * loading a list.
 *
 * `content` is UNTRUSTED INPUT (docs/03 risk #6): for a generated instrument it
 * is HTML the platform rendered, for an upload it is base64 of a file somebody
 * scanned. Nothing in this app interprets it — the HTML case goes to
 * `DocumentViewer`, which hands it to a sandboxed iframe and never to the app's
 * own DOM.
 */
export interface DocumentContentInfo {
  documentId: string;
  version: number;
  mime: string;
  contentSha256: string;
  encoding: 'utf8' | 'base64';
  content: string;
}

export interface GeneratedDocumentInfo {
  documentId: string;
  version: number;
  contentSha256: string;
  executionStatus: string;
}

/** One intake answer: exactly one of `text` and `boolean` (the BFF refuses both/neither). */
export interface DocumentVariableInput {
  name: string;
  text?: string;
  boolean?: boolean;
}

export interface ReadinessInfo {
  funding: AnalysisInfo;
  missingDocuments: AnalysisInfo;
  beneficiaryConflicts: AnalysisInfo;
  estateTax: AnalysisInfo;
}

/**
 * The caller's own profile. `ssnLast4` is the only SSN-shaped value that ever
 * reaches the browser, and there is no mutation that can write the full number
 * — see the BFF's Profile type. Null fields mean "not on file".
 */
export interface ProfileInfo {
  userId: string;
  legalName: string;
  dob: string | null;
  ssnLast4: string | null;
  address: string | null;
  phone: string | null;
  occupation: string | null;
  maritalStatus: string | null;
  stateOfResidence: string | null;
}

export interface FamilyMemberInfo {
  id: string;
  relation: string;
  name: string;
  dob: string | null;
  /** Null when the date of birth is unknown, so minority is unknown too. */
  isMinor: boolean | null;
  notes: string | null;
}

/**
 * A contact as the list gives it: one audited decrypt per row downstream. The
 * `has` flags are what let a row say what is on file without decrypting it.
 */
export interface ContactSummaryInfo {
  id: string;
  name: string;
  relationship: string | null;
  professionalKind: string | null;
  hasEmail: boolean;
  hasPhone: boolean;
  hasAddress: boolean;
  hasNotes: boolean;
  linked: boolean;
}

export interface ContactDetailInfo {
  id: string;
  name: string;
  email: string | null;
  phone: string | null;
  address: string | null;
  relationship: string | null;
  professionalKind: string | null;
  notes: string | null;
}

export interface RoleAssignmentInfo {
  id: string;
  contactId: string;
  role: string;
  scopeType: string;
  scopeId: string | null;
  effectiveCondition: string;
  startsAt: string | null;
  endsAt: string | null;
}

export interface PermissionGrantInfo {
  id: string;
  resource: string;
  action: string;
  createdAt: string;
}

type EmptyVariables = Record<string, never>;

/**
 * Exported for the shared read cache (M24 PR1), which needs an operation's
 * `data` shape to type what it serves — a TYPE-ONLY dependency; the transport
 * never imports the cache.
 */
export interface OperationSignatures {
  Register: {
    variables: { email: string; password: string };
    data: { register: { ok: boolean } };
  };
  Login: {
    variables: { email: string; password: string };
    data: { login: { ok: boolean } };
  };
  Refresh: { variables: EmptyVariables; data: { refresh: { ok: boolean } } };
  Sessions: { variables: EmptyVariables; data: { sessions: LiveSessionInfo[] } };
  RevokeSession: { variables: { sessionId: string }; data: { revokeSession: { ok: boolean } } };
  StartExtensionPairing: {
    variables: EmptyVariables;
    data: { startExtensionPairing: { code: string; expiresAt: string } };
  };
  Passkeys: { variables: EmptyVariables; data: { passkeys: PasskeyInfo[] } };
  WebauthnRegisterOptions: {
    variables: EmptyVariables;
    data: { webauthnRegisterOptions: unknown };
  };
  WebauthnRegister: {
    variables: { response: Record<string, unknown> };
    data: { webauthnRegister: { ok: boolean } };
  };
  WebauthnStepUpOptions: {
    variables: EmptyVariables;
    data: { webauthnStepUpOptions: unknown };
  };
  WebauthnStepUp: {
    variables: { response: Record<string, unknown> };
    data: { webauthnStepUp: { stepupExpiresAt: string } };
  };
  RevokePasskey: { variables: { id: string }; data: { revokePasskey: { ok: boolean } } };
  RenamePasskey: {
    variables: { id: string; nickname: string };
    data: { renamePasskey: { ok: boolean } };
  };
  TotpEnroll: { variables: EmptyVariables; data: { totpEnroll: { otpauthUri: string } } };
  TotpVerify: { variables: { code: string }; data: { totpVerify: { ok: boolean } } };
  StepUp: { variables: { code: string }; data: { stepUp: { ok: boolean } } };
  StartVaultHandoff: {
    variables: EmptyVariables;
    data: { startVaultHandoff: { code: string; expiresAt: string; vaultOrigin: string } };
  };
  /**
   * M21 PR3a. A SEPARATE ENTRY for a separate operation, mirroring the two mint
   * routes at identity — there is no `audience` variable here for the same
   * reason there is none on the wire.
   */
  StartOperatorHandoff: {
    variables: EmptyVariables;
    data: { startOperatorHandoff: { code: string; expiresAt: string; operatorOrigin: string } };
  };
  ExportDemo: { variables: EmptyVariables; data: { exportDemo: { ok: boolean } } };
  Session: { variables: EmptyVariables; data: { session: SessionInfo } };
  Logout: { variables: EmptyVariables; data: { logout: { ok: boolean } } };
  Assets: {
    variables: { includeRetired?: boolean };
    data: { assets: AssetInfo[] };
  };
  Asset: {
    variables: { assetId: string };
    data: { asset: AssetDetailInfo };
  };
  AssetHistory: {
    variables: { assetId: string };
    data: { assetHistory: AssetHistoryEntryInfo[] };
  };
  NetWorth: { variables: EmptyVariables; data: { netWorth: NetWorthInfo } };
  CreateAsset: {
    variables: { input: CreateAssetInputInfo };
    data: { createAsset: AssetCommandAckInfo };
  };
  UpdateAsset: {
    variables: {
      assetId: string;
      expectedVersion: string;
      title?: string;
      /** ABSENT = unchanged; explicit null = clear. */
      location?: string | null;
      notes?: string | null;
      inTrust?: boolean;
      fundingStatus?: string | null;
      clientEventId?: string;
    };
    data: { updateAsset: AssetCommandAckInfo };
  };
  RecordValuation: {
    variables: {
      assetId: string;
      expectedVersion: string;
      estValue: string;
      valuationAsOf: string;
      valuationSource: string;
      clientEventId?: string;
    };
    data: { recordValuation: AssetCommandAckInfo };
  };
  ChangeOwnership: {
    variables: {
      assetId: string;
      expectedVersion: string;
      ownershipPct: number;
      costBasis?: string | null;
      clientEventId?: string;
    };
    data: { changeOwnership: AssetCommandAckInfo };
  };
  RetireAsset: {
    variables: {
      assetId: string;
      expectedVersion: string;
      reason?: string;
      clientEventId?: string;
    };
    data: { retireAsset: AssetCommandAckInfo };
  };
  AssetBeneficiaries: {
    variables: { assetId: string };
    data: { assetBeneficiaries: AssetBeneficiariesInfo };
  };
  DesignateBeneficiary: {
    variables: {
      assetId: string;
      expectedVersion: string;
      contactId: string;
      designation: string;
      sharePct: number;
      clientEventId?: string;
    };
    data: { designateBeneficiary: AssetCommandAckInfo };
  };
  RemoveBeneficiary: {
    variables: {
      assetId: string;
      expectedVersion: string;
      contactId: string;
      designation: string;
      clientEventId?: string;
    };
    data: { removeBeneficiary: AssetCommandAckInfo };
  };
  LinkedEstates: {
    variables: EmptyVariables;
    data: { linkedEstates: LinkedEstateInfo[] };
  };
  SettlementCases: {
    variables: EmptyVariables;
    data: { settlementCases: SettlementCaseInfo[] };
  };
  ReportableEstates: {
    variables: EmptyVariables;
    data: { reportableEstates: ReportableEstateInfo[] };
  };
  ReportDeath: {
    variables: { contactId: string; documentId?: string; documentVersion?: number };
    data: { reportDeath: SettlementCaseInfo };
  };
  AttachCaseEvidence: {
    variables: { caseId: string; documentId: string; version: number };
    data: { attachCaseEvidence: SettlementCaseInfo };
  };
  VoidSettlementCase: {
    variables: { caseId: string };
    data: { voidSettlementCase: SettlementCaseInfo };
  };
  SettlementSettings: {
    variables: EmptyVariables;
    data: { settlementSettings: SettlementSettingsInfo };
  };
  ExecutorCases: {
    variables: EmptyVariables;
    data: { executorCases: ExecutorCaseInfo[] };
  };
  EstateStages: {
    variables: { caseId: string };
    data: { estateStages: EstateAccessStageInfo[] };
  };
  EstateInventory: {
    variables: { caseId: string };
    data: { estateInventory: AssetInfo[] };
  };
  RequestEstateAccess: {
    variables: { caseId: string; stage: AccessStage };
    data: { requestEstateAccess: EstateAccessStageInfo };
  };
  EstateContacts: {
    variables: { caseId: string };
    data: { estateContacts: ContactSummaryInfo[] };
  };
  EstateTasks: {
    variables: { caseId: string };
    data: { estateTasks: EstateTaskInfo[] };
  };
  SetEstateTaskCompletion: {
    variables: { taskId: string; completed: boolean };
    data: { setEstateTaskCompletion: EstateTaskInfo };
  };
  EstateDistributions: {
    variables: { caseId: string };
    data: { estateDistributions: EstateDistributionInfo[] };
  };
  EstateDistributionAmount: {
    variables: { distributionId: string };
    data: { estateDistributionAmount: EstateDistributionAmountInfo };
  };
  RecordEstateDistribution: {
    variables: {
      caseId: string;
      beneficiaryContactId: string;
      /** Omitted or null alike mean "no asset named" — the BFF drops both. */
      assetId?: string | null;
      /** A decimal STRING, never a number. Null where none is recorded. */
      amount?: string | null;
    };
    data: { recordEstateDistribution: EstateDistributionInfo };
  };
  SetEstateDistributionStatus: {
    variables: { distributionId: string; status: EstateDistributionStatusChange };
    data: { setEstateDistributionStatus: EstateDistributionInfo };
  };
  SetSettlementWaitingPeriod: {
    variables: { days: number };
    data: { setSettlementWaitingPeriod: SettlementSettingsInfo };
  };
  Readiness: { variables: EmptyVariables; data: { readiness: ReadinessInfo } };
  Conversations: { variables: EmptyVariables; data: { conversations: ConversationInfo[] } };
  Conversation: {
    variables: { conversationId: string };
    data: { conversation: TranscriptInfo };
  };
  StartConversation: { variables: EmptyVariables; data: { startConversation: ConversationInfo } };
  SendMessage: {
    variables: { conversationId: string; text: string };
    data: { sendMessage: TurnInfo };
  };
  DeleteConversation: {
    variables: { conversationId: string };
    data: { deleteConversation: { ok: boolean } };
  };
  DocumentTemplates: {
    variables: { state: string };
    data: { documentTemplates: DocumentTemplateInfo[] };
  };
  Documents: { variables: EmptyVariables; data: { documents: DocumentInfo[] } };
  Document: { variables: { documentId: string }; data: { document: DocumentDetailInfo } };
  DocumentSearch: { variables: { query: string }; data: { documentSearch: DocumentInfo[] } };
  UploadDocument: {
    variables: { kind: string; title: string; mime: string; contentBase64: string };
    data: { uploadDocument: UploadedDocumentInfo };
  };
  SetDocumentStatus: {
    variables: { documentId: string; status: string; executedAt?: string };
    data: { setDocumentStatus: DocumentDetailInfo };
  };
  DeleteDocument: {
    variables: { documentId: string };
    data: { deleteDocument: { ok: boolean } };
  };
  Profile: { variables: EmptyVariables; data: { profile: ProfileInfo | null } };
  SaveProfile: {
    /**
     * ABSENT and `null` mean DIFFERENT THINGS all the way down: omit a key to
     * leave that field alone, pass null to clear it. There is deliberately no
     * `ssn` — nothing here can set or clear the full number.
     */
    variables: {
      legalName: string;
      dob?: string | null;
      address?: string | null;
      phone?: string | null;
      occupation?: string | null;
      maritalStatus?: string | null;
      stateOfResidence?: string | null;
    };
    data: { saveProfile: ProfileInfo };
  };
  FamilyMembers: { variables: EmptyVariables; data: { familyMembers: FamilyMemberInfo[] } };
  AddFamilyMember: {
    variables: { relation: string; name: string; dob?: string; isMinor?: boolean; notes?: string };
    data: { addFamilyMember: FamilyMemberInfo[] };
  };
  DeleteFamilyMember: {
    variables: { id: string };
    data: { deleteFamilyMember: FamilyMemberInfo[] };
  };
  Contacts: { variables: EmptyVariables; data: { contacts: ContactSummaryInfo[] } };
  Contact: { variables: { contactId: string }; data: { contact: ContactDetailInfo } };
  AddContact: {
    variables: {
      name: string;
      email?: string;
      phone?: string;
      address?: string;
      relationship?: string;
      professionalKind?: string;
      notes?: string;
    };
    data: { addContact: ContactSummaryInfo[] };
  };
  UpdateContact: {
    variables: {
      contactId: string;
      name: string;
      email?: string;
      phone?: string;
      address?: string;
      relationship?: string;
      professionalKind?: string;
      notes?: string;
    };
    data: { updateContact: ContactDetailInfo };
  };
  DeleteContact: {
    variables: { contactId: string };
    data: { deleteContact: ContactSummaryInfo[] };
  };
  RoleAssignments: {
    variables: EmptyVariables;
    data: { roleAssignments: RoleAssignmentInfo[] };
  };
  GrantRole: {
    variables: {
      contactId: string;
      role: string;
      scopeType: string;
      effectiveCondition?: string;
    };
    data: { grantRole: RoleAssignmentInfo[] };
  };
  RevokeRole: {
    variables: { roleAssignmentId: string };
    data: { revokeRole: RoleAssignmentInfo[] };
  };
  RolePermissions: {
    variables: { roleAssignmentId: string };
    data: { rolePermissions: PermissionGrantInfo[] };
  };
  GrantRolePermission: {
    variables: { roleAssignmentId: string; resource: string; action: string };
    data: { grantRolePermission: PermissionGrantInfo[] };
  };
  RevokeRolePermission: {
    variables: { roleAssignmentId: string; grantId: string };
    data: { revokeRolePermission: PermissionGrantInfo[] };
  };
  InviteContactLink: {
    variables: { contactId: string };
    data: { inviteContactLink: { code: string; expiresAt: string } };
  };
  RevokeContactLinkInvitation: {
    variables: { contactId: string };
    data: { revokeContactLinkInvitation: { ok: boolean } };
  };
  UnlinkContact: {
    variables: { contactId: string };
    data: { unlinkContact: { ok: boolean } };
  };
  RedeemContactLink: {
    variables: { code: string };
    data: { redeemContactLink: { ok: boolean } };
  };
  DocumentVersions: {
    variables: { documentId: string };
    data: { documentVersions: DocumentVersionInfo[] };
  };
  DocumentContent: {
    variables: { documentId: string; version: number };
    data: { documentContent: DocumentContentInfo };
  };
  GenerateDocument: {
    variables: {
      docType: string;
      state: string;
      templateId?: string;
      title?: string;
      variables: DocumentVariableInput[];
    };
    data: { generateDocument: GeneratedDocumentInfo };
  };
  RegenerateDocument: {
    variables: {
      documentId: string;
      templateId?: string;
      title?: string;
      variables: DocumentVariableInput[];
    };
    data: { regenerateDocument: GeneratedDocumentInfo };
  };
  /**
   * M14. The three states are the BFF enum verbatim: UNAVAILABLE is a fact
   * about the platform, not about the user, and collapsing it into UNVERIFIED
   * would send somebody to complete a ceremony that cannot run.
   */
  EmailVerification: {
    variables: EmptyVariables;
    data: { emailVerification: EmailVerificationStatus };
  };
  /**
   * M24 PR2. Every answer is an audited decrypt on the caller's own trail, so
   * this is asked on an EXPLICIT REVEAL only — never on mount, never enrolled
   * in the shared read cache (both bars written in read-cache.ts and the
   * frontend rules). CONTENT_ERASED is a real answer here, not an outage.
   */
  AccountEmail: {
    variables: EmptyVariables;
    data: { accountEmail: string };
  };
  ResendEmailVerification: {
    variables: EmptyVariables;
    data: { resendEmailVerification: ResendVerificationOutcome };
  };
  VerifyEmail: { variables: { code: string }; data: { verifyEmail: { ok: boolean } } };
  ChangePassword: {
    variables: { currentPassword: string; newPassword: string };
    data: { changePassword: { ok: boolean } };
  };
  RequestEmailChange: {
    variables: { currentPassword: string; newEmail: string };
    data: { requestEmailChange: { ok: boolean } };
  };
  CompleteEmailChange: {
    variables: { code: string };
    data: { completeEmailChange: { ok: boolean } };
  };
  CancelEmailChange: { variables: EmptyVariables; data: { cancelEmailChange: { ok: boolean } } };
  /**
   * ACCOUNT ERASURE (M25 PR4). All three answer a NULLABLE request rather than
   * `ok`, and the null carries meaning on each: no request outstanding on the
   * read, and on the cancel "nothing left to withdraw". A non-null cancel means
   * the withdrawal did NOT take.
   *
   * `status` is a plain string, mirroring the SDL: identity's vocabulary grows,
   * and a union here would fail to parse a state this build has not met rather
   * than degrading to "in progress".
   */
  AccountErasure: {
    variables: EmptyVariables;
    data: { accountErasure: ErasureRequestInfo | null };
  };
  RequestAccountErasure: {
    variables: EmptyVariables;
    data: { requestAccountErasure: ErasureRequestInfo | null };
  };
  CancelAccountErasure: {
    variables: EmptyVariables;
    data: { cancelAccountErasure: ErasureRequestInfo | null };
  };
  RequestPasswordReset: {
    variables: { email: string };
    data: { requestPasswordReset: { ok: boolean } };
  };
  CompletePasswordReset: {
    variables: { code: string; newPassword: string };
    data: { completePasswordReset: { ok: boolean } };
  };
  Consents: { variables: EmptyVariables; data: { consents: string[] } };
  GrantConsent: { variables: { scope: string }; data: { grantConsent: string[] } };
  RevokeConsent: { variables: { scope: string }; data: { revokeConsent: string[] } };
}

const hashByDocument: ReadonlyMap<string, string> = new Map(
  Object.entries(manifest as Record<string, string>).map(([hash, document]) => [document, hash]),
);

function isGqlErrorCode(value: unknown): value is GqlErrorCode {
  return typeof value === 'string' && (GQL_ERROR_CODES as readonly string[]).includes(value);
}

/** Extracts errors[0].extensions.code from an untrusted payload, if present. */
function extractErrorCode(payload: unknown): GqlFailureCode | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const errors = (payload as { errors?: unknown }).errors;
  if (!Array.isArray(errors) || errors.length === 0) return null;
  const first: unknown = errors[0];
  if (typeof first !== 'object' || first === null) return 'UNKNOWN';
  const extensions = (first as { extensions?: unknown }).extensions;
  if (typeof extensions !== 'object' || extensions === null) return 'UNKNOWN';
  const code = (extensions as { code?: unknown }).code;
  return isGqlErrorCode(code) ? code : 'UNKNOWN';
}

/**
 * The transport half of {@link gqlRequest}: one network send, no retry.
 * Resolves to a discriminated result; never throws on server or network
 * failure and never exposes server-provided message text.
 */
async function send<Name extends OperationName>(
  operation: Name,
  variables: OperationSignatures[Name]['variables'],
): Promise<GqlResult<OperationSignatures[Name]['data']>> {
  const document = operations[operation];
  const sha256Hash = hashByDocument.get(document);
  if (sha256Hash === undefined) {
    // Build-time misconfiguration, not a runtime condition: the checked-in
    // manifest is out of sync with operations.ts.
    throw new Error(
      `No persisted hash for operation "${operation}". Run: node scripts/build-persisted-manifest.mjs`,
    );
  }

  const body: Record<string, unknown> = {
    variables,
    // `version: 1` is REQUIRED by the APQ protocol the BFF's plugin
    // implements: without it the extractor finds no operation id and every
    // request is refused as "Operation not allowed". Omitting it was invisible
    // for a long time because non-production builds also send `query` below,
    // so the document carried the request and the hash was never consulted —
    // it would have failed only in production. Found by driving the real
    // production web image against the stack (M8 PR5).
    extensions: { persistedQuery: { version: 1, sha256Hash } },
  };
  if (process.env.NODE_ENV !== 'production') {
    body.query = document;
  }

  let response: Response;
  try {
    response = await fetch('/graphql', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-estate-csrf': '1',
      },
      credentials: 'include',
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, code: 'NETWORK' };
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { ok: false, code: 'NETWORK' };
  }

  const errorCode = extractErrorCode(payload);
  if (errorCode !== null) return { ok: false, code: errorCode };

  const data =
    typeof payload === 'object' && payload !== null
      ? (payload as { data?: unknown }).data
      : undefined;
  if (!response.ok || data === undefined || data === null) {
    return { ok: false, code: 'UNKNOWN' };
  }
  return { ok: true, data: data as OperationSignatures[Name]['data'] };
}

/**
 * SESSION CONTINUITY (M20 PR4). The access cookie lives 15 minutes and the
 * refresh cookie 30 days; until this existed the app had NO refresh wiring, so
 * the access TTL was the whole usable session — measured in the M20 PR1 drive
 * as "Your session has ended" over a live session row. The `Refresh` operation
 * had existed at every layer since M8 with no caller; this is its caller, and
 * `operation-consumers.test.ts` is the fence that refuses the next uncalled
 * operation.
 *
 * SINGLE-FLIGHT IS A CORRECTNESS REQUIREMENT, NOT AN OPTIMIZATION. Identity's
 * rotation-reuse detection (M16) treats an already-rotated refresh token as
 * THEFT and revokes the whole session. Two concurrent Refresh calls carry the
 * same cookie: the first rotates it, and the second then presents the
 * rotated-away value — indistinguishable, by design, from a thief replaying a
 * stolen one. So concurrency is removed BY CONSTRUCTION at two scopes: an
 * in-tab promise latch, and a cross-tab Web Lock, because every tab of this
 * origin shares one cookie jar. A tab that waited on the lock still sends its
 * own Refresh afterwards — by then the jar holds the NEW token (the winner's
 * Set-Cookie landed before the lock released), so that is an ordinary second
 * rotation, not a reuse.
 */
let inflightRefresh: Promise<RefreshOutcome> | null = null;

function withCrossTabLock<T>(fn: () => Promise<T>): Promise<T> {
  // jsdom and pre-15.4 Safari have no Web Locks; the in-tab latch still holds
  // there, and the remaining cross-TAB race in those browsers is a recorded
  // residual (docs/03 §6x), not a silent one.
  const locks = (globalThis.navigator as (Navigator & { locks?: LockManager }) | undefined)?.locks;
  if (locks !== undefined) {
    return locks.request('estate.session.refresh', fn) as Promise<T>;
  }
  return fn();
}

/**
 * WHAT HAPPENED TO THE REFRESH — three answers, not two, because the M20 PR5
 * review found the boolean collapsing the two that matter most.
 *
 * `refused` means identity answered and said no: the session is genuinely gone,
 * revoked from the owner's paired-devices list or expired past its 30 days. The
 * BFF has already cleared the cookies. "Your session has ended" is TRUE.
 *
 * `unavailable` means the refresh never COMPLETED — a connection that dropped
 * between the first call and this one, an identity outage the BFF rethrows
 * without touching cookies, or a response whose shape this build does not
 * recognise. The session may be perfectly alive. Reporting the original
 * UNAUTHENTICATED here is what made an outage wear the face of a revocation,
 * which is the M16 PR2a rule the surrounding code cites and the boolean broke.
 */
type RefreshOutcome =
  { status: 'renewed' } | { status: 'refused' } | { status: 'unavailable'; code: GqlFailureCode };

function refreshSession(): Promise<RefreshOutcome> {
  inflightRefresh ??= withCrossTabLock(async (): Promise<RefreshOutcome> => {
    // Through gqlRequest, NOT send: the Refresh short-circuit below is what
    // makes this non-recursive, and going through the public entry keeps
    // `operation-consumers.test.ts` honest — the fence counts gqlRequest
    // callers, and this is the Refresh operation's one product caller.
    const result = await gqlRequest('Refresh', {});
    if (!result.ok) {
      // UNAUTHENTICATED from the refresh itself is the one refusal that means
      // the credential is dead. Everything else — NETWORK, UNKNOWN, a code this
      // build has not learned — is the platform failing to answer, and is
      // reported as itself so the copy names the right remedy.
      return result.code === 'UNAUTHENTICATED'
        ? { status: 'refused' }
        : { status: 'unavailable', code: result.code };
    }
    // A missing field is NO DATA, never data (M11) — and NOT a refusal: a BFF
    // predating the mutation is a version skew, so it says nothing whatever
    // about whether this session is alive.
    return result.data.refresh?.ok === true
      ? { status: 'renewed' }
      : { status: 'unavailable', code: 'UNKNOWN' };
  })
    // `gqlRequest` never rejects; this guards the lock API itself, because
    // the never-throws contract must survive a misbehaving LockManager. A lock
    // that throws is this process failing, not identity refusing.
    .catch((): RefreshOutcome => ({ status: 'unavailable', code: 'UNKNOWN' }))
    .finally(() => {
      inflightRefresh = null;
    });
  return inflightRefresh;
}

/**
 * Sends one persisted GraphQL operation to the same-origin `/graphql`
 * endpoint. On UNAUTHENTICATED it silently refreshes the session once and
 * retries once, so an expired 15-minute access token never surfaces while the
 * 30-day refresh credential is good — and "Your session has ended" is TRUE
 * when a caller finally renders it, because it now means the refresh itself
 * was refused.
 *
 * ONLY QUERIES ARE RETRIED, AND THAT IS A CORRECTNESS LINE RATHER THAN A
 * PREFERENCE. The tempting claim is that a retry can never repeat a side
 * effect, because UNAUTHENTICATED means a guard refused before any handler ran
 * — true of a SINGLE hop, and false of the eleven BFF resolvers that write and
 * then read back (`addContact` → `contacts`, `addFamilyMember` → `family`, and
 * so on). If the write succeeds and the read-back is refused, the whole
 * resolver re-runs, and `createContact`/`createFamilyMember` carry no
 * idempotency key — there is nothing to make a second create a replay, and two
 * contacts of the same name are legitimate, so no constraint catches it
 * either. One click would silently produce two rows. The asset commands are
 * safe (payload-keyed `eventId`, M19) and the profile grants are safe (M13's
 * unique indexes answer 409), but "safe" is a per-resolver fact this transport
 * cannot see, so it does not guess: the operation's own document says whether
 * it is a `query`, and only those repeat.
 *
 * A refused MUTATION therefore reports `SESSION_RENEWED`, not the original
 * UNAUTHENTICATED — the session really was renewed, nothing was performed, and
 * the next attempt will work. Rendering "your session has ended" there would
 * be the false sentence this PR exists to delete, one case over.
 *
 * The retry's own answer is returned as-is, whatever it says: a second
 * UNAUTHENTICATED means the session died between refresh and retry, and
 * looping would hammer a dead credential.
 */
export async function gqlRequest<Name extends OperationName>(
  operation: Name,
  variables: OperationSignatures[Name]['variables'],
): Promise<GqlResult<OperationSignatures[Name]['data']>> {
  const result = await performRequest(operation, variables);
  if (result.ok && !isQuery(operation)) {
    // A mutation SUCCEEDED, so some cached read may now be describing the
    // world it just changed. Announced from the one place every mutation
    // passes through, so no ceremony call site is trusted to remember it —
    // the §6v banner residual was exactly that forgotten call. Queries never
    // announce (a read changes nothing), and a refused mutation announces
    // nothing either: SESSION_RENEWED means it was never performed.
    notifyOperationSuccess(operation);
  }
  return result;
}

async function performRequest<Name extends OperationName>(
  operation: Name,
  variables: OperationSignatures[Name]['variables'],
): Promise<GqlResult<OperationSignatures[Name]['data']>> {
  const first = await send(operation, variables);
  if (first.ok || first.code !== 'UNAUTHENTICATED' || operation === 'Refresh') {
    // The Refresh guard is THE recursion control: refreshSession itself calls
    // gqlRequest('Refresh'), and without this short-circuit a refused refresh
    // would try to refresh in order to refresh.
    return first;
  }
  const refreshed = await refreshSession();
  if (refreshed.status === 'refused') {
    // Genuinely signed out. The original UNAUTHENTICATED is the honest answer
    // and the surfaces already render it as "your session has ended".
    return first;
  }
  if (refreshed.status === 'unavailable') {
    // The refresh could not be COMPLETED, so nothing is known about the
    // session — reporting UNAUTHENTICATED here would tell a user with a live
    // 30-day credential that they had been signed out, during an outage, on
    // cookies the BFF deliberately left in place.
    return { ok: false, code: refreshed.code };
  }
  if (!isQuery(operation)) {
    return { ok: false, code: 'SESSION_RENEWED' };
  }
  return send(operation, variables);
}

/**
 * Read off the operation's OWN document, never a hand-kept list: a list of
 * retry-safe operations is a list that goes stale the day someone adds the
 * fifty-seventh mutation. Every document in `operations` begins with `query`
 * or `mutation` (asserted in `operation-consumers.test.ts`), so the
 * classification is total and cannot silently default a mutation into the
 * retried set.
 */
function isQuery(operation: OperationName): boolean {
  return operations[operation].trimStart().startsWith('query ');
}
