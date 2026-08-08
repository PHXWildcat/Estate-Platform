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
  /** The document moved on between read and write. Reload, then retry (M12). */
  'VERSION_CONFLICT',
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
] as const;

/** Error codes the BFF contract defines. */
export type GqlErrorCode = (typeof GQL_ERROR_CODES)[number];

/** Every way a request can fail, as seen by the UI. */
export type GqlFailureCode = GqlErrorCode | 'NETWORK' | 'UNKNOWN';

export type GqlResult<T> = { ok: true; data: T } | { ok: false; code: GqlFailureCode };

export type MfaLevel = 'none' | 'mfa' | 'stepup';

export interface SessionInfo {
  userId: string;
  mfaLevel: MfaLevel;
  stepUpFresh: boolean;
}

export interface AssetInfo {
  assetId: string;
  category: string;
  title: string;
  /** Decimal string — money is never a Float. */
  estValue: string | null;
  ownershipPct: number;
  inTrust: boolean;
  version: string;
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

interface OperationSignatures {
  Register: {
    variables: { email: string; password: string };
    data: { register: { ok: boolean } };
  };
  Login: {
    variables: { email: string; password: string };
    data: { login: { ok: boolean } };
  };
  Refresh: { variables: EmptyVariables; data: { refresh: { ok: boolean } } };
  TotpEnroll: { variables: EmptyVariables; data: { totpEnroll: { otpauthUri: string } } };
  TotpVerify: { variables: { code: string }; data: { totpVerify: { ok: boolean } } };
  StepUp: { variables: { code: string }; data: { stepUp: { ok: boolean } } };
  StartVaultHandoff: {
    variables: EmptyVariables;
    data: { startVaultHandoff: { code: string; expiresAt: string; vaultOrigin: string } };
  };
  ExportDemo: { variables: EmptyVariables; data: { exportDemo: { ok: boolean } } };
  Session: { variables: EmptyVariables; data: { session: SessionInfo } };
  Logout: { variables: EmptyVariables; data: { logout: { ok: boolean } } };
  Assets: { variables: EmptyVariables; data: { assets: AssetInfo[] } };
  NetWorth: { variables: EmptyVariables; data: { netWorth: NetWorthInfo } };
  CreateAsset: {
    variables: {
      category: string;
      title: string;
      /** All three together, or none: the ledger refuses a partial valuation. */
      estValue?: string;
      valuationAsOf?: string;
      valuationSource?: string;
    };
    data: { createAsset: { assetId: string; version: string } };
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
    data: { emailVerification: 'VERIFIED' | 'UNVERIFIED' | 'UNAVAILABLE' };
  };
  ResendEmailVerification: {
    variables: EmptyVariables;
    data: {
      resendEmailVerification: 'SENT' | 'TOO_SOON' | 'ALREADY_VERIFIED' | 'UNAVAILABLE';
    };
  };
  VerifyEmail: { variables: { code: string }; data: { verifyEmail: { ok: boolean } } };
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
 * Sends one persisted GraphQL operation to the same-origin `/graphql` endpoint.
 * Resolves to a discriminated result; never throws on server or network
 * failure and never exposes server-provided message text.
 */
export async function gqlRequest<Name extends OperationName>(
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
