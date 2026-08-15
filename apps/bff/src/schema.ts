import type { IncomingMessage, ServerResponse } from 'node:http';
import type { GraphQLSchema } from 'graphql';
import { createSchema } from 'graphql-yoga';
import type { MfaLevel, SessionAudience } from '@estate/contracts';
import type {
  Asset,
  AssetDetail,
  AssetsClient,
  Beneficiaries,
  CommandAck,
  HistoryEntry,
  NetWorth,
} from './assets-client';
import type {
  AnalysisName,
  AnalysisView,
  AssistantClient,
  Conversation,
  Transcript,
  Turn,
} from './assistant-client';
import type {
  Document,
  DocumentContent,
  DocumentDetail,
  DocumentTemplate,
  DocumentVersion,
  DocumentsClient,
  GenerateResult,
  IntakeValue,
  UploadResult,
} from './documents-client';
import type {
  ContactDetail,
  ContactInput,
  ContactSummary,
  FamilyMember,
  LinkInvitation,
  FamilyMemberInput,
  PermissionGrant,
  Profile,
  ProfileClient,
  RoleAssignment,
  SaveProfileInput,
} from './profile-client';
import {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  clearSessionCookies,
  parseCookies,
  setSessionCookies,
} from './cookies';
import { bffError, type IdentityClient } from './identity-client';

/**
 * Auth slice of the BFF schema (Milestone 1). Deliberately small: login and
 * refresh return ONLY `{ ok }` — tokens live exclusively in httpOnly cookies
 * (see cookies.ts). `sessionId` is intentionally not exposed to the client.
 */
export const typeDefs = /* GraphQL */ `
  enum MfaLevel {
    NONE
    MFA
    STEPUP
  }

  """
  What a session may be spent on. ACCOUNT is an ordinary sign-in; VAULT is the
  isolated vault origin's short-lived session; EXTENSION is a paired browser
  extension.
  """
  enum SessionAudience {
    ACCOUNT
    VAULT
    EXTENSION
  }

  type Session {
    userId: ID!
    mfaLevel: MfaLevel!
    "True while the session's step-up window (fresh ≤5 min) is open."
    stepUpFresh: Boolean!
    "What this session may be spent on."
    audience: SessionAudience!
  }

  type Ok {
    ok: Boolean!
  }

  type TotpEnroll {
    otpauthUri: String!
  }

  """
  The LIST shape. It deliberately has NO costBasis/location/notes fields —
  the service's list decrypts exactly est_value (one audited decrypt per
  row), and a field the list cannot carry must be unrequestable rather than
  null (null would conflate "not carried" with "not set"). Detail fields
  live on AssetDetail.
  """
  type Asset {
    assetId: ID!
    category: String!
    title: String!
    "Decimal string — money is never a Float."
    estValue: String
    valuationAsOf: String
    valuationSource: String
    ownershipPct: Float!
    inTrust: Boolean!
    fundingStatus: String
    "live | retired — a retired asset is a record of a disposal, not a deletion."
    status: String!
    retiredAt: String
    "Optimistic-concurrency token: pass back as expectedVersion on mutations."
    version: String!
  }

  "The full record, served by the asset detail query (four audited decrypts)."
  type AssetDetail {
    assetId: ID!
    category: String!
    title: String!
    estValue: String
    valuationAsOf: String
    valuationSource: String
    ownershipPct: Float!
    costBasis: String
    location: String
    notes: String
    inTrust: Boolean!
    fundingStatus: String
    status: String!
    retiredAt: String
    version: String!
  }

  """
  One ledger event. The payload is the assets service's own validated event
  body (an OUTPUT of data it already parsed — the readiness JSON precedent);
  the client renders known keys defensively and never treats it as input.
  """
  type AssetHistoryEntry {
    version: String!
    eventId: ID!
    eventType: String!
    occurredAt: String!
    payload: JSON!
  }

  """
  One beneficiary designation. The name is composed from the caller's own
  contacts on their own bearer; NULL means the contact is no longer on file —
  a fact worth showing, never hiding, and the designation stays removable.
  """
  type AssetBeneficiary {
    contactId: ID!
    name: String
    designation: String!
    sharePct: Float!
  }

  type DesignationTotal {
    designation: String!
    sharePct: Float!
    designationComplete: Boolean!
  }

  type AssetBeneficiaries {
    assetId: ID!
    beneficiaries: [AssetBeneficiary!]!
    totals: [DesignationTotal!]!
  }

  type NetWorth {
    "Decimal string: Σ estValue × ownership%, over assets with a known value."
    totalValue: String!
    assetCount: Int!
    valuedAssetCount: Int!
    inTrustValue: String!
  }

  """
  Every asset command's acknowledgement. replayed=true means the command was
  an idempotent retry (same clientEventId) answered with the ORIGINAL ack.
  """
  type AssetCommandAck {
    assetId: ID!
    eventId: ID!
    version: String!
    occurredAt: String!
    replayed: Boolean!
  }

  """
  Records an asset. A valuation is all-or-nothing: estValue, valuationAsOf
  and valuationSource together, or none. clientEventId is the idempotency
  key — mint it in the browser and hold it across retries of the SAME
  payload, so a resend after a lost response is a no-op.
  """
  input CreateAssetInput {
    category: String!
    title: String!
    ownershipPct: Float
    inTrust: Boolean
    fundingStatus: String
    estValue: String
    valuationAsOf: String
    valuationSource: String
    costBasis: String
    location: String
    notes: String
    clientEventId: ID
  }

  """
  Why an analysis has a STATUS rather than throwing. The readiness page asks
  for all four at once, so one unavailable analysis must not blank the other
  three. Four values where the service has three: DISABLED is the master
  consent switch being off, which is the one the user can act on.
  """
  enum AnalysisStatus {
    OK
    UNAVAILABLE
    REFUSED
    DISABLED
  }

  type FindingSubject {
    "asset | document | estate."
    kind: String!
    "The owning service's row id, or null for an estate-level finding."
    ref: ID
    "User-authored title, or null. Rendered as data, never as instructions."
    label: String
  }

  """
  One deterministic finding. 'code' is a closed token the UI turns into a
  sentence — the analyser computes, and no model is involved on this path.
  """
  type Finding {
    code: String!
    "high | medium | info."
    severity: String!
    subject: FindingSubject!
    "Numbers behind the code: counts, enum tokens, money as decimal STRINGS."
    detail: JSON!
  }

  type Analysis {
    status: AnalysisStatus!
    "Enum token when the analysis did not run ('reference_unreviewed'); never prose."
    reason: String
    "Empty for every status but OK — a failure is never an empty result."
    findings: [Finding!]!
    "docs/01 §2.8's non-legal-advice watermark. Present on every status."
    disclaimer: String!
  }

  type Readiness {
    funding: Analysis!
    missingDocuments: Analysis!
    beneficiaryConflicts: Analysis!
    estateTax: Analysis!
  }

  "Opaque JSON for a finding's detail map (scalars only, validated upstream)."
  scalar JSON

  type Conversation {
    conversationId: ID!
    createdAt: String!
    updatedAt: String!
  }

  """
  One message. 'text' is MODEL-AUTHORED on the assistant side and is UNTRUSTED
  MARKUP: the web app renders it through MessageText, which builds text nodes
  and nothing else, so a model-emitted image or link is characters on a screen
  rather than a request (docs/03 §6d).
  """
  type TranscriptMessage {
    messageId: ID!
    seq: Int!
    "user | assistant."
    role: String!
    text: String!
    createdAt: String!
  }

  type Transcript {
    conversationId: ID!
    messages: [TranscriptMessage!]!
  }

  type Turn {
    conversationId: ID!
    messageId: ID!
    text: String!
    "How many read-only retrievals the assistant made while composing this."
    toolCalls: Int!
  }

  """
  One declared intake variable of a template. The web app builds its
  questionnaire from these — the template is the authority on what a
  state-specific instrument asks for, never the client.
  """
  type TemplateVariable {
    name: String!
    "text | boolean | date | enum."
    kind: String!
    label: String
    required: Boolean!
    "Text variables only: the template's own cap on the value's length."
    maxLength: Int
    "Enum variables only."
    options: [String!]
  }

  "Per-state formalities (docs/02 §4). The execution ladder is built from these."
  type ExecutionRequirements {
    witnesses: Int!
    notarization: Boolean!
    selfProvingAffidavit: Boolean!
  }

  """
  A published, attorney-signed-off template. PRODUCT CONTENT, not user data:
  the service serves the catalog to any authenticated caller and there is no
  mutation surface anywhere — templates publish from in-repo sources by CLI, so
  git review IS the sign-off gate.
  """
  type DocumentTemplate {
    templateId: ID!
    docType: String!
    state: String!
    version: Int!
    legalReviewAt: String!
    executionRequirements: ExecutionRequirements!
    variables: [TemplateVariable!]!
  }

  """
  Document METADATA. 'title' is the one plaintext user-authored label in the
  documents cluster (accepted low-sensitivity metadata, the assets_view.title
  precedent); everything else with content in it lives inside the encrypted
  blob and arrives only through documentContent, one deliberate read at a time.
  """
  type Document {
    documentId: ID!
    docType: String!
    "generated | uploaded."
    source: String!
    title: String!
    currentVersion: Int!
    executionStatus: String!
    "ISO date, present only once 'executed' has been attested."
    executedAt: String
    "Set by settlement when an estate is frozen. Blocks deletion."
    legalHold: Boolean!
    "The owner moved it to Zone A — the server can no longer read it."
    sealed: Boolean!
    templateId: ID
    createdAt: String!
    updatedAt: String!
  }

  """
  One document plus the execution transitions IT may take next — computed by
  the service from the template's own sha256-verified execution_requirements,
  so a client renders the attestations this instrument in this state actually
  requires rather than a hardcoded ladder. An EMPTY list is the service's
  fail-closed answer when it cannot resolve the ladder from a verified
  template, not an error.
  """
  type DocumentDetail {
    documentId: ID!
    docType: String!
    source: String!
    title: String!
    currentVersion: Int!
    executionStatus: String!
    executedAt: String
    legalHold: Boolean!
    sealed: Boolean!
    templateId: ID
    createdAt: String!
    updatedAt: String!
    allowedTransitions: [String!]!
  }

  type UploadedDocument {
    documentId: ID!
    version: Int!
    contentSha256: String!
    executionStatus: String!
    "Whether OCR text made it into the encrypted index. Best-effort, never a gate."
    ocrIndexed: Boolean!
  }

  type DocumentVersion {
    version: Int!
    contentSha256: String!
    sizeBytes: Int!
    mime: String!
    createdAt: String!
  }

  """
  One version's decrypted content. FETCHING THIS IS AN AUDITED DECRYPT
  downstream, so it is never batched into a list query and never prefetched:
  one user action is meant to produce exactly one such event.

  'encoding' is utf8 for canonical HTML (generated instruments) and base64 for
  binary uploads. The HTML case is rendered inside a sandboxed iframe and never
  as app-origin markup — document content is untrusted input (docs/03 risk #6).
  """
  type DocumentContent {
    documentId: ID!
    version: Int!
    mime: String!
    contentSha256: String!
    "utf8 | base64."
    encoding: String!
    content: String!
  }

  type GeneratedDocument {
    documentId: ID!
    version: Int!
    contentSha256: String!
    executionStatus: String!
  }

  """
  One intake answer. Exactly one of 'text' and 'boolean' must be supplied — a
  variable with neither, or both, is refused before anything downstream sees it.

  This is a TYPED input rather than the JSON scalar the readiness surface uses
  for finding detail. That scalar is an OUTPUT of data the service already
  validated; putting an untyped shape on the one mutation that reaches a legal
  instrument's renderer would be the opposite trade.
  """
  input DocumentVariableInput {
    name: String!
    text: String
    boolean: Boolean
  }

  """
  The caller's own profile.

  'ssnLast4' is the ONLY SSN-shaped value that crosses this boundary, and it is
  read-only everywhere: the service derives it from the full value and there is
  no mutation on this schema that can write an SSN at all. M13's decision is to
  display whether one is on file and never to collect one — nothing shipped
  reads the full value, and an SSN input on a web surface is a phishing
  template.
  """
  type Profile {
    userId: ID!
    legalName: String!
    dob: String
    "Last four digits only. There is no field, anywhere, for the whole number."
    ssnLast4: String
    address: String
    phone: String
    occupation: String
    maritalStatus: String
    "Two-letter code. Drives document template selection."
    stateOfResidence: String
  }

  "A household member: who is in the family, and whether a child is still a minor."
  type FamilyMember {
    id: ID!
    "spouse | child | parent | sibling | other."
    relation: String!
    name: String!
    dob: String
    "Null when the date of birth is unknown, so minority is unknown too."
    isMinor: Boolean
    notes: String
  }

  """
  A contact as a LIST returns it: one audited decrypt per row, not five.

  The 'has' flags come from column nullity downstream, so a list can say what is
  on file without decrypting it. There is deliberately no email, phone, address
  or notes field here — those arrive only from 'contact(contactId:)', one
  explicit read at a time, because each is an audited decrypt on the owner's own
  trail and a list that fetched them would turn one page load into dozens
  (docs/03 §6f, and §4 TB4's per-principal decrypt-rate baseline).
  """
  type ContactSummary {
    id: ID!
    name: String!
    relationship: String
    "attorney | cpa | financial_advisor | doctor | other."
    professionalKind: String
    hasEmail: Boolean!
    hasPhone: Boolean!
    hasAddress: Boolean!
    hasNotes: Boolean!
    """
    Whether this person has a platform account. Without a link a designation
    still records the owner's intent but nobody can exercise it — no role-holder
    read, no executor resolution, no death report — so a surface that hid this
    would show designations that silently do nothing.
    """
    linked: Boolean!
  }

  "One contact, decrypted in full. Every field here cost an audited decrypt."
  type ContactDetail {
    id: ID!
    name: String!
    email: String
    phone: String
    address: String
    relationship: String
    professionalKind: String
    notes: String
  }

  """
  Who is trustee/executor/beneficiary/guardian/agent of what.

  'effectiveCondition' is load-bearing and must never be rendered as access:
  'immediate' means the holder can act now (if a permission grant says so),
  while 'on_incapacity' and 'on_death_verified' are DESIGNATIONS that confer
  nothing at all until settlement resolves them. Designation alone grants
  nothing (M7).
  """
  type RoleAssignment {
    id: ID!
    contactId: ID!
    role: String!
    "estate | trust | document | asset | account."
    scopeType: String!
    "Null means the whole estate."
    scopeId: ID
    "immediate | on_incapacity | on_death_verified."
    effectiveCondition: String!
    startsAt: String
    endsAt: String
  }

  """
  A minted link invitation.

  'code' is the ONLY time this value exists outside the owner's own head: the
  service keeps its sha256 and cannot re-show it. A client that loses it must
  mint another, which retires this one.
  """
  type LinkInvitation {
    code: String!
    expiresAt: String!
  }

  "One live permission grant attached to a role assignment."
  type PermissionGrant {
    id: ID!
    resource: String!
    "read | download | manage."
    action: String!
    createdAt: String!
  }

  """
  Whether the platform can PROVE it reaches the caller (M14).

  THREE states, not a boolean, because UNAVAILABLE is a fact about the
  platform rather than about the user: telling somebody their address is
  unverified during a notifications outage would send them to complete a
  ceremony that cannot run, and saying nothing would leave the arming gates
  refusing with no explanation.
  """
  enum EmailVerificationStatus {
    VERIFIED
    UNVERIFIED
    UNAVAILABLE
  }

  """
  What a resend attempt actually did. Reported honestly rather than always
  claiming a send: TOO_SOON is the re-issue floor, which is the only rate
  limit on this path and would otherwise look like a silent failure.
  """
  enum ResendVerificationOutcome {
    SENT
    TOO_SOON
    ALREADY_VERIFIED
    UNAVAILABLE
  }

  type Query {
    "Current session, or null when unauthenticated."
    session: Session
    """
    Whether the caller has proved they receive mail at the address on file.

    A DEDICATED query, deliberately not a field on the session query: that resolver
    backs every authenticated request in the app, and identity's own session
    route is the cross-service introspection hot path. Putting a notifications
    round trip on either would make a settings-page question cost something on
    every call in the product.
    """
    emailVerification: EmailVerificationStatus!
    """
    Every live credential on the caller's account (M16) — the paired-devices
    surface. The first read of its kind in the product: until an extension
    credential could outlive the browser, a session was a cookie and there was
    nothing to list.
    """
    sessions: [UserSession!]!
    """
    The caller's passkeys (M17 PR5). Its own query, deliberately not a field on
    session: that resolver backs every authenticated request (the M14 PR3
    rule), and a factor inventory is a settings-page question.
    """
    passkeys: [Passkey!]!
    "The caller's assets. The BFF forwards the caller's own bearer token."
    assets(includeRetired: Boolean): [Asset!]!
    "One asset's full record — retired assets stay readable (M19 PR2)."
    asset(assetId: ID!): AssetDetail!
    """
    The asset's full ledger history, oldest first. Requested EXPLICITLY and
    never prefetched: the service decrypts one payload per event, each an
    audited crypto.field.decrypted (the M18 decrypt budget).
    """
    assetHistory(assetId: ID!): [AssetHistoryEntry!]!
    """
    Beneficiary designations with contact names composed in. Names are
    resolved from the caller's own contacts ONLY when designations exist —
    a zero-designation asset costs zero contact decrypts.
    """
    assetBeneficiaries(assetId: ID!): AssetBeneficiaries!
    netWorth: NetWorth!
    """
    The four deterministic analyses, computed by the assistant service from the
    caller's own estate. No model provider is involved on this path: the
    analysers compute, and consent scopes gate egress rather than this read.
    """
    readiness: Readiness!
    "Consent scopes the caller has granted the assistant. Absence is denial."
    consents: [String!]!
    "The caller's own conversations."
    conversations: [Conversation!]!
    """
    One decrypted transcript. A conversation that does not exist and one
    belonging to somebody else answer identically — the service's uniform
    not-found, kept uniform here so an id cannot be probed.
    """
    conversation(conversationId: ID!): Transcript!
    "The published templates for one state. Product content, not user data."
    documentTemplates(state: String!): [DocumentTemplate!]!
    "The caller's own documents — metadata only, no content is decrypted."
    documents: [Document!]!
    document(documentId: ID!): DocumentDetail!
    """
    Encrypted search over the caller's own documents. The query becomes
    per-user HMAC tokens downstream and matches ciphertext-side, so NOTHING is
    decrypted to serve it — which is also why there is no decrypt audit event
    on this path. Minimum 3 characters (the service's own bound).
    """
    documentSearch(query: String!): [Document!]!
    documentVersions(documentId: ID!): [DocumentVersion!]!
    """
    One version's content. Each call is an audited decrypt downstream, so ask
    for it only when someone has asked to read that exact version.
    """
    documentContent(documentId: ID!, version: Int!): DocumentContent!
    """
    The caller's own profile, or NULL when they have never saved one. Null is a
    real answer — "nothing on file" — and distinct from an error, which is what
    lets the household surface invite a first save instead of showing a failure.
    """
    profile: Profile
    "The caller's household members."
    familyMembers: [FamilyMember!]!
    "The caller's estate contacts — summaries only, one decrypt per row."
    contacts: [ContactSummary!]!
    """
    One contact in full. Each call is several audited decrypts downstream, so ask
    only when someone has opened that exact person.
    """
    contact(contactId: ID!): ContactDetail!
    "The caller's role assignments. Contact names come from 'contacts'."
    roleAssignments: [RoleAssignment!]!
    "The live permission grants on one of the caller's role assignments."
    rolePermissions(roleAssignmentId: ID!): [PermissionGrant!]!
  }

  """
  What the app needs to hand a user to the vault origin (M15).

  'vaultOrigin' comes from the BFF's configuration at REQUEST time rather than
  from the web bundle, because Next bakes build-time values into its routes
  manifest and the M8 PR5 review found exactly that shipping a wrong one.
  """
  type VaultHandoff {
    code: String!
    expiresAt: String!
    vaultOrigin: String!
  }

  "One live credential on this account (M16). The current one is the session you are using."
  type UserSession {
    sessionId: ID!
    audience: SessionAudience!
    createdAt: String!
    expiresAt: String!
    current: Boolean!
  }

  type Passkey {
    id: ID!
    nickname: String
    isHardwareKey: Boolean!
    createdAt: String!
    lastUsedAt: String
  }

  "What a successful step-up reports: when the elevation lapses."
  type StepUpOutcome {
    stepupExpiresAt: String!
  }

  """
  A single-use code the user types into the browser extension. Returned in the
  body and never placed in a URL, so it cannot land in history, a Referer, or an
  intermediary's log. Ten minutes, single use, burned on the attempt.
  """
  type ExtensionPairing {
    code: String!
    expiresAt: String!
  }

  type Mutation {
    register(email: String!, password: String!): Ok!
    "Sets httpOnly session cookies; no token material in the response body."
    login(email: String!, password: String!): Ok!
    "Rotates the token pair using the refresh cookie; re-sets both cookies."
    refresh: Ok!
    "Revokes THIS session server-side, then expires both cookies."
    logout: Ok!
    totpEnroll: TotpEnroll!
    totpVerify(code: String!): Ok!
    stepUp(code: String!): Ok!
    """
    Mint a single-use code for the ISOLATED VAULT ORIGIN (M15, docs/03 TB6).

    Step-up gated at identity. The code is returned in the response BODY so the
    app can put it in a hidden field and submit a top-level POST to
    'vaultOrigin' — it must never reach a URL, a Referer or a history entry.
    Sixty seconds, single use, burned on the attempt.
    """
    startVaultHandoff: VaultHandoff!
    """
    Mint a pairing code for the browser extension. Step-up gated at identity and
    account-audience only: a non-account session cannot mint one, or a
    short-lived credential could chain itself into a long-lived one.
    """
    startExtensionPairing: ExtensionPairing!
    """
    Revoke one of your own sessions. NOT step-up gated — minting a credential is
    the gated action and taking one away can only reduce authority, so the
    protective action stays one click (the M6 rule). Answers NOT_FOUND for an
    unknown id and for someone else's alike, because identity's own answer is
    uniform and the edge adds no distinction of its own.
    """
    revokeSession(sessionId: ID!): Ok!
    "Step-up-gated demo action (stands in for data export)."
    exportDemo: Ok!
    """
    Passkey registration, step 1 (M17 PR5): mint a challenge and return the
    browser's creation options.

    THE CEREMONY PAYLOADS CROSS AS JSON, and this is a recorded second use of
    the scalar, not an erosion of the M12 rule beside createDocument. That rule
    exists because the BFF REFUSES things there — a duplicate variable, a
    both-or-neither pair — so an untyped shape would bypass refusals this edge
    owns. Here the edge owns NONE: attestation semantics belong to identity's
    WebAuthn library, identity re-validates shape and substance before any
    effect, and a second validator here would be the PR3 wire-drift class (two
    declarations of one wire, free to disagree, the disagreement invisible
    until production). Opaque pass-through whose sole validator is downstream
    is the mirror image of the readiness surface's validated OUTPUT.
    """
    webauthnRegisterOptions: JSON!
    "Passkey registration, step 2: forward the attestation; identity verifies and binds."
    webauthnRegister(response: JSON!): Ok!
    "Passkey step-up, step 1: mint an assertion challenge."
    webauthnStepUpOptions: JSON!
    """
    Passkey step-up, step 2: verify the assertion. On success the session is
    elevated exactly as a TOTP step-up elevates it — same window, same
    freshness predicate downstream.
    """
    webauthnStepUp(response: JSON!): StepUpOutcome!
    """
    Revoke one passkey. STEP-UP GATED at identity — the one factor-WEAKENING
    verb in the product, deliberately unlike the ungated session revoke: a
    removed session only reduces authority, while a removed factor disarms the
    gate that protects everything else (an ungated revoke plus a stolen bearer
    is the factor-strip downgrade into the 2026-08-12 escalation). NOT_FOUND
    for unknown and not-yours alike.
    """
    revokePasskey(id: ID!): Ok!
    "Label one passkey (display metadata; session-only)."
    renamePasskey(id: ID!, nickname: String!): Ok!
    """
    Mail another address-verification code to the address already on file.

    NOT step-up gated: it grants nothing, and the strongest thing a caller
    achieves is receiving their own mail. The re-issue floor in identity is the
    rate limit, and its outcome is returned rather than hidden.
    """
    resendEmailVerification: ResendVerificationOutcome!
    """
    Redeem a mailed verification code. The code is the ONLY selector — there is
    no user id on this mutation — and every refusal is one uniform error.
    """
    verifyEmail(code: String!): Ok!
    """
    Change the account password (M20 PR1).

    BOTH halves are required and each covers what the other cannot: the current
    password is the one thing a stolen SESSION does not carry, and the fresh
    factor is the one thing a stolen PASSWORD does not carry. Step-up is
    CONDITIONAL — identity refuses only when the account already holds a
    verified factor, so an account with no factor is let through rather than
    having its password made unchangeable forever.

    This is NOT the vault password. Zone A derives its master key from the vault
    password and the Secret Key, never from this one, so changing this leaves
    every vault item exactly as it was.

    On success identity revokes every OTHER live session and leaves the
    caller's own alive.
    """
    changePassword(currentPassword: String!, newPassword: String!): Ok!
    """
    Stage a change of the account's sign-in address (M20 PR2).

    VERIFY-THEN-SWITCH: nothing on file moves until a code mailed to the NEW
    address comes back. Login resolves accounts by their address, so storing an
    unproven one would lock its owner out of signing in; the old address, and
    every notification, keeps working until the proof lands.

    THE RESULT IS NOT A DELIVERY RECEIPT. Identity answers before it sends, and
    an address that already belongs to another account gets exactly the same
    answer and is never mailed — the caller learns nothing about who holds an
    address. Copy built on this must stay conditional.

    Step-up is CONDITIONAL, on the same gate as changePassword.
    """
    requestEmailChange(currentPassword: String!, newEmail: String!): Ok!
    """
    Finish an address change with the code mailed to the new address (M20 PR2).

    One refusal covers every way a code can fail — unknown, expired, already
    used, too many attempts, or the address having been taken during the
    ceremony. That uniformity is the control, so this does not distinguish them.

    On success the new address is live and already confirmed, and every OTHER
    session is signed out.
    """
    completeEmailChange(code: String!): Ok!
    """
    Abandon a staged address change (M20 PR2). Idempotent — it succeeds whether
    or not anything was pending — and deliberately needs no step-up: the
    protective action must never be harder than the permissive one.
    """
    cancelEmailChange: Ok!
    """
    Records an asset (full input — M19 PR2). A valuation is all-or-nothing:
    supply estValue, valuationAsOf and valuationSource together, or none —
    an amount with no date and no provenance is not an auditable claim.
    """
    createAsset(input: CreateAssetInput!): AssetCommandAck!
    """
    Edits an asset's details. ABSENT means unchanged; explicit NULL clears
    (location, notes, fundingStatus). expectedVersion is the version the
    caller last read — a stale one answers VERSION_CONFLICT, and the remedy
    is re-read, never blind retry.
    """
    updateAsset(
      assetId: ID!
      expectedVersion: String!
      title: String
      location: String
      notes: String
      inTrust: Boolean
      fundingStatus: String
      clientEventId: ID
    ): AssetCommandAck!
    "Appends a valuation (the all-or-nothing triple, all three required here)."
    recordValuation(
      assetId: ID!
      expectedVersion: String!
      estValue: String!
      valuationAsOf: String!
      valuationSource: String!
      clientEventId: ID
    ): AssetCommandAck!
    "Changes the ownership share; costBasis NULL clears it."
    changeOwnership(
      assetId: ID!
      expectedVersion: String!
      ownershipPct: Float!
      costBasis: String
      clientEventId: ID
    ): AssetCommandAck!
    """
    Retires an asset — records a disposal (sold, gifted, lost…). The record
    and its full history remain readable; further changes are refused.
    """
    retireAsset(
      assetId: ID!
      expectedVersion: String!
      reason: String
      clientEventId: ID
    ): AssetCommandAck!
    """
    Designates a beneficiary on one asset. STEP-UP GATED downstream
    (docs/01 §5: beneficiary changes). The contact must be one of the
    CALLER'S OWN — the BFF is the only layer that sees both the financial
    cluster's designation and the core cluster's contact, so the membership
    check lives here; the service accepts a UUID by design (docs/02 §8, no
    cross-cluster FK). Naming someone grants them NOTHING — a designation is
    not access, and beneficiary visibility does not exist yet.
    """
    designateBeneficiary(
      assetId: ID!
      expectedVersion: String!
      contactId: ID!
      designation: String!
      sharePct: Float!
      clientEventId: ID
    ): AssetCommandAck!
    """
    Removes a designation. Equally step-up gated (the profile role-removal
    precedent: equal, never harder). Deliberately NO membership check —
    removing a designation whose contact is no longer on file must work.
    """
    removeBeneficiary(
      assetId: ID!
      expectedVersion: String!
      contactId: ID!
      designation: String!
      clientEventId: ID
    ): AssetCommandAck!
    """
    Grants one assistant consent scope. STEP-UP GATED downstream (docs/01 §5:
    a grant widens what may reach a third-party model provider, which is
    export-class), so this can fail with STEPUP_REQUIRED. Returns the caller's
    full grant set so a client never has to guess the result.
    """
    grantConsent(scope: String!): [String!]!
    """
    Revokes one scope. Deliberately NOT step-up gated, the M6
    emergency-access-denial rule: the protective action must never be harder
    than the permissive one.
    """
    revokeConsent(scope: String!): [String!]!
    startConversation: Conversation!
    """
    Take one turn. Slow by nature — it waits on a real provider round trip —
    and refused outright when the assistant.enabled master switch is off, so a
    client should ask for consents before offering a composer.
    """
    sendMessage(conversationId: ID!, text: String!): Turn!
    "Soft delete downstream: the ciphertext survives, erasure is a separate act."
    deleteConversation(conversationId: ID!): Ok!
    """
    Generates a state-specific instrument from a reviewed template. STEP-UP
    GATED downstream (docs/01 §5 names document generation explicitly), so this
    can fail with STEPUP_REQUIRED — the client is expected to collect a code and
    retry the same call.
    """
    generateDocument(
      docType: String!
      state: String!
      templateId: ID
      title: String
      variables: [DocumentVariableInput!]!
    ): GeneratedDocument!
    """
    Re-renders a document as its next version. Equally step-up gated, and
    refused with DOCUMENT_NOT_EDITABLE once signing has started: a signed
    instrument's content is a legal record, so the way forward is to revoke or
    supersede it rather than rewrite it under the signatures.
    """
    regenerateDocument(
      documentId: ID!
      templateId: ID
      title: String
      variables: [DocumentVariableInput!]!
    ): GeneratedDocument!
    """
    Uploads a document. NOT step-up gated (docs/01 §5 covers generation, export
    and deletion; adding content is not on that list) — the gate is the
    service's pipeline: size cap, magic-byte sniff against the declared mime,
    and a FAIL-CLOSED malware scan, with nothing written anywhere unless all
    three pass. So MALWARE_DETECTED, UNSUPPORTED_CONTENT and SCAN_UNAVAILABLE
    all mean the same thing about storage — nothing was stored — and are kept
    apart because they mean different things to the person holding the file.

    'mime' is what the client CLAIMS. The service sniffs the bytes and decides;
    a mismatch is refused.
    """
    uploadDocument(
      kind: String!
      title: String!
      mime: String!
      contentBase64: String!
    ): UploadedDocument!
    """
    Attests one rung of the execution ladder. The platform RECORDS a real-world
    act; it does not witness one. 'executedAt' accompanies exactly the
    'executed' attestation, and the service refuses a skipped formality against
    the template's own requirements.
    """
    setDocumentStatus(documentId: ID!, status: String!, executedAt: String): DocumentDetail!
    """
    Soft delete: the row and its version history survive, and erasure is a
    separate act. STEP-UP GATED downstream (docs/01 §5), and refused outright
    with LEGAL_HOLD while the estate is preserved for a settlement matter —
    the one refusal here that authenticating harder cannot resolve.
    """
    deleteDocument(documentId: ID!): Ok!
    """
    Saves the caller's profile. A MERGE, not a replace: an omitted argument
    leaves that field as it was and an explicit null clears it, which is what
    lets a form that holds six fields write six fields.

    NOTE WHAT IS ABSENT: there is no 'ssn' argument. Nothing reachable from a
    browser can set or clear the full number — see the Profile type.
    """
    saveProfile(
      legalName: String!
      dob: String
      address: String
      phone: String
      occupation: String
      maritalStatus: String
      stateOfResidence: String
    ): Profile!
    """
    EVERY MUTATION BELOW RETURNS WHAT THE SURFACE MUST RE-RENDER, AND NOTHING
    MORE. Rendering the server's answer rather than a local guess is the M10
    consent rule (absence is denial, so an optimistic toggle can show a grant
    that was refused); returning no more than that is the decrypt-volume rule,
    since every contact field in a response cost an audited decrypt. So the
    household and role mutations return their list — which is what the panel
    shows, and for roles is free, being all plaintext columns — while a contact
    EDIT returns the one record whose panel the user is looking at.
    """
    addFamilyMember(
      relation: String!
      name: String!
      dob: String
      isMinor: Boolean
      notes: String
    ): [FamilyMember!]!
    "Replaces the member's fields (its read returns all of them, so it can round-trip)."
    updateFamilyMember(
      id: ID!
      relation: String!
      name: String!
      dob: String
      isMinor: Boolean
      notes: String
    ): [FamilyMember!]!
    deleteFamilyMember(id: ID!): [FamilyMember!]!
    addContact(
      name: String!
      email: String
      phone: String
      address: String
      relationship: String
      professionalKind: String
      notes: String
    ): [ContactSummary!]!
    "Replaces the contact's fields. The platform link is untouched by any edit."
    updateContact(
      contactId: ID!
      name: String!
      email: String
      phone: String
      address: String
      relationship: String
      professionalKind: String
      notes: String
    ): ContactDetail!
    """
    Soft delete. Refused with CONTACT_IN_USE while a live role assignment names
    this person: retiring a fiduciary is a separate, step-up-gated act, and it
    must not happen as a side effect of tidying an address book.
    """
    deleteContact(contactId: ID!): [ContactSummary!]!
    """
    Names someone to a role over a scope. STEP-UP GATED downstream (docs/01 §5
    names trustee/executor and beneficiary changes), so this can fail with
    STEPUP_REQUIRED and the client is expected to collect a code and retry.

    A designation is not access: with 'effectiveCondition' other than
    'immediate' nothing is conferred until settlement resolves it, and even
    'immediate' confers nothing without a permission grant.
    """
    grantRole(
      contactId: ID!
      role: String!
      scopeType: String!
      scopeId: ID
      effectiveCondition: String
    ): [RoleAssignment!]!
    """
    Retires a designation. ALSO step-up gated, and that is not a contradiction of
    the rule that protective actions stay easy: revoking here destroys the
    executor-resolution path and can strip the last linked contact able to report
    a death, so it is not purely protective.
    """
    revokeRole(roleAssignmentId: ID!): [RoleAssignment!]!
    """
    Widens what a role-holder may read. STEP-UP GATED downstream.
    Returns the assignment's full live grant set so a client never guesses.
    """
    grantRolePermission(
      roleAssignmentId: ID!
      resource: String!
      action: String!
    ): [PermissionGrant!]!
    """
    Narrows it again. Deliberately NOT step-up gated — the protective action must
    never be harder than the permissive one. Returns the remaining grants.
    """
    revokeRolePermission(roleAssignmentId: ID!, grantId: ID!): [PermissionGrant!]!
    """
    Mint a single-use code that lets one person link their existing account to
    this contact. STEP-UP GATED downstream: a linked contact can open a death
    case against the owner (docs/03 §6b), so handing out the capability is in the
    same class as naming a fiduciary.

    The owner delivers the code out of band — the platform never emails it, and
    nothing here handles an address.
    """
    inviteContactLink(contactId: ID!): LinkInvitation!
    "Withdraw an unredeemed code. No step-up: it only takes capability away."
    revokeContactLinkInvitation(contactId: ID!): Ok!
    "Remove a live link. No step-up, for the same reason."
    unlinkContact(contactId: ID!): Ok!
    """
    Redeem a code, as the person being linked. Takes NO id of any kind — the code
    is the whole request, so there is no parameter in which to name an account
    and therefore no way to learn whether one exists. Every failure is one code.
    """
    redeemContactLink(code: String!): Ok!
  }
`;

/** Server context wired by the express↔yoga integration in app.ts. */
export interface RequestContext {
  req: IncomingMessage;
  res: ServerResponse;
}

export interface SchemaDeps {
  identity: IdentityClient;
  assets: AssetsClient;
  assistant: AssistantClient;
  documents: DocumentsClient;
  profile: ProfileClient;
  /** Adds the Secure attribute to session cookies (production). */
  secureCookies: boolean;
  /**
   * Browser-facing origin of the isolated vault surface (M15). Handed to the
   * client in `startVaultHandoff`; the BFF never calls it and holds no
   * credential for it.
   */
  vaultOrigin: string;
  /** Clock override for tests. */
  now?: () => number;
}

interface UserSessionPayload {
  readonly sessionId: string;
  readonly audience: 'ACCOUNT' | 'VAULT' | 'EXTENSION';
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly current: boolean;
}

interface SessionPayload {
  readonly userId: string;
  readonly mfaLevel: 'NONE' | 'MFA' | 'STEPUP';
  readonly stepUpFresh: boolean;
  readonly audience: 'ACCOUNT' | 'VAULT' | 'EXTENSION';
}

interface CredentialsArgs {
  readonly email: string;
  readonly password: string;
}

interface CodeArgs {
  readonly code: string;
}

interface ScopeArgs {
  readonly scope: string;
}

interface ConversationArgs {
  readonly conversationId: string;
}

interface DocumentArgs {
  readonly documentId: string;
}

interface DocumentVariableInput {
  readonly name: string;
  readonly text?: string | null;
  readonly boolean?: boolean | null;
}

/**
 * Collapse the typed intake list into the record the document service takes.
 *
 * EXACTLY ONE VALUE PER VARIABLE, AND NO DUPLICATE NAMES. Both refusals happen
 * here rather than downstream, and neither is decoration:
 *
 * - A variable carrying neither value, or both, is ambiguous, and the one thing
 *   that must never happen to a will is a silently-chosen answer. The renderer
 *   already fails closed on an unsubstitutable placeholder, but "fails closed
 *   two layers away" is a worse error message than "that answer was malformed".
 * - A duplicate name would resolve by last-write-wins in the record, so the
 *   value the user saw in the form and the value rendered into the instrument
 *   could differ with nothing in between to notice.
 *
 * Names and values are NOT inspected beyond that: what a variable may contain
 * is the TEMPLATE's declaration to enforce, and the service re-validates the
 * whole payload against the resolved template's typed intake schema before a
 * render can happen. Guessing at that here would be a second, drifting copy of
 * a legal gate.
 */
function intakeRecord(inputs: readonly DocumentVariableInput[]): Record<string, IntakeValue> {
  // A NULL-PROTOTYPE object, so every name behaves like every other name.
  // On a plain `{}`, `__proto__` goes through the inherited setter instead of
  // becoming an own property: the duplicate check silently misses it and the
  // answer silently vanishes before `JSON.stringify`. Nothing is exploitable
  // there (no template can declare that name — VARIABLE_NAME requires a
  // lowercase first character — and the value never reaches the wire), but a
  // key whose behaviour differs from its neighbours' is exactly the kind of
  // exception that outlives the reasoning that made it safe.
  const record: Record<string, IntakeValue> = Object.create(null) as Record<string, IntakeValue>;
  for (const input of inputs) {
    const { text, boolean } = input;
    const hasText = typeof text === 'string';
    const hasBoolean = typeof boolean === 'boolean';
    if (hasText === hasBoolean) {
      throw bffError('INVALID_REQUEST');
    }
    if (Object.prototype.hasOwnProperty.call(record, input.name)) {
      throw bffError('INVALID_REQUEST');
    }
    record[input.name] = hasText ? text : (boolean as boolean);
  }
  return record;
}

/** The four analyses, as the readiness query returns them. */
interface Readiness {
  readonly funding: AnalysisView;
  readonly missingDocuments: AnalysisView;
  readonly beneficiaryConflicts: AnalysisView;
  readonly estateTax: AnalysisView;
}

const MFA_LEVEL_GQL: Record<MfaLevel, SessionPayload['mfaLevel']> = {
  none: 'NONE',
  mfa: 'MFA',
  stepup: 'STEPUP',
};

/**
 * An exhaustive Record, so a fourth audience is a COMPILE ERROR here rather
 * than a value that silently reaches the client unmapped — the same shape as
 * MFA_LEVEL_GQL above and the reason both are written this way.
 */
const AUDIENCE_GQL: Record<SessionAudience, SessionPayload['audience']> = {
  account: 'ACCOUNT',
  vault: 'VAULT',
  extension: 'EXTENSION',
};

const OK = { ok: true } as const;

/** The document service's own minimum (SearchQuerySchema). */
const DOCUMENT_SEARCH_MIN_LENGTH = 3;

/**
 * Base64 length of the service's 10 MiB decoded upload cap, with padding slack
 * — the same arithmetic the service does, for the same number. It bounds what
 * this process will hold in memory on the way to a request that would be
 * refused anyway; the service remains the authority on size.
 */
const UPLOAD_MAX_BASE64_CHARS = Math.ceil((10 * 1024 * 1024) / 3) * 4 + 4;

function cookieValue(ctx: RequestContext, name: string): string | null {
  return parseCookies(ctx.req.headers.cookie).get(name) ?? null;
}

function requireAccessToken(ctx: RequestContext): string {
  const token = cookieValue(ctx, ACCESS_COOKIE);
  if (token === null) {
    throw bffError('UNAUTHENTICATED');
  }
  return token;
}

/**
 * Profile save arguments. Every optional field is three-valued and the three
 * values mean three different things — ABSENT is "leave it alone", `null` is
 * "clear it", a string is "set it".
 */
interface SaveProfileArgs {
  readonly legalName: string;
  readonly dob?: string | null;
  readonly address?: string | null;
  readonly phone?: string | null;
  readonly occupation?: string | null;
  readonly maritalStatus?: string | null;
  readonly stateOfResidence?: string | null;
}

/**
 * Carry the caller's three-way distinction through to the service unflattened.
 *
 * graphql-js omits an argument key entirely when the operation did not supply
 * it, and sets it to `null` when the operation passed an explicit null — so
 * `in` is the only thing that can tell "don't touch my SSN's neighbours" from
 * "clear this field". Collapsing the two (`args.dob ?? null`) is precisely the
 * defect M13 PR1 fixed one layer down: it would turn every partial save into a
 * wipe of everything the form did not hold.
 */
const PROFILE_MERGE_FIELDS = [
  'dob',
  'address',
  'phone',
  'occupation',
  'maritalStatus',
  'stateOfResidence',
] as const;

function saveProfileInput(args: SaveProfileArgs): SaveProfileInput {
  const out: Record<string, string | null> = {};
  for (const key of PROFILE_MERGE_FIELDS) {
    if (key in args) {
      out[key] = args[key] ?? null;
    }
  }
  return { legalName: args.legalName, ...out };
}

interface ContactArgs {
  readonly name: string;
  readonly email?: string | null;
  readonly phone?: string | null;
  readonly address?: string | null;
  readonly relationship?: string | null;
  readonly professionalKind?: string | null;
  readonly notes?: string | null;
}

/**
 * Contacts keep REPLACE semantics downstream (their read returns every field
 * they store, so a client can round-trip them), which is why absent and null are
 * treated alike here and both mean "not set". Only non-empty strings travel: the
 * service's schema requires `min(1)` on every optional text field, so forwarding
 * a blank one would be a 400 for something the user expressed as "leave empty".
 */
const CONTACT_TEXT_FIELDS = [
  'email',
  'phone',
  'address',
  'relationship',
  'professionalKind',
  'notes',
] as const;

function contactInput(args: ContactArgs): ContactInput {
  const out: Record<string, string> = {};
  for (const key of CONTACT_TEXT_FIELDS) {
    const value = args[key];
    if (typeof value === 'string' && value.length > 0) {
      out[key] = value;
    }
  }
  return { name: args.name, ...out };
}

interface FamilyMemberArgs {
  readonly relation: string;
  readonly name: string;
  readonly dob?: string | null;
  readonly isMinor?: boolean | null;
  readonly notes?: string | null;
}

function familyInput(args: FamilyMemberArgs): FamilyMemberInput {
  const text: Record<string, string> = {};
  if (typeof args.dob === 'string' && args.dob.length > 0) {
    text['dob'] = args.dob;
  }
  if (typeof args.notes === 'string' && args.notes.length > 0) {
    text['notes'] = args.notes;
  }
  return {
    relation: args.relation,
    name: args.name,
    ...text,
    ...(typeof args.isMinor === 'boolean' ? { isMinor: args.isMinor } : {}),
  };
}

export function createBffSchema(deps: SchemaDeps): GraphQLSchema {
  const { identity, assets, assistant, documents, profile, secureCookies, vaultOrigin } = deps;
  const now = deps.now ?? ((): number => Date.now());

  return createSchema<RequestContext>({
    typeDefs,
    resolvers: {
      Query: {
        session: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<SessionPayload | null> => {
          const token = cookieValue(ctx, ACCESS_COOKIE);
          if (token === null) {
            return null;
          }
          const session = await identity.session(token);
          if (session === null) {
            return null;
          }
          const expiresAt =
            session.stepupExpiresAt === null ? Number.NaN : Date.parse(session.stepupExpiresAt);
          return {
            userId: session.userId,
            mfaLevel: MFA_LEVEL_GQL[session.mfaLevel],
            audience: AUDIENCE_GQL[session.audience],
            stepUpFresh: Number.isFinite(expiresAt) && expiresAt > now(),
          };
        },
        emailVerification: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<string> =>
          (await identity.emailVerificationStatus(requireAccessToken(ctx))).toUpperCase(),
        sessions: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<UserSessionPayload[]> => {
          const rows = await identity.sessions(requireAccessToken(ctx));
          return rows.map((row) => ({ ...row, audience: AUDIENCE_GQL[row.audience] }));
        },
        passkeys: async (_parent: unknown, _args: unknown, ctx: RequestContext) =>
          identity.passkeys(requireAccessToken(ctx)),
        assets: async (
          _parent: unknown,
          args: { includeRetired?: boolean | null },
          ctx: RequestContext,
        ): Promise<Asset[]> => assets.list(requireAccessToken(ctx), args.includeRetired === true),
        asset: async (
          _parent: unknown,
          args: { assetId: string },
          ctx: RequestContext,
        ): Promise<AssetDetail> => assets.get(requireAccessToken(ctx), args.assetId),
        assetHistory: async (
          _parent: unknown,
          args: { assetId: string },
          ctx: RequestContext,
        ): Promise<HistoryEntry[]> => assets.history(requireAccessToken(ctx), args.assetId),
        assetBeneficiaries: async (
          _parent: unknown,
          args: { assetId: string },
          ctx: RequestContext,
        ): Promise<{
          assetId: string;
          totals: Beneficiaries['totals'];
          beneficiaries: Array<Beneficiaries['beneficiaries'][number] & { name: string | null }>;
        }> => {
          const token = requireAccessToken(ctx);
          const result = await assets.beneficiaries(token, args.assetId);
          // Contact names cost one audited decrypt per contact row (M13's
          // narrowed list), so they are composed ONLY when there is a
          // designation to name — the common zero-designation asset costs
          // nothing (the M18 decrypt budget).
          const names =
            result.beneficiaries.length > 0
              ? new Map((await profile.contacts(token)).map((c) => [c.id, c.name] as const))
              : new Map<string, string>();
          return {
            assetId: result.assetId,
            totals: result.totals,
            beneficiaries: result.beneficiaries.map((b) => ({
              ...b,
              // NULL means "no longer in your contacts" — shown, not hidden.
              name: names.get(b.contactId) ?? null,
            })),
          };
        },
        netWorth: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<NetWorth> => assets.netWorth(requireAccessToken(ctx)),
        // The four analyses run CONCURRENTLY and independently: each carries
        // its own status, so a peer blinking during one of them costs that
        // card and not the page. `Promise.all` rather than `allSettled`
        // because the client already turns every non-401 downstream failure
        // into a status — what still rejects is UNAUTHENTICATED, which is a
        // fact about the whole request and should surface as one.
        readiness: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Readiness> => {
          const token = requireAccessToken(ctx);
          const names: readonly AnalysisName[] = [
            'funding',
            'missing-documents',
            'beneficiary-conflicts',
            'estate-tax',
          ];
          const [funding, missingDocuments, beneficiaryConflicts, estateTax] = await Promise.all(
            names.map((name) => assistant.analysis(token, name)),
          );
          return {
            funding: funding as AnalysisView,
            missingDocuments: missingDocuments as AnalysisView,
            beneficiaryConflicts: beneficiaryConflicts as AnalysisView,
            estateTax: estateTax as AnalysisView,
          };
        },
        consents: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.consents(requireAccessToken(ctx)),
        conversations: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Conversation[]> => assistant.conversations(requireAccessToken(ctx)),
        conversation: async (
          _parent: unknown,
          args: ConversationArgs,
          ctx: RequestContext,
        ): Promise<Transcript> =>
          assistant.transcript(requireAccessToken(ctx), args.conversationId),
        documentTemplates: async (
          _parent: unknown,
          args: { readonly state: string },
          ctx: RequestContext,
        ): Promise<DocumentTemplate[]> => documents.templates(requireAccessToken(ctx), args.state),
        documents: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Document[]> => documents.list(requireAccessToken(ctx)),
        document: async (
          _parent: unknown,
          args: DocumentArgs,
          ctx: RequestContext,
        ): Promise<DocumentDetail> => documents.get(requireAccessToken(ctx), args.documentId),
        // The 3-character minimum is the SERVICE's bound, checked here only so
        // a too-short query is a stable INVALID_REQUEST rather than a masked
        // downstream 400 — the createAsset partial-valuation precedent.
        documentSearch: async (
          _parent: unknown,
          args: { readonly query: string },
          ctx: RequestContext,
        ): Promise<Document[]> => {
          const query = args.query.trim();
          if (query.length < DOCUMENT_SEARCH_MIN_LENGTH) {
            throw bffError('INVALID_REQUEST');
          }
          return documents.search(requireAccessToken(ctx), query);
        },
        documentVersions: async (
          _parent: unknown,
          args: DocumentArgs,
          ctx: RequestContext,
        ): Promise<DocumentVersion[]> =>
          documents.versions(requireAccessToken(ctx), args.documentId),
        // One audited decrypt per call. There is deliberately no field on
        // Document that resolves content, and no list variant of this: a
        // convenience that let a page render N documents' text would turn one
        // page load into N decrypt events on the user's own audit trail.
        documentContent: async (
          _parent: unknown,
          args: DocumentArgs & { readonly version: number },
          ctx: RequestContext,
        ): Promise<DocumentContent> =>
          documents.content(requireAccessToken(ctx), args.documentId, args.version),
        profile: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Profile | null> => profile.profile(requireAccessToken(ctx)),
        familyMembers: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<FamilyMember[]> => profile.family(requireAccessToken(ctx)),
        contacts: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<ContactSummary[]> => profile.contacts(requireAccessToken(ctx)),
        contact: async (
          _parent: unknown,
          args: { contactId: string },
          ctx: RequestContext,
        ): Promise<ContactDetail> => profile.contact(requireAccessToken(ctx), args.contactId),
        roleAssignments: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<RoleAssignment[]> => profile.roleAssignments(requireAccessToken(ctx)),
        rolePermissions: async (
          _parent: unknown,
          args: { roleAssignmentId: string },
          ctx: RequestContext,
        ): Promise<PermissionGrant[]> =>
          profile.permissions(requireAccessToken(ctx), args.roleAssignmentId),
      },
      Mutation: {
        register: async (
          _parent: unknown,
          args: CredentialsArgs,
          _ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.register(args.email, args.password);
          return OK;
        },
        login: async (
          _parent: unknown,
          args: CredentialsArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          const tokens = await identity.login(args.email, args.password);
          setSessionCookies(ctx.res, tokens, secureCookies);
          return OK;
        },
        refresh: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          const refreshToken = cookieValue(ctx, REFRESH_COOKIE);
          if (refreshToken === null) {
            throw bffError('UNAUTHENTICATED');
          }
          const tokens = await identity.refresh(refreshToken);
          setSessionCookies(ctx.res, tokens, secureCookies);
          return OK;
        },
        logout: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // Revoke server-side FIRST — the cookies are the only copies of the
          // tokens, so clearing them before a failed revocation would strand a
          // live session that only a thief could still use.
          //
          // TWO CREDENTIALS, because they expire on different clocks. The
          // access token lasts 15 minutes and the refresh token 30 days, so
          // any tab older than the access TTL cannot revoke through the
          // guarded route — identity answers 401. Treating that 401 as success
          // was the M8-review finding: it revoked nothing, cleared the
          // cookies, and reported "signed out" over a session that remained
          // valid for up to a month. So a dead access token falls through to
          // the refresh credential rather than being read as done.
          const accessToken = cookieValue(ctx, ACCESS_COOKIE);
          const refreshToken = cookieValue(ctx, REFRESH_COOKIE);
          let revoked = false;
          if (accessToken !== null) {
            revoked = await identity.logout(accessToken);
          }
          if (!revoked && refreshToken !== null) {
            await identity.logoutByRefresh(refreshToken);
            revoked = true;
          }
          // Cookies are cleared when the session is genuinely gone, or when
          // there was no credential to revoke in the first place (already
          // signed out — clearing is then just tidying). Never after a
          // revocation we could not complete: that path throws above.
          clearSessionCookies(ctx.res, secureCookies);
          return OK;
        },
        createAsset: async (
          _parent: unknown,
          args: {
            input: {
              category: string;
              title: string;
              ownershipPct?: number | null;
              inTrust?: boolean | null;
              fundingStatus?: string | null;
              estValue?: string | null;
              valuationAsOf?: string | null;
              valuationSource?: string | null;
              costBasis?: string | null;
              location?: string | null;
              notes?: string | null;
              clientEventId?: string | null;
            };
          },
          ctx: RequestContext,
        ): Promise<CommandAck> => {
          const input = args.input;
          // Reject a PARTIAL valuation here rather than forwarding it: the
          // ledger would refuse it anyway, and a stable INVALID_REQUEST is a
          // better answer than a masked downstream 400.
          const parts = [input.estValue, input.valuationAsOf, input.valuationSource].filter(
            (part): part is string => typeof part === 'string' && part.length > 0,
          );
          if (parts.length !== 0 && parts.length !== 3) {
            throw bffError('INVALID_REQUEST');
          }
          return assets.create(requireAccessToken(ctx), {
            category: input.category,
            title: input.title,
            ...(typeof input.ownershipPct === 'number' ? { ownershipPct: input.ownershipPct } : {}),
            ...(typeof input.inTrust === 'boolean' ? { inTrust: input.inTrust } : {}),
            ...(typeof input.fundingStatus === 'string'
              ? { fundingStatus: input.fundingStatus }
              : {}),
            ...(typeof input.costBasis === 'string' ? { costBasis: input.costBasis } : {}),
            ...(typeof input.location === 'string' ? { location: input.location } : {}),
            ...(typeof input.notes === 'string' ? { notes: input.notes } : {}),
            ...(typeof input.clientEventId === 'string'
              ? { clientEventId: input.clientEventId }
              : {}),
            ...(parts.length === 3
              ? {
                  valuation: {
                    estValue: parts[0] as string,
                    valuationAsOf: parts[1] as string,
                    valuationSource: parts[2] as string,
                  },
                }
              : {}),
          });
        },
        updateAsset: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            title?: string | null;
            location?: string | null;
            notes?: string | null;
            inTrust?: boolean | null;
            fundingStatus?: string | null;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> => {
          // ABSENT (undefined) = unchanged; explicit NULL = clear. GraphQL
          // keeps the two apart in coerced args, and JSON.stringify in the
          // client preserves exactly that split on the wire.
          return assets.updateDetails(
            requireAccessToken(ctx),
            args.assetId,
            {
              ...(typeof args.title === 'string' ? { title: args.title } : {}),
              ...(args.location !== undefined ? { location: args.location } : {}),
              ...(args.notes !== undefined ? { notes: args.notes } : {}),
              ...(typeof args.inTrust === 'boolean' ? { inTrust: args.inTrust } : {}),
              ...(args.fundingStatus !== undefined ? { fundingStatus: args.fundingStatus } : {}),
              ...(typeof args.clientEventId === 'string'
                ? { clientEventId: args.clientEventId }
                : {}),
            },
            args.expectedVersion,
          );
        },
        recordValuation: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            estValue: string;
            valuationAsOf: string;
            valuationSource: string;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> =>
          assets.recordValuation(
            requireAccessToken(ctx),
            args.assetId,
            {
              estValue: args.estValue,
              valuationAsOf: args.valuationAsOf,
              valuationSource: args.valuationSource,
              ...(typeof args.clientEventId === 'string'
                ? { clientEventId: args.clientEventId }
                : {}),
            },
            args.expectedVersion,
          ),
        changeOwnership: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            ownershipPct: number;
            costBasis?: string | null;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> =>
          assets.changeOwnership(
            requireAccessToken(ctx),
            args.assetId,
            {
              ownershipPct: args.ownershipPct,
              ...(args.costBasis !== undefined ? { costBasis: args.costBasis } : {}),
              ...(typeof args.clientEventId === 'string'
                ? { clientEventId: args.clientEventId }
                : {}),
            },
            args.expectedVersion,
          ),
        retireAsset: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            reason?: string | null;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> =>
          assets.retire(
            requireAccessToken(ctx),
            args.assetId,
            {
              ...(typeof args.reason === 'string' ? { reason: args.reason } : {}),
              ...(typeof args.clientEventId === 'string'
                ? { clientEventId: args.clientEventId }
                : {}),
            },
            args.expectedVersion,
          ),
        designateBeneficiary: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            contactId: string;
            designation: string;
            sharePct: number;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> => {
          const token = requireAccessToken(ctx);
          // THE MEMBERSHIP CHECK. The service accepts any UUID by design
          // (docs/02 §8 — no cross-cluster FK), so the BFF, the only layer
          // that sees both the caller's contacts and their assets, refuses a
          // contactId that is not the CALLER'S OWN before anything reaches
          // the ledger. Closes the product path against the cross-owner
          // designation shape the M13 review closed in profile. This is
          // EDGE HYGIENE, not a security boundary — a caller speaking to the
          // assets service directly walks past it, in their own estate, and
          // that residual with its bounds is recorded in docs/03 §6r.
          const contacts = await profile.contacts(token);
          if (!contacts.some((contact) => contact.id === args.contactId)) {
            throw bffError('INVALID_REQUEST');
          }
          return assets.designateBeneficiary(
            token,
            args.assetId,
            {
              contactId: args.contactId,
              designation: args.designation,
              sharePct: args.sharePct,
              ...(typeof args.clientEventId === 'string'
                ? { clientEventId: args.clientEventId }
                : {}),
            },
            args.expectedVersion,
          );
        },
        removeBeneficiary: async (
          _parent: unknown,
          args: {
            assetId: string;
            expectedVersion: string;
            contactId: string;
            designation: string;
            clientEventId?: string | null;
          },
          ctx: RequestContext,
        ): Promise<CommandAck> =>
          // Deliberately NO membership check: a designation whose contact was
          // deleted must stay removable, or the dangling row is permanent.
          assets.removeBeneficiary(
            requireAccessToken(ctx),
            args.assetId,
            args.contactId,
            args.designation,
            typeof args.clientEventId === 'string' ? args.clientEventId : undefined,
            args.expectedVersion,
          ),
        startConversation: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<Conversation> => assistant.startConversation(requireAccessToken(ctx)),
        sendMessage: async (
          _parent: unknown,
          args: ConversationArgs & { readonly text: string },
          ctx: RequestContext,
        ): Promise<Turn> =>
          assistant.sendMessage(requireAccessToken(ctx), args.conversationId, args.text),
        deleteConversation: async (
          _parent: unknown,
          args: ConversationArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await assistant.deleteConversation(requireAccessToken(ctx), args.conversationId);
          return OK;
        },
        generateDocument: async (
          _parent: unknown,
          args: {
            docType: string;
            state: string;
            templateId?: string | null;
            title?: string | null;
            variables: readonly DocumentVariableInput[];
          },
          ctx: RequestContext,
        ): Promise<GenerateResult> =>
          documents.generate(requireAccessToken(ctx), {
            docType: args.docType,
            state: args.state,
            ...(typeof args.templateId === 'string' ? { templateId: args.templateId } : {}),
            ...(typeof args.title === 'string' && args.title.length > 0
              ? { title: args.title }
              : {}),
            variables: intakeRecord(args.variables),
          }),
        regenerateDocument: async (
          _parent: unknown,
          args: DocumentArgs & {
            templateId?: string | null;
            title?: string | null;
            variables: readonly DocumentVariableInput[];
          },
          ctx: RequestContext,
        ): Promise<GenerateResult> =>
          documents.regenerate(requireAccessToken(ctx), args.documentId, {
            ...(typeof args.templateId === 'string' ? { templateId: args.templateId } : {}),
            ...(typeof args.title === 'string' && args.title.length > 0
              ? { title: args.title }
              : {}),
            variables: intakeRecord(args.variables),
          }),
        uploadDocument: async (
          _parent: unknown,
          args: { kind: string; title: string; mime: string; contentBase64: string },
          ctx: RequestContext,
        ): Promise<UploadResult> => {
          // A DECODED-SIZE CEILING AT THE EDGE, matching the service's own cap.
          // The service enforces it again and is the authority; refusing here
          // means an oversized body is not proxied through the BFF's memory to
          // be rejected downstream. Stated rather than implied: this is not a
          // request-size limit — the BFF has none, and bounding request bodies
          // at the edge is CloudFront/WAF's job in the deployed topology
          // (docs/01 §2), which does not exist yet.
          if (args.contentBase64.length > UPLOAD_MAX_BASE64_CHARS) {
            throw bffError('UNSUPPORTED_CONTENT');
          }
          return documents.upload(requireAccessToken(ctx), {
            kind: args.kind,
            title: args.title,
            mime: args.mime,
            contentBase64: args.contentBase64,
          });
        },
        setDocumentStatus: async (
          _parent: unknown,
          args: DocumentArgs & { status: string; executedAt?: string | null },
          ctx: RequestContext,
        ): Promise<DocumentDetail> =>
          documents.setStatus(
            requireAccessToken(ctx),
            args.documentId,
            args.status,
            typeof args.executedAt === 'string' && args.executedAt.length > 0
              ? args.executedAt
              : undefined,
          ),
        deleteDocument: async (
          _parent: unknown,
          args: DocumentArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await documents.remove(requireAccessToken(ctx), args.documentId);
          return OK;
        },
        saveProfile: async (
          _parent: unknown,
          args: SaveProfileArgs,
          ctx: RequestContext,
        ): Promise<Profile> => {
          const token = requireAccessToken(ctx);
          await profile.saveProfile(token, saveProfileInput(args));
          const saved = await profile.profile(token);
          if (saved === null) {
            // A save that reports success and then reads back nothing is a skew
            // we must not paper over with an invented row.
            throw new Error('profile save did not persist');
          }
          return saved;
        },
        addFamilyMember: async (
          _parent: unknown,
          args: FamilyMemberArgs,
          ctx: RequestContext,
        ): Promise<FamilyMember[]> => {
          const token = requireAccessToken(ctx);
          await profile.createFamilyMember(token, familyInput(args));
          return profile.family(token);
        },
        updateFamilyMember: async (
          _parent: unknown,
          args: FamilyMemberArgs & { id: string },
          ctx: RequestContext,
        ): Promise<FamilyMember[]> => {
          const token = requireAccessToken(ctx);
          await profile.updateFamilyMember(token, args.id, familyInput(args));
          return profile.family(token);
        },
        deleteFamilyMember: async (
          _parent: unknown,
          args: { id: string },
          ctx: RequestContext,
        ): Promise<FamilyMember[]> => {
          const token = requireAccessToken(ctx);
          await profile.deleteFamilyMember(token, args.id);
          return profile.family(token);
        },
        addContact: async (
          _parent: unknown,
          args: ContactArgs,
          ctx: RequestContext,
        ): Promise<ContactSummary[]> => {
          const token = requireAccessToken(ctx);
          await profile.createContact(token, contactInput(args));
          return profile.contacts(token);
        },
        updateContact: async (
          _parent: unknown,
          args: ContactArgs & { contactId: string },
          ctx: RequestContext,
        ): Promise<ContactDetail> => {
          const token = requireAccessToken(ctx);
          await profile.updateContact(token, args.contactId, contactInput(args));
          // Re-read the one record whose panel the user is on, so what they see
          // is the stored row and not an echo of what they typed.
          return profile.contact(token, args.contactId);
        },
        deleteContact: async (
          _parent: unknown,
          args: { contactId: string },
          ctx: RequestContext,
        ): Promise<ContactSummary[]> => {
          const token = requireAccessToken(ctx);
          await profile.deleteContact(token, args.contactId);
          return profile.contacts(token);
        },
        grantRole: async (
          _parent: unknown,
          args: {
            contactId: string;
            role: string;
            scopeType: string;
            scopeId?: string | null;
            effectiveCondition?: string | null;
          },
          ctx: RequestContext,
        ): Promise<RoleAssignment[]> => {
          const token = requireAccessToken(ctx);
          await profile.grantRole(token, {
            contactId: args.contactId,
            role: args.role,
            scopeType: args.scopeType,
            ...(typeof args.scopeId === 'string' ? { scopeId: args.scopeId } : {}),
            ...(typeof args.effectiveCondition === 'string'
              ? { effectiveCondition: args.effectiveCondition }
              : {}),
          });
          return profile.roleAssignments(token);
        },
        revokeRole: async (
          _parent: unknown,
          args: { roleAssignmentId: string },
          ctx: RequestContext,
        ): Promise<RoleAssignment[]> => {
          const token = requireAccessToken(ctx);
          await profile.revokeRole(token, args.roleAssignmentId);
          return profile.roleAssignments(token);
        },
        grantRolePermission: async (
          _parent: unknown,
          args: { roleAssignmentId: string; resource: string; action: string },
          ctx: RequestContext,
        ): Promise<PermissionGrant[]> => {
          const token = requireAccessToken(ctx);
          await profile.grantPermission(token, args.roleAssignmentId, {
            resource: args.resource,
            action: args.action,
          });
          return profile.permissions(token, args.roleAssignmentId);
        },
        inviteContactLink: async (
          _parent: unknown,
          args: { contactId: string },
          ctx: RequestContext,
        ): Promise<LinkInvitation> => profile.inviteLink(requireAccessToken(ctx), args.contactId),
        revokeContactLinkInvitation: async (
          _parent: unknown,
          args: { contactId: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await profile.revokeLinkInvitation(requireAccessToken(ctx), args.contactId);
          return OK;
        },
        unlinkContact: async (
          _parent: unknown,
          args: { contactId: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await profile.unlink(requireAccessToken(ctx), args.contactId);
          return OK;
        },
        redeemContactLink: async (
          _parent: unknown,
          args: { code: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await profile.redeemLink(requireAccessToken(ctx), args.code);
          return OK;
        },
        revokeRolePermission: async (
          _parent: unknown,
          args: { roleAssignmentId: string; grantId: string },
          ctx: RequestContext,
        ): Promise<PermissionGrant[]> => {
          const token = requireAccessToken(ctx);
          await profile.revokePermission(token, args.roleAssignmentId, args.grantId);
          return profile.permissions(token, args.roleAssignmentId);
        },
        grantConsent: async (
          _parent: unknown,
          args: ScopeArgs,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.grantConsent(requireAccessToken(ctx), args.scope),
        revokeConsent: async (
          _parent: unknown,
          args: ScopeArgs,
          ctx: RequestContext,
        ): Promise<string[]> => assistant.revokeConsent(requireAccessToken(ctx), args.scope),
        totpEnroll: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<{ otpauthUri: string }> => {
          return identity.totpEnroll(requireAccessToken(ctx));
        },
        totpVerify: async (
          _parent: unknown,
          args: CodeArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.totpVerify(requireAccessToken(ctx), args.code);
          return OK;
        },
        stepUp: async (
          _parent: unknown,
          args: CodeArgs,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.stepUp(requireAccessToken(ctx), args.code);
          return OK;
        },
        startExtensionPairing: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<{ code: string; expiresAt: string }> =>
          identity.startExtensionPairing(requireAccessToken(ctx)),
        webauthnRegisterOptions: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<unknown> => identity.webauthnRegisterOptions(requireAccessToken(ctx)),
        webauthnRegister: async (
          _parent: unknown,
          args: { response: Record<string, unknown> },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.webauthnRegister(requireAccessToken(ctx), args.response);
          return OK;
        },
        webauthnStepUpOptions: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<unknown> => identity.webauthnStepUpOptions(requireAccessToken(ctx)),
        webauthnStepUp: async (
          _parent: unknown,
          args: { response: Record<string, unknown> },
          ctx: RequestContext,
        ): Promise<{ stepupExpiresAt: string }> =>
          identity.webauthnStepUp(requireAccessToken(ctx), args.response),
        revokePasskey: async (
          _parent: unknown,
          args: { id: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.revokePasskey(requireAccessToken(ctx), args.id);
          return OK;
        },
        renamePasskey: async (
          _parent: unknown,
          args: { id: string; nickname: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.renamePasskey(requireAccessToken(ctx), args.id, args.nickname);
          return OK;
        },
        revokeSession: async (
          _parent: unknown,
          args: { sessionId: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.revokeSession(requireAccessToken(ctx), args.sessionId);
          return OK;
        },
        startVaultHandoff: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<{ code: string; expiresAt: string; vaultOrigin: string }> => {
          // The BFF adds no authority here: identity's own StepUpGuard decides,
          // and this forwards the caller's bearer like every other resolver.
          // What it contributes is the ORIGIN, which only the deployment knows.
          const minted = await identity.mintVaultHandoff(requireAccessToken(ctx));
          return { ...minted, vaultOrigin };
        },
        exportDemo: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.exportDemo(requireAccessToken(ctx));
          return OK;
        },
        resendEmailVerification: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<string> =>
          (await identity.resendEmailVerification(requireAccessToken(ctx))).toUpperCase(),
        verifyEmail: async (
          _parent: unknown,
          args: { code: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // The code is passed through unchanged: canonicalizing it here would
          // be a SECOND copy of identity's fold, and two copies of a matching
          // rule is how they drift. Identity measures the canonical form.
          await identity.verifyEmail(requireAccessToken(ctx), args.code);
          return OK;
        },
        changePassword: async (
          _parent: unknown,
          args: { currentPassword: string; newPassword: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // Both values pass through UNCHECKED, deliberately. Identity's
          // `ChangePasswordSchema` is the gate (min 12 on the new password),
          // and a second copy of a validation rule at the edge is a copy free
          // to drift from the one that decides — the M12 upload-client rule.
          // The web form mirrors the minimum as a usability hint and pins it to
          // identity's own source; it is not a control, and this is not one
          // either.
          await identity.changePassword(
            requireAccessToken(ctx),
            args.currentPassword,
            args.newPassword,
          );
          return OK;
        },
        requestEmailChange: async (
          _parent: unknown,
          args: { currentPassword: string; newEmail: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // The address is forwarded UNVALIDATED, and that is deliberate on the
          // `changePassword` reasoning: identity's schema is the gate, and this
          // edge adding a second opinion about what an address may look like is
          // a rule free to disagree with the one that decides. Identity itself
          // does not apply `.email()` either — it normalizes and blind-indexes,
          // and the real answer comes from whether a code arrives.
          await identity.requestEmailChange(
            requireAccessToken(ctx),
            args.currentPassword,
            args.newEmail,
          );
          return OK;
        },
        completeEmailChange: async (
          _parent: unknown,
          args: { code: string },
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          // Unchanged, for `verifyEmail`'s reason: identity folds and measures
          // the canonical form, and a second fold here could disagree with it.
          await identity.completeEmailChange(requireAccessToken(ctx), args.code);
          return OK;
        },
        cancelEmailChange: async (
          _parent: unknown,
          _args: unknown,
          ctx: RequestContext,
        ): Promise<typeof OK> => {
          await identity.cancelEmailChange(requireAccessToken(ctx));
          return OK;
        },
      },
    },
  });
}
