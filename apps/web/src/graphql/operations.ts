/**
 * Single source of truth for every GraphQL operation this app sends.
 *
 * Format contract (relied on by scripts/build-persisted-manifest.mjs, which
 * extracts these documents with a line-anchored pattern, and guarded by the
 * manifest sync test): each document is declared as
 * `export const <NAME>_(MUTATION|QUERY) = \`...\`;` with no interpolation and
 * no backticks inside the document. Edit a document -> regenerate the
 * manifest: `node scripts/build-persisted-manifest.mjs`.
 */

export const REGISTER_MUTATION = `mutation Register($email: String!, $password: String!) {
  register(email: $email, password: $password) {
    ok
  }
}`;

export const LOGIN_MUTATION = `mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    ok
  }
}`;

export const REFRESH_MUTATION = `mutation Refresh {
  refresh {
    ok
  }
}`;

export const TOTP_ENROLL_MUTATION = `mutation TotpEnroll {
  totpEnroll {
    otpauthUri
  }
}`;

export const TOTP_VERIFY_MUTATION = `mutation TotpVerify($code: String!) {
  totpVerify(code: $code) {
    ok
  }
}`;

/**
 * Open the ISOLATED VAULT ORIGIN (M15).
 *
 * Returns a single-use code and the origin to submit it to. The code lives for
 * sixty seconds, is burned on the attempt, and must go into a hidden field —
 * never a URL.
 */
export const START_VAULT_HANDOFF_MUTATION = `mutation StartVaultHandoff {
  startVaultHandoff {
    code
    expiresAt
    vaultOrigin
  }
}`;

/**
 * Mint a single-use code for the ISOLATED OPERATOR ORIGIN (M21 PR3a, docs/03
 * TB7).
 *
 * A SEPARATE OPERATION from StartVaultHandoff, mirroring the two mint routes at
 * identity: the operation is the selector, so nothing on the wire names an
 * audience and no client can ask for the wrong one. Same handling as the vault
 * code — sixty seconds, burned on the attempt, into a hidden field and never a
 * URL.
 */
export const START_OPERATOR_HANDOFF_MUTATION = `mutation StartOperatorHandoff {
  startOperatorHandoff {
    code
    expiresAt
    operatorOrigin
  }
}`;

export const STEP_UP_MUTATION = `mutation StepUp($code: String!) {
  stepUp(code: $code) {
    ok
  }
}`;

export const EXPORT_DEMO_MUTATION = `mutation ExportDemo {
  exportDemo {
    ok
  }
}`;

export const SESSION_QUERY = `query Session {
  session {
    userId
    mfaLevel
    stepUpFresh
    audience
  }
}`;

export const SESSIONS_QUERY = `query Sessions {
  sessions {
    sessionId
    audience
    createdAt
    expiresAt
    current
  }
}`;

export const REVOKE_SESSION_MUTATION = `mutation RevokeSession($sessionId: ID!) {
  revokeSession(sessionId: $sessionId) {
    ok
  }
}`;

export const START_EXTENSION_PAIRING_MUTATION = `mutation StartExtensionPairing {
  startExtensionPairing {
    code
    expiresAt
  }
}`;

export const PASSKEYS_QUERY = `query Passkeys {
  passkeys {
    id
    nickname
    isHardwareKey
    createdAt
    lastUsedAt
  }
}`;

export const WEBAUTHN_REGISTER_OPTIONS_MUTATION = `mutation WebauthnRegisterOptions {
  webauthnRegisterOptions
}`;

export const WEBAUTHN_REGISTER_MUTATION = `mutation WebauthnRegister($response: JSON!) {
  webauthnRegister(response: $response) {
    ok
  }
}`;

export const WEBAUTHN_STEP_UP_OPTIONS_MUTATION = `mutation WebauthnStepUpOptions {
  webauthnStepUpOptions
}`;

export const WEBAUTHN_STEP_UP_MUTATION = `mutation WebauthnStepUp($response: JSON!) {
  webauthnStepUp(response: $response) {
    stepupExpiresAt
  }
}`;

export const REVOKE_PASSKEY_MUTATION = `mutation RevokePasskey($id: ID!) {
  revokePasskey(id: $id) {
    ok
  }
}`;

export const RENAME_PASSKEY_MUTATION = `mutation RenamePasskey($id: ID!, $nickname: String!) {
  renamePasskey(id: $id, nickname: $nickname) {
    ok
  }
}`;

export const LOGOUT_MUTATION = `mutation Logout {
  logout {
    ok
  }
}`;

export const ASSETS_QUERY = `query Assets($includeRetired: Boolean) {
  assets(includeRetired: $includeRetired) {
    assetId
    category
    title
    estValue
    valuationAsOf
    valuationSource
    ownershipPct
    inTrust
    fundingStatus
    status
    retiredAt
    version
  }
}`;

export const ASSET_QUERY = `query Asset($assetId: ID!) {
  asset(assetId: $assetId) {
    assetId
    category
    title
    estValue
    valuationAsOf
    valuationSource
    ownershipPct
    costBasis
    location
    notes
    inTrust
    fundingStatus
    status
    retiredAt
    version
  }
}`;

export const ASSET_HISTORY_QUERY = `query AssetHistory($assetId: ID!) {
  assetHistory(assetId: $assetId) {
    version
    eventId
    eventType
    occurredAt
    payload
  }
}`;

export const NET_WORTH_QUERY = `query NetWorth {
  netWorth {
    totalValue
    assetCount
    valuedAssetCount
    inTrustValue
  }
}`;

export const CREATE_ASSET_MUTATION = `mutation CreateAsset($input: CreateAssetInput!) {
  createAsset(input: $input) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const UPDATE_ASSET_MUTATION = `mutation UpdateAsset($assetId: ID!, $expectedVersion: String!, $title: String, $location: String, $notes: String, $inTrust: Boolean, $fundingStatus: String, $clientEventId: ID) {
  updateAsset(assetId: $assetId, expectedVersion: $expectedVersion, title: $title, location: $location, notes: $notes, inTrust: $inTrust, fundingStatus: $fundingStatus, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const RECORD_VALUATION_MUTATION = `mutation RecordValuation($assetId: ID!, $expectedVersion: String!, $estValue: String!, $valuationAsOf: String!, $valuationSource: String!, $clientEventId: ID) {
  recordValuation(assetId: $assetId, expectedVersion: $expectedVersion, estValue: $estValue, valuationAsOf: $valuationAsOf, valuationSource: $valuationSource, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const CHANGE_OWNERSHIP_MUTATION = `mutation ChangeOwnership($assetId: ID!, $expectedVersion: String!, $ownershipPct: Float!, $costBasis: String, $clientEventId: ID) {
  changeOwnership(assetId: $assetId, expectedVersion: $expectedVersion, ownershipPct: $ownershipPct, costBasis: $costBasis, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const RETIRE_ASSET_MUTATION = `mutation RetireAsset($assetId: ID!, $expectedVersion: String!, $reason: String, $clientEventId: ID) {
  retireAsset(assetId: $assetId, expectedVersion: $expectedVersion, reason: $reason, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const ASSET_BENEFICIARIES_QUERY = `query AssetBeneficiaries($assetId: ID!) {
  assetBeneficiaries(assetId: $assetId) {
    assetId
    beneficiaries {
      contactId
      name
      designation
      sharePct
    }
    totals {
      designation
      sharePct
      designationComplete
    }
  }
}`;

export const DESIGNATE_BENEFICIARY_MUTATION = `mutation DesignateBeneficiary($assetId: ID!, $expectedVersion: String!, $contactId: ID!, $designation: String!, $sharePct: Float!, $clientEventId: ID) {
  designateBeneficiary(assetId: $assetId, expectedVersion: $expectedVersion, contactId: $contactId, designation: $designation, sharePct: $sharePct, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const REMOVE_BENEFICIARY_MUTATION = `mutation RemoveBeneficiary($assetId: ID!, $expectedVersion: String!, $contactId: ID!, $designation: String!, $clientEventId: ID) {
  removeBeneficiary(assetId: $assetId, expectedVersion: $expectedVersion, contactId: $contactId, designation: $designation, clientEventId: $clientEventId) {
    assetId
    eventId
    version
    replayed
  }
}`;

export const READINESS_QUERY = `query Readiness {
  readiness {
    funding {
      ...AnalysisFields
    }
    missingDocuments {
      ...AnalysisFields
    }
    beneficiaryConflicts {
      ...AnalysisFields
    }
    estateTax {
      ...AnalysisFields
    }
  }
}

fragment AnalysisFields on Analysis {
  status
  reason
  disclaimer
  findings {
    code
    severity
    subject {
      kind
      ref
      label
    }
    detail
  }
}`;

export const EMAIL_VERIFICATION_QUERY = `query EmailVerification {
  emailVerification
}`;

export const RESEND_EMAIL_VERIFICATION_MUTATION = `mutation ResendEmailVerification {
  resendEmailVerification
}`;

export const VERIFY_EMAIL_MUTATION = `mutation VerifyEmail($code: String!) {
  verifyEmail(code: $code) {
    ok
  }
}`;

export const CHANGE_PASSWORD_MUTATION = `mutation ChangePassword($currentPassword: String!, $newPassword: String!) {
  changePassword(currentPassword: $currentPassword, newPassword: $newPassword) {
    ok
  }
}`;

export const REQUEST_EMAIL_CHANGE_MUTATION = `mutation RequestEmailChange($currentPassword: String!, $newEmail: String!) {
  requestEmailChange(currentPassword: $currentPassword, newEmail: $newEmail) {
    ok
  }
}`;

export const COMPLETE_EMAIL_CHANGE_MUTATION = `mutation CompleteEmailChange($code: String!) {
  completeEmailChange(code: $code) {
    ok
  }
}`;

export const CANCEL_EMAIL_CHANGE_MUTATION = `mutation CancelEmailChange {
  cancelEmailChange {
    ok
  }
}`;

export const ACCOUNT_ERASURE_QUERY = `query AccountErasure {
  accountErasure {
    status
    requestedAt
  }
}`;

export const REQUEST_ACCOUNT_ERASURE_MUTATION = `mutation RequestAccountErasure {
  requestAccountErasure {
    status
    requestedAt
  }
}`;

export const CANCEL_ACCOUNT_ERASURE_MUTATION = `mutation CancelAccountErasure {
  cancelAccountErasure {
    status
    requestedAt
  }
}`;

export const REQUEST_PASSWORD_RESET_MUTATION = `mutation RequestPasswordReset($email: String!) {
  requestPasswordReset(email: $email) {
    ok
  }
}`;

export const COMPLETE_PASSWORD_RESET_MUTATION = `mutation CompletePasswordReset($code: String!, $newPassword: String!) {
  completePasswordReset(code: $code, newPassword: $newPassword) {
    ok
  }
}`;

export const CONSENTS_QUERY = `query Consents {
  consents
}`;

export const GRANT_CONSENT_MUTATION = `mutation GrantConsent($scope: String!) {
  grantConsent(scope: $scope)
}`;

export const REVOKE_CONSENT_MUTATION = `mutation RevokeConsent($scope: String!) {
  revokeConsent(scope: $scope)
}`;

export const CONVERSATIONS_QUERY = `query Conversations {
  conversations {
    conversationId
    createdAt
    updatedAt
  }
}`;

export const CONVERSATION_QUERY = `query Conversation($conversationId: ID!) {
  conversation(conversationId: $conversationId) {
    conversationId
    messages {
      messageId
      seq
      role
      text
      createdAt
    }
  }
}`;

export const START_CONVERSATION_MUTATION = `mutation StartConversation {
  startConversation {
    conversationId
    createdAt
    updatedAt
  }
}`;

export const SEND_MESSAGE_MUTATION = `mutation SendMessage($conversationId: ID!, $text: String!) {
  sendMessage(conversationId: $conversationId, text: $text) {
    conversationId
    messageId
    text
    toolCalls
  }
}`;

export const DELETE_CONVERSATION_MUTATION = `mutation DeleteConversation($conversationId: ID!) {
  deleteConversation(conversationId: $conversationId) {
    ok
  }
}`;

export const DOCUMENT_TEMPLATES_QUERY = `query DocumentTemplates($state: String!) {
  documentTemplates(state: $state) {
    templateId
    docType
    state
    version
    legalReviewAt
    executionRequirements {
      witnesses
      notarization
      selfProvingAffidavit
    }
    variables {
      name
      kind
      label
      required
      maxLength
      options
    }
  }
}`;

export const DOCUMENTS_QUERY = `query Documents {
  documents {
    documentId
    docType
    source
    title
    currentVersion
    executionStatus
    executedAt
    legalHold
    sealed
    templateId
    createdAt
    updatedAt
  }
}`;

export const DOCUMENT_QUERY = `query Document($documentId: ID!) {
  document(documentId: $documentId) {
    documentId
    docType
    source
    title
    currentVersion
    executionStatus
    executedAt
    legalHold
    sealed
    templateId
    createdAt
    updatedAt
    allowedTransitions
  }
}`;

export const DOCUMENT_SEARCH_QUERY = `query DocumentSearch($query: String!) {
  documentSearch(query: $query) {
    documentId
    docType
    source
    title
    currentVersion
    executionStatus
    executedAt
    legalHold
    sealed
    templateId
    createdAt
    updatedAt
  }
}`;

export const UPLOAD_DOCUMENT_MUTATION = `mutation UploadDocument($kind: String!, $title: String!, $mime: String!, $contentBase64: String!) {
  uploadDocument(kind: $kind, title: $title, mime: $mime, contentBase64: $contentBase64) {
    documentId
    version
    contentSha256
    executionStatus
    ocrIndexed
  }
}`;

export const SET_DOCUMENT_STATUS_MUTATION = `mutation SetDocumentStatus($documentId: ID!, $status: String!, $executedAt: String) {
  setDocumentStatus(documentId: $documentId, status: $status, executedAt: $executedAt) {
    documentId
    executionStatus
    executedAt
    allowedTransitions
  }
}`;

export const DELETE_DOCUMENT_MUTATION = `mutation DeleteDocument($documentId: ID!) {
  deleteDocument(documentId: $documentId) {
    ok
  }
}`;

export const DOCUMENT_VERSIONS_QUERY = `query DocumentVersions($documentId: ID!) {
  documentVersions(documentId: $documentId) {
    version
    contentSha256
    sizeBytes
    mime
    createdAt
  }
}`;

export const DOCUMENT_CONTENT_QUERY = `query DocumentContent($documentId: ID!, $version: Int!) {
  documentContent(documentId: $documentId, version: $version) {
    documentId
    version
    mime
    contentSha256
    encoding
    content
  }
}`;

export const GENERATE_DOCUMENT_MUTATION = `mutation GenerateDocument($docType: String!, $state: String!, $templateId: ID, $title: String, $variables: [DocumentVariableInput!]!) {
  generateDocument(docType: $docType, state: $state, templateId: $templateId, title: $title, variables: $variables) {
    documentId
    version
    contentSha256
    executionStatus
  }
}`;

export const REGENERATE_DOCUMENT_MUTATION = `mutation RegenerateDocument($documentId: ID!, $templateId: ID, $title: String, $variables: [DocumentVariableInput!]!) {
  regenerateDocument(documentId: $documentId, templateId: $templateId, title: $title, variables: $variables) {
    documentId
    version
    contentSha256
    executionStatus
  }
}`;

export const PROFILE_QUERY = `query Profile {
  profile {
    userId
    legalName
    dob
    ssnLast4
    address
    phone
    occupation
    maritalStatus
    stateOfResidence
  }
}`;

export const SAVE_PROFILE_MUTATION = `mutation SaveProfile($legalName: String!, $dob: String, $address: String, $phone: String, $occupation: String, $maritalStatus: String, $stateOfResidence: String) {
  saveProfile(legalName: $legalName, dob: $dob, address: $address, phone: $phone, occupation: $occupation, maritalStatus: $maritalStatus, stateOfResidence: $stateOfResidence) {
    userId
    legalName
    dob
    ssnLast4
    address
    phone
    occupation
    maritalStatus
    stateOfResidence
  }
}`;

export const FAMILY_MEMBERS_QUERY = `query FamilyMembers {
  familyMembers {
    id
    relation
    name
    dob
    isMinor
    notes
  }
}`;

export const ADD_FAMILY_MEMBER_MUTATION = `mutation AddFamilyMember($relation: String!, $name: String!, $dob: String, $isMinor: Boolean, $notes: String) {
  addFamilyMember(relation: $relation, name: $name, dob: $dob, isMinor: $isMinor, notes: $notes) {
    id
    relation
    name
    dob
    isMinor
    notes
  }
}`;

export const DELETE_FAMILY_MEMBER_MUTATION = `mutation DeleteFamilyMember($id: ID!) {
  deleteFamilyMember(id: $id) {
    id
    relation
    name
    dob
    isMinor
    notes
  }
}`;

export const CONTACTS_QUERY = `query Contacts {
  contacts {
    id
    name
    relationship
    professionalKind
    hasEmail
    hasPhone
    hasAddress
    hasNotes
    linked
  }
}`;

export const CONTACT_QUERY = `query Contact($contactId: ID!) {
  contact(contactId: $contactId) {
    id
    name
    email
    phone
    address
    relationship
    professionalKind
    notes
  }
}`;

export const ADD_CONTACT_MUTATION = `mutation AddContact($name: String!, $email: String, $phone: String, $address: String, $relationship: String, $professionalKind: String, $notes: String) {
  addContact(name: $name, email: $email, phone: $phone, address: $address, relationship: $relationship, professionalKind: $professionalKind, notes: $notes) {
    id
    name
    relationship
    professionalKind
    hasEmail
    hasPhone
    hasAddress
    hasNotes
    linked
  }
}`;

export const UPDATE_CONTACT_MUTATION = `mutation UpdateContact($contactId: ID!, $name: String!, $email: String, $phone: String, $address: String, $relationship: String, $professionalKind: String, $notes: String) {
  updateContact(contactId: $contactId, name: $name, email: $email, phone: $phone, address: $address, relationship: $relationship, professionalKind: $professionalKind, notes: $notes) {
    id
    name
    email
    phone
    address
    relationship
    professionalKind
    notes
  }
}`;

export const DELETE_CONTACT_MUTATION = `mutation DeleteContact($contactId: ID!) {
  deleteContact(contactId: $contactId) {
    id
    name
    relationship
    professionalKind
    hasEmail
    hasPhone
    hasAddress
    hasNotes
    linked
  }
}`;

export const ROLE_ASSIGNMENTS_QUERY = `query RoleAssignments {
  roleAssignments {
    id
    contactId
    role
    scopeType
    scopeId
    effectiveCondition
    startsAt
    endsAt
  }
}`;

export const GRANT_ROLE_MUTATION = `mutation GrantRole($contactId: ID!, $role: String!, $scopeType: String!, $effectiveCondition: String) {
  grantRole(contactId: $contactId, role: $role, scopeType: $scopeType, effectiveCondition: $effectiveCondition) {
    id
    contactId
    role
    scopeType
    scopeId
    effectiveCondition
    startsAt
    endsAt
  }
}`;

export const REVOKE_ROLE_MUTATION = `mutation RevokeRole($roleAssignmentId: ID!) {
  revokeRole(roleAssignmentId: $roleAssignmentId) {
    id
    contactId
    role
    scopeType
    scopeId
    effectiveCondition
    startsAt
    endsAt
  }
}`;

export const ROLE_PERMISSIONS_QUERY = `query RolePermissions($roleAssignmentId: ID!) {
  rolePermissions(roleAssignmentId: $roleAssignmentId) {
    id
    resource
    action
    createdAt
  }
}`;

export const GRANT_ROLE_PERMISSION_MUTATION = `mutation GrantRolePermission($roleAssignmentId: ID!, $resource: String!, $action: String!) {
  grantRolePermission(roleAssignmentId: $roleAssignmentId, resource: $resource, action: $action) {
    id
    resource
    action
    createdAt
  }
}`;

export const REVOKE_ROLE_PERMISSION_MUTATION = `mutation RevokeRolePermission($roleAssignmentId: ID!, $grantId: ID!) {
  revokeRolePermission(roleAssignmentId: $roleAssignmentId, grantId: $grantId) {
    id
    resource
    action
    createdAt
  }
}`;

export const INVITE_CONTACT_LINK_MUTATION = `mutation InviteContactLink($contactId: ID!) {
  inviteContactLink(contactId: $contactId) {
    code
    expiresAt
  }
}`;

export const REVOKE_CONTACT_LINK_INVITATION_MUTATION = `mutation RevokeContactLinkInvitation($contactId: ID!) {
  revokeContactLinkInvitation(contactId: $contactId) {
    ok
  }
}`;

export const UNLINK_CONTACT_MUTATION = `mutation UnlinkContact($contactId: ID!) {
  unlinkContact(contactId: $contactId) {
    ok
  }
}`;

export const REDEEM_CONTACT_LINK_MUTATION = `mutation RedeemContactLink($code: String!) {
  redeemContactLink(code: $code) {
    ok
  }
}`;

/**
 * The settlement owner surface (M22 PR3).
 *
 * `settlementCases` returns BOTH kinds of row — a case opened about you, and one
 * you reported — because settlement selects them with one OR. `aboutMe` is what
 * tells them apart, and `voidable` is what decides whether the kill switch is
 * offered. Neither the decedent nor the reporter user id is requestable: the BFF
 * drops both, so there is no field here to ask for.
 *
 * `resolution` is selected on every case-shaped operation ON PURPOSE. The DDL
 * forces a voided case to carry the status `rejected_fraud`, so a surface that
 * renders `status` without `resolution` tells the person who just closed a
 * fraudulent case about themselves that fraud was found against them.
 */
export const SETTLEMENT_CASES_QUERY = `query SettlementCases {
  settlementCases {
    caseId
    status
    reportSource
    evidenceCount
    waitingPeriodEnds
    resolution
    resolvedAt
    createdAt
    aboutMe
    voidable
  }
}`;

export const VOID_SETTLEMENT_CASE_MUTATION = `mutation VoidSettlementCase($caseId: ID!) {
  voidSettlementCase(caseId: $caseId) {
    caseId
    status
    reportSource
    evidenceCount
    waitingPeriodEnds
    resolution
    resolvedAt
    createdAt
    aboutMe
    voidable
  }
}`;

/**
 * THE EXECUTOR SURFACE (M23 PR2).
 *
 * Every operation here is keyed on `caseId` and nothing else. Settlement
 * identifies an estate by `decedentUserId`; the BFF resolves the case id back
 * to one against settlement's own list, so this app never holds another
 * person's user id and never sends one. There is no field to ask for.
 *
 * `estateInventory` selects exactly the fields `assets` does, because it is the
 * SAME `Asset` type — the difference is the authorization behind it, not the
 * shape. A separate list type would have been a second thing to keep in step
 * with the service's one audited decrypt per row.
 */
export const EXECUTOR_CASES_QUERY = `query ExecutorCases {
  executorCases {
    caseId
    ownerName
    status
    verifiedAt
  }
}`;

export const ESTATE_STAGES_QUERY = `query EstateStages($caseId: ID!) {
  estateStages(caseId: $caseId) {
    stage
    status
    requestedAt
    decidedAt
  }
}`;

export const ESTATE_INVENTORY_QUERY = `query EstateInventory($caseId: ID!) {
  estateInventory(caseId: $caseId) {
    assetId
    category
    title
    estValue
    valuationAsOf
    valuationSource
    ownershipPct
    inTrust
    fundingStatus
    status
    retiredAt
    version
  }
}`;

export const REQUEST_ESTATE_ACCESS_MUTATION = `mutation RequestEstateAccess($caseId: ID!, $stage: AccessStage!) {
  requestEstateAccess(caseId: $caseId, stage: $stage) {
    stage
    status
    requestedAt
    decidedAt
  }
}`;

/**
 * THE ESTATE CHECKLIST (M23 PR3).
 *
 * `completedAt` and nothing about WHO — the BFF has no such field to ask for,
 * because settlement answers it with a raw user UUID. Co-executors are real, so
 * the question is real, but a UUID is not an answer a reader can use.
 *
 * The tick and the untick are ONE mutation with a boolean, not two, so the
 * server cannot grow a path to complete that has no matching path to correct.
 */
/**
 * THE ESTATE'S CONTACT CARDS (M23 PR4a) — docs/03 §5.4's phishing control.
 *
 * Selects the SUMMARY fields only. There is no `estateContact(contactId:)`
 * detail read on this surface and deliberately so: an executor needs to know
 * WHO the estate's attorney is in order to recognise an impostor, and that is
 * a name and a role. Their email and phone are several more audited decrypts
 * on a dead person's trail, bought for a reason nobody has yet stated.
 */
export const ESTATE_CONTACTS_QUERY = `query EstateContacts($caseId: ID!) {
  estateContacts(caseId: $caseId) {
    id
    name
    relationship
    professionalKind
    hasEmail
    hasPhone
    hasAddress
    hasNotes
    linked
  }
}`;

export const ESTATE_TASKS_QUERY = `query EstateTasks($caseId: ID!) {
  estateTasks(caseId: $caseId) {
    taskId
    title
    category
    assignedRole
    dueAt
    completedAt
  }
}`;

export const SET_ESTATE_TASK_COMPLETION_MUTATION = `mutation SetEstateTaskCompletion($taskId: ID!, $completed: Boolean!) {
  setEstateTaskCompletion(taskId: $taskId, completed: $completed) {
    taskId
    title
    category
    assignedRole
    dueAt
    completedAt
  }
}`;

/**
 * WHAT THE ESTATE HAS PLANNED OR PAID OUT (M23 PR4b).
 *
 * NO AMOUNT IN THE SELECTION SET, and that is a decrypt-budget decision rather
 * than a secrecy one: `hasAmount` is a boolean the service reads off a column,
 * while the figure is one audited decrypt on the DECEDENT's own key plus an
 * event on their trail. A list of eight distributions rendered with amounts
 * would spend eight of both for a page nobody had asked a question about
 * (docs/03 §6f — no content field on a list type, no prefetch).
 *
 * NO ACTOR IDS either, because the BFF has none to give: settlement answers
 * with `createdBy` and `approvedBy`, and the second names a member of staff.
 */
export const ESTATE_DISTRIBUTIONS_QUERY = `query EstateDistributions($caseId: ID!) {
  estateDistributions(caseId: $caseId) {
    distributionId
    beneficiaryContactId
    assetId
    status
    approvedAt
    hasAmount
    createdAt
  }
}`;

/**
 * ONE AMOUNT, ASKED FOR DELIBERATELY (M23 PR4b).
 *
 * Its own document, so a reveal is always an act somebody took rather than a
 * side effect of a list rendering. The id comes BACK with the figure, so the
 * screen cannot pin an amount to a row it was not read from.
 */
export const ESTATE_DISTRIBUTION_AMOUNT_QUERY = `query EstateDistributionAmount($distributionId: ID!) {
  estateDistributionAmount(distributionId: $distributionId) {
    distributionId
    amount
  }
}`;

/**
 * RECORD ONE (M23 PR4b). Step-up gated — it plans a transfer of value out of a
 * dead person's estate.
 *
 * It records; it never approves. The row comes back 'planned' and stays there
 * until an operator clears it under dual control, which is why the selection
 * set asks for `status` — the screen shows what the server actually did rather
 * than what the form assumed.
 */
export const RECORD_ESTATE_DISTRIBUTION_MUTATION = `mutation RecordEstateDistribution($caseId: ID!, $beneficiaryContactId: ID!, $assetId: ID, $amount: String) {
  recordEstateDistribution(caseId: $caseId, beneficiaryContactId: $beneficiaryContactId, assetId: $assetId, amount: $amount) {
    distributionId
    beneficiaryContactId
    assetId
    status
    approvedAt
    hasAmount
    createdAt
  }
}`;

/** Move an APPROVED distribution on, or dispute it (M23 PR4b). Step-up gated. */
export const SET_ESTATE_DISTRIBUTION_STATUS_MUTATION = `mutation SetEstateDistributionStatus($distributionId: ID!, $status: EstateDistributionStatusChange!) {
  setEstateDistributionStatus(distributionId: $distributionId, status: $status) {
    distributionId
    beneficiaryContactId
    assetId
    status
    approvedAt
    hasAmount
    createdAt
  }
}`;

export const SETTLEMENT_SETTINGS_QUERY = `query SettlementSettings {
  settlementSettings {
    waitingPeriodDays
  }
}`;

export const SET_SETTLEMENT_WAITING_PERIOD_MUTATION = `mutation SetSettlementWaitingPeriod($days: Int!) {
  setSettlementWaitingPeriod(days: $days) {
    waitingPeriodDays
  }
}`;

/**
 * The estates that name you (M22 PR4a) — the reverse of CONTACTS_QUERY.
 *
 * 'ownerName' is nullable and the null means the owner never saved a profile.
 * Render it as an estate without a name; never as "Unknown", which would be
 * this app asserting something the server declined to say.
 */
export const LINKED_ESTATES_QUERY = `query LinkedEstates {
  linkedEstates {
    ownerUserId
    contactId
    ownerName
    roles
  }
}`;

/**
 * THE REPORTER'S PICKER (M22 PR4c).
 *
 * No user id is selected because the type has none: an estate is named by
 * `contactId` and the reporting mutation takes the same handle, so a death
 * report can be filed without another person's user id ever reaching this app.
 */
export const REPORTABLE_ESTATES_QUERY = `query ReportableEstates {
  reportableEstates {
    contactId
    ownerName
    roles
  }
}`;

/**
 * There is no `source` argument, and that is the service's rule respected
 * rather than a shortcut: a report carrying a death certificate IS a
 * `death_certificate_upload` and one without IS a `trusted_contact`. The BFF
 * derives it from the document, so the two facts cannot disagree.
 */
export const REPORT_DEATH_MUTATION = `mutation ReportDeath($contactId: ID!, $documentId: ID, $documentVersion: Int) {
  reportDeath(contactId: $contactId, documentId: $documentId, documentVersion: $documentVersion) {
    caseId
    status
    reportSource
    evidenceCount
    waitingPeriodEnds
    resolution
    resolvedAt
    createdAt
    aboutMe
    voidable
  }
}`;

export const ATTACH_CASE_EVIDENCE_MUTATION = `mutation AttachCaseEvidence($caseId: ID!, $documentId: ID!, $version: Int!) {
  attachCaseEvidence(caseId: $caseId, documentId: $documentId, version: $version) {
    caseId
    status
    reportSource
    evidenceCount
    waitingPeriodEnds
    resolution
    resolvedAt
    createdAt
    aboutMe
    voidable
  }
}`;

export const operations = {
  Register: REGISTER_MUTATION,
  Login: LOGIN_MUTATION,
  Refresh: REFRESH_MUTATION,
  Logout: LOGOUT_MUTATION,
  TotpEnroll: TOTP_ENROLL_MUTATION,
  TotpVerify: TOTP_VERIFY_MUTATION,
  StepUp: STEP_UP_MUTATION,
  StartVaultHandoff: START_VAULT_HANDOFF_MUTATION,
  StartOperatorHandoff: START_OPERATOR_HANDOFF_MUTATION,
  ExportDemo: EXPORT_DEMO_MUTATION,
  EmailVerification: EMAIL_VERIFICATION_QUERY,
  ResendEmailVerification: RESEND_EMAIL_VERIFICATION_MUTATION,
  VerifyEmail: VERIFY_EMAIL_MUTATION,
  ChangePassword: CHANGE_PASSWORD_MUTATION,
  RequestEmailChange: REQUEST_EMAIL_CHANGE_MUTATION,
  CompleteEmailChange: COMPLETE_EMAIL_CHANGE_MUTATION,
  CancelEmailChange: CANCEL_EMAIL_CHANGE_MUTATION,
  AccountErasure: ACCOUNT_ERASURE_QUERY,
  RequestAccountErasure: REQUEST_ACCOUNT_ERASURE_MUTATION,
  CancelAccountErasure: CANCEL_ACCOUNT_ERASURE_MUTATION,
  RequestPasswordReset: REQUEST_PASSWORD_RESET_MUTATION,
  CompletePasswordReset: COMPLETE_PASSWORD_RESET_MUTATION,
  Session: SESSION_QUERY,
  Sessions: SESSIONS_QUERY,
  RevokeSession: REVOKE_SESSION_MUTATION,
  StartExtensionPairing: START_EXTENSION_PAIRING_MUTATION,
  Passkeys: PASSKEYS_QUERY,
  WebauthnRegisterOptions: WEBAUTHN_REGISTER_OPTIONS_MUTATION,
  WebauthnRegister: WEBAUTHN_REGISTER_MUTATION,
  WebauthnStepUpOptions: WEBAUTHN_STEP_UP_OPTIONS_MUTATION,
  WebauthnStepUp: WEBAUTHN_STEP_UP_MUTATION,
  RevokePasskey: REVOKE_PASSKEY_MUTATION,
  RenamePasskey: RENAME_PASSKEY_MUTATION,
  Assets: ASSETS_QUERY,
  Asset: ASSET_QUERY,
  AssetHistory: ASSET_HISTORY_QUERY,
  NetWorth: NET_WORTH_QUERY,
  CreateAsset: CREATE_ASSET_MUTATION,
  UpdateAsset: UPDATE_ASSET_MUTATION,
  RecordValuation: RECORD_VALUATION_MUTATION,
  ChangeOwnership: CHANGE_OWNERSHIP_MUTATION,
  RetireAsset: RETIRE_ASSET_MUTATION,
  AssetBeneficiaries: ASSET_BENEFICIARIES_QUERY,
  DesignateBeneficiary: DESIGNATE_BENEFICIARY_MUTATION,
  RemoveBeneficiary: REMOVE_BENEFICIARY_MUTATION,
  Readiness: READINESS_QUERY,
  Consents: CONSENTS_QUERY,
  GrantConsent: GRANT_CONSENT_MUTATION,
  RevokeConsent: REVOKE_CONSENT_MUTATION,
  Conversations: CONVERSATIONS_QUERY,
  Conversation: CONVERSATION_QUERY,
  StartConversation: START_CONVERSATION_MUTATION,
  SendMessage: SEND_MESSAGE_MUTATION,
  DeleteConversation: DELETE_CONVERSATION_MUTATION,
  DocumentTemplates: DOCUMENT_TEMPLATES_QUERY,
  Documents: DOCUMENTS_QUERY,
  Document: DOCUMENT_QUERY,
  DocumentVersions: DOCUMENT_VERSIONS_QUERY,
  DocumentContent: DOCUMENT_CONTENT_QUERY,
  GenerateDocument: GENERATE_DOCUMENT_MUTATION,
  RegenerateDocument: REGENERATE_DOCUMENT_MUTATION,
  DocumentSearch: DOCUMENT_SEARCH_QUERY,
  UploadDocument: UPLOAD_DOCUMENT_MUTATION,
  SetDocumentStatus: SET_DOCUMENT_STATUS_MUTATION,
  DeleteDocument: DELETE_DOCUMENT_MUTATION,
  Profile: PROFILE_QUERY,
  SaveProfile: SAVE_PROFILE_MUTATION,
  FamilyMembers: FAMILY_MEMBERS_QUERY,
  AddFamilyMember: ADD_FAMILY_MEMBER_MUTATION,
  DeleteFamilyMember: DELETE_FAMILY_MEMBER_MUTATION,
  Contacts: CONTACTS_QUERY,
  Contact: CONTACT_QUERY,
  AddContact: ADD_CONTACT_MUTATION,
  UpdateContact: UPDATE_CONTACT_MUTATION,
  DeleteContact: DELETE_CONTACT_MUTATION,
  RoleAssignments: ROLE_ASSIGNMENTS_QUERY,
  GrantRole: GRANT_ROLE_MUTATION,
  RevokeRole: REVOKE_ROLE_MUTATION,
  RolePermissions: ROLE_PERMISSIONS_QUERY,
  GrantRolePermission: GRANT_ROLE_PERMISSION_MUTATION,
  RevokeRolePermission: REVOKE_ROLE_PERMISSION_MUTATION,
  InviteContactLink: INVITE_CONTACT_LINK_MUTATION,
  RevokeContactLinkInvitation: REVOKE_CONTACT_LINK_INVITATION_MUTATION,
  UnlinkContact: UNLINK_CONTACT_MUTATION,
  RedeemContactLink: REDEEM_CONTACT_LINK_MUTATION,
  LinkedEstates: LINKED_ESTATES_QUERY,
  ReportableEstates: REPORTABLE_ESTATES_QUERY,
  ReportDeath: REPORT_DEATH_MUTATION,
  AttachCaseEvidence: ATTACH_CASE_EVIDENCE_MUTATION,
  SettlementCases: SETTLEMENT_CASES_QUERY,
  VoidSettlementCase: VOID_SETTLEMENT_CASE_MUTATION,
  SettlementSettings: SETTLEMENT_SETTINGS_QUERY,
  SetSettlementWaitingPeriod: SET_SETTLEMENT_WAITING_PERIOD_MUTATION,
  ExecutorCases: EXECUTOR_CASES_QUERY,
  EstateStages: ESTATE_STAGES_QUERY,
  EstateInventory: ESTATE_INVENTORY_QUERY,
  RequestEstateAccess: REQUEST_ESTATE_ACCESS_MUTATION,
  EstateContacts: ESTATE_CONTACTS_QUERY,
  EstateTasks: ESTATE_TASKS_QUERY,
  SetEstateTaskCompletion: SET_ESTATE_TASK_COMPLETION_MUTATION,
  EstateDistributions: ESTATE_DISTRIBUTIONS_QUERY,
  EstateDistributionAmount: ESTATE_DISTRIBUTION_AMOUNT_QUERY,
  RecordEstateDistribution: RECORD_ESTATE_DISTRIBUTION_MUTATION,
  SetEstateDistributionStatus: SET_ESTATE_DISTRIBUTION_STATUS_MUTATION,
} as const;

export type OperationName = keyof typeof operations;
