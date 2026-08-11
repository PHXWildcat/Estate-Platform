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

export const LOGOUT_MUTATION = `mutation Logout {
  logout {
    ok
  }
}`;

export const ASSETS_QUERY = `query Assets {
  assets {
    assetId
    category
    title
    estValue
    ownershipPct
    inTrust
    version
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

export const CREATE_ASSET_MUTATION = `mutation CreateAsset($category: String!, $title: String!, $estValue: String, $valuationAsOf: String, $valuationSource: String) {
  createAsset(category: $category, title: $title, estValue: $estValue, valuationAsOf: $valuationAsOf, valuationSource: $valuationSource) {
    assetId
    version
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

export const operations = {
  Register: REGISTER_MUTATION,
  Login: LOGIN_MUTATION,
  Refresh: REFRESH_MUTATION,
  Logout: LOGOUT_MUTATION,
  TotpEnroll: TOTP_ENROLL_MUTATION,
  TotpVerify: TOTP_VERIFY_MUTATION,
  StepUp: STEP_UP_MUTATION,
  StartVaultHandoff: START_VAULT_HANDOFF_MUTATION,
  ExportDemo: EXPORT_DEMO_MUTATION,
  EmailVerification: EMAIL_VERIFICATION_QUERY,
  ResendEmailVerification: RESEND_EMAIL_VERIFICATION_MUTATION,
  VerifyEmail: VERIFY_EMAIL_MUTATION,
  Session: SESSION_QUERY,
  Sessions: SESSIONS_QUERY,
  RevokeSession: REVOKE_SESSION_MUTATION,
  StartExtensionPairing: START_EXTENSION_PAIRING_MUTATION,
  Assets: ASSETS_QUERY,
  NetWorth: NET_WORTH_QUERY,
  CreateAsset: CREATE_ASSET_MUTATION,
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
} as const;

export type OperationName = keyof typeof operations;
