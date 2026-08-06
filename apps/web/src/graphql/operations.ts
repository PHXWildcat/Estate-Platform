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

export const operations = {
  Register: REGISTER_MUTATION,
  Login: LOGIN_MUTATION,
  Refresh: REFRESH_MUTATION,
  Logout: LOGOUT_MUTATION,
  TotpEnroll: TOTP_ENROLL_MUTATION,
  TotpVerify: TOTP_VERIFY_MUTATION,
  StepUp: STEP_UP_MUTATION,
  ExportDemo: EXPORT_DEMO_MUTATION,
  Session: SESSION_QUERY,
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
} as const;

export type OperationName = keyof typeof operations;
