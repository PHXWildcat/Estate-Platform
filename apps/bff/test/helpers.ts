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
import type { BffConfig } from '../src/config';
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

export interface TestAppOptions {
  config?: BffConfig;
  identity?: IdentityClient;
  assets?: AssetsClient;
  manifest?: PersistedOperationsManifest;
}

export async function makeApp(options: TestAppOptions = {}): Promise<INestApplication> {
  const app = await createBffApp({
    config: options.config ?? testConfig(),
    identity: options.identity ?? new FakeIdentityClient(),
    assets: options.assets ?? new FakeAssetsClient(),
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
