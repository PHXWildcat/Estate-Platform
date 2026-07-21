import { GraphQLError } from 'graphql';
import { z } from 'zod';
import { MfaLevelSchema, type MfaLevel } from '@estate/contracts';

/**
 * Client for the identity service's internal REST API (apps/services/identity).
 *
 * Error handling contract: identity's generic machine-readable error tokens
 * are mapped onto a small set of GraphQL error codes. Raw identity response
 * text is NEVER forwarded to GraphQL clients — unknown/5xx responses become a
 * plain Error, which yoga's maskedErrors turns into a generic message.
 */

export interface IssuedTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly sessionId: string;
  readonly userId: string;
}

export interface IdentitySession {
  readonly userId: string;
  readonly sessionId: string;
  readonly mfaLevel: MfaLevel;
  /** ISO timestamp, or null when the session has no active step-up. */
  readonly stepupExpiresAt: string | null;
}

export interface TotpEnrollment {
  readonly otpauthUri: string;
}

export interface IdentityClient {
  register(email: string, password: string): Promise<void>;
  login(email: string, password: string): Promise<IssuedTokens>;
  refresh(refreshToken: string): Promise<IssuedTokens>;
  /** Returns null when the access token is invalid/expired (identity 401). */
  session(accessToken: string): Promise<IdentitySession | null>;
  totpEnroll(accessToken: string): Promise<TotpEnrollment>;
  totpVerify(accessToken: string, code: string): Promise<void>;
  stepUp(accessToken: string, code: string): Promise<void>;
  exportDemo(accessToken: string): Promise<void>;
}

export type BffErrorCode =
  'UNAUTHENTICATED' | 'STEPUP_REQUIRED' | 'INVALID_REQUEST' | 'INVALID_CREDENTIALS';

const ERROR_MESSAGES: Record<BffErrorCode, string> = {
  UNAUTHENTICATED: 'Not authenticated',
  STEPUP_REQUIRED: 'Step-up verification required',
  INVALID_REQUEST: 'Invalid request',
  INVALID_CREDENTIALS: 'Invalid credentials',
};

/** GraphQLError with a stable machine-readable code; safe to expose. */
export function bffError(code: BffErrorCode): GraphQLError {
  return new GraphQLError(ERROR_MESSAGES[code], { extensions: { code } });
}

const TokensSchema = z.object({
  accessToken: z.string().min(1),
  refreshToken: z.string().min(1),
  sessionId: z.string().min(1),
  userId: z.string().min(1),
});

const SessionSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().min(1),
  mfaLevel: MfaLevelSchema,
  stepupExpiresAt: z.string().nullable(),
});

const EnrollSchema = z.object({
  methodId: z.string().min(1),
  otpauthUri: z.string().min(1),
});

const ErrorBodySchema = z.object({ error: z.string() });

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

interface RequestOptions {
  method: 'GET' | 'POST';
  path: string;
  accessToken?: string;
  body?: Record<string, string>;
}

export class FetchIdentityClient implements IdentityClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  async register(email: string, password: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/register',
      body: { email, password },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async login(email: string, password: string): Promise<IssuedTokens> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email, password },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, TokensSchema);
  }

  async refresh(refreshToken: string): Promise<IssuedTokens> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/refresh',
      body: { refreshToken },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, TokensSchema);
  }

  async session(accessToken: string): Promise<IdentitySession | null> {
    const res = await this.request({ method: 'GET', path: '/v1/auth/session', accessToken });
    if (res.status === 401) {
      // Invalid/expired token ⇒ "not authenticated", not an error.
      return null;
    }
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, SessionSchema);
  }

  async totpEnroll(accessToken: string): Promise<TotpEnrollment> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/totp/enroll', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const { otpauthUri } = await this.parseBody(res, EnrollSchema);
    return { otpauthUri };
  }

  async totpVerify(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/totp/verify',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async stepUp(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/stepup',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async exportDemo(accessToken: string): Promise<void> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/export-demo', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  private async request(options: RequestOptions): Promise<Response> {
    const headers: Record<string, string> = {};
    if (options.accessToken !== undefined) {
      headers.authorization = `Bearer ${options.accessToken}`;
    }
    const init: RequestInit = { method: options.method, headers };
    if (options.body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    try {
      return await this.fetchFn(`${this.baseUrl}${options.path}`, init);
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('identity service unreachable');
    }
  }

  /**
   * Maps identity's generic error tokens to stable GraphQL error codes.
   * Anything unrecognized (5xx, malformed) becomes a plain Error so yoga's
   * error masking replaces it with a generic message.
   */
  private async mapError(res: Response): Promise<Error> {
    let token = '';
    try {
      const body: unknown = await res.json();
      const parsed = ErrorBodySchema.safeParse(body);
      if (parsed.success) {
        token = parsed.data.error;
      }
    } catch {
      // Non-JSON body: fall through to status-based mapping.
    }
    if (res.status === 401) {
      return token === 'invalid_credentials' || token === 'invalid_code'
        ? bffError('INVALID_CREDENTIALS')
        : bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    if (res.status === 400) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`identity responded with status ${res.status}`);
  }

  private async parseBody<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('identity response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Field paths only — never response values.
      throw new Error('identity response failed validation');
    }
    return parsed.data as z.infer<T>;
  }
}
