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

/**
 * Whether the platform can PROVE it reaches this user (M14).
 *
 * Three states, not two, because `unavailable` is a fact about the platform
 * rather than about the user: telling somebody "your address is unverified"
 * during a notifications outage would send them to complete a ceremony that
 * cannot run, and telling them nothing at all would leave the arming gates
 * refusing with no explanation.
 */
export type EmailVerificationStatus = 'verified' | 'unverified' | 'unavailable';

/** What a resend attempt did — reported honestly rather than always "sent". */
export type ResendOutcome = 'sent' | 'too_soon' | 'already_verified' | 'unavailable';

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
  /** M14: has this user proved they receive mail at the stored address? */
  emailVerificationStatus(accessToken: string): Promise<EmailVerificationStatus>;
  /** M14: mail another code to the address already on file for this user. */
  resendEmailVerification(accessToken: string): Promise<ResendOutcome>;
  /** M14: redeem a mailed code. Throws INVALID_CREDENTIALS on any refusal. */
  verifyEmail(accessToken: string, code: string): Promise<void>;
  /**
   * Revokes exactly the presented session. Resolves false when identity
   * refuses the ACCESS token (401) — which means only that the 15-minute
   * token expired, NOT that the session is gone; use `logoutByRefresh`.
   */
  logout(accessToken: string): Promise<boolean>;
  /** Revokes the session behind a refresh token (the 30-day credential). */
  logoutByRefresh(refreshToken: string): Promise<void>;
}

export type BffErrorCode =
  | 'UNAUTHENTICATED'
  | 'STEPUP_REQUIRED'
  | 'INVALID_REQUEST'
  | 'INVALID_CREDENTIALS'
  /**
   * The assistant's UNIFORM not-found (M11). It covers "no such conversation"
   * and "someone else's conversation" identically, on purpose: a code that told
   * them apart would turn an id into an oracle for whether a given user has the
   * assistant and how much they use it. Named rather than folded into a generic
   * failure because a client still has to render "that conversation is gone".
   */
  | 'NOT_FOUND'
  /**
   * The `assistant.enabled` master switch is off (M11). Distinct from every
   * other refusal because it is the one the USER can fix, and telling them so
   * is the difference between a feature that looks broken and one that looks
   * gated.
   */
  | 'ASSISTANT_DISABLED'
  /**
   * No reviewed template exists for that instrument in that state (M12). A 404
   * like NOT_FOUND, and deliberately not folded into it: one is a fact about
   * the platform's catalog, the other a fact about the caller's own documents,
   * and only one of them is worth telling someone to pick a different state
   * over.
   */
  | 'TEMPLATE_NOT_FOUND'
  /**
   * The version's content DEK was crypto-shredded, so the ciphertext can never
   * be opened again (M12). Its own code because the answer is PERMANENT —
   * rendering it as a transient failure would have someone retry forever
   * against a key destroyed on purpose.
   */
  | 'CONTENT_ERASED'
  /**
   * Someone else advanced the document between read and write (M12). Distinct
   * from DOCUMENT_NOT_EDITABLE because the remedy is different: reload, then
   * try again.
   */
  | 'VERSION_CONFLICT'
  /**
   * Regeneration refused because signing has started (M12). A signed or
   * executed instrument's content is a legal record; the way forward is to
   * revoke or supersede it, not to rewrite it underneath the signatures.
   */
  | 'DOCUMENT_NOT_EDITABLE'
  /**
   * The document is preserved as part of an estate matter (M12 PR2). The one
   * refusal on this surface the owner cannot resolve by authenticating harder,
   * so it must not look like one that step-up would fix.
   */
  | 'LEGAL_HOLD'
  /**
   * The attested status is not the next rung of THIS document's ladder (M12
   * PR2) — a skipped witness or notary step, or a move from a terminal status.
   */
  | 'INVALID_TRANSITION'
  /**
   * A real scanner found a signature match (M12 PR2). Deliberately its own
   * code: it must never be softened into "unsupported file", because the user
   * is holding a file somebody sent them and needs to know why.
   */
  | 'MALWARE_DETECTED'
  /**
   * The bytes are not a format this platform accepts, or the declared type did
   * not match the magic bytes (M12 PR2). Nothing was stored.
   */
  | 'UNSUPPORTED_CONTENT'
  /**
   * The malware scanner could not be reached (M12 PR2). FAIL CLOSED: nothing
   * was stored, and the honest answer is "we could not check it".
   */
  | 'SCAN_UNAVAILABLE'
  /**
   * A contact still named by a live role assignment. Actionable and deliberately
   * distinct: deleting such a contact used to silently retire its fiduciary
   * designations (M13 PR1), so the refusal has to say what to do about it —
   * revoke the roles naming this person first.
   */
  | 'CONTACT_IN_USE'
  /** The contact already has a platform user linked to it (M13). */
  | 'ALREADY_LINKED'
  /**
   * A link code was refused. ONE code for every reason — unknown, expired,
   * spent, revoked, self-directed — because distinguishing them tells whoever is
   * holding a guess that it named something real (M13).
   */
  | 'INVALID_LINK_CODE'
  /**
   * Redemption refused because the owner could not be told about it. Not an
   * outage to work around: the notification IS the control that makes a claimed
   * link visible to the person whose estate it opens (M13).
   */
  | 'NOTIFICATIONS_UNAVAILABLE'
  /** That exact designation is already live on that contact (M13, migration 004). */
  | 'ROLE_ALREADY_GRANTED'
  /** That exact permission is already live on that role (M13, migration 005). */
  | 'PERMISSION_ALREADY_GRANTED'
  /**
   * M14's address-verification code was refused. The `INVALID_LINK_CODE`
   * shape, for the same reason: identity answers ONE `invalid_code` for
   * unknown, expired, spent, revoked, attempt-exhausted and
   * belonging-to-someone-else, and that uniformity IS the control — the edge
   * carries it through rather than re-deriving distinctions from status codes.
   *
   * Kept out of `INVALID_CREDENTIALS` deliberately. That token already means
   * "email and password" on the login surface, and the M12 review's finding
   * was precisely that one code changing meaning with the surface produces
   * copy telling a user to check a password on a form that has none.
   */
  | 'INVALID_VERIFICATION_CODE'
  /**
   * The platform could not complete a verification it otherwise accepted —
   * the delivery store has no live row to vouch for (never fed, soft-deleted,
   * crypto-shredded). Distinct from `INVALID_VERIFICATION_CODE` because the
   * code was fine and there is nothing for the user to re-check, and distinct
   * from `NOTIFICATIONS_UNAVAILABLE` because nothing is down.
   */
  | 'VERIFICATION_UNAVAILABLE';

const ERROR_MESSAGES: Record<BffErrorCode, string> = {
  UNAUTHENTICATED: 'Not authenticated',
  STEPUP_REQUIRED: 'Step-up verification required',
  INVALID_REQUEST: 'Invalid request',
  INVALID_CREDENTIALS: 'Invalid credentials',
  NOT_FOUND: 'Not found',
  ASSISTANT_DISABLED: 'The assistant is switched off',
  TEMPLATE_NOT_FOUND: 'No template available',
  CONTENT_ERASED: 'This content has been erased',
  VERSION_CONFLICT: 'This document changed since it was loaded',
  DOCUMENT_NOT_EDITABLE: 'This document can no longer be regenerated',
  LEGAL_HOLD: 'This document is under legal hold',
  INVALID_TRANSITION: 'That is not the next step for this document',
  MALWARE_DETECTED: 'That file was refused by the malware scanner',
  UNSUPPORTED_CONTENT: 'That file type is not accepted',
  SCAN_UNAVAILABLE: 'That file could not be checked for malware',
  CONTACT_IN_USE: 'This person still holds a role in your estate',
  ALREADY_LINKED: 'This person already has an account linked',
  INVALID_LINK_CODE: 'That invitation code was not accepted',
  NOTIFICATIONS_UNAVAILABLE: 'We cannot notify the account owner right now',
  ROLE_ALREADY_GRANTED: 'That role is already recorded for this person',
  PERMISSION_ALREADY_GRANTED: 'That permission is already allowed for this role',
  INVALID_VERIFICATION_CODE: 'That code was not accepted',
  VERIFICATION_UNAVAILABLE: 'We could not confirm that address right now',
};

/**
 * The machine-readable token from an error body, or '' when there is not one.
 * Shared so a mapper can look at the token WITHOUT consuming the response the
 * shared mapper will read again.
 */
async function readErrorToken(res: Response): Promise<string> {
  try {
    const parsed = ErrorBodySchema.safeParse(await res.json());
    return parsed.success ? parsed.data.error : '';
  } catch {
    return '';
  }
}

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

const VerificationStatusSchema = z.object({
  status: z.enum(['verified', 'unverified', 'unavailable']),
});

const ResendSchema = z.object({
  outcome: z.enum(['sent', 'too_soon', 'already_verified', 'unavailable']),
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

  async emailVerificationStatus(accessToken: string): Promise<EmailVerificationStatus> {
    const res = await this.request({
      method: 'GET',
      path: '/v1/auth/email/verification',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, VerificationStatusSchema)).status;
  }

  async resendEmailVerification(accessToken: string): Promise<ResendOutcome> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/verification/resend',
      accessToken,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return (await this.parseBody(res, ResendSchema)).outcome;
  }

  async verifyEmail(accessToken: string, code: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/email/verification/verify',
      accessToken,
      body: { code },
    });
    if (!res.ok) {
      // Every refusal identity makes here is the SAME `invalid_code`, and it
      // has to stay that way through the edge: unknown, expired, spent,
      // revoked, attempt-exhausted and belonging-to-someone-else must remain
      // indistinguishable, or the edge re-creates the oracle the uniform
      // answer removes from the service.
      throw await this.mapVerifyError(res);
    }
  }

  async exportDemo(accessToken: string): Promise<void> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/export-demo', accessToken });
    if (!res.ok) {
      throw await this.mapError(res);
    }
  }

  async logout(accessToken: string): Promise<boolean> {
    const res = await this.request({ method: 'POST', path: '/v1/auth/logout', accessToken });
    if (res.status === 401) {
      // The ACCESS token is dead. That is NOT "logged out": the session and
      // its 30-day refresh token are still live, and treating this as success
      // is the M8-review defect — it revoked nothing while telling the user
      // they were signed out. The caller must fall back to the refresh path.
      return false;
    }
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return true;
  }

  async logoutByRefresh(refreshToken: string): Promise<void> {
    const res = await this.request({
      method: 'POST',
      path: '/v1/auth/logout/refresh',
      body: { refreshToken },
    });
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
  /**
   * The verify route's two 400s mean different things to the person holding
   * the code, so they do not both collapse to INVALID_REQUEST. Everything
   * else falls through to the shared mapping.
   */
  private async mapVerifyError(res: Response): Promise<Error> {
    if (res.status === 400) {
      const token = await readErrorToken(res.clone());
      if (token === 'verification_unavailable') {
        return bffError('VERIFICATION_UNAVAILABLE');
      }
      return bffError('INVALID_VERIFICATION_CODE');
    }
    return this.mapError(res);
  }

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
