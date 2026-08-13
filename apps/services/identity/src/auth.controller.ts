import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { MfaLevel } from '@estate/contracts';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { z } from 'zod';
import { AuthService, type IssuedTokens, type StepUpResult } from './auth.service';
import { EmailVerificationService, type ReissueOutcome } from './email-verification.service';
import { ExtensionPairingService } from './extension-pairing.service';
import { HandoffService, type MintedHandoff } from './handoff.service';
import { AllowSessionAudiences } from './session-audience.decorator';
import { SessionGuard, type AuthedRequest, type SessionContext } from './session.guard';
import { StepUpGuard } from './stepup.guard';
import { WebAuthnService } from './webauthn.service';

const RegisterSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(256),
});

// Login deliberately validates only shape, not email format: a malformed
// identifier must take the same code path (and produce the same generic 401)
// as a well-formed unknown one.
const LoginSchema = z.object({
  email: z.string().min(1).max(320),
  password: z.string().min(1).max(1024),
});

const RefreshSchema = z.object({
  refreshToken: z.string().min(1).max(1024),
});

/**
 * The password-change wire (M17 PR2).
 *
 * `currentPassword` is bounded only for shape and NOT held to the new-password
 * minimum: it has to admit whatever the account already has, including a
 * password minted before any rule existed, or a user whose password predates a
 * tightening could never change it — which is precisely the user who should.
 * `newPassword` gets the registration rule, from the same numbers, because a
 * change that could weaken a password below what registration demands would
 * make the rule advisory.
 */
const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(1024),
  newPassword: z.string().min(12).max(256),
});

const CodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
});

/**
 * The vault handoff code (M15). Shape only, and generous: the AUTHORITY is the
 * digest lookup, so a strict alphabet here would add a second place for the
 * encoding to drift and a shape rejection that differed from a wrong-code
 * rejection would reintroduce the oracle the uniform answer removes. The bound
 * exists so an unbounded body cannot be hashed.
 */
const HandoffCodeSchema = z.object({
  code: z.string().min(1).max(256),
});

/**
 * The extension pairing code (M16). Shape only and generous, for the handoff's
 * reason: the AUTHORITY is the digest lookup, the length is measured on the
 * CANONICAL form inside the service, and a shape rejection that differed from a
 * wrong-code rejection would be a free oracle for the format.
 */
const PairingCodeSchema = z.object({
  code: z.string().min(1).max(128),
});

/**
 * The mailed verification code. Shape only, bounded generously: the AUTHORITY
 * is the digest lookup and the length is measured on the CANONICAL form inside
 * the service, so a strict pattern here would only add a second place for the
 * alphabet to drift — and a shape rejection that differed from a wrong-code
 * rejection would be a free oracle for the format (M13's reasoning).
 */
const VerificationCodeSchema = z.object({
  code: z.string().min(1).max(128),
});

// WebAuthn ceremony responses are validated for shape only here; the security
// verification (challenge, origin, signature, counter) happens in the service
// via @simplewebauthn/server. The nested `response`/`clientExtensionResults`
// objects are passed through and interpreted by the library.
const WebAuthnResponseSchema = z
  .object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    response: z.object({}).passthrough(),
    type: z.literal('public-key'),
    clientExtensionResults: z.object({}).passthrough(),
    authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
  })
  .passthrough();

/**
 * A path parameter is untrusted input exactly as a body is, so it is parsed the
 * same way and refused with the same token. Not a security control on its own —
 * the value travels as a bound SQL parameter regardless — but a malformed id
 * should be `invalid_request` at the edge rather than a miss deep in a query
 * that then reads as "no such session".
 */
const UuidSchema = z.string().uuid();

function parseParam<T extends z.ZodTypeAny>(schema: T, value: unknown): z.infer<T> {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

function parseBody<T extends z.ZodTypeAny>(schema: T, body: unknown): z.infer<T> {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    // Field names only — never echo submitted values.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data as z.infer<T>;
}

function requireAuth(request: AuthedRequest): SessionContext {
  const auth = request.auth;
  if (!auth) {
    // Unreachable behind SessionGuard; guards against wiring mistakes.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return auth;
}

@Controller('v1/auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly webauthn: WebAuthnService,
    private readonly emailVerification: EmailVerificationService,
    private readonly handoff: HandoffService,
    private readonly extensionPairing: ExtensionPairingService,
  ) {}

  @Post('register')
  @HttpCode(201)
  async register(@Body() body: unknown): Promise<{ status: string }> {
    const { email, password } = parseBody(RegisterSchema, body);
    await this.auth.register(email, password);
    // Identical response whether or not the email already had an account.
    return { status: 'ok' };
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: unknown): Promise<IssuedTokens> {
    const { email, password } = parseBody(LoginSchema, body);
    return this.auth.login(email, password);
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Body() body: unknown): Promise<IssuedTokens> {
    const { refreshToken } = parseBody(RefreshSchema, body);
    return this.auth.refresh(refreshToken);
  }

  /**
   * Session introspection for the BFF and for every downstream service's
   * `HttpSessionVerifier`: context of the presented token only.
   *
   * ADMITS EVERY AUDIENCE (M15), and must. This route is how a token becomes a
   * verified caller anywhere in the product, so refusing a vault session here
   * would not tighten the boundary — it would make the vault audience unusable
   * and take the whole isolated origin down. It ACTS on no authority: it reads
   * a session and describes it, `audience` included, which is precisely what
   * lets the callers downstream apply the deny-by-default rule.
   */
  @Get('session')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  @AllowSessionAudiences('vault', 'extension')
  session(@Req() request: AuthedRequest): {
    userId: string;
    sessionId: string;
    mfaLevel: MfaLevel;
    stepupExpiresAt: string | null;
    audience: string;
  } {
    const auth = requireAuth(request);
    return {
      userId: auth.userId,
      sessionId: auth.sessionId,
      mfaLevel: auth.mfaLevel,
      stepupExpiresAt: auth.stepupExpiresAt?.toISOString() ?? null,
      audience: auth.audience,
    };
  }

  /**
   * Logout: revokes the PRESENTED session only (other devices stay live).
   *
   * Admits a vault session (M15) so the vault origin can sign itself out.
   * Revoking the credential you are holding is the one action that can only
   * ever reduce authority, and the M6 rule is that the protective action must
   * never be the harder one.
   */
  @Post('logout')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  @AllowSessionAudiences('vault', 'extension')
  async logout(@Req() request: AuthedRequest): Promise<{ status: string }> {
    const auth = requireAuth(request);
    await this.auth.logout(auth.userId, auth.sessionId);
    return { status: 'ok' };
  }

  /**
   * Logout by REFRESH token — deliberately NOT behind SessionGuard.
   *
   * SessionGuard requires a live ACCESS token (15 min), but a session and its
   * refresh token live 30 days, so the guarded route above cannot revoke the
   * ordinary case of a tab left open. Presenting the refresh token IS the
   * authorization here: it is the same credential `POST /refresh` accepts to
   * mint a new access token, and this route only ever DESTROYS the session it
   * resolves — the strictly safer of the two things that credential can do.
   *
   * Returns 200 whether or not a session was found: an unresolvable refresh
   * token is already logged out, and distinguishing the two would turn this
   * into an oracle for whether a captured token is still live.
   */
  @Post('logout/refresh')
  @HttpCode(200)
  async logoutByRefresh(@Body() body: unknown): Promise<{ status: string }> {
    const { refreshToken } = parseBody(RefreshSchema, body);
    await this.auth.logoutByRefreshToken(refreshToken);
    return { status: 'ok' };
  }

  /**
   * Whether the delivery store can provably reach this user (M14).
   *
   * A DEDICATED ROUTE rather than a field on `GET /v1/auth/session`. That route
   * is the cross-service introspection hot path — every guarded request in
   * every downstream service resolves through it — and giving it a
   * notifications round trip would put a second service on the critical path of
   * every authenticated call in the product. This one is read by a settings
   * page.
   *
   * `unavailable` is its own state, not a `false`: telling a user "your address
   * is unverified" during a notifications outage would send them to complete a
   * ceremony that cannot run.
   */
  @Get('email/verification')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async emailVerificationStatus(
    @Req() request: AuthedRequest,
  ): Promise<{ status: 'verified' | 'unverified' | 'unavailable' }> {
    const auth = requireAuth(request);
    const status = await this.emailVerification.status(auth.userId);
    if (status === null) {
      return { status: 'unavailable' };
    }
    return { status: status.verified ? 'verified' : 'unverified' };
  }

  /**
   * Send another code. Not step-up gated: it mails the address already on file
   * for the calling user and grants nothing — the strongest thing a caller
   * achieves is receiving their own mail. The floor between mints
   * (`REISSUE_FLOOR_MS`) is the rate limit, and `too_soon` is reported honestly
   * rather than dressed up as a send.
   */
  @Post('email/verification/resend')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async resendEmailVerification(
    @Req() request: AuthedRequest,
  ): Promise<{ outcome: ReissueOutcome }> {
    const auth = requireAuth(request);
    return { outcome: await this.emailVerification.reissue(auth.userId) };
  }

  /**
   * Redeem a mailed code. THE CODE IS THE ONLY SELECTOR — the body carries no
   * user id and no address, and the caller's own session supplies who they are.
   * Every failure is the same `invalid_code`.
   */
  @Post('email/verification/verify')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async verifyEmail(
    @Req() request: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ verified: true }> {
    const auth = requireAuth(request);
    const { code } = parseBody(VerificationCodeSchema, body);
    await this.emailVerification.verify(auth.userId, auth.sessionId, code);
    return { verified: true };
  }

  /**
   * Change the account password (M17 PR2).
   *
   * ACCOUNT AUDIENCE ONLY — undecorated, which is the deny-by-default answer.
   * A vault session and a browser-extension session must not be able to replace
   * the credential that mints them: both are derived, narrow-purpose
   * credentials, and letting either rewrite the account password would let a
   * leaked one chain itself into permanent control. `test/session-audience.spec.ts`
   * names that fact rather than leaving it to the sweep.
   *
   * NO `StepUpGuard`, and that is not an omission — the requirement is
   * CONDITIONAL on whether the account holds a verified factor, which a route
   * decorator cannot see. The service owns the condition and applies the
   * guard's own freshness predicate through `SecondFactorGate`, exactly as
   * `totp/enroll` does. `test/factor-routes.spec.ts` is what keeps a
   * service-level gate from being invisible to the fences that scan decorators.
   *
   * The CURRENT password is in the body because a stolen session does not carry
   * it; see `AuthService.changePassword` for why both halves are asked for.
   */
  @Post('password')
  @HttpCode(204)
  @UseGuards(SessionGuard)
  async changePassword(@Req() request: AuthedRequest, @Body() body: unknown): Promise<void> {
    const auth = requireAuth(request);
    const { currentPassword, newPassword } = parseBody(ChangePasswordSchema, body);
    await this.auth.changePassword(auth.userId, auth.sessionId, auth, currentPassword, newPassword);
  }

  @Post('totp/enroll')
  @HttpCode(201)
  @UseGuards(SessionGuard)
  async enrollTotp(
    @Req() request: AuthedRequest,
  ): Promise<{ methodId: string; otpauthUri: string }> {
    const auth = requireAuth(request);
    // NO `StepUpGuard` here, and that is not an omission: the requirement is
    // CONDITIONAL — an account with no verified factor has nothing to step up
    // with, so a guard would make the first enrolment unreachable. The service
    // owns the condition and applies the guard's own freshness predicate to the
    // session context the guard already attached. See `AuthService.enrollTotp`.
    return this.auth.enrollTotp(auth.userId, auth.sessionId, auth);
  }

  @Post('totp/verify')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async verifyTotp(
    @Req() request: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ verified: boolean }> {
    const auth = requireAuth(request);
    const { code } = parseBody(CodeSchema, body);
    await this.auth.verifyTotp(auth.userId, auth.sessionId, code);
    return { verified: true };
  }

  /**
   * Elevate the PRESENTED session. Admits a vault session (M15): the vault
   * origin has to be able to re-prove a factor when its five-minute window
   * lapses mid-session, and sending the user back across the origin boundary
   * for a fresh handoff would make deleting an item a navigation. Step-up
   * strengthens the session presenting it and confers nothing else — a
   * stepped-up vault session is still a vault session, and still reaches only
   * the vault service.
   */
  @Post('stepup')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  @AllowSessionAudiences('vault', 'extension')
  async stepUp(@Req() request: AuthedRequest, @Body() body: unknown): Promise<StepUpResult> {
    const auth = requireAuth(request);
    const { code } = parseBody(CodeSchema, body);
    return this.auth.stepUp(auth.userId, auth.sessionId, code);
  }

  /**
   * Mint a single-use code for the ISOLATED VAULT ORIGIN (M15, docs/03 TB6).
   *
   * SessionGuard + StepUpGuard, and deliberately account-audience only: a vault
   * session cannot mint another handoff, so a leaked one cannot chain itself
   * forward or reach a future second audience. The step-up here is docs/01 §5's
   * re-auth before vault access — and ONLY that. It does NOT carry into the
   * redeemed session: the M15 review found that a step-up-fresh redeemed
   * session let whoever held a stolen code reach `POST /v1/vault/reset`, which
   * is gated on step-up alone. The vault origin proves its own factor now.
   *
   * Returns the code IN THE BODY, never in a URL or a redirect: the app origin
   * puts it in a hidden field and the browser submits it by top-level POST, so
   * it never lands in history, a Referer, or an intermediary's access log.
   */
  @Post('handoff')
  @HttpCode(201)
  @UseGuards(SessionGuard, StepUpGuard)
  async mintHandoff(@Req() request: AuthedRequest): Promise<{ code: string; expiresAt: string }> {
    const auth = requireAuth(request);
    const minted: MintedHandoff = await this.handoff.mint(auth.userId, auth.sessionId);
    return { code: minted.code, expiresAt: minted.expiresAt.toISOString() };
  }

  /**
   * Spend one. UNAUTHENTICATED by construction — the code is the authority, and
   * there is no field in this request that could name an account (the M13 §6g
   * anti-enumeration shape).
   *
   * Every failure is one `invalid_code`: unknown, expired, already spent, and
   * lost a race are indistinguishable here and in the audit trail.
   */
  @Post('handoff/redeem')
  @HttpCode(200)
  async redeemHandoff(
    @Body() body: unknown,
  ): Promise<{ accessToken: string; userId: string; sessionId: string; expiresAt: string }> {
    const { code } = parseBody(HandoffCodeSchema, body);
    const redeemed = await this.handoff.redeem(code);
    return {
      accessToken: redeemed.accessToken,
      userId: redeemed.userId,
      sessionId: redeemed.sessionId,
      expiresAt: redeemed.expiresAt.toISOString(),
    };
  }

  /**
   * The caller's live sessions — the paired-devices surface (M16).
   *
   * ACCOUNT AUDIENCE ONLY (undecorated = deny by default). An extension has no
   * business enumerating the user's other devices: its whole reach is five
   * vault routes and three identity ones, and a list of live credentials is
   * reconnaissance rather than something it needs to function.
   */
  @Get('sessions')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async listSessions(@Req() request: AuthedRequest): Promise<{
    sessions: Array<{
      sessionId: string;
      audience: string;
      createdAt: string;
      expiresAt: string;
      current: boolean;
    }>;
  }> {
    const auth = requireAuth(request);
    return { sessions: await this.auth.listSessions(auth.userId, auth.sessionId) };
  }

  /**
   * Revoke one of the caller's own sessions.
   *
   * NO StepUpGuard, deliberately — the M6 rule that the protective action must
   * never be harder than the permissive one. Minting a pairing is step-up
   * gated; killing one is a single click, because a user who believes their
   * extension is compromised must not be sent to find an authenticator first.
   *
   * A UNIFORM 404 covers "no such session" and "not yours" alike; the owner
   * predicate is in the UPDATE, so this is not a check-then-act and the answer
   * is no oracle for whether an id names a real session.
   */
  @Delete('sessions/:sessionId')
  @HttpCode(204)
  @UseGuards(SessionGuard)
  async revokeSession(
    @Req() request: AuthedRequest,
    @Param('sessionId') sessionId: string,
  ): Promise<void> {
    const auth = requireAuth(request);
    await this.auth.revokeOwnSession(auth.userId, parseParam(UuidSchema, sessionId));
  }

  /**
   * Mint a pairing code for the BROWSER EXTENSION (M16).
   *
   * SessionGuard + StepUpGuard, and ACCOUNT AUDIENCE ONLY — undecorated, which
   * is the deny-by-default answer. That is the same posture as `mintHandoff`
   * and for a stronger reason: this ceremony produces a credential with a REAL
   * refresh token, so a non-account session able to mint one could chain a
   * short-lived credential into a long-lived one. `test/session-audience.spec.ts`
   * names the fact rather than leaving it to the sweep.
   *
   * The code is returned IN THE BODY, for the app origin to display and the
   * user to type into the extension. It is never put in a URL, so it does not
   * land in history, a Referer, or an intermediary's access log.
   */
  @Post('extension/pairing')
  @HttpCode(201)
  @UseGuards(SessionGuard, StepUpGuard)
  async mintExtensionPairing(
    @Req() request: AuthedRequest,
  ): Promise<{ code: string; expiresAt: string }> {
    const auth = requireAuth(request);
    const minted = await this.extensionPairing.mint(auth.userId, auth.sessionId);
    return { code: minted.code, expiresAt: minted.expiresAt.toISOString() };
  }

  /**
   * Spend one. UNAUTHENTICATED by construction — the extension has no session
   * yet, so the code is the authority and there is no field in this request
   * that could name an account (the M13 §6g anti-enumeration shape).
   *
   * Every failure is one `invalid_code`: unknown, expired, already spent,
   * revoked, mis-shaped and lost-a-race are indistinguishable here and in the
   * audit trail.
   */
  @Post('extension/pairing/redeem')
  @HttpCode(200)
  async redeemExtensionPairing(@Body() body: unknown): Promise<{
    accessToken: string;
    refreshToken: string;
    userId: string;
    sessionId: string;
    expiresAt: string;
  }> {
    const { code } = parseBody(PairingCodeSchema, body);
    const paired = await this.extensionPairing.redeem(code);
    return {
      accessToken: paired.accessToken,
      refreshToken: paired.refreshToken,
      userId: paired.userId,
      sessionId: paired.sessionId,
      expiresAt: paired.expiresAt.toISOString(),
    };
  }

  /**
   * WebAuthn registration — step 1: mint + persist a challenge, return the
   * creation options the browser passes to navigator.credentials.create().
   * Session-scoped (M2): the passkey is bound to the authenticated user.
   */
  @Post('webauthn/register/options')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async webauthnRegisterOptions(
    @Req() request: AuthedRequest,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const auth = requireAuth(request);
    // The gate is CONDITIONAL on account state, so it lives in the service
    // and needs the context SessionGuard attached. See `SecondFactorGate`.
    return this.webauthn.startRegistration(auth.userId, auth);
  }

  /** WebAuthn registration — step 2: verify attestation, persist the credential. */
  @Post('webauthn/register/verify')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async webauthnRegisterVerify(
    @Req() request: AuthedRequest,
    @Body() body: unknown,
  ): Promise<{ verified: true }> {
    const auth = requireAuth(request);
    const response = parseBody(WebAuthnResponseSchema, body);
    // Shape-validated above; the library owns the semantic verification.
    return this.webauthn.finishRegistration(
      auth.userId,
      response as unknown as RegistrationResponseJSON,
      auth,
    );
  }

  /**
   * WebAuthn authentication — step 1: challenge for an assertion.
   *
   * SCOPING (M2): session-scoped by design — we require a live session
   * (SessionGuard) and derive the user from it, rather than accepting an
   * `{ email }` body. Passwordless discovery login (resident keys, no prior
   * session) is a larger feature deferred to a later milestone; see README.
   */
  @Post('webauthn/authenticate/options')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async webauthnAuthenticateOptions(
    @Req() request: AuthedRequest,
  ): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const auth = requireAuth(request);
    return this.webauthn.startAuthentication(auth.userId);
  }

  /**
   * WebAuthn authentication — step 2: verify the assertion and, on success,
   * elevate the session to a fresh step-up (a passkey is a valid step-up
   * factor per docs/01 §5). Failures return a single generic error.
   */
  @Post('webauthn/authenticate/verify')
  @HttpCode(200)
  @UseGuards(SessionGuard)
  async webauthnAuthenticateVerify(
    @Req() request: AuthedRequest,
    @Body() body: unknown,
  ): Promise<StepUpResult> {
    const auth = requireAuth(request);
    const response = parseBody(WebAuthnResponseSchema, body);
    return this.webauthn.finishAuthentication(
      auth.userId,
      auth.sessionId,
      response as unknown as AuthenticationResponseJSON,
    );
  }

  /**
   * Demo endpoint proving the step-up window end to end: reachable only with
   * a live session AND a fresh (≤5 min) step-up. Stands in for data export,
   * which is on the docs/01 §5 step-up-mandatory list.
   */
  @Post('export-demo')
  @HttpCode(204)
  @UseGuards(SessionGuard, StepUpGuard)
  exportDemo(): void {
    // 204 No Content — the guards are the feature.
  }
}
