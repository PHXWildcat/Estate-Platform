import { randomUUID } from 'node:crypto';
import {
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  DEFAULT_SESSION_AUDIENCE,
  type SessionAudience,
  type SessionContext,
} from '@estate/auth-guard';
import {
  emailBlindIndex,
  normalizeEmail,
  type DekRepository,
  type FieldCrypto,
} from '@estate/crypto';
import { NOTIFICATIONS, type NotificationsPort } from '@estate/notifications-client';
import { AddressAttemptBound } from './address-bound';
import { AuthEventsRepo } from './auth-events.repo';
import type { IdentityConfig } from './config';
import { CLOCK, CONFIG, DEK_REPOSITORY, FIELD_CRYPTO, type Clock } from './di-tokens';
import { EmailVerificationService } from './email-verification.service';
import { EventsService } from './events.service';
import { MfaRepo } from './mfa.repo';
import { PasswordHasher } from './password';
import { SecondFactorGate } from './second-factor-gate';
import {
  LOGIN_ADDRESS_BOUND,
  LOGIN_BOUND,
  REGISTER_ADDRESS_BOUND,
  REGISTER_REFUSAL_KIND,
  STEP_UP_BOUND,
  type LedgerRateBound,
} from './rate-bounds';
import { SessionsRepo } from './sessions.repo';
import { ACCESS_TOKEN_TTL_MS, SESSION_TTL_MS, STEPUP_WINDOW_MS } from './stepup';
import { generateOpaqueToken, hashToken } from './tokens';
import { generateTotpSecretBase32, totpProvisioningUri, verifyTotpCode } from './totp';
import { UsersRepo } from './users.repo';

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  userId: string;
}

export interface StepUpResult {
  mfaLevel: 'stepup';
  stepupExpiresAt: string;
}

/** Field labels used in AAD + decrypt-audit events (IDs/enums only, no PII). */
const EMAIL_FIELD = 'users.email';
const TOTP_SECRET_FIELD = 'mfa_methods.totp_secret';

function invalidCredentials(): UnauthorizedException {
  return new UnauthorizedException({ error: 'invalid_credentials' });
}

@Injectable()
export class AuthService {
  constructor(
    private readonly users: UsersRepo,
    private readonly sessions: SessionsRepo,
    private readonly mfa: MfaRepo,
    private readonly authEvents: AuthEventsRepo,
    private readonly hasher: PasswordHasher,
    private readonly events: EventsService,
    @Inject(FIELD_CRYPTO) private readonly fieldCrypto: FieldCrypto,
    @Inject(DEK_REPOSITORY) private readonly deks: DekRepository,
    @Inject(CONFIG) private readonly config: IdentityConfig,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(NOTIFICATIONS) private readonly notifications: NotificationsPort,
    private readonly emailVerification: EmailVerificationService,
    private readonly factors: SecondFactorGate,
  ) {}

  /**
   * The two ADDRESS-keyed bounds, constructed here rather than provided.
   *
   * They are per-process state and Nest services are singletons, so an instance
   * field IS the process-wide bound — no module wiring, and the injected clock
   * (which every test already controls) reaches them for free. `rate-bounds.ts`
   * carries why they are in memory rather than on the ledger.
   */
  private readonly loginAddresses = new AddressAttemptBound(LOGIN_ADDRESS_BOUND, () =>
    this.clock(),
  );
  private readonly registerAddresses = new AddressAttemptBound(REGISTER_ADDRESS_BOUND, () =>
    this.clock(),
  );

  /**
   * Feed the notifications recipient store (M9) — fire-and-forget on the two
   * paths where the USER supplied the plaintext address, so no service ever
   * needs an email-ciphertext read path. Deliberately not awaited: the client
   * never throws and a notifications outage must not slow or block auth (on
   * register, an awaited call would also widen the documented enumeration
   * timing channel). A missed upsert self-heals at the next login; the send
   * log's no_recipient outcomes make persistent gaps visible.
   */
  private feedRecipientStore(userId: string, email: string): void {
    void this.notifications.upsertRecipient({ userId, email });
  }

  /**
   * Ask the user to prove they own that address (M14) — LOGIN ONLY.
   *
   * NOT at registration, which is unauthenticated: a notification kind firing
   * there would be a mail-bomb primitive addressable by anyone holding a
   * victim's address. (This used to add "and this repo has no rate-limiting
   * machinery to bound it", which M17 made false — register now carries an
   * address-keyed bound. The decision stands on the first clause alone: that
   * bound is per-process and best-effort, which is not what a mail-bomb defence
   * should rest on.) docs/03 §6c's mitigation, "no notification kind fires at
   * registration", stays literally true.
   *
   * CHAINED ONTO THE UPSERT, not fired beside it. The verification send
   * resolves the address from the recipient store, so on a user's FIRST login
   * the two racing would leave the send with nothing to mail — a
   * `no_recipient` outcome and a burned code — every time. Chaining orders them
   * without awaiting either: the whole chain is still fire-and-forget, so login
   * latency is never coupled to SES.
   *
   * The `ensureVerificationRequested` half is idempotent (it mints only when
   * the address is unverified and no live code exists), which is what keeps
   * every login from mailing another code.
   */
  private requestAddressVerification(userId: string, email: string): void {
    void this.notifications
      .upsertRecipient({ userId, email })
      .then(() => this.emailVerification.ensureVerificationRequested(userId))
      .catch(() => {
        // Neither half may reach the auth path. The client narrows failures to
        // outcomes and the service swallows its own; this catch is the backstop
        // that keeps an unhandled rejection from a detached promise out of the
        // process, not a place where a decision is made.
      });
  }

  /**
   * Registration. The response body/status upstream is IDENTICAL for new and
   * existing emails, and both paths pay the Argon2 cost.
   *
   * KNOWN LIMITATION (tracked for M2, docs/04): this does NOT fully close the
   * account-enumeration *timing* channel. The new-email path additionally
   * awaits KMS + DB inserts + Kafka publishes on the critical path, so under
   * production wiring (real MSK/KMS — not the in-process dev doubles) an
   * existing email returns measurably faster. Argon2 is a shared additive
   * constant and does not equalize that post-branch asymmetry. The correct fix
   * is an email-verification flow that returns a fixed-shape, fixed-time
   * response regardless of whether the address exists (unlike login(), decoy
   * work here would risk orphaned DEKs / side effects, and deferring the
   * publishes would break the audit-before-completion invariant).
   */
  async register(email: string, password: string): Promise<void> {
    const normalized = normalizeEmail(email);
    const emailBidx = emailBlindIndex(this.config.emailIndexKey, normalized);

    // ═══ THE ADDRESS BOUND, BEFORE ARGON2 ═══
    //
    // This route is the most expensive unauthenticated thing in the product:
    // Argon2id at 64 MiB × parallelism 4, paid BEFORE the existence probe
    // below (deliberately — probing first would leak existence by timing). No
    // ledger-derived bound can cover it, because the duplicate path returns
    // having written no row in either direction, so there is nothing to count.
    //
    // COUNTED PER ATTEMPT, NOT PER FAILURE, because register has no failure to
    // speak of: it answers the same 201 whether the address was new or already
    // had an account, and that identical answer is the anti-enumeration control.
    // The bound is therefore on COST and on address probing, not on guessing.
    //
    // 429 IS SAFE HERE, unlike on login. The count depends only on how many
    // times this caller submitted this address, which they already know, so the
    // refusal tells them nothing about whether an account exists.
    if (this.registerAddresses.exhausted(emailBidx)) {
      await this.authEvents.insert({ userId: null, kind: REGISTER_REFUSAL_KIND });
      await this.events.registerRateLimited();
      throw new HttpException({ error: 'too_many_attempts' }, HttpStatus.TOO_MANY_REQUESTS);
    }
    this.registerAddresses.record(emailBidx);

    const passwordHash = await this.hasher.hashPassword(password);

    const existing = await this.users.findByEmailBidx(emailBidx);
    if (existing) {
      return; // do nothing; caller returns the generic success-shaped response
    }

    const userId = randomUUID();
    const dekId = await this.fieldCrypto.getOrCreateDek(userId);
    const { ciphertext: emailCt } = await this.fieldCrypto.encryptField(
      userId,
      EMAIL_FIELD,
      normalized,
    );
    const outcome = await this.users.insert({
      id: userId,
      emailCt,
      emailBidx,
      passwordHash,
      dekId,
    });
    if (outcome === 'duplicate') {
      return; // raced with a concurrent registration for the same email
    }

    await this.authEvents.insert({ userId, kind: 'user.registered' });
    await this.events.userRegistered(userId);
    this.feedRecipientStore(userId, normalized);
  }

  /**
   * Password login. Every failure path (unknown email, bad password, locked
   * account, rate-limited) costs one Argon2 verification and returns the same
   * generic 401.
   *
   * ═══ WHERE THE TWO BOUNDS SIT, AND WHY IT IS NOT THE OBVIOUS PLACE (M17) ═══
   *
   * The ADDRESS bound is checked first and short-circuits before anything
   * expensive. That is safe because its answer is EXISTENCE-INDEPENDENT: an
   * address with no account reaches its cap on exactly the same schedule as one
   * with, so the fast refusal cannot be correlated with whether the account is
   * real, and `dummyVerify`'s timing equalization is untouched.
   *
   * The ACCOUNT bound is checked AFTER the password verification, which looks
   * wasteful and is the only correct placement. It can only be evaluated once
   * the user is resolved, so checking it before `verifyPassword` would make an
   * over-cap account answer fast while an unknown address still paid a full
   * Argon2 — the account-existence timing oracle this route burns a dummy
   * verification to close, re-opened by the control added to protect it. It
   * costs one hash on a path that is refusing anyway.
   *
   * BOTH REFUSALS ARE THE SAME 401 as a wrong password. A 429 on login is an
   * account-existence oracle however the counter is keyed, because past the
   * threshold a real address would answer differently from one that was never
   * counted at all. `rate-bounds.ts` carries the full reasoning; the bound's
   * visibility is the audit trail, not the status code.
   */
  async login(email: string, password: string): Promise<IssuedTokens> {
    const emailBidx = emailBlindIndex(this.config.emailIndexKey, normalizeEmail(email));

    if (this.loginAddresses.exhausted(emailBidx)) {
      await this.refuseLoginForRate(null, 'address');
    }

    const user = await this.users.findByEmailBidx(emailBidx);

    if (!user || user.password_hash === null) {
      await this.hasher.dummyVerify(); // timing equalization: unknown identifier still burns a verify
      this.loginAddresses.record(emailBidx);
      await this.recordLoginFailure(null, 'bad_credentials');
      throw invalidCredentials();
    }

    const passwordOk = await this.hasher.verifyPassword(user.password_hash, password);

    const overCap = await this.boundExceeded(LOGIN_BOUND, user.id, null);
    if (overCap) {
      await this.refuseLoginForRate(user.id, 'account', overCap.count);
    }

    if (!passwordOk) {
      this.loginAddresses.record(emailBidx);
      await this.recordLoginFailure(user.id, 'bad_credentials');
      throw invalidCredentials();
    }

    // Status allowlist (M7). 'deceased_pending' logins are PERMITTED by
    // design: docs/03 §5.1's rescue path is the owner signing in and voiding
    // the case, so a death report must never lock the living owner out. At
    // 'settlement' (verified) a correct password gets the same generic 401 as
    // every other failure — no status oracle — but a distinct recorded reason,
    // because decedent-credential replay post-verification is a detection
    // signal (docs/01 §6 settlement-trigger anomalies).
    if (user.status !== 'active' && user.status !== 'deceased_pending') {
      const reason =
        user.status === 'settlement' || user.status === 'closed'
          ? 'account_settled'
          : 'account_locked';
      this.loginAddresses.record(emailBidx);
      await this.recordLoginFailure(user.id, reason);
      throw invalidCredentials();
    }

    const now = this.clock();
    const sessionId = randomUUID();
    const refreshToken = generateOpaqueToken();
    const accessToken = generateOpaqueToken();
    await this.sessions.create({
      id: sessionId,
      userId: user.id,
      refreshTokenH: hashToken(refreshToken),
      accessTokenH: hashToken(accessToken),
      accessExpiresAt: new Date(now.getTime() + ACCESS_TOKEN_TTL_MS),
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
      // Stated rather than defaulted (M16). A login is the ordinary session,
      // and this is the line that says so — `SessionsRepo.create` no longer
      // decides on a caller's behalf.
      audience: DEFAULT_SESSION_AUDIENCE,
    });

    // The address's budget is forgiven by a success, mirroring the ledger
    // bound's "count since the last success": a user who fumbles twice and then
    // gets it right must not spend the rest of the window one attempt from a
    // refusal.
    this.loginAddresses.clear(emailBidx);
    await this.authEvents.insert({ userId: user.id, sessionId, kind: 'login.succeeded' });
    await this.events.loginSucceeded(user.id, sessionId, 'none');
    // The address a login carries is by construction the one already on file —
    // the user was resolved by `email_bidx` above — which is what lets the
    // recipient store preserve its `verified_at` across this re-feed.
    this.requestAddressVerification(user.id, normalizeEmail(email));
    return { accessToken, refreshToken, sessionId, userId: user.id };
  }

  /**
   * Refresh rotation. Presenting the CURRENT refresh token rotates both
   * tokens; presenting an ALREADY-ROTATED one is treated as theft and revokes
   * the whole session (rotation-reuse detection).
   */
  async refresh(refreshToken: string): Promise<IssuedTokens> {
    const presentedH = hashToken(refreshToken);
    const now = this.clock();

    const session = await this.sessions.findLiveByRefreshHash(presentedH, now);
    if (session) {
      const newRefreshToken = generateOpaqueToken();
      const newAccessToken = generateOpaqueToken();
      await this.sessions.rotateTokens(session.id, {
        newRefreshTokenH: hashToken(newRefreshToken),
        previousRefreshTokenH: presentedH,
        newAccessTokenH: hashToken(newAccessToken),
        accessExpiresAt: new Date(now.getTime() + ACCESS_TOKEN_TTL_MS),
      });
      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        sessionId: session.id,
        userId: session.user_id,
      };
    }

    const reused = await this.sessions.findLiveByPrevRefreshHash(presentedH);
    if (reused) {
      await this.sessions.revoke(reused.id, 'rotation_reuse_detected', now);
      await this.authEvents.insert({
        userId: reused.user_id,
        sessionId: reused.id,
        kind: 'session.revoked',
        decision: 'rotation_reuse_detected',
      });
      await this.events.sessionRevoked(reused.user_id, reused.id, 'rotation_reuse_detected');
    }
    throw new UnauthorizedException({ error: 'invalid_token' });
  }

  /**
   * TOTP enrollment: encrypted secret at rest, PII-free provisioning URI out.
   *
   * ═══ ADDING A SECOND FACTOR TO AN ACCOUNT THAT HAS ONE IS STEP-UP GATED ═══
   *
   * Found by the M16 review and PRE-EXISTING — this route has been
   * `SessionGuard`-only since M2, and nothing since revisited it. Measured
   * against real Postgres: a caller holding nothing but a stolen session could
   * enrol a secret OF THEIR OWN, confirm it with a code they computed
   * themselves, and then step up — because `revokeUnverifiedTotp` spares the
   * owner's VERIFIED method while `findActiveTotp` takes the NEWEST one. Three
   * ordinary requests, no guessing, and step-up stops being a second factor for
   * anyone holding a session: vault reset, document generation, data export,
   * beneficiary changes, deletion. The same run showed the owner's own
   * authenticator answering 401 afterwards, so it is a takeover AND a lockout,
   * including of docs/03 §5.1's liveness proof.
   *
   * The repository had already seen the mechanism and read it as a test-seeding
   * nuisance (CLAUDE.md 2026-08-06: "enrolling twice would leave two verified
   * secrets and make `findActiveTotp`'s choice decide whether a later step-up
   * works"). It is the escalation primitive.
   *
   * SO THE GATE IS CONDITIONAL, and it has to be: the FIRST enrolment cannot
   * require a step-up, because step-up needs a verified factor and the account
   * has none — `checkTotp` returns invalid for a user with no method, so an
   * unconditional gate would make a second factor unreachable forever. The rule
   * is therefore "you may add your first factor with a session; you may add
   * another only by proving the one you have", which is also what every other
   * step-up-gated action in the product asks for.
   *
   * RESIDUAL, STATED RATHER THAN IMPLIED (docs/03 §6j): for an account that has
   * never enrolled a factor, a stolen session still buys the bootstrap. Nothing
   * here can close that — the account has no proof to demand — and identity
   * cannot warn the owner either, because M14 deliberately made it not a holder
   * of the notifications SEND credential ("the service that mints sessions must
   * not be able to ring 'a death report was filed on your account'"). What
   * bounds it is that such an account had no second factor to defeat.
   */
  async enrollTotp(
    userId: string,
    sessionId: string,
    caller: Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'>,
  ): Promise<{ methodId: string; otpauthUri: string }> {
    // ONE PREDICATE ACROSS BOTH FACTOR TYPES. This asked `hasVerifiedTotp` when
    // the M16 PR5 review first closed it, which left two holes: WebAuthn
    // registration was ungated entirely, and an account holding only a passkey
    // answered FALSE here, so a stolen session could still enrol TOTP on it.
    // `SecondFactorGate` carries the reasoning.
    await this.factors.assertMayAddFactor(userId, caller, this.clock());
    const now = this.clock();
    const secretBase32 = generateTotpSecretBase32();
    await this.mfa.revokeUnverifiedTotp(userId, now);
    const { ciphertext } = await this.fieldCrypto.encryptField(
      userId,
      TOTP_SECRET_FIELD,
      secretBase32,
    );
    const methodId = randomUUID();
    await this.mfa.insertTotp({ id: methodId, userId, secretCt: ciphertext });
    await this.authEvents.insert({ userId, sessionId, kind: 'totp.enrolled' });
    return { methodId, otpauthUri: totpProvisioningUri(secretBase32, userId) };
  }

  /**
   * Confirm enrollment by proving possession of the secret once.
   *
   * CAPPED ON THE SAME COUNTER AS STEP-UP, because it checks the same secret.
   * The M16 review measured this route as an uncapped oracle: forty wrong codes
   * produced forty 401s, never a 429, and left the step-up counter at zero —
   * after which the code the guessing found elevated at `stepup` on the first
   * try, spending none of the five. `assertStepUpAttemptsAvailable` is the one
   * gate both routes now pass through.
   */
  async verifyTotp(userId: string, sessionId: string, code: string): Promise<void> {
    await this.assertStepUpAttemptsAvailable(userId, sessionId);
    const ok = await this.checkTotp(userId, code, 'auth.totp.verify', { verifiedOnly: false });
    if (!ok.valid) {
      await this.authEvents.insert({ userId, sessionId, kind: 'totp.verify_failed' });
      throw new UnauthorizedException({ error: 'invalid_code' });
    }
    if (ok.verifiedAt === null) {
      await this.mfa.markVerified(ok.methodId, this.clock());
    }
    await this.authEvents.insert({ userId, sessionId, kind: 'totp.verified' });
  }

  /**
   * Step-up: fresh TOTP proof elevates the session for a ≤5-minute window
   * (docs/01 §5). The decrypt of the TOTP secret deliberately runs through
   * FieldCrypto so the crypto.field.decrypted audit path is exercised.
   */
  /**
   * Logout: revoke exactly the presented session, server-side.
   *
   * The M1 open item, landed with the first UI that needs it (M8 PR5's
   * persona switching). Only `revoke`, never `revokeAllForUser` — logging out
   * one browser must not kill the user's other devices; that stronger verb
   * stays reserved for theft response and the settlement lock. Idempotent by
   * construction: the repo's UPDATE is a no-op on an already-revoked row, so
   * a double-click cannot error.
   */
  async logout(userId: string, sessionId: string): Promise<void> {
    await this.revokeSession(userId, sessionId);
  }

  /**
   * Logout by REFRESH token, for the ordinary case where the access token has
   * already expired.
   *
   * The M8 security review's load-bearing finding: `POST /v1/auth/logout` sits
   * behind SessionGuard, which requires a live ACCESS token (15-minute TTL),
   * while the session and its refresh token live 30 DAYS. Any tab older than
   * fifteen minutes therefore got a 401 — which the BFF treated as "already
   * logged out" — so the session was never revoked, nothing entered the audit
   * trail, and the user was told they were signed out. This is the path that
   * makes the promise true: `findLiveByRefreshHash` deliberately has no
   * access-expiry predicate, so it still resolves the session the browser
   * holds.
   *
   * Returns false when the refresh token resolves nothing (already revoked,
   * expired, or an account whose status no longer permits token use) — the
   * caller decides whether that is "already logged out" or a failure.
   */
  async logoutByRefreshToken(refreshToken: string): Promise<boolean> {
    const session = await this.sessions.findLiveByRefreshHash(
      hashToken(refreshToken),
      this.clock(),
    );
    if (!session) {
      return false;
    }
    await this.revokeSession(session.user_id, session.id);
    return true;
  }

  /**
   * The user's live sessions — the paired-devices surface (M16).
   *
   * `current` is computed here rather than left to the client, because the
   * caller's own session id is something the SERVER knows and the browser would
   * otherwise have to be told separately. A row that is `current` is the one
   * revoking would sign you out of.
   */
  async listSessions(
    userId: string,
    currentSessionId: string,
  ): Promise<
    Array<{
      sessionId: string;
      audience: SessionAudience;
      createdAt: string;
      expiresAt: string;
      current: boolean;
    }>
  > {
    const rows = await this.sessions.listLiveForUser(userId, this.clock());
    return rows.map((row) => ({
      sessionId: row.id,
      audience: row.audience,
      createdAt: row.created_at.toISOString(),
      expiresAt: row.expires_at.toISOString(),
      current: row.id === currentSessionId,
    }));
  }

  /**
   * Revoke one of the caller's own sessions.
   *
   * NOT STEP-UP GATED, and that asymmetry is the M6 rule rather than an
   * oversight: minting a pairing IS gated, because it hands out a long-lived
   * credential, while taking one away can only ever reduce authority. The
   * protective action must never be the harder one — a user who thinks their
   * extension is compromised must not be sent to find an authenticator first.
   *
   * A UNIFORM NOT-FOUND covers both "no such session" and "not yours". The
   * owner predicate lives in the UPDATE (see `revokeOwned`), so this is not a
   * check-then-act, and the answer cannot be used to discover whether a session
   * id names something real.
   */
  async revokeOwnSession(userId: string, sessionId: string): Promise<void> {
    const revoked = await this.sessions.revokeOwned(
      sessionId,
      userId,
      'user_revoked',
      this.clock(),
    );
    if (!revoked) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await this.authEvents.insert({
      userId,
      sessionId,
      kind: 'session.revoked',
      decision: 'user_revoked',
    });
    await this.events.sessionRevoked(userId, sessionId, 'admin');
  }

  /** One revocation path: row, append-only ledger, audit event, in that order. */
  private async revokeSession(userId: string, sessionId: string): Promise<void> {
    await this.sessions.revoke(sessionId, 'user_logout', this.clock());
    await this.authEvents.insert({
      userId,
      sessionId,
      kind: 'session.revoked',
      decision: 'user_logout',
    });
    await this.events.sessionRevoked(userId, sessionId, 'logout');
  }

  /**
   * THE ATTEMPT CAP, BEFORE THE CODE IS EVEN LOOKED AT (M16), for every route
   * that checks the TOTP secret.
   *
   * Order matters twice over. Checking first means an exhausted caller never
   * causes the stored TOTP secret to be read, and it means the refusal cannot
   * vary in timing with whether the submitted code happened to be right —
   * which would turn the rate limiter into the oracle it exists to close.
   *
   * `stepup.rate_limited` IS NOT a failure kind, and that is load-bearing
   * rather than tidy. `failedFactorAttempts` counts failures; if a refusal
   * emitted one, every refused attempt would extend the window it was refused
   * by, and a client retrying in a loop would lock its own user out
   * permanently. The counter must not be able to feed itself. (This is the
   * M14 shape from the other side: there, a control's outcome was recorded as
   * a user failure and poisoned an investigation; here it would poison the
   * control.)
   *
   * TWO SCOPES, SESSION FIRST. The per-session cap is what a stolen credential
   * exhausts; the account cap is the real bound on guessing. Asking the session
   * question first means the common refusal — one credential hammering — never
   * touches the account total, which is exactly what keeps the owner's other
   * sessions working. `stepup.ts` carries the full reasoning and the measurement
   * that forced it.
   *
   * The refusal is 429 with its own token — never `invalid_code`, which
   * already means "that code was wrong" and would send a user to re-read an
   * authenticator when the remedy is to wait (the M12 lesson about one token
   * changing meaning with the surface).
   */
  /**
   * The step-up gate, unchanged in behaviour: two scopes, session first, before
   * the code is even looked at. `stepup.ts` carries the reasoning and the
   * measurement that forced the pair.
   *
   * Kept as a named method with one call per reader so the fence can still
   * assert that every route reading the factor passes a gate FIRST — the check
   * that caught `POST /v1/auth/totp/verify` being an uncapped oracle.
   */
  private async assertStepUpAttemptsAvailable(userId: string, sessionId: string): Promise<void> {
    const overCap = await this.boundExceeded(STEP_UP_BOUND, userId, sessionId);
    if (overCap) {
      await this.refuseStepUpForRate(userId, sessionId, overCap.count);
    }
  }

  private async boundExceeded(
    bound: LedgerRateBound,
    userId: string,
    scopeId: string | null,
  ): Promise<{ scope: 'session' | 'account'; count: number } | null> {
    const windowStart = new Date(this.clock().getTime() - bound.windowMs);
    const counted = { failures: bound.failures, successes: bound.successes };

    if (scopeId !== null && bound.maxPerScope !== null) {
      const mine = await this.authEvents.failedAttempts(userId, windowStart, {
        ...counted,
        sessionId: scopeId,
      });
      if (mine >= bound.maxPerScope) {
        return { scope: 'session', count: mine };
      }
    }
    const account = await this.authEvents.failedAttempts(userId, windowStart, counted);
    return account >= bound.maxPerAccount ? { scope: 'account', count: account } : null;
  }

  /**
   * The step-up refusal: 429 with its own token.
   *
   * Never `invalid_code`, which already means "that code was wrong" and would
   * send a user to re-read an authenticator when the remedy is to wait (the M12
   * lesson about one token changing meaning with the surface). A distinct status
   * is safe HERE and not on login, because this route already required a
   * resolved, authenticated caller — it tells them something about themselves.
   */
  private async refuseStepUpForRate(
    userId: string,
    sessionId: string,
    denials: number,
  ): Promise<never> {
    await this.authEvents.insert({
      userId,
      sessionId,
      kind: STEP_UP_BOUND.refusalKind,
      decision: 'too_many_attempts',
    });
    await this.events.stepUpRateLimited(userId, sessionId, denials);
    throw new HttpException({ error: 'too_many_attempts' }, HttpStatus.TOO_MANY_REQUESTS);
  }

  /**
   * The login refusal: the SAME 401 `invalid_credentials` a wrong password
   * gets, and this is the single most important line in the milestone.
   *
   * A 429 here would be an account-existence oracle regardless of how the
   * counter is keyed, because it is a state reachable only by naming something
   * the platform counted. The address half counts everything and so is safe on
   * its own — but making the two halves answer differently would let an
   * attacker tell which fired, and the ordering that keeps that harmless is an
   * invariant nobody would think to preserve through a later edit. One uniform
   * answer is robust to that; two are correct only by accident.
   *
   * The control's visibility is HERE, in the trail: a ledger row under a kind
   * no bound counts (so the counter cannot feed itself), plus an audit action
   * distinct from `auth.login.failed` — a control firing must not read as an
   * ordinary failure (the M9 rule).
   */
  private async refuseLoginForRate(
    userId: string | null,
    scope: 'address' | 'account',
    attempts?: number,
  ): Promise<never> {
    await this.authEvents.insert({
      userId,
      kind: LOGIN_BOUND.refusalKind,
      decision: scope === 'address' ? 'address_rate' : 'account_rate',
    });
    await this.events.loginRateLimited(userId, scope, attempts ?? null);
    throw invalidCredentials();
  }

  async stepUp(userId: string, sessionId: string, code: string): Promise<StepUpResult> {
    await this.assertStepUpAttemptsAvailable(userId, sessionId);

    const ok = await this.checkTotp(userId, code, 'auth.totp.stepup', { verifiedOnly: true });
    if (!ok.valid) {
      await this.authEvents.insert({
        userId,
        sessionId,
        kind: 'stepup.denied',
        decision: 'invalid_code',
      });
      throw new UnauthorizedException({ error: 'invalid_code' });
    }
    const now = this.clock();
    const stepupExpiresAt = new Date(now.getTime() + STEPUP_WINDOW_MS);
    await this.sessions.grantStepUp(sessionId, stepupExpiresAt);
    await this.authEvents.insert({ userId, sessionId, kind: 'stepup.granted' });
    await this.events.stepUpGranted(userId, sessionId, stepupExpiresAt);
    return { mfaLevel: 'stepup', stepupExpiresAt: stepupExpiresAt.toISOString() };
  }

  private async recordLoginFailure(
    userId: string | null,
    reason: 'bad_credentials' | 'account_locked' | 'risk_blocked' | 'account_settled',
  ): Promise<void> {
    await this.authEvents.insert({ userId, kind: 'login.failed', decision: reason });
    await this.events.loginFailed(userId, reason);
  }

  private async checkTotp(
    userId: string,
    code: string,
    purpose: string,
    opts: { verifiedOnly: boolean },
  ): Promise<{ valid: true; methodId: string; verifiedAt: Date | null } | { valid: false }> {
    const method = await this.mfa.findActiveTotp(userId, opts);
    if (!method) {
      return { valid: false };
    }
    const dek = await this.deks.findActiveByUser(userId);
    if (!dek) {
      return { valid: false };
    }
    const secret = await this.fieldCrypto.decryptField({
      userId,
      dekId: dek.dekId,
      field: TOTP_SECRET_FIELD,
      ciphertext: method.secret_ct,
      actorId: userId,
      actorType: 'user',
      purpose,
    });
    const secretBase32 = secret.toString('utf8');
    secret.fill(0);
    if (!verifyTotpCode(secretBase32, code)) {
      return { valid: false };
    }
    return { valid: true, methodId: method.id, verifiedAt: method.verified_at };
  }
}
