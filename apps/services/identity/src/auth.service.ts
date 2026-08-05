import { randomUUID } from 'node:crypto';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import {
  emailBlindIndex,
  normalizeEmail,
  type DekRepository,
  type FieldCrypto,
} from '@estate/crypto';
import { NOTIFICATIONS, type NotificationsPort } from '@estate/notifications-client';
import { AuthEventsRepo } from './auth-events.repo';
import type { IdentityConfig } from './config';
import { CLOCK, CONFIG, DEK_REPOSITORY, FIELD_CRYPTO, type Clock } from './di-tokens';
import { EventsService } from './events.service';
import { MfaRepo } from './mfa.repo';
import { PasswordHasher } from './password';
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
  ) {}

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
   * account) costs one Argon2 verification and returns the same generic 401.
   */
  async login(email: string, password: string): Promise<IssuedTokens> {
    const emailBidx = emailBlindIndex(this.config.emailIndexKey, normalizeEmail(email));
    const user = await this.users.findByEmailBidx(emailBidx);

    if (!user || user.password_hash === null) {
      await this.hasher.dummyVerify(); // timing equalization: unknown identifier still burns a verify
      await this.recordLoginFailure(null, 'bad_credentials');
      throw invalidCredentials();
    }

    const passwordOk = await this.hasher.verifyPassword(user.password_hash, password);
    if (!passwordOk) {
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
    });

    await this.authEvents.insert({ userId: user.id, sessionId, kind: 'login.succeeded' });
    await this.events.loginSucceeded(user.id, sessionId, 'none');
    this.feedRecipientStore(user.id, normalizeEmail(email));
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

  /** TOTP enrollment: encrypted secret at rest, PII-free provisioning URI out. */
  async enrollTotp(
    userId: string,
    sessionId: string,
  ): Promise<{ methodId: string; otpauthUri: string }> {
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

  /** Confirm enrollment by proving possession of the secret once. */
  async verifyTotp(userId: string, sessionId: string, code: string): Promise<void> {
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

  async stepUp(userId: string, sessionId: string, code: string): Promise<StepUpResult> {
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
