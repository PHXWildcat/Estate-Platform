import { UnauthorizedException } from '@nestjs/common';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import type { SessionRow, SessionsRepo } from '../src/sessions.repo';
import { STEPUP_DENIAL_WINDOW_MS, STEPUP_MAX_DENIALS } from '../src/stepup';
import { generateOpaqueToken, hashToken } from '../src/tokens';
import type { UsersRepo } from '../src/users.repo';

const NOW = new Date('2026-07-20T12:00:00Z');

function makeFakes(): {
  users: { findByEmailBidx: jest.Mock; insert: jest.Mock };
  sessions: {
    create: jest.Mock;
    findLiveByAccessHash: jest.Mock;
    findLiveByRefreshHash: jest.Mock;
    findLiveByPrevRefreshHash: jest.Mock;
    rotateTokens: jest.Mock;
    revoke: jest.Mock;
    grantStepUp: jest.Mock;
  };
  mfa: {
    insertTotp: jest.Mock;
    revokeUnverifiedTotp: jest.Mock;
    findActiveTotp: jest.Mock;
    markVerified: jest.Mock;
  };
  authEvents: { insert: jest.Mock; failedFactorAttempts: jest.Mock };
  hasher: { hashPassword: jest.Mock; verifyPassword: jest.Mock; dummyVerify: jest.Mock };
  events: {
    userRegistered: jest.Mock;
    loginSucceeded: jest.Mock;
    loginFailed: jest.Mock;
    stepUpGranted: jest.Mock;
    stepUpRateLimited: jest.Mock;
    sessionRevoked: jest.Mock;
  };
  fieldCrypto: { getOrCreateDek: jest.Mock; encryptField: jest.Mock; decryptField: jest.Mock };
  deks: { findActiveByUser: jest.Mock };
  notifications: {
    upsertRecipient: jest.Mock;
    send: jest.Mock;
    sendAddressVerification: jest.Mock;
    markRecipientVerified: jest.Mock;
    recipientStatus: jest.Mock;
  };
  emailVerification: { ensureVerificationRequested: jest.Mock };
} {
  return {
    users: { findByEmailBidx: jest.fn().mockResolvedValue(null), insert: jest.fn() },
    sessions: {
      create: jest.fn(),
      findLiveByAccessHash: jest.fn().mockResolvedValue(null),
      findLiveByRefreshHash: jest.fn().mockResolvedValue(null),
      findLiveByPrevRefreshHash: jest.fn().mockResolvedValue(null),
      rotateTokens: jest.fn(),
      revoke: jest.fn(),
      grantStepUp: jest.fn(),
    },
    mfa: {
      insertTotp: jest.fn(),
      revokeUnverifiedTotp: jest.fn(),
      findActiveTotp: jest.fn().mockResolvedValue(null),
      markVerified: jest.fn(),
    },
    authEvents: { insert: jest.fn(), failedFactorAttempts: jest.fn().mockResolvedValue(0) },
    hasher: {
      hashPassword: jest.fn().mockResolvedValue('argon2-hash'),
      verifyPassword: jest.fn().mockResolvedValue(false),
      dummyVerify: jest.fn().mockResolvedValue(undefined),
    },
    events: {
      userRegistered: jest.fn(),
      loginSucceeded: jest.fn(),
      loginFailed: jest.fn(),
      stepUpGranted: jest.fn(),
      stepUpRateLimited: jest.fn(),
      sessionRevoked: jest.fn(),
    },
    fieldCrypto: {
      getOrCreateDek: jest.fn().mockResolvedValue('dek-1'),
      encryptField: jest.fn().mockResolvedValue({ ciphertext: Buffer.from('ct'), dekId: 'dek-1' }),
      decryptField: jest.fn(),
    },
    deks: { findActiveByUser: jest.fn().mockResolvedValue(null) },
    notifications: {
      upsertRecipient: jest.fn().mockResolvedValue({ ok: true }),
      send: jest.fn().mockResolvedValue({ accepted: false }),
      sendAddressVerification: jest.fn().mockResolvedValue({ accepted: false }),
      markRecipientVerified: jest.fn().mockResolvedValue({ ok: true }),
      recipientStatus: jest.fn().mockResolvedValue({ verified: true }),
    },
    // M14: the login hook is fire-and-forget, so a double that RESOLVES is
    // what keeps these tests deterministic — an unhandled rejection from a
    // detached promise would surface in an unrelated test.
    emailVerification: { ensureVerificationRequested: jest.fn().mockResolvedValue(undefined) },
  };
}

const config: IdentityConfig = {
  nodeEnv: 'test',
  port: 3001,
  databaseUrl: 'postgres://unused',
  kms: { mode: 'local', masterKey: Buffer.alloc(32, 7) },
  emailIndexKey: Buffer.alloc(32, 9),
  kafkaBrokers: null,
  kekAlias: 'test/kek',
  rpId: 'localhost',
  rpOrigin: 'http://localhost:3000',
  rpName: 'Estate Platform',
  internalApiToken: '',
  notificationsUrl: 'http://localhost:3008',
  notificationsInternalToken: '',
  notificationsVerifyToken: '',
  notificationsStatusToken: '',
};

function makeService(fakes: ReturnType<typeof makeFakes>): AuthService {
  return new AuthService(
    fakes.users as unknown as UsersRepo,
    fakes.sessions as unknown as SessionsRepo,
    fakes.mfa as unknown as MfaRepo,
    fakes.authEvents as unknown as AuthEventsRepo,
    fakes.hasher as unknown as PasswordHasher,
    fakes.events as unknown as EventsService,
    fakes.fieldCrypto as unknown as FieldCrypto,
    fakes.deks as unknown as DekRepository,
    config,
    () => NOW,
    fakes.notifications,
    fakes.emailVerification as unknown as EmailVerificationService,
  );
}

describe('AuthService.login timing equalization', () => {
  it('burns a dummy argon2 verify when the identifier is unknown', async () => {
    const fakes = makeFakes();
    const service = makeService(fakes);
    await expect(service.login('nobody@example.com', 'pw-123456789012')).rejects.toThrow(
      UnauthorizedException,
    );
    expect(fakes.hasher.dummyVerify).toHaveBeenCalledTimes(1);
    expect(fakes.hasher.verifyPassword).not.toHaveBeenCalled();
    expect(fakes.events.loginFailed).toHaveBeenCalledWith(null, 'bad_credentials');
  });

  it('runs a real verify (no dummy) for a known identifier with a wrong password', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'active',
      dek_id: 'dek-1',
    });
    const service = makeService(fakes);
    await expect(service.login('user@example.com', 'wrong')).rejects.toThrow(UnauthorizedException);
    expect(fakes.hasher.verifyPassword).toHaveBeenCalledTimes(1);
    expect(fakes.hasher.dummyVerify).not.toHaveBeenCalled();
    expect(fakes.events.loginFailed).toHaveBeenCalledWith('u-1', 'bad_credentials');
  });

  it('locked accounts fail with the SAME generic error after a real verify', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'locked',
      dek_id: 'dek-1',
    });
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    const service = makeService(fakes);
    const failure = service.login('user@example.com', 'correct-password');
    await expect(failure).rejects.toThrow(UnauthorizedException);
    await expect(
      service
        .login('user@example.com', 'correct-password')
        .catch((e: UnauthorizedException) => e.getResponse()),
    ).resolves.toEqual({ error: 'invalid_credentials' });
    expect(fakes.events.loginFailed).toHaveBeenCalledWith('u-1', 'account_locked');
    expect(fakes.sessions.create).not.toHaveBeenCalled();
  });

  it('deceased_pending logins SUCCEED — the docs/03 §5.1 owner rescue path', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'deceased_pending',
      dek_id: 'dek-1',
    });
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    const service = makeService(fakes);
    const result = await service.login('user@example.com', 'correct-password');
    expect(result.userId).toBe('u-1');
    expect(fakes.sessions.create).toHaveBeenCalledTimes(1);
    expect(fakes.events.loginFailed).not.toHaveBeenCalled();
  });

  it('settlement-status logins fail with the generic 401 but the account_settled reason', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'settlement',
      dek_id: 'dek-1',
    });
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    const service = makeService(fakes);
    await expect(
      service
        .login('user@example.com', 'correct-password')
        .catch((e: UnauthorizedException) => e.getResponse()),
    ).resolves.toEqual({ error: 'invalid_credentials' });
    expect(fakes.events.loginFailed).toHaveBeenCalledWith('u-1', 'account_settled');
    expect(fakes.sessions.create).not.toHaveBeenCalled();
  });

  it('successful login creates a session storing only token hashes', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'active',
      dek_id: 'dek-1',
    });
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    const service = makeService(fakes);
    const result = await service.login('user@example.com', 'correct-password');

    expect(result.userId).toBe('u-1');
    expect(fakes.sessions.create).toHaveBeenCalledTimes(1);
    const [created] = fakes.sessions.create.mock.calls[0] as [
      { refreshTokenH: Buffer; accessTokenH: Buffer; accessExpiresAt: Date },
    ];
    expect(created.refreshTokenH.equals(hashToken(result.refreshToken))).toBe(true);
    expect(created.accessTokenH.equals(hashToken(result.accessToken))).toBe(true);
    expect(created.accessExpiresAt.getTime()).toBe(NOW.getTime() + 15 * 60 * 1000);
    expect(fakes.events.loginSucceeded).toHaveBeenCalledWith('u-1', result.sessionId, 'none');
  });
});

describe('AuthService.refresh rotation + reuse detection', () => {
  const session: SessionRow = {
    id: 's-1',
    user_id: 'u-1',
    mfa_level: 'none',
    stepup_expires_at: null,
    audience: 'account',
  };

  it('rotates both tokens and retains the presented hash as previous', async () => {
    const fakes = makeFakes();
    fakes.sessions.findLiveByRefreshHash.mockResolvedValue(session);
    const service = makeService(fakes);
    const presented = generateOpaqueToken();
    const result = await service.refresh(presented);

    expect(result.refreshToken).not.toBe(presented);
    expect(fakes.sessions.rotateTokens).toHaveBeenCalledTimes(1);
    const [sessionId, rotation] = fakes.sessions.rotateTokens.mock.calls[0] as [
      string,
      { newRefreshTokenH: Buffer; previousRefreshTokenH: Buffer; newAccessTokenH: Buffer },
    ];
    expect(sessionId).toBe('s-1');
    expect(rotation.previousRefreshTokenH.equals(hashToken(presented))).toBe(true);
    expect(rotation.newRefreshTokenH.equals(hashToken(result.refreshToken))).toBe(true);
    expect(rotation.newAccessTokenH.equals(hashToken(result.accessToken))).toBe(true);
    expect(fakes.sessions.revoke).not.toHaveBeenCalled();
  });

  /**
   * THE STEP-UP ATTEMPT CAP — the DECISION layer only (M16).
   *
   * These fake the repo, so they say nothing about whether the COUNT is right:
   * that predicate lives in SQL and is proven in `stepup-cap.int.spec.ts`
   * against real Postgres. Stated here rather than left implied, because "a
   * green unit test is not evidence about a repo layer" is a rule this codebase
   * has had to relearn (M13), and a suite named for a cap that only ever sees a
   * stubbed number is exactly how it gets relearned again.
   *
   * What IS proven here: when the count is at the cap, the service refuses
   * before touching the secret, refuses with the right token and status, and
   * does not write the kind it counts.
   */
  describe('the step-up attempt cap', () => {
    it('refuses at the cap with 429 too_many_attempts, before reading the TOTP secret', async () => {
      const fakes = makeFakes();
      fakes.authEvents.failedFactorAttempts.mockResolvedValue(STEPUP_MAX_DENIALS);
      const service = makeService(fakes);

      await expect(service.stepUp('u-1', 's-1', '000000')).rejects.toMatchObject({
        status: 429,
        response: { error: 'too_many_attempts' },
      });
      // The secret is never fetched: an exhausted caller must not be able to
      // make the refusal's timing depend on whether their guess was right.
      expect(fakes.mfa.findActiveTotp).not.toHaveBeenCalled();
      expect(fakes.sessions.grantStepUp).not.toHaveBeenCalled();
    });

    it('asks the SESSION question first, so one credential cannot spend the account budget', () => {
      // The M16 review's finding: a user-keyed cap alone let five wrong codes
      // from one stolen credential refuse the owner's own sessions. The order
      // is the fix — a session at its own cap is refused without the account
      // total ever being read, so it cannot grow.
      const fakes = makeFakes();
      fakes.authEvents.failedFactorAttempts.mockResolvedValue(STEPUP_MAX_DENIALS);
      const service = makeService(fakes);

      return expect(service.stepUp('u-1', 's-1', '000000'))
        .rejects.toMatchObject({ status: 429 })
        .then(() => {
          expect(fakes.authEvents.failedFactorAttempts).toHaveBeenCalledTimes(1);
          expect(fakes.authEvents.failedFactorAttempts).toHaveBeenCalledWith(
            'u-1',
            expect.any(Date),
            { sessionId: 's-1' },
          );
        });
    });

    it('records the refusal as its OWN kind, never as a denial', async () => {
      // The counter must not feed itself. If a refusal wrote `stepup.denied`,
      // every refused attempt would extend the window that refused it and a
      // retrying client would lock its own user out permanently.
      const fakes = makeFakes();
      fakes.authEvents.failedFactorAttempts.mockResolvedValue(STEPUP_MAX_DENIALS + 3);
      const service = makeService(fakes);

      await expect(service.stepUp('u-1', 's-1', '000000')).rejects.toBeDefined();

      const kinds = fakes.authEvents.insert.mock.calls.map(
        (call: [{ kind: string }]) => call[0].kind,
      );
      expect(kinds).toEqual(['stepup.rate_limited']);
      expect(kinds).not.toContain('stepup.denied');
      expect(fakes.events.stepUpRateLimited).toHaveBeenCalledWith(
        'u-1',
        's-1',
        STEPUP_MAX_DENIALS + 3,
      );
    });

    it('below the cap, a wrong code is still an ordinary denial', async () => {
      // The permissive path must stay unchanged, or the cap has quietly become
      // a different control. One below the cap is the interesting boundary.
      const fakes = makeFakes();
      fakes.authEvents.failedFactorAttempts.mockResolvedValue(STEPUP_MAX_DENIALS - 1);
      const service = makeService(fakes);

      await expect(service.stepUp('u-1', 's-1', '000000')).rejects.toThrow(UnauthorizedException);
      expect(fakes.authEvents.insert).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'stepup.denied', decision: 'invalid_code' }),
      );
      expect(fakes.events.stepUpRateLimited).not.toHaveBeenCalled();
    });

    it('asks for denials within the configured window, not for all time', async () => {
      // A cap that counted every failure a user ever had would lock out an
      // honest long-lived account rather than a guesser — the difference
      // between a rate limit and a permanent ban, decided by one argument.
      const fakes = makeFakes();
      const service = makeService(fakes);
      await expect(service.stepUp('u-1', 's-1', '000000')).rejects.toBeDefined();

      expect(fakes.authEvents.failedFactorAttempts).toHaveBeenCalledWith(
        'u-1',
        new Date(NOW.getTime() - STEPUP_DENIAL_WINDOW_MS),
        { sessionId: 's-1' },
      );
    });
  });

  it('revokes the session when a previously-used refresh token is replayed', async () => {
    const fakes = makeFakes();
    fakes.sessions.findLiveByRefreshHash.mockResolvedValue(null);
    fakes.sessions.findLiveByPrevRefreshHash.mockResolvedValue(session);
    const service = makeService(fakes);

    await expect(service.refresh(generateOpaqueToken())).rejects.toThrow(UnauthorizedException);
    expect(fakes.sessions.revoke).toHaveBeenCalledWith('s-1', 'rotation_reuse_detected', NOW);
    expect(fakes.events.sessionRevoked).toHaveBeenCalledWith(
      'u-1',
      's-1',
      'rotation_reuse_detected',
    );
    expect(fakes.authEvents.insert).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'session.revoked', decision: 'rotation_reuse_detected' }),
    );
    expect(fakes.sessions.rotateTokens).not.toHaveBeenCalled();
  });

  it('an unknown token is a plain 401 with no revocation side effects', async () => {
    const fakes = makeFakes();
    const service = makeService(fakes);
    await expect(service.refresh(generateOpaqueToken())).rejects.toThrow(UnauthorizedException);
    expect(fakes.sessions.revoke).not.toHaveBeenCalled();
    expect(fakes.events.sessionRevoked).not.toHaveBeenCalled();
  });
});

describe('AuthService.register (no account enumeration)', () => {
  it('does nothing but still hashes the password when the email exists', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue({
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'active',
      dek_id: 'dek-1',
    });
    const service = makeService(fakes);
    await expect(service.register('user@example.com', 'a-long-password!')).resolves.toBeUndefined();
    expect(fakes.hasher.hashPassword).toHaveBeenCalledTimes(1); // time-shaped like success
    expect(fakes.users.insert).not.toHaveBeenCalled();
    expect(fakes.events.userRegistered).not.toHaveBeenCalled();
  });

  it('treats an insert-race duplicate as silent success-shape too', async () => {
    const fakes = makeFakes();
    fakes.users.insert.mockResolvedValue('duplicate');
    const service = makeService(fakes);
    await expect(service.register('user@example.com', 'a-long-password!')).resolves.toBeUndefined();
    expect(fakes.events.userRegistered).not.toHaveBeenCalled();
    expect(fakes.authEvents.insert).not.toHaveBeenCalled();
  });

  it('registers a new user under a fresh DEK and emits events', async () => {
    const fakes = makeFakes();
    fakes.users.insert.mockResolvedValue('inserted');
    const service = makeService(fakes);
    await service.register('user@example.com', 'a-long-password!');
    expect(fakes.fieldCrypto.getOrCreateDek).toHaveBeenCalledTimes(1);
    expect(fakes.users.insert).toHaveBeenCalledWith(
      expect.objectContaining({ passwordHash: 'argon2-hash', dekId: 'dek-1' }),
    );
    expect(fakes.authEvents.insert).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'user.registered' }),
    );
    expect(fakes.events.userRegistered).toHaveBeenCalledTimes(1);
  });

  it('feeds the recipient store but does NOT ask for verification (M14)', async () => {
    // docs/03 §6c's mitigation — "no notification kind fires at registration" —
    // stays literally true. Registration is unauthenticated, so a kind firing
    // there would be a mail-bomb primitive addressable by anyone holding a
    // victim's address, and this repo has no rate-limiting machinery to bound
    // it. The ceremony starts at the first authenticated LOGIN instead.
    const fakes = makeFakes();
    fakes.users.insert.mockResolvedValue('inserted');
    await makeService(fakes).register('user@example.com', 'a-long-password!');
    await Promise.resolve();
    expect(fakes.notifications.upsertRecipient).toHaveBeenCalledTimes(1);
    expect(fakes.emailVerification.ensureVerificationRequested).not.toHaveBeenCalled();
    expect(fakes.notifications.sendAddressVerification).not.toHaveBeenCalled();
  });
});

describe('AuthService login → address verification (M14)', () => {
  const liveUser = {
    id: 'u-1',
    password_hash: 'argon2-hash',
    status: 'active',
    dek_id: 'dek-1',
  };

  /** Let the detached fire-and-forget chain settle. */
  const settle = async (): Promise<void> => {
    for (let i = 0; i < 5; i += 1) {
      await Promise.resolve();
    }
  };

  it('CHAINS the verification request AFTER the recipient upsert', async () => {
    // Not fired beside it. The verification send resolves the address from the
    // recipient store, so on a user's FIRST login the two racing would leave
    // the send with nothing to mail — a no_recipient outcome and a burned code
    // — every time.
    const order: string[] = [];
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue(liveUser);
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    fakes.notifications.upsertRecipient.mockImplementation(() => {
      order.push('upsert');
      return Promise.resolve({ ok: true });
    });
    fakes.emailVerification.ensureVerificationRequested.mockImplementation(() => {
      order.push('verify-request');
      return Promise.resolve();
    });

    await makeService(fakes).login('user@example.com', 'a-long-password!');
    await settle();
    expect(order).toEqual(['upsert', 'verify-request']);
  });

  it('does not couple login to the chain: it resolves before either lands', async () => {
    // Fire-and-forget, exactly like the M9 upsert it follows. Login latency
    // must never depend on SES.
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue(liveUser);
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    fakes.notifications.upsertRecipient.mockReturnValue(new Promise(() => undefined));

    await expect(
      makeService(fakes).login('user@example.com', 'a-long-password!'),
    ).resolves.toMatchObject({ userId: 'u-1' });
    expect(fakes.emailVerification.ensureVerificationRequested).not.toHaveBeenCalled();
  });

  it('survives a rejecting chain without an unhandled rejection', async () => {
    const fakes = makeFakes();
    fakes.users.findByEmailBidx.mockResolvedValue(liveUser);
    fakes.hasher.verifyPassword.mockResolvedValue(true);
    fakes.notifications.upsertRecipient.mockRejectedValue(new Error('notifications down'));

    await expect(
      makeService(fakes).login('user@example.com', 'a-long-password!'),
    ).resolves.toMatchObject({ userId: 'u-1' });
    await settle();
    expect(fakes.emailVerification.ensureVerificationRequested).not.toHaveBeenCalled();
  });
});
