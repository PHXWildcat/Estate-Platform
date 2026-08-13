import { ForbiddenException, HttpException, UnauthorizedException } from '@nestjs/common';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { SecondFactorGate } from '../src/second-factor-gate';
import type { EmailVerificationService } from '../src/email-verification.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import {
  LOGIN_ADDRESS_BOUND,
  LOGIN_BOUND,
  REGISTER_ADDRESS_BOUND,
  STEP_UP_BOUND,
} from '../src/rate-bounds';
import type { SessionRow, SessionsRepo } from '../src/sessions.repo';
import { STEPUP_DENIAL_WINDOW_MS, STEPUP_MAX_DENIALS } from '../src/stepup';
import { generateOpaqueToken, hashToken } from '../src/tokens';
import type { UsersRepo } from '../src/users.repo';
import type { Db } from '../src/db';

const NOW = new Date('2026-07-20T12:00:00Z');

/**
 * The refusal an awaited call threw, TYPED.
 *
 * `.catch((e) => e)` yields `any`, and `any` is exactly wrong on these cases:
 * what they assert is a precise status and body, and an `any` would let a typo
 * in a property name assert nothing at all while staying green.
 */
async function refusalFrom(promise: Promise<unknown>): Promise<HttpException> {
  let caught: unknown;
  try {
    await promise;
  } catch (err) {
    caught = err;
  }
  if (!(caught instanceof HttpException)) {
    throw new Error(`expected an HttpException refusal, got: ${String(caught)}`);
  }
  return caught;
}

function makeFakes(): {
  users: {
    findByEmailBidx: jest.Mock;
    insert: jest.Mock;
    findById: jest.Mock;
    updatePasswordHash: jest.Mock;
  };
  sessions: {
    create: jest.Mock;
    findLiveByAccessHash: jest.Mock;
    findLiveByRefreshHash: jest.Mock;
    findLiveByPrevRefreshHash: jest.Mock;
    rotateTokens: jest.Mock;
    revoke: jest.Mock;
    grantStepUp: jest.Mock;
    revokeAllForUserExcept: jest.Mock;
  };
  mfa: {
    insertTotp: jest.Mock;
    revokeUnverifiedTotp: jest.Mock;
    findActiveTotp: jest.Mock;
    markVerified: jest.Mock;
  };
  authEvents: { insert: jest.Mock; failedAttempts: jest.Mock };
  factors: { assertMayAddFactor: jest.Mock; holdsVerifiedFactor: jest.Mock };
  hasher: { hashPassword: jest.Mock; verifyPassword: jest.Mock; dummyVerify: jest.Mock };
  events: {
    userRegistered: jest.Mock;
    loginSucceeded: jest.Mock;
    loginFailed: jest.Mock;
    stepUpGranted: jest.Mock;
    stepUpRateLimited: jest.Mock;
    loginRateLimited: jest.Mock;
    registerRateLimited: jest.Mock;
    passwordChanged: jest.Mock;
    sessionRevoked: jest.Mock;
  };
  fieldCrypto: { getOrCreateDek: jest.Mock; encryptField: jest.Mock; decryptField: jest.Mock };
  deks: { findActiveByUser: jest.Mock };
  notifications: {
    upsertRecipient: jest.Mock;
    send: jest.Mock;
    sendAddressVerification: jest.Mock;
    sendAccountSecurity: jest.Mock;
    markRecipientVerified: jest.Mock;
    recipientStatus: jest.Mock;
  };
  emailVerification: { ensureVerificationRequested: jest.Mock };
  db: { withTransaction: jest.Mock; query: jest.Mock };
} {
  return {
    users: {
      findByEmailBidx: jest.fn().mockResolvedValue(null),
      insert: jest.fn(),
      findById: jest.fn().mockResolvedValue(null),
      updatePasswordHash: jest.fn().mockResolvedValue(true),
    },
    sessions: {
      create: jest.fn(),
      findLiveByAccessHash: jest.fn().mockResolvedValue(null),
      findLiveByRefreshHash: jest.fn().mockResolvedValue(null),
      findLiveByPrevRefreshHash: jest.fn().mockResolvedValue(null),
      rotateTokens: jest.fn(),
      revoke: jest.fn(),
      grantStepUp: jest.fn(),
      revokeAllForUserExcept: jest.fn().mockResolvedValue([]),
    },
    mfa: {
      insertTotp: jest.fn(),
      revokeUnverifiedTotp: jest.fn(),
      findActiveTotp: jest.fn().mockResolvedValue(null),
      markVerified: jest.fn(),
    },
    authEvents: { insert: jest.fn(), failedAttempts: jest.fn().mockResolvedValue(0) },
    // Stubbed: the gate has its own Postgres-backed spec, and these cases are
    // about the cap and the step-up path rather than enrolment policy.
    factors: {
      assertMayAddFactor: jest.fn().mockResolvedValue(undefined),
      holdsVerifiedFactor: jest.fn().mockResolvedValue(false),
    },
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
      loginRateLimited: jest.fn(),
      registerRateLimited: jest.fn(),
      passwordChanged: jest.fn(),
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
      sendAccountSecurity: jest.fn().mockResolvedValue({ accepted: true }),
      markRecipientVerified: jest.fn().mockResolvedValue({ ok: true }),
      recipientStatus: jest.fn().mockResolvedValue({ verified: true }),
    },
    // M14: the login hook is fire-and-forget, so a double that RESOLVES is
    // what keeps these tests deterministic — an unhandled rejection from a
    // detached promise would surface in an unrelated test.
    emailVerification: { ensureVerificationRequested: jest.fn().mockResolvedValue(undefined) },
    // The transaction is REAL enough to be wrong about: the fake runs the
    // callback, so a service that forgets to await inside it, or throws after a
    // partial write, still behaves observably here. What it cannot prove is
    // that the two statements COMMIT together — that is SQL, and
    // `password-change.int.spec.ts` drives it against real Postgres.
    db: {
      withTransaction: jest.fn(
        async (_actorId: string, fn: (tx: unknown) => Promise<unknown>): Promise<unknown> =>
          fn({ query: jest.fn().mockResolvedValue([]) }),
      ),
      query: jest.fn().mockResolvedValue([]),
    },
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
  notificationsSecurityToken: '',
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
    fakes.factors as unknown as SecondFactorGate,
    fakes.db as unknown as Db,
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
  /**
   * THE LOGIN BOUND (M17). The DECISION layer only — `address-bound.spec.ts`
   * proves the in-memory primitive and `login-bound.int.spec.ts` proves the
   * ledger predicate against real Postgres.
   *
   * Each case is a way the bound could be present and wrong: refusing with a
   * distinguishable status turns it into the account-existence oracle it was
   * added to close, and counting its own refusals turns a cooldown into a
   * permanent lockout.
   */
  describe('the login attempt bound', () => {
    const knownUser = {
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'active',
      dek_id: 'dek-1',
    };

    it('refuses on the ACCOUNT ceiling with the SAME 401 a wrong password gets', async () => {
      // The single most important assertion in the milestone. A 429 here would
      // be reachable only by naming an address that has an account, which is a
      // perfectly reliable existence oracle — the control manufacturing the
      // thing it exists to prevent.
      const fakes = makeFakes();
      fakes.users.findByEmailBidx.mockResolvedValue(knownUser);
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      fakes.authEvents.failedAttempts.mockResolvedValue(LOGIN_BOUND.maxPerAccount);
      const service = makeService(fakes);

      const refused = await refusalFrom(service.login('user@example.com', 'correct-horse'));
      expect(refused).toBeInstanceOf(UnauthorizedException);
      expect(refused.getStatus()).toBe(401);
      expect(refused.getResponse()).toEqual({ error: 'invalid_credentials' });
      expect(fakes.sessions.create).not.toHaveBeenCalled();
    });

    it('a refused login is indistinguishable from a wrong password, to the byte', async () => {
      // Same shape asserted from the other side: whatever an ordinary failure
      // answers, the rate refusal answers too. Written as a comparison rather
      // than a literal so it cannot drift if the ordinary token ever changes.
      const ordinary = makeFakes();
      ordinary.users.findByEmailBidx.mockResolvedValue(knownUser);
      const wrongPassword = await refusalFrom(
        makeService(ordinary).login('user@example.com', 'nope'),
      );

      const bounded = makeFakes();
      bounded.users.findByEmailBidx.mockResolvedValue(knownUser);
      bounded.hasher.verifyPassword.mockResolvedValue(true);
      bounded.authEvents.failedAttempts.mockResolvedValue(LOGIN_BOUND.maxPerAccount);
      const refused = await refusalFrom(
        makeService(bounded).login('user@example.com', 'correct-horse'),
      );

      expect(refused.getStatus()).toBe(wrongPassword.getStatus());
      expect(refused.getResponse()).toEqual(wrongPassword.getResponse());
    });

    it('records the refusal as its OWN kind, never as a login failure', async () => {
      // The counter must not feed itself: a refusal recorded as `login.failed`
      // would extend the window that refused it, and a retrying client would
      // hold its own account down permanently.
      const fakes = makeFakes();
      fakes.users.findByEmailBidx.mockResolvedValue(knownUser);
      fakes.authEvents.failedAttempts.mockResolvedValue(LOGIN_BOUND.maxPerAccount);
      const service = makeService(fakes);

      await expect(service.login('user@example.com', 'x')).rejects.toBeDefined();

      const kinds = fakes.authEvents.insert.mock.calls.map(
        (call: [{ kind: string }]) => call[0].kind,
      );
      expect(kinds).toEqual([LOGIN_BOUND.refusalKind]);
      expect(kinds).not.toContain('login.failed');
      expect(fakes.events.loginFailed).not.toHaveBeenCalled();
      expect(fakes.events.loginRateLimited).toHaveBeenCalledWith(
        'u-1',
        'account',
        LOGIN_BOUND.maxPerAccount,
      );
    });

    it('the ADDRESS half refuses before the user is ever looked up', async () => {
      // Existence-independent, so the early exit cannot correlate with whether
      // the account is real — and it is what keeps an unauthenticated caller
      // away from a 64 MiB Argon2 verification.
      const fakes = makeFakes();
      fakes.users.findByEmailBidx.mockResolvedValue(knownUser);
      const service = makeService(fakes);

      for (let i = 0; i < LOGIN_ADDRESS_BOUND.max; i += 1) {
        await expect(service.login('user@example.com', 'wrong')).rejects.toBeDefined();
      }
      fakes.users.findByEmailBidx.mockClear();
      fakes.hasher.verifyPassword.mockClear();
      fakes.hasher.dummyVerify.mockClear();

      const refused = await refusalFrom(service.login('user@example.com', 'wrong'));
      expect(refused.getResponse()).toEqual({ error: 'invalid_credentials' });
      expect(fakes.users.findByEmailBidx).not.toHaveBeenCalled();
      expect(fakes.hasher.verifyPassword).not.toHaveBeenCalled();
      expect(fakes.hasher.dummyVerify).not.toHaveBeenCalled();
      expect(fakes.events.loginRateLimited).toHaveBeenLastCalledWith(null, 'address', null);
    });

    it('bounds an UNKNOWN address too — the half the ledger cannot see', async () => {
      // `recordLoginFailure(null, …)` writes a NULL user, so the account-keyed
      // count is structurally blind here. If the address half did not cover it,
      // spraying one password across many addresses would be unbounded.
      const fakes = makeFakes();
      const service = makeService(fakes);

      for (let i = 0; i < LOGIN_ADDRESS_BOUND.max; i += 1) {
        await expect(service.login('nobody@example.com', 'wrong')).rejects.toBeDefined();
      }
      fakes.hasher.dummyVerify.mockClear();

      await expect(service.login('nobody@example.com', 'wrong')).rejects.toBeDefined();
      expect(fakes.hasher.dummyVerify).not.toHaveBeenCalled();
    });

    it('a SUCCESSFUL login forgives the address, so a fumble costs nothing later', async () => {
      // THE COUNT HAS TO CROSS THE CAP FOR THIS TO MEAN ANYTHING. The first
      // version of this case stopped one short and then made a single further
      // attempt — which stays under the cap whether or not the success cleared
      // anything, so it passed with the forgiveness deleted. Caught by mutation,
      // and it is the M13 lesson exactly: a test named for a property must
      // exercise the boundary that property decides.
      const fakes = makeFakes();
      fakes.users.findByEmailBidx.mockResolvedValue(knownUser);
      const service = makeService(fakes);

      // One short of the cap…
      for (let i = 0; i < LOGIN_ADDRESS_BOUND.max - 1; i += 1) {
        await expect(service.login('user@example.com', 'wrong')).rejects.toBeDefined();
      }
      // …then a success, which must reset the count to zero…
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      await expect(service.login('user@example.com', 'right')).resolves.toMatchObject({
        userId: 'u-1',
      });

      // …so that another full run of failures is affordable. Without the
      // forgiveness the count is already at the cap after the first of these,
      // and the last one is refused before the lookup.
      fakes.hasher.verifyPassword.mockResolvedValue(false);
      for (let i = 0; i < LOGIN_ADDRESS_BOUND.max - 1; i += 1) {
        await expect(service.login('user@example.com', 'wrong')).rejects.toBeDefined();
      }
      fakes.users.findByEmailBidx.mockClear();
      await expect(service.login('user@example.com', 'wrong')).rejects.toBeDefined();
      expect(fakes.users.findByEmailBidx).toHaveBeenCalled();
    });

    it('asks for failures within the configured window, with LOGIN’s own kinds', async () => {
      // A bound reading another bound's kinds is the M17 defect: the watermark
      // is one shared subquery, so a `login.succeeded` row in the step-up set
      // would zero the second-factor counter.
      const fakes = makeFakes();
      fakes.users.findByEmailBidx.mockResolvedValue(knownUser);
      const service = makeService(fakes);

      await expect(service.login('user@example.com', 'wrong')).rejects.toBeDefined();

      expect(fakes.authEvents.failedAttempts).toHaveBeenCalledWith(
        'u-1',
        new Date(NOW.getTime() - LOGIN_BOUND.windowMs),
        { failures: LOGIN_BOUND.failures, successes: LOGIN_BOUND.successes },
      );
    });
  });

  describe('the register attempt bound', () => {
    it('refuses with 429 — safe HERE, because the count says nothing about existence', async () => {
      // Register's bound is keyed on the submitted address alone and counted
      // whether or not an account exists, so the refusal depends on nothing the
      // caller does not already know. Login is the opposite and gets a 401.
      const fakes = makeFakes();
      const service = makeService(fakes);

      for (let i = 0; i < REGISTER_ADDRESS_BOUND.max; i += 1) {
        await service.register('new@example.com', 'a-long-password!');
      }
      fakes.hasher.hashPassword.mockClear();

      await expect(service.register('new@example.com', 'a-long-password!')).rejects.toMatchObject({
        status: 429,
        response: { error: 'too_many_attempts' },
      });
      // …and refused BEFORE the memory-hard hash, which is the point.
      expect(fakes.hasher.hashPassword).not.toHaveBeenCalled();
      expect(fakes.events.registerRateLimited).toHaveBeenCalledTimes(1);
    });

    it('counts attempts, not failures — there is no failure to count', async () => {
      // Register answers the same 201 for a new address and an existing one,
      // and that identical answer is the anti-enumeration control. So the bound
      // is on cost and probing, and a successful registration spends budget.
      const fakes = makeFakes();
      const service = makeService(fakes);

      for (let i = 0; i < REGISTER_ADDRESS_BOUND.max; i += 1) {
        fakes.users.findByEmailBidx.mockResolvedValue(i % 2 === 0 ? null : { id: 'u-1' });
        await service.register('new@example.com', 'a-long-password!');
      }
      await expect(service.register('new@example.com', 'a-long-password!')).rejects.toMatchObject({
        status: 429,
      });
    });
  });

  /**
   * THE PASSWORD CHANGE (M17 PR2) — the DECISION layer.
   * `password-change.int.spec.ts` drives the SQL: the redaction, the
   * transaction and the status predicate.
   */
  describe('changePassword', () => {
    const knownUser = {
      id: 'u-1',
      password_hash: 'argon2-hash',
      status: 'active',
      dek_id: 'dek-1',
    };
    const caller = { mfaLevel: 'none' as const, stepupExpiresAt: null };

    function withUser(fakes: ReturnType<typeof makeFakes>): void {
      fakes.users.findById = jest.fn().mockResolvedValue(knownUser);
      fakes.users.updatePasswordHash = jest.fn().mockResolvedValue(true);
      fakes.sessions.revokeAllForUserExcept = jest.fn().mockResolvedValue(['s-2', 's-3']);
    }

    it('ASKS THE STEP-UP QUESTION BEFORE checking the password', () => {
      // Order matters twice. An account that needs a fresh factor is told so
      // without the route first becoming a free password oracle; and the
      // refusal cannot vary in timing with whether the current password
      // happened to be right.
      const fakes = makeFakes();
      withUser(fakes);
      fakes.factors.assertMayAddFactor.mockRejectedValue(
        new ForbiddenException({ error: 'stepup_required' }),
      );
      const service = makeService(fakes);

      return expect(service.changePassword('u-1', 's-1', caller, 'old', 'new-long-password'))
        .rejects.toMatchObject({ response: { error: 'stepup_required' } })
        .then(() => {
          expect(fakes.hasher.verifyPassword).not.toHaveBeenCalled();
          expect(fakes.users.updatePasswordHash).not.toHaveBeenCalled();
        });
    });

    it('REQUIRES THE CURRENT PASSWORD — a stolen session alone is not enough', async () => {
      // The half a hijacked bearer token does not carry. Without it, anyone
      // holding a session could lock the owner out of their own account.
      const fakes = makeFakes();
      withUser(fakes);
      fakes.hasher.verifyPassword.mockResolvedValue(false);
      const service = makeService(fakes);

      await expect(
        service.changePassword('u-1', 's-1', caller, 'wrong', 'new-long-password'),
      ).rejects.toMatchObject({ response: { error: 'invalid_credentials' } });
      expect(fakes.users.updatePasswordHash).not.toHaveBeenCalled();
      expect(fakes.notifications.sendAccountSecurity).not.toHaveBeenCalled();
    });

    it('hashes the NEW password and never stores it in the clear', async () => {
      const fakes = makeFakes();
      withUser(fakes);
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      const service = makeService(fakes);

      await service.changePassword('u-1', 's-1', caller, 'old', 'new-long-password');

      expect(fakes.hasher.hashPassword).toHaveBeenCalledWith('new-long-password');
      const written = fakes.users.updatePasswordHash.mock.calls[0] as unknown[];
      expect(written[2]).toBe('argon2-hash'); // the hasher's output, not the input
      expect(written).not.toContain('new-long-password');
    });

    it('revokes the OTHER sessions and keeps the caller’s', async () => {
      const fakes = makeFakes();
      withUser(fakes);
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      const service = makeService(fakes);

      await service.changePassword('u-1', 's-1', caller, 'old', 'new-long-password');

      expect(fakes.sessions.revokeAllForUserExcept).toHaveBeenCalledWith(
        expect.anything(),
        'u-1',
        's-1',
        'password_changed',
        NOW,
      );
    });

    it('NOTIFIES the owner, and puts the outcome on the audit event', async () => {
      // The notice is the only thing that surfaces a change the owner did not
      // make, so a delivery failure has to be visible enough to re-drive rather
      // than swallowed (the M13 `ownerNotified` shape).
      const fakes = makeFakes();
      withUser(fakes);
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      fakes.notifications.sendAccountSecurity.mockResolvedValue({ accepted: false });
      const service = makeService(fakes);

      await service.changePassword('u-1', 's-1', caller, 'old', 'new-long-password');

      expect(fakes.notifications.sendAccountSecurity).toHaveBeenCalledWith({
        userId: 'u-1',
        kind: 'identity.password_changed',
      });
      expect(fakes.events.passwordChanged).toHaveBeenCalledWith('u-1', 's-1', 2, false);
    });

    it('a failed NOTIFICATION does not undo the change', async () => {
      // The change is committed before the notice is attempted. A password that
      // silently reverted because a mail failed would be far worse than a late
      // notice — the user would believe their credentials had moved when they
      // had not.
      const fakes = makeFakes();
      withUser(fakes);
      fakes.hasher.verifyPassword.mockResolvedValue(true);
      fakes.notifications.sendAccountSecurity.mockResolvedValue({ accepted: false });
      const service = makeService(fakes);

      await expect(
        service.changePassword('u-1', 's-1', caller, 'old', 'new-long-password'),
      ).resolves.toBeUndefined();
      expect(fakes.users.updatePasswordHash).toHaveBeenCalled();
    });
  });

  describe('the step-up attempt cap', () => {
    it('refuses at the cap with 429 too_many_attempts, before reading the TOTP secret', async () => {
      const fakes = makeFakes();
      fakes.authEvents.failedAttempts.mockResolvedValue(STEPUP_MAX_DENIALS);
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
      fakes.authEvents.failedAttempts.mockResolvedValue(STEPUP_MAX_DENIALS);
      const service = makeService(fakes);

      return expect(service.stepUp('u-1', 's-1', '000000'))
        .rejects.toMatchObject({ status: 429 })
        .then(() => {
          expect(fakes.authEvents.failedAttempts).toHaveBeenCalledTimes(1);
          expect(fakes.authEvents.failedAttempts).toHaveBeenCalledWith('u-1', expect.any(Date), {
            failures: STEP_UP_BOUND.failures,
            successes: STEP_UP_BOUND.successes,
            sessionId: 's-1',
          });
        });
    });

    it('records the refusal as its OWN kind, never as a denial', async () => {
      // The counter must not feed itself. If a refusal wrote `stepup.denied`,
      // every refused attempt would extend the window that refused it and a
      // retrying client would lock its own user out permanently.
      const fakes = makeFakes();
      fakes.authEvents.failedAttempts.mockResolvedValue(STEPUP_MAX_DENIALS + 3);
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
      fakes.authEvents.failedAttempts.mockResolvedValue(STEPUP_MAX_DENIALS - 1);
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

      expect(fakes.authEvents.failedAttempts).toHaveBeenCalledWith(
        'u-1',
        new Date(NOW.getTime() - STEPUP_DENIAL_WINDOW_MS),
        {
          failures: STEP_UP_BOUND.failures,
          successes: STEP_UP_BOUND.successes,
          sessionId: 's-1',
        },
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
    // victim's address. (M17 gave register a bound, so the old "no
    // rate-limiting machinery exists" half of this reasoning is gone; the
    // decision rests on the first half, since that bound is per-process and
    // best-effort.) The ceremony starts at the first authenticated LOGIN.
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
