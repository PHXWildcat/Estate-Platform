import { UnauthorizedException } from '@nestjs/common';
import type { DekRepository, FieldCrypto } from '@estate/crypto';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import { AuthService } from '../src/auth.service';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { MfaRepo } from '../src/mfa.repo';
import type { PasswordHasher } from '../src/password';
import type { SessionRow, SessionsRepo } from '../src/sessions.repo';
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
  authEvents: { insert: jest.Mock };
  hasher: { hashPassword: jest.Mock; verifyPassword: jest.Mock; dummyVerify: jest.Mock };
  events: {
    userRegistered: jest.Mock;
    loginSucceeded: jest.Mock;
    loginFailed: jest.Mock;
    stepUpGranted: jest.Mock;
    sessionRevoked: jest.Mock;
  };
  fieldCrypto: { getOrCreateDek: jest.Mock; encryptField: jest.Mock; decryptField: jest.Mock };
  deks: { findActiveByUser: jest.Mock };
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
    authEvents: { insert: jest.fn() },
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
      sessionRevoked: jest.fn(),
    },
    fieldCrypto: {
      getOrCreateDek: jest.fn().mockResolvedValue('dek-1'),
      encryptField: jest.fn().mockResolvedValue({ ciphertext: Buffer.from('ct'), dekId: 'dek-1' }),
      decryptField: jest.fn(),
    },
    deks: { findActiveByUser: jest.fn().mockResolvedValue(null) },
  };
}

const config: IdentityConfig = {
  nodeEnv: 'test',
  port: 3001,
  databaseUrl: 'postgres://unused',
  kmsMasterKey: Buffer.alloc(32, 7),
  emailIndexKey: Buffer.alloc(32, 9),
  kafkaBrokers: null,
  kekAlias: 'test/kek',
  rpId: 'localhost',
  rpOrigin: 'http://localhost:3000',
  rpName: 'Estate Platform',
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
});
