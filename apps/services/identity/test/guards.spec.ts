import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { SessionGuard, type AuthedRequest } from '../src/session.guard';
import type { SessionsRepo } from '../src/sessions.repo';
import { StepUpGuard } from '../src/stepup.guard';
import { generateOpaqueToken, hashToken } from '../src/tokens';

const NOW = new Date('2026-07-20T12:00:00Z');

function contextFor(request: AuthedRequest): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

describe('SessionGuard', () => {
  function makeGuard(findResult: unknown): {
    guard: SessionGuard;
    findLiveByAccessHash: jest.Mock;
  } {
    const findLiveByAccessHash = jest.fn().mockResolvedValue(findResult);
    const sessions = { findLiveByAccessHash } as unknown as SessionsRepo;
    return { guard: new SessionGuard(sessions, () => NOW), findLiveByAccessHash };
  }

  it('rejects a missing Authorization header without touching the DB', async () => {
    const { guard, findLiveByAccessHash } = makeGuard(null);
    await expect(guard.canActivate(contextFor({ headers: {} }))).rejects.toThrow(
      UnauthorizedException,
    );
    expect(findLiveByAccessHash).not.toHaveBeenCalled();
  });

  it('rejects a non-Bearer scheme', async () => {
    const { guard } = makeGuard(null);
    const request: AuthedRequest = { headers: { authorization: 'Basic abc' } };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(UnauthorizedException);
  });

  it('rejects when no live session matches the token hash', async () => {
    const { guard, findLiveByAccessHash } = makeGuard(null);
    const token = generateOpaqueToken();
    const request: AuthedRequest = { headers: { authorization: `Bearer ${token}` } };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(UnauthorizedException);
    const [presentedHash, at] = findLiveByAccessHash.mock.calls[0] as [Buffer, Date];
    expect(presentedHash.equals(hashToken(token))).toBe(true); // only the hash is looked up
    expect(at).toBe(NOW);
  });

  it('attaches the session context for a live session', async () => {
    const stepupExpiresAt = new Date(NOW.getTime() + 60_000);
    const { guard } = makeGuard({
      id: 's-1',
      user_id: 'u-1',
      mfa_level: 'stepup',
      stepup_expires_at: stepupExpiresAt,
    });
    const request: AuthedRequest = {
      headers: { authorization: `Bearer ${generateOpaqueToken()}` },
    };
    await expect(guard.canActivate(contextFor(request))).resolves.toBe(true);
    expect(request.auth).toEqual({
      userId: 'u-1',
      sessionId: 's-1',
      mfaLevel: 'stepup',
      stepupExpiresAt,
    });
  });
});

describe('StepUpGuard', () => {
  const guard = new StepUpGuard(() => NOW);

  it('allows a fresh stepped-up session', () => {
    const request: AuthedRequest = {
      headers: {},
      auth: {
        userId: 'u-1',
        sessionId: 's-1',
        mfaLevel: 'stepup',
        stepupExpiresAt: new Date(NOW.getTime() + 1000),
      },
    };
    expect(guard.canActivate(contextFor(request))).toBe(true);
  });

  it('rejects when the freshness window has lapsed', () => {
    const request: AuthedRequest = {
      headers: {},
      auth: {
        userId: 'u-1',
        sessionId: 's-1',
        mfaLevel: 'stepup',
        stepupExpiresAt: new Date(NOW.getTime() - 1000),
      },
    };
    expect(() => guard.canActivate(contextFor(request))).toThrow(ForbiddenException);
  });

  it('rejects sessions without step-up level', () => {
    const request: AuthedRequest = {
      headers: {},
      auth: {
        userId: 'u-1',
        sessionId: 's-1',
        mfaLevel: 'none',
        stepupExpiresAt: new Date(NOW.getTime() + 1000),
      },
    };
    expect(() => guard.canActivate(contextFor(request))).toThrow(ForbiddenException);
  });

  it('rejects when SessionGuard did not run (no auth context)', () => {
    expect(() => guard.canActivate(contextFor({ headers: {} }))).toThrow(ForbiddenException);
  });

  it('the 403 body is the machine token stepup_required', () => {
    try {
      guard.canActivate(contextFor({ headers: {} }));
      throw new Error('expected ForbiddenException');
    } catch (err) {
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'stepup_required' });
    }
  });
});
