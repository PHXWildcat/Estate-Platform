import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SESSION_AUDIENCE_METADATA } from '../src/session-audience.decorator';
import { SessionGuard, type AuthedRequest } from '../src/session.guard';
import type { SessionsRepo } from '../src/sessions.repo';
import { StepUpGuard } from '../src/stepup.guard';
import { generateOpaqueToken, hashToken } from '../src/tokens';

const NOW = new Date('2026-07-20T12:00:00Z');

/**
 * `getHandler`/`getClass` are what the M15 audience check reflects over, so the
 * double has to supply them; an undecorated pair is the deny-by-default case.
 */
function contextFor(request: AuthedRequest): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => function handler(): void {},
    getClass: () => class Controller {},
  } as unknown as ExecutionContext;
}

/**
 * The M15 per-route audience gate on identity's OWN routes. Identity is the one
 * service that cannot take a single service-wide decision: introspection must
 * admit every audience or the vault origin cannot exist, while the routes that
 * MINT authority must admit none but `account`.
 */
describe('SessionGuard audience gate (per route, deny by default)', () => {
  const vaultRow = {
    id: 's-1',
    user_id: 'u-1',
    mfa_level: 'stepup' as const,
    stepup_expires_at: new Date(NOW.getTime() + 60_000),
    audience: 'vault' as const,
  };

  /** A context whose handler carries (or lacks) the widening decorator. */
  function decoratedContext(
    request: AuthedRequest,
    audiences?: readonly string[],
  ): ExecutionContext {
    const handler = function handler(): void {};
    if (audiences) {
      Reflect.defineMetadata(SESSION_AUDIENCE_METADATA, audiences, handler);
    }
    return {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => handler,
      getClass: () => class Controller {},
    } as unknown as ExecutionContext;
  }

  function guardFor(row: unknown): SessionGuard {
    const sessions = {
      findLiveByAccessHash: jest.fn().mockResolvedValue(row),
    } as unknown as SessionsRepo;
    return new SessionGuard(sessions, () => NOW, new Reflector());
  }

  const bearer = (): AuthedRequest => ({
    headers: { authorization: `Bearer ${generateOpaqueToken()}` },
  });

  it('REFUSES a vault session on an undecorated route', async () => {
    // The default, and the one that covers TOTP enrollment, WebAuthn
    // registration, the data export and — the load-bearing one — minting
    // another handoff.
    const request = bearer();
    await expect(guardFor(vaultRow).canActivate(decoratedContext(request))).rejects.toThrow(
      UnauthorizedException,
    );
    expect(request.auth).toBeUndefined();
  });

  it('admits a vault session on a route that widened', async () => {
    const request = bearer();
    await expect(
      guardFor(vaultRow).canActivate(decoratedContext(request, ['account', 'vault'])),
    ).resolves.toBe(true);
    expect(request.auth?.audience).toBe('vault');
  });

  it('still admits an account session on a widened route', async () => {
    const request = bearer();
    const accountRow = { ...vaultRow, audience: 'account' as const };
    await expect(
      guardFor(accountRow).canActivate(decoratedContext(request, ['account', 'vault'])),
    ).resolves.toBe(true);
  });

  it('refuses with the same body as an unknown token (no oracle)', async () => {
    const unknown = await guardFor(null)
      .canActivate(decoratedContext(bearer()))
      .catch((e: unknown) => e);
    const wrongAudience = await guardFor(vaultRow)
      .canActivate(decoratedContext(bearer()))
      .catch((e: unknown) => e);
    expect((wrongAudience as UnauthorizedException).getResponse()).toEqual(
      (unknown as UnauthorizedException).getResponse(),
    );
  });
});

describe('SessionGuard', () => {
  function makeGuard(findResult: unknown): {
    guard: SessionGuard;
    findLiveByAccessHash: jest.Mock;
  } {
    const findLiveByAccessHash = jest.fn().mockResolvedValue(findResult);
    const sessions = { findLiveByAccessHash } as unknown as SessionsRepo;
    return {
      guard: new SessionGuard(sessions, () => NOW, new Reflector()),
      findLiveByAccessHash,
    };
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
      audience: 'account',
    });
    const request: AuthedRequest = {
      headers: { authorization: `Bearer ${generateOpaqueToken()}` },
    };
    await expect(guard.canActivate(contextFor(request))).resolves.toBe(true);
    expect(request.auth).toEqual({
      userId: 'u-1',
      sessionId: 's-1',
      mfaLevel: 'stepup',
      audience: 'account',
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
        audience: 'account',
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
        audience: 'account',
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
        audience: 'account',
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
