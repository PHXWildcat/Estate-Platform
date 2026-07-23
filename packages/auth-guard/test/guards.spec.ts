import { randomUUID } from 'node:crypto';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { CallerGuard } from '../src/caller.guard';
import { StepUpGuard } from '../src/stepup.guard';
import { STEPUP_WINDOW_MS, type SessionContext } from '../src/session';
import type { SessionVerifier } from '../src/verifier';

function contextFor(headers: Record<string, string | string[] | undefined>): {
  context: ExecutionContext;
  request: { headers: typeof headers; caller?: SessionContext };
} {
  const request: { headers: typeof headers; caller?: SessionContext } = { headers };
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

function session(over: Partial<SessionContext> = {}): SessionContext {
  return {
    userId: randomUUID(),
    sessionId: randomUUID(),
    mfaLevel: 'mfa',
    stepupExpiresAt: null,
    ...over,
  };
}

/** A verifier that resolves exactly one token to one session. */
function fakeVerifier(token: string, resolved: SessionContext | null): SessionVerifier {
  return { verify: (t) => Promise.resolve(t === token ? resolved : null) };
}

describe('CallerGuard (real session verification)', () => {
  it('attaches the verified session for a valid bearer token', async () => {
    const ctx = session();
    const { context, request } = contextFor({ authorization: 'Bearer good-token' });
    const guard = new CallerGuard(fakeVerifier('good-token', ctx));
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.caller).toEqual(ctx);
  });

  it.each([
    ['missing header', {}],
    ['non-bearer scheme', { authorization: 'Basic abc' }],
    ['array-smuggled', { authorization: ['Bearer a', 'Bearer b'] }],
  ])('rejects %s with a generic 401', async (_label, headers) => {
    const { context } = contextFor(headers);
    const guard = new CallerGuard(fakeVerifier('good-token', session()));
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });

  it('rejects a token the verifier does not recognize (invalid/expired/revoked ⇒ 401)', async () => {
    const { context } = contextFor({ authorization: 'Bearer forged' });
    const guard = new CallerGuard(fakeVerifier('good-token', session()));
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
  });
});

describe('StepUpGuard (verified freshness, not a header)', () => {
  const now = new Date('2026-07-23T12:00:00Z');
  const clock = (): Date => now;

  function withCaller(caller: SessionContext): ExecutionContext {
    const request = { headers: {}, caller };
    return { switchToHttp: () => ({ getRequest: () => request }) } as unknown as ExecutionContext;
  }

  it('passes a fresh step-up session', () => {
    const caller = session({
      mfaLevel: 'stepup',
      stepupExpiresAt: new Date(now.getTime() + STEPUP_WINDOW_MS),
    });
    expect(new StepUpGuard(clock).canActivate(withCaller(caller))).toBe(true);
  });

  it.each([
    ['mfa but not stepped up', session({ mfaLevel: 'mfa', stepupExpiresAt: null })],
    [
      'stepup that has expired',
      session({ mfaLevel: 'stepup', stepupExpiresAt: new Date(now.getTime() - 1000) }),
    ],
    ['stepup level but null expiry', session({ mfaLevel: 'stepup', stepupExpiresAt: null })],
  ])('rejects %s with stepup_required', (_label, caller) => {
    expect(() => new StepUpGuard(clock).canActivate(withCaller(caller))).toThrow(
      ForbiddenException,
    );
  });

  it('defaults to the real clock when no clock is injected', () => {
    // A step-up comfortably inside the window is fresh against `new Date()`.
    const caller = session({
      mfaLevel: 'stepup',
      stepupExpiresAt: new Date(Date.now() + 60_000),
    });
    expect(new StepUpGuard().canActivate(withCaller(caller))).toBe(true);
  });

  it('throws invalid_request when CallerGuard did not run (no caller attached)', () => {
    const request = { headers: {} };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
    expect(() => new StepUpGuard(clock).canActivate(ctx)).toThrow();
  });
});
