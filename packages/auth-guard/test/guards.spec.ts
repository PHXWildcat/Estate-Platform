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
    audience: 'account',
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

/**
 * The M15 audience gate. These are the assertions that say a leaked vault
 * handoff is not authority over the rest of the estate, so they are written
 * from the attacker's side: the interesting case is the one where the token is
 * genuine, live, and simply not for this door.
 */
describe('CallerGuard audience gate (deny by default)', () => {
  const vaultSession = session({ audience: 'vault' });

  it('admits an account session when nothing is configured', async () => {
    const { context, request } = contextFor({ authorization: 'Bearer good-token' });
    const guard = new CallerGuard(fakeVerifier('good-token', session()));
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.caller?.audience).toBe('account');
  });

  it('REFUSES a valid vault session at a service that never opted in', async () => {
    const { context, request } = contextFor({ authorization: 'Bearer stolen-handoff' });
    const guard = new CallerGuard(fakeVerifier('stolen-handoff', vaultSession));
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    // Nothing is attached, so no handler can run on a refused audience even if
    // a future controller forgot to check.
    expect(request.caller).toBeUndefined();
  });

  it('refuses it with the SAME body as an invalid token (no oracle)', async () => {
    const forged = contextFor({ authorization: 'Bearer forged' });
    const stolen = contextFor({ authorization: 'Bearer stolen-handoff' });
    const guard = new CallerGuard(fakeVerifier('stolen-handoff', vaultSession));

    const forgedErr = await guard.canActivate(forged.context).catch((e: unknown) => e);
    const stolenErr = await guard.canActivate(stolen.context).catch((e: unknown) => e);
    expect(forgedErr).toBeInstanceOf(UnauthorizedException);
    expect(stolenErr).toBeInstanceOf(UnauthorizedException);
    expect((stolenErr as UnauthorizedException).getResponse()).toEqual(
      (forgedErr as UnauthorizedException).getResponse(),
    );
  });

  it('admits a vault session where the service opted in', async () => {
    const { context, request } = contextFor({ authorization: 'Bearer handoff' });
    const guard = new CallerGuard(fakeVerifier('handoff', vaultSession), ['account', 'vault']);
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(request.caller?.audience).toBe('vault');
  });

  it('still admits an account session at a service that opted in', async () => {
    const { context } = contextFor({ authorization: 'Bearer ordinary' });
    const guard = new CallerGuard(fakeVerifier('ordinary', session()), ['account', 'vault']);
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('treats an empty allowlist as unwired rather than as "admit nothing"', async () => {
    // A mis-provided token must not silently take a service offline; the
    // secure reading of "no audiences configured" is the default one.
    const { context } = contextFor({ authorization: 'Bearer ordinary' });
    const guard = new CallerGuard(fakeVerifier('ordinary', session()), []);
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('an opted-in service does not thereby admit a THIRD audience', async () => {
    // Guards the shape of the check: `includes`, never "not the default".
    const future = session({ audience: 'future' as never });
    const { context } = contextFor({ authorization: 'Bearer future' });
    const guard = new CallerGuard(fakeVerifier('future', future), ['account', 'vault']);
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
