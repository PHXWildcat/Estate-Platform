import { randomUUID } from 'node:crypto';
import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { CallerGuard, type CallerRequest } from '../src/caller.guard';
import { StepUpGuard } from '../src/stepup.guard';

function contextFor(headers: Record<string, string | string[] | undefined>): {
  ctx: ExecutionContext;
  request: CallerRequest;
} {
  const request: CallerRequest = { headers };
  const ctx = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { ctx, request };
}

describe('CallerGuard', () => {
  const guard = new CallerGuard();

  it('attaches the gateway-asserted caller', () => {
    const userId = randomUUID();
    const { ctx, request } = contextFor({ 'x-estate-user-id': userId });
    expect(guard.canActivate(ctx)).toBe(true);
    expect(request.caller).toEqual({ userId });
  });

  it.each([
    ['missing header', {}],
    ['malformed value', { 'x-estate-user-id': 'admin' }],
    ['array smuggling', { 'x-estate-user-id': ['a', 'b'] }],
  ])('rejects %s with a generic 401', (_label, headers) => {
    const { ctx } = contextFor(headers);
    expect(() => guard.canActivate(ctx)).toThrow(UnauthorizedException);
  });
});

describe('StepUpGuard', () => {
  const guard = new StepUpGuard();

  it('passes only the exact gateway assertion', () => {
    const { ctx } = contextFor({ 'x-estate-stepup-verified': 'true' });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it.each([
    ['missing header', {}],
    ['wrong value', { 'x-estate-stepup-verified': '1' }],
    ['case trickery', { 'x-estate-stepup-verified': 'TRUE' }],
  ])('rejects %s with stepup_required', (_label, headers) => {
    const { ctx } = contextFor(headers);
    try {
      guard.canActivate(ctx);
      fail('expected ForbiddenException');
    } catch (err) {
      expect(err).toBeInstanceOf(ForbiddenException);
      expect((err as ForbiddenException).getResponse()).toEqual({ error: 'stepup_required' });
    }
  });
});
