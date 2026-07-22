import { randomUUID } from 'node:crypto';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { CallerGuard, requireCaller, type CallerRequest } from '../src/caller.guard';
import { StepUpGuard } from '../src/stepup.guard';

function contextFor(headers: Record<string, string | string[] | undefined>): {
  context: ExecutionContext;
  request: CallerRequest;
} {
  const request: CallerRequest = { headers };
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  return { context, request };
}

describe('CallerGuard (gateway-injected identity)', () => {
  it('accepts a UUID caller header and attaches the caller context', () => {
    const userId = randomUUID();
    const { context, request } = contextFor({ 'x-estate-user-id': userId });
    expect(new CallerGuard().canActivate(context)).toBe(true);
    expect(requireCaller(request).userId).toBe(userId);
  });

  it.each([
    ['missing', {}],
    ['malformed', { 'x-estate-user-id': 'not-a-uuid' }],
    ['array-smuggled', { 'x-estate-user-id': ['a', 'b'] }],
  ])('rejects a %s header with a generic 401', (_label, headers) => {
    const { context } = contextFor(headers);
    expect(() => new CallerGuard().canActivate(context)).toThrow(UnauthorizedException);
  });
});

describe('StepUpGuard (revocation gate)', () => {
  it('passes only the exact gateway assertion', () => {
    const { context } = contextFor({ 'x-estate-stepup-verified': 'true' });
    expect(new StepUpGuard().canActivate(context)).toBe(true);
  });

  it.each([
    ['missing', {}],
    ['false', { 'x-estate-stepup-verified': 'false' }],
    ['casing games', { 'x-estate-stepup-verified': 'TRUE' }],
  ])('rejects %s with stepup_required', (_label, headers) => {
    const { context } = contextFor(headers);
    expect(() => new StepUpGuard().canActivate(context)).toThrow(ForbiddenException);
  });
});
