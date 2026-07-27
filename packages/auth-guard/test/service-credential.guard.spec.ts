import { UnauthorizedException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { SERVICE_CREDENTIAL_HEADER, ServiceCredentialGuard } from '../src/service-credential.guard';

function contextFor(headers: Record<string, string | string[] | undefined>): ExecutionContext {
  const request = { headers };
  return { switchToHttp: () => ({ getRequest: () => request }) } as unknown as ExecutionContext;
}

describe('ServiceCredentialGuard (internal service-to-service routes)', () => {
  const secret = 'a-long-random-internal-credential';

  it('passes when the presented credential matches', () => {
    const guard = new ServiceCredentialGuard(secret);
    expect(guard.canActivate(contextFor({ [SERVICE_CREDENTIAL_HEADER]: secret }))).toBe(true);
  });

  it.each([
    ['missing header', {}],
    ['wrong credential', { [SERVICE_CREDENTIAL_HEADER]: 'wrong' }],
    ['empty credential', { [SERVICE_CREDENTIAL_HEADER]: '' }],
    ['array-smuggled header', { [SERVICE_CREDENTIAL_HEADER]: [secret, secret] }],
    ['prefix of the secret', { [SERVICE_CREDENTIAL_HEADER]: secret.slice(0, -1) }],
    ['secret plus a suffix', { [SERVICE_CREDENTIAL_HEADER]: `${secret}x` }],
  ])('rejects %s with a generic 401', (_label, headers) => {
    const guard = new ServiceCredentialGuard(secret);
    expect(() => guard.canActivate(contextFor(headers))).toThrow(UnauthorizedException);
  });

  it('fails closed when the expected credential is unwired (empty)', () => {
    // A misconfigured host must refuse everything, including an empty match —
    // an empty shared secret is a wiring error, not a credential.
    const guard = new ServiceCredentialGuard('');
    expect(() => guard.canActivate(contextFor({ [SERVICE_CREDENTIAL_HEADER]: '' }))).toThrow(
      UnauthorizedException,
    );
    expect(() => guard.canActivate(contextFor({}))).toThrow(UnauthorizedException);
  });

  it('never leaks which side mismatched: same error token for every failure', () => {
    const guard = new ServiceCredentialGuard(secret);
    let caught: unknown;
    try {
      guard.canActivate(contextFor({ [SERVICE_CREDENTIAL_HEADER]: 'wrong' }));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(UnauthorizedException);
    expect((caught as UnauthorizedException).getResponse()).toEqual({ error: 'unauthorized' });
  });
});
