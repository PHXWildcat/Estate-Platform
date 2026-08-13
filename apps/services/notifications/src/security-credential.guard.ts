import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { SECURITY_CREDENTIAL } from './di-tokens';

/**
 * The account-security send surface's guard (M17). Same mechanism as
 * `ServiceCredentialGuard` — constant-time digest compare, fail closed on an
 * unwired or absent credential — bound to a different secret.
 *
 * Subclassing rather than re-implementing keeps the comparison in one place:
 * the security-relevant code is inherited verbatim and only the injected
 * expectation differs, exactly as `VerificationCredentialGuard` and
 * `RecipientsCredentialGuard` do.
 */
@Injectable()
export class SecurityCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(SECURITY_CREDENTIAL) expected: string) {
    super(expected);
  }
}
