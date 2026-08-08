import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { VERIFICATION_CREDENTIAL } from './di-tokens';

/**
 * The address-verification send surface's guard (M14). Same mechanism as
 * `ServiceCredentialGuard` — constant-time digest compare, fail closed on an
 * unwired or absent credential — bound to a different secret.
 *
 * Subclassing rather than re-implementing keeps the comparison in one place:
 * the security-relevant code is inherited verbatim and only the injected
 * expectation differs, exactly as `RecipientsCredentialGuard` does.
 */
@Injectable()
export class VerificationCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(VERIFICATION_CREDENTIAL) expected: string) {
    super(expected);
  }
}
