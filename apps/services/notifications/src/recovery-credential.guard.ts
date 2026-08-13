import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { RECOVERY_CREDENTIAL } from './di-tokens';

/**
 * The password-reset send surface's guard (M17 PR3). Same mechanism as
 * `ServiceCredentialGuard` — constant-time digest compare, fail closed on an
 * unwired or absent credential — bound to a different secret.
 *
 * Subclassing rather than re-implementing keeps the comparison in one place, as
 * `VerificationCredentialGuard` and `SecurityCredentialGuard` do.
 */
@Injectable()
export class RecoveryCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(RECOVERY_CREDENTIAL) expected: string) {
    super(expected);
  }
}
