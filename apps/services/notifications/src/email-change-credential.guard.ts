import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { EMAIL_CHANGE_CREDENTIAL } from './di-tokens';

/**
 * The email-change challenge surface's guard (M17 PR4). Same mechanism as
 * `ServiceCredentialGuard` — constant-time digest compare, fail closed on an
 * unwired or absent credential — bound to a different secret.
 *
 * Subclassing rather than re-implementing keeps the comparison in one place,
 * as its three siblings do.
 */
@Injectable()
export class EmailChangeCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(EMAIL_CHANGE_CREDENTIAL) expected: string) {
    super(expected);
  }
}
