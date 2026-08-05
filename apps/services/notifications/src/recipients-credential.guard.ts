import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { RECIPIENTS_CREDENTIAL } from './di-tokens';

/**
 * The recipient-upsert surface's guard: identical mechanism to
 * `ServiceCredentialGuard` (constant-time digest compare, fail closed on an
 * unwired or absent credential), bound to a DIFFERENT secret.
 *
 * It exists because a guard can only bind one token, and this service's two
 * internal surfaces must not share one. Sending is broadly held (vault,
 * settlement); saying where a user's notifications GO is identity's alone.
 * Subclassing rather than re-implementing keeps the comparison logic in one
 * place — the security-relevant code is inherited verbatim, and only the
 * injected expectation differs.
 */
@Injectable()
export class RecipientsCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(RECIPIENTS_CREDENTIAL) expected: string) {
    super(expected);
  }
}
