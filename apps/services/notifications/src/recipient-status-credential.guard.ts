import { Inject, Injectable } from '@nestjs/common';
import { ServiceCredentialGuard } from '@estate/auth-guard';
import { RECIPIENT_STATUS_CREDENTIAL } from './di-tokens';

/**
 * The recipient-status read surface's guard (M14). Same inherited mechanism as
 * the other two, bound to its own secret — a guard binds exactly one token, so
 * the token IS the partition between capability classes.
 */
@Injectable()
export class RecipientStatusCredentialGuard extends ServiceCredentialGuard {
  constructor(@Inject(RECIPIENT_STATUS_CREDENTIAL) expected: string) {
    super(expected);
  }
}
