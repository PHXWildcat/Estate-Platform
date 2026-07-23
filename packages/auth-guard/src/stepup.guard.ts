import {
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { requireCaller, type CallerRequest } from './caller.guard';
import { isStepUpFresh, type Clock } from './session';
import { SESSION_CLOCK } from './verifier';

/**
 * Step-up gate for sensitive actions (docs/01 §5: trustee/executor/beneficiary
 * changes, deletion-class actions, etc. require step-up MFA fresh within 5 min).
 *
 * Unlike the M2 `x-estate-stepup-verified: true` header this replaces, the gate
 * now reads the VERIFIED session that CallerGuard attached and checks real
 * freshness (`mfa_level == 'stepup'` AND `stepup_expires_at > now`) — the same
 * `isStepUpFresh` identity uses when it grants the elevation. A boolean header
 * can no longer stand in for a fresh step-up. Must run AFTER CallerGuard.
 *
 * A distinct 403 `stepup_required` tells well-behaved clients to elevate,
 * leaking nothing else.
 */
@Injectable()
export class StepUpGuard implements CanActivate {
  private readonly clock: Clock;

  constructor(@Optional() @Inject(SESSION_CLOCK) clock?: Clock) {
    this.clock = clock ?? ((): Date => new Date());
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<CallerRequest>();
    const caller = requireCaller(request);
    if (!isStepUpFresh(caller.mfaLevel, caller.stepupExpiresAt, this.clock())) {
      throw new ForbiddenException({ error: 'stepup_required' });
    }
    return true;
  }
}
