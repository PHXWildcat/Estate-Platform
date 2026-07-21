import {
  ForbiddenException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { CLOCK, type Clock } from './di-tokens';
import type { AuthedRequest } from './session.guard';
import { isStepUpFresh } from './stepup';

/**
 * Enforces the docs/01 §5 step-up rule: sensitive operations require a
 * session at mfa_level 'stepup' whose ≤5-minute freshness window is still
 * open. Must run AFTER SessionGuard (it reads the attached session context).
 */
@Injectable()
export class StepUpGuard implements CanActivate {
  constructor(@Inject(CLOCK) private readonly clock: Clock) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthedRequest>();
    const auth = request.auth;
    if (!auth || !isStepUpFresh(auth.mfaLevel, auth.stepupExpiresAt, this.clock())) {
      throw new ForbiddenException({ error: 'stepup_required' });
    }
    return true;
  }
}
