import {
  ForbiddenException,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { CallerRequest } from './caller.guard';

const HEADER = 'x-estate-stepup-verified';

/**
 * Step-up assertion gate for beneficiary changes (docs/01 §5: trustee/
 * executor/beneficiary changes require step-up MFA fresh within 5 minutes).
 *
 * TRUST MODEL (M2 boundary — an explicit, documented deviation): this guard
 * trusts the gateway-injected `x-estate-stepup-verified: true` header, which
 * the BFF/gateway sets ONLY after verifying with the identity service that
 * the caller's session holds `mfa_level = 'stepup'` inside the ≤5-minute
 * freshness window, and STRIPS from any inbound client request — exactly the
 * trust level of `x-estate-user-id` in CallerGuard. Real cross-service
 * session verification upgrades both headers at once (see README).
 *
 * A distinct 403 token tells well-behaved clients to elevate, leaking
 * nothing else. Must run after CallerGuard.
 */
@Injectable()
export class StepUpGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<CallerRequest>();
    const raw = request.headers[HEADER];
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (value !== 'true') {
      throw new ForbiddenException({ error: 'stepup_required' });
    }
    return true;
  }
}
