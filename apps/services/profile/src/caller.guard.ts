import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { z } from 'zod';

export interface CallerContext {
  /** The authenticated end-user's id, as asserted by the gateway/BFF. */
  userId: string;
}

/** Extract the CallerGuard-attached context; a wiring guard, never user-facing. */
export function requireCaller(request: CallerRequest): CallerContext {
  if (!request.caller) {
    // Unreachable behind CallerGuard; guards against a wiring mistake.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return request.caller;
}

/** The slice of the express request this guard reads/writes. */
export interface CallerRequest {
  headers: Record<string, string | string[] | undefined>;
  caller?: CallerContext;
}

const HEADER = 'x-estate-user-id';
const UuidSchema = z.string().uuid();

/**
 * Trust boundary (M2). This service does NOT yet call the identity service to
 * verify a session; instead it trusts the `x-estate-user-id` header, which the
 * BFF / API gateway injects AFTER verifying the caller's session token and
 * STRIPS from any inbound client request. It is therefore gateway-injected,
 * never user-supplied. Real cross-service session verification (calling
 * identity's `/v1/auth/session`, or mTLS + signed identity assertions) is a
 * later integration — see README.
 *
 * The guard only shape-checks the header is a UUID and attaches it to the
 * request; a missing/malformed header is a single generic 401.
 */
@Injectable()
export class CallerGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<CallerRequest>();
    const raw = request.headers[HEADER];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const parsed = UuidSchema.safeParse(value);
    if (!parsed.success) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    request.caller = { userId: parsed.data };
    return true;
  }
}
