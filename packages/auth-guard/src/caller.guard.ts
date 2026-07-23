import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { SessionContext } from './session';
import { SESSION_VERIFIER, type SessionVerifier } from './verifier';

/**
 * The verified caller. A superset of the old `{ userId }` — controllers that
 * read `.userId` are unchanged; step-up-aware code can read `mfaLevel` /
 * `stepupExpiresAt` from the same context.
 */
export type CallerContext = SessionContext;

/** The slice of the express request the guard reads/writes. */
export interface CallerRequest {
  headers: Record<string, string | string[] | undefined>;
  caller?: CallerContext;
}

/** Extract the CallerGuard-attached context; a wiring guard, never user-facing. */
export function requireCaller(request: CallerRequest): CallerContext {
  if (!request.caller) {
    // Unreachable behind CallerGuard; guards against a wiring mistake.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return request.caller;
}

function bearerToken(request: CallerRequest): string | null {
  const raw = request.headers['authorization'];
  const header = Array.isArray(raw) ? raw[0] : raw;
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : null;
}

/**
 * Real cross-service session verification (replaces the M2 `x-estate-user-id`
 * header trust). The caller presents their opaque access token as
 * `Authorization: Bearer <token>`; the injected SessionVerifier resolves it
 * against the identity service (which owns the session store), and the verified
 * `SessionContext` is attached to the request. A missing/invalid/expired/revoked
 * token is a single generic 401 — the service trusts identity's answer, not a
 * spoofable header. Downstream authorization (Cedar PEP) still runs on top.
 */
@Injectable()
export class CallerGuard implements CanActivate {
  constructor(@Inject(SESSION_VERIFIER) private readonly verifier: SessionVerifier) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<CallerRequest>();
    const token = bearerToken(request);
    if (!token) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    const session = await this.verifier.verify(token);
    if (!session) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    request.caller = session;
    return true;
  }
}
