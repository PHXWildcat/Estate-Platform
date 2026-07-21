import {
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { MfaLevel } from '@estate/contracts';
import { CLOCK, type Clock } from './di-tokens';
import { SessionsRepo } from './sessions.repo';
import { hashToken } from './tokens';

export interface SessionContext {
  userId: string;
  sessionId: string;
  mfaLevel: MfaLevel;
  stepupExpiresAt: Date | null;
}

/** The slice of the express request this service reads/writes. */
export interface AuthedRequest {
  headers: Record<string, string | string[] | undefined>;
  auth?: SessionContext;
}

/**
 * Bearer access-token guard: hash the presented opaque token, look up a live
 * session (revocation + both expiries enforced in SQL), attach the session
 * context to the request. Failures are a single generic 401.
 */
@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly sessions: SessionsRepo,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthedRequest>();
    const header = request.headers['authorization'];
    const token =
      typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    const session = await this.sessions.findLiveByAccessHash(hashToken(token), this.clock());
    if (!session) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    request.auth = {
      userId: session.user_id,
      sessionId: session.id,
      mfaLevel: session.mfa_level,
      stepupExpiresAt: session.stepup_expires_at,
    };
    return true;
  }
}
