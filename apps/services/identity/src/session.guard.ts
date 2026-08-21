import {
  BadRequestException,
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { MfaLevel } from '@estate/contracts';
import { DEFAULT_SESSION_AUDIENCE, type SessionAudience } from '@estate/auth-guard';
import { CLOCK, type Clock } from './di-tokens';
import { SESSION_AUDIENCE_METADATA } from './session-audience.decorator';
import { SessionsRepo } from './sessions.repo';
import { hashToken } from './tokens';

export interface SessionContext {
  userId: string;
  sessionId: string;
  mfaLevel: MfaLevel;
  stepupExpiresAt: Date | null;
  /** M15: what this session may be spent on. */
  audience: SessionAudience;
}

/** The slice of the express request this service reads/writes. */
export interface AuthedRequest {
  headers: Record<string, string | string[] | undefined>;
  auth?: SessionContext;
}

/**
 * The session a guarded handler is entitled to assume. Lives here rather than
 * in a controller because both controllers behind `SessionGuard` need it and a
 * second copy is a copy that drifts (M25 PR2 moved it; `auth.controller.ts`
 * held the only definition).
 */
export function requireAuth(request: AuthedRequest): SessionContext {
  const auth = request.auth;
  if (!auth) {
    // Unreachable behind SessionGuard; guards against wiring mistakes.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return auth;
}

/**
 * Bearer access-token guard: hash the presented opaque token, look up a live
 * session (revocation + both expiries enforced in SQL), attach the session
 * context to the request. Failures are a single generic 401.
 *
 * M15 adds the per-route AUDIENCE check, deny by default: a route admits
 * `account` alone unless `@AllowSessionAudiences(...)` widens it. The refusal
 * is the same generic 401 as an unknown token, so presenting a leaked vault
 * session at, say, the TOTP-enrollment route learns nothing about whether that
 * session is real — the uniform-refusal rule, and the same choice
 * `CallerGuard` makes downstream.
 */
@Injectable()
export class SessionGuard implements CanActivate {
  constructor(
    private readonly sessions: SessionsRepo,
    @Inject(CLOCK) private readonly clock: Clock,
    private readonly reflector: Reflector,
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
    // getAllAndOverride so a handler decorator wins over a controller-level
    // one; absent metadata is the restrictive default, never "unrestricted".
    const allowed = this.reflector.getAllAndOverride<readonly SessionAudience[] | undefined>(
      SESSION_AUDIENCE_METADATA,
      [context.getHandler(), context.getClass()],
    ) ?? [DEFAULT_SESSION_AUDIENCE];
    if (!allowed.includes(session.audience)) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    request.auth = {
      userId: session.user_id,
      sessionId: session.id,
      mfaLevel: session.mfa_level,
      stepupExpiresAt: session.stepup_expires_at,
      audience: session.audience,
    };
    return true;
  }
}
