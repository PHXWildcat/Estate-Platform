import {
  BadRequestException,
  Inject,
  Injectable,
  Optional,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  DEFAULT_SESSION_AUDIENCE,
  SESSION_AUDIENCE_METADATA,
  type SessionAudience,
  type SessionContext,
} from './session';
import { SESSION_VERIFIER, type SessionVerifier } from './verifier';

/**
 * DI token for the session audiences a service admits (M15).
 *
 * Optional, and its ABSENCE is the secure setting: unwired, `CallerGuard`
 * admits `account` alone. A service widens it by binding this token to a list
 * in its own app.module, which is a line a reviewer sees and which
 * `test/session-audience.spec.ts` checks against the declaration in
 * `session.ts`. See AUDIENCE_ADMITTERS there for who may.
 */
export const ALLOWED_SESSION_AUDIENCES = Symbol('ALLOWED_SESSION_AUDIENCES');

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
 *
 * M15 adds the AUDIENCE check, deny by default: a verified session is refused
 * unless its audience is one this service admits, which is `account` alone
 * until a service says otherwise. That is what stops a leaked vault handoff
 * from becoming authority over assets, documents, profile or identity — the
 * eight services that never opt in reject it without changing a line.
 *
 * The refusal is the SAME generic 401 as an invalid token, on purpose. A
 * distinct "wrong audience" token would tell whoever presented a stolen vault
 * session that it is a real, live credential and merely pointed at the wrong
 * door, which is exactly the confirmation the uniform answer exists to
 * withhold (the M13/M14 uniform-refusal rule).
 */
@Injectable()
export class CallerGuard implements CanActivate {
  private readonly allowedAudiences: readonly SessionAudience[];

  constructor(
    @Inject(SESSION_VERIFIER) private readonly verifier: SessionVerifier,
    @Optional() @Inject(ALLOWED_SESSION_AUDIENCES) allowedAudiences?: readonly SessionAudience[],
    @Optional() private readonly reflector?: Reflector,
  ) {
    // An explicitly EMPTY list would admit nothing and lock the service out of
    // itself; treat it as unwired rather than as a configured denial, so a
    // mis-provided token cannot silently take a service offline.
    this.allowedAudiences =
      allowedAudiences && allowedAudiences.length > 0
        ? allowedAudiences
        : [DEFAULT_SESSION_AUDIENCE];
  }

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
    if (!this.audiencesFor(context).includes(session.audience)) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    request.caller = session;
    return true;
  }

  /**
   * The service-wide grant, WIDENED by a route that declares more.
   *
   * `getAllAndOverride` so a handler decorator wins over a controller-level
   * one; absent metadata is the service-wide list, never "unrestricted". The
   * two are UNIONED rather than replaced, so decorating a route in the vault
   * service could never accidentally narrow it below what the service admits —
   * a route-level table that could take authority away as well as add it would
   * be a second place to look when something is unexpectedly 401.
   */
  private audiencesFor(context: ExecutionContext): readonly SessionAudience[] {
    const perRoute = this.reflector?.getAllAndOverride<readonly SessionAudience[] | undefined>(
      SESSION_AUDIENCE_METADATA,
      [context.getHandler(), context.getClass()],
    );
    if (!perRoute) return this.allowedAudiences;
    return [...new Set([...this.allowedAudiences, ...perRoute])];
  }
}
