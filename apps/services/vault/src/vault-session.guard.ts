import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { requireCaller, type CallerRequest } from '@estate/auth-guard';
import { CLOCK, type Clock } from './di-tokens';
import { Db } from './db';
import { VaultSessionsRepo } from './sessions.repo';
import { hashToken } from './tokens';

export const VAULT_SESSION_HEADER = 'x-estate-vault-session';

export interface VaultSessionContext {
  readonly id: string;
  readonly userId: string;
  readonly accountSessionId: string;
  readonly keysetAuthKey: Buffer;
  readonly expiresAt: Date;
}

export interface VaultRequest extends CallerRequest {
  vaultSession?: VaultSessionContext;
}

export function requireVaultSession(request: VaultRequest): VaultSessionContext {
  const session = request.vaultSession;
  // Unreachable when the guard is wired; a wiring mistake must not fall
  // through to an unauthenticated handler.
  if (!session) throw new BadRequestException({ error: 'invalid_request' });
  return session;
}

/**
 * Requires an open vault: a live vault session, obtained by completing an SRP
 * exchange under a step-up-fresh account session.
 *
 * Two bindings beyond "the token exists":
 *  - the session's user must be the verified caller, and
 *  - it must have been opened from THIS account session, so a stolen vault
 *    token is useless from another login.
 *
 * Runs after CallerGuard, which is what puts the verified caller on the
 * request. Item CRUD rides this session rather than re-asserting step-up on
 * every call: the vault was opened under step-up at most 15 minutes ago, which
 * is the freshness docs/01 §5 asks for on vault access.
 */
@Injectable()
export class VaultSessionGuard implements CanActivate {
  constructor(
    private readonly db: Db,
    private readonly sessions: VaultSessionsRepo,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<VaultRequest>();
    const caller = requireCaller(request);

    const header = request.headers[VAULT_SESSION_HEADER];
    const token = Array.isArray(header) ? header[0] : header;
    if (!token) throw new ForbiddenException({ error: 'vault_locked' });

    const row = await this.sessions.findLiveByTokenHash(this.db, hashToken(token), this.clock());
    if (!row || row.user_id !== caller.userId || row.account_session_id !== caller.sessionId) {
      // One token for every failure: absent, expired, revoked, someone else's,
      // or opened from a different login. Distinguishing them would say which
      // vaults are open.
      throw new ForbiddenException({ error: 'vault_locked' });
    }

    request.vaultSession = {
      id: row.id,
      userId: row.user_id,
      accountSessionId: row.account_session_id,
      keysetAuthKey: row.keyset_auth_key,
      expiresAt: row.expires_at,
    };
    return true;
  }
}
