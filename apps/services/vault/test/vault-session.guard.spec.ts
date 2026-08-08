import { BadRequestException, ForbiddenException, type ExecutionContext } from '@nestjs/common';
import type { SessionContext } from '@estate/auth-guard';
import {
  requireVaultSession,
  VAULT_SESSION_HEADER,
  VaultSessionGuard,
  type VaultRequest,
} from '../src/vault-session.guard';
import { hashToken } from '../src/tokens';
import type { VaultSessionRow } from '../src/sessions.repo';
import type { Db } from '../src/db';
import type { VaultSessionsRepo } from '../src/sessions.repo';

const USER = 'd4c3b2a1-0f9e-4d8c-8b7a-695847362514';
const ACCOUNT_SESSION = '10203040-5060-4708-8090-a0b0c0d0e0f0';
const TOKEN = 'a-vault-session-token';
const NOW = new Date('2026-07-25T12:00:00.000Z');

function callerOf(overrides: Partial<SessionContext> = {}): SessionContext {
  return {
    userId: USER,
    sessionId: ACCOUNT_SESSION,
    mfaLevel: 'stepup',
    stepupExpiresAt: new Date(NOW.getTime() + 60_000),
    audience: 'account',
    ...overrides,
  };
}

function rowOf(overrides: Partial<VaultSessionRow> = {}): VaultSessionRow {
  return {
    id: 'fedcba98-7654-4321-8fed-cba987654321',
    user_id: USER,
    token_h: hashToken(TOKEN),
    account_session_id: ACCOUNT_SESSION,
    keyset_auth_key: Buffer.alloc(32, 9),
    created_at: NOW,
    expires_at: new Date(NOW.getTime() + 900_000),
    revoked_at: null,
    revoke_reason: null,
    ...overrides,
  };
}

function contextFor(request: VaultRequest): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: <T>(): T => request as T }),
  } as unknown as ExecutionContext;
}

function guardWith(row: VaultSessionRow | null): {
  guard: VaultSessionGuard;
  lookups: Buffer[];
} {
  const lookups: Buffer[] = [];
  const sessions = {
    findLiveByTokenHash: (_db: unknown, tokenHash: Buffer): Promise<VaultSessionRow | null> => {
      lookups.push(tokenHash);
      return Promise.resolve(row);
    },
  } as unknown as VaultSessionsRepo;
  return {
    guard: new VaultSessionGuard({} as Db, sessions, () => NOW),
    lookups,
  };
}

describe('VaultSessionGuard', () => {
  it('admits a live session for the verified caller', async () => {
    const { guard, lookups } = guardWith(rowOf());
    const request: VaultRequest = {
      headers: { [VAULT_SESSION_HEADER]: TOKEN },
      caller: callerOf(),
    };

    await expect(guard.canActivate(contextFor(request))).resolves.toBe(true);
    expect(request.vaultSession).toMatchObject({ userId: USER, accountSessionId: ACCOUNT_SESSION });
    // Looked up by digest, never by the token itself.
    expect(lookups[0]).toEqual(hashToken(TOKEN));
  });

  it('accepts the header as an array (proxy duplication)', async () => {
    const { guard } = guardWith(rowOf());
    const request: VaultRequest = {
      headers: { [VAULT_SESSION_HEADER]: [TOKEN, 'other'] },
      caller: callerOf(),
    };
    await expect(guard.canActivate(contextFor(request))).resolves.toBe(true);
  });

  it('refuses when no vault session header is present', async () => {
    const { guard } = guardWith(rowOf());
    const request: VaultRequest = { headers: {}, caller: callerOf() };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(ForbiddenException);
  });

  it('refuses when the session is unknown, expired or revoked', async () => {
    // findLiveByTokenHash enforces expiry and revocation in SQL, so all three
    // arrive here as "no row".
    const { guard } = guardWith(null);
    const request: VaultRequest = {
      headers: { [VAULT_SESSION_HEADER]: TOKEN },
      caller: callerOf(),
    };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(ForbiddenException);
  });

  it("refuses another user's vault session", async () => {
    const { guard } = guardWith(rowOf({ user_id: '00000000-0000-4000-8000-000000000000' }));
    const request: VaultRequest = {
      headers: { [VAULT_SESSION_HEADER]: TOKEN },
      caller: callerOf(),
    };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(ForbiddenException);
  });

  it('refuses a vault session opened from a different login', async () => {
    // The binding that makes a stolen vault token useless elsewhere.
    const { guard } = guardWith(
      rowOf({ account_session_id: 'ffffffff-0000-4000-8000-000000000000' }),
    );
    const request: VaultRequest = {
      headers: { [VAULT_SESSION_HEADER]: TOKEN },
      caller: callerOf(),
    };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(ForbiddenException);
  });

  it('reports every failure with the same token', async () => {
    const cases: Array<VaultSessionRow | null> = [
      null,
      rowOf({ user_id: '00000000-0000-4000-8000-000000000000' }),
      rowOf({ account_session_id: 'ffffffff-0000-4000-8000-000000000000' }),
    ];
    for (const row of cases) {
      const { guard } = guardWith(row);
      const request: VaultRequest = {
        headers: { [VAULT_SESSION_HEADER]: TOKEN },
        caller: callerOf(),
      };
      await expect(guard.canActivate(contextFor(request))).rejects.toMatchObject({
        response: { error: 'vault_locked' },
      });
    }
  });

  it('requires CallerGuard to have run first', async () => {
    const { guard } = guardWith(rowOf());
    const request: VaultRequest = { headers: { [VAULT_SESSION_HEADER]: TOKEN } };
    await expect(guard.canActivate(contextFor(request))).rejects.toThrow(BadRequestException);
  });
});

describe('requireVaultSession', () => {
  it('returns the attached session', () => {
    const session = {
      id: 'x',
      userId: USER,
      accountSessionId: ACCOUNT_SESSION,
      keysetAuthKey: Buffer.alloc(32),
      expiresAt: NOW,
    };
    expect(requireVaultSession({ headers: {}, vaultSession: session })).toBe(session);
  });

  it('throws rather than falling through when the guard did not run', () => {
    expect(() => requireVaultSession({ headers: {} })).toThrow(BadRequestException);
  });
});
