import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface VaultSessionRow {
  id: string;
  user_id: string;
  token_h: Buffer;
  account_session_id: string;
  keyset_auth_key: Buffer;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  revoke_reason: string | null;
}

const COLUMNS = `id, user_id, token_h, account_session_id, keyset_auth_key, created_at, expires_at, revoked_at, revoke_reason`;

/** Open-vault sessions: proof that this user recently completed SRP. */
@Injectable()
export class VaultSessionsRepo {
  /**
   * The id is supplied rather than defaulted because the keyset-auth key is
   * derived from the SRP session key AND this session's id, so it has to exist
   * before the row is written.
   */
  async create(
    q: Queryable | Db,
    input: {
      id: string;
      userId: string;
      tokenHash: Buffer;
      accountSessionId: string;
      keysetAuthKey: Buffer;
      expiresAt: Date;
    },
  ): Promise<VaultSessionRow> {
    const rows = await q.query<VaultSessionRow>(
      `INSERT INTO vault_sessions (id, user_id, token_h, account_session_id, keyset_auth_key, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING ${COLUMNS}`,
      [
        input.id,
        input.userId,
        input.tokenHash,
        input.accountSessionId,
        input.keysetAuthKey,
        input.expiresAt,
      ],
    );
    return rows[0]!;
  }

  /**
   * Look up a live session by token digest. Revocation and expiry are enforced
   * in SQL, not in JS, so there is no window where a caller forgets to check.
   */
  async findLiveByTokenHash(
    q: Queryable | Db,
    tokenHash: Buffer,
    now: Date,
  ): Promise<VaultSessionRow | null> {
    const rows = await q.query<VaultSessionRow>(
      `SELECT ${COLUMNS} FROM vault_sessions
        WHERE token_h = $1 AND revoked_at IS NULL AND expires_at > $2`,
      [tokenHash, now],
    );
    return rows[0] ?? null;
  }

  async revoke(q: Queryable | Db, id: string, reason: string, at: Date): Promise<void> {
    await q.query(
      `UPDATE vault_sessions SET revoked_at = $3, revoke_reason = $2
        WHERE id = $1 AND revoked_at IS NULL`,
      [id, reason, at],
    );
  }

  /**
   * Revoke every live session for a user except one. Used on keyset
   * replacement: changing the vault password is the canonical response to a
   * suspected compromise, so an attacker's already-open vault session must not
   * survive it.
   */
  async revokeAllForUserExcept(
    q: Queryable | Db,
    input: { userId: string; exceptId: string | null; reason: string; at: Date },
  ): Promise<number> {
    const rows = await q.query<{ id: string }>(
      `UPDATE vault_sessions SET revoked_at = $4, revoke_reason = $3
        WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)
        RETURNING id`,
      [input.userId, input.exceptId, input.reason, input.at],
    );
    return rows.length;
  }
}
