import { Injectable } from '@nestjs/common';
import type { MfaLevel } from '@estate/contracts';
import type { SessionAudience } from '@estate/auth-guard';
import { Db } from './db';

export interface SessionRow {
  id: string;
  user_id: string;
  mfa_level: MfaLevel;
  stepup_expires_at: Date | null;
  /** M15: what this session may be spent on. See the 004 migration. */
  audience: SessionAudience;
}

@Injectable()
export class SessionsRepo {
  constructor(private readonly db: Db) {}

  async create(input: {
    id: string;
    userId: string;
    refreshTokenH: Buffer;
    accessTokenH: Buffer;
    accessExpiresAt: Date;
    expiresAt: Date;
    /** Omitted ⇒ the ordinary session every pre-M15 caller means. */
    audience?: SessionAudience;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO sessions (id, user_id, refresh_token_h, access_token_h, access_expires_at, expires_at, audience)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        input.id,
        input.userId,
        input.refreshTokenH,
        input.accessTokenH,
        input.accessExpiresAt,
        input.expiresAt,
        input.audience ?? 'account',
      ],
    );
  }

  /**
   * Live session for a presented access token (expiry + revocation enforced in
   * SQL). Joined to users with a status ALLOWLIST (M7): a session only works
   * while the account is 'active' or 'deceased_pending' — the latter by
   * design, because the owner rescuing themselves out of a fraudulent death
   * case (docs/03 §5.1) needs their sessions to keep working. 'settlement' and
   * every other status kills token use here even if bulk revocation missed a
   * session, and any future status value fails closed.
   */
  async findLiveByAccessHash(accessTokenH: Buffer, now: Date): Promise<SessionRow | null> {
    const rows = await this.db.query<SessionRow>(
      `SELECT s.id, s.user_id, s.mfa_level, s.stepup_expires_at, s.audience
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.access_token_h = $1
          AND s.revoked_at IS NULL
          AND s.access_expires_at > $2
          AND s.expires_at > $2
          AND u.deleted_at IS NULL
          AND u.status IN ('active', 'deceased_pending')`,
      [accessTokenH, now],
    );
    return rows[0] ?? null;
  }

  /** Live session for a presented refresh token (current hash). Same status
   * allowlist as findLiveByAccessHash — a refresh token must not outlive the
   * account state that minted it. */
  async findLiveByRefreshHash(refreshTokenH: Buffer, now: Date): Promise<SessionRow | null> {
    const rows = await this.db.query<SessionRow>(
      `SELECT s.id, s.user_id, s.mfa_level, s.stepup_expires_at, s.audience
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.refresh_token_h = $1
          AND s.revoked_at IS NULL
          AND s.expires_at > $2
          AND u.deleted_at IS NULL
          AND u.status IN ('active', 'deceased_pending')`,
      [refreshTokenH, now],
    );
    return rows[0] ?? null;
  }

  /**
   * Session whose PREVIOUS refresh-token hash matches — i.e. a token that was
   * already rotated away is being replayed (theft signal).
   */
  async findLiveByPrevRefreshHash(refreshTokenH: Buffer): Promise<SessionRow | null> {
    const rows = await this.db.query<SessionRow>(
      `SELECT id, user_id, mfa_level, stepup_expires_at, audience
         FROM sessions
        WHERE refresh_token_prev_h = $1
          AND revoked_at IS NULL`,
      [refreshTokenH],
    );
    return rows[0] ?? null;
  }

  /** Rotate both tokens; the outgoing refresh hash is retained for reuse detection. */
  async rotateTokens(
    sessionId: string,
    input: {
      newRefreshTokenH: Buffer;
      previousRefreshTokenH: Buffer;
      newAccessTokenH: Buffer;
      accessExpiresAt: Date;
    },
  ): Promise<void> {
    await this.db.query(
      `UPDATE sessions
          SET refresh_token_h = $2,
              refresh_token_prev_h = $3,
              access_token_h = $4,
              access_expires_at = $5
        WHERE id = $1`,
      [
        sessionId,
        input.newRefreshTokenH,
        input.previousRefreshTokenH,
        input.newAccessTokenH,
        input.accessExpiresAt,
      ],
    );
  }

  async revoke(sessionId: string, reason: string, at: Date): Promise<void> {
    await this.db.query(
      `UPDATE sessions
          SET revoked_at = $2, revoke_reason = $3
        WHERE id = $1 AND revoked_at IS NULL`,
      [sessionId, at, reason],
    );
  }

  /**
   * Revoke every live session for a user (M7: verified settlement — the
   * account is now estate-administered, so no credential minted by the
   * decedent may survive). Returns the revoked ids for the audit trail.
   */
  async revokeAllForUser(userId: string, reason: string, at: Date): Promise<string[]> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE sessions
          SET revoked_at = $2, revoke_reason = $3
        WHERE user_id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [userId, at, reason],
    );
    return rows.map((r) => r.id);
  }

  async grantStepUp(sessionId: string, stepupExpiresAt: Date): Promise<void> {
    await this.db.query(
      `UPDATE sessions
          SET mfa_level = 'stepup', stepup_expires_at = $2
        WHERE id = $1`,
      [sessionId, stepupExpiresAt],
    );
  }
}
