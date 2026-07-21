import { Injectable } from '@nestjs/common';
import type { MfaLevel } from '@estate/contracts';
import { Db } from './db';

export interface SessionRow {
  id: string;
  user_id: string;
  mfa_level: MfaLevel;
  stepup_expires_at: Date | null;
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
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO sessions (id, user_id, refresh_token_h, access_token_h, access_expires_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        input.id,
        input.userId,
        input.refreshTokenH,
        input.accessTokenH,
        input.accessExpiresAt,
        input.expiresAt,
      ],
    );
  }

  /** Live session for a presented access token (expiry + revocation enforced in SQL). */
  async findLiveByAccessHash(accessTokenH: Buffer, now: Date): Promise<SessionRow | null> {
    const rows = await this.db.query<SessionRow>(
      `SELECT id, user_id, mfa_level, stepup_expires_at
         FROM sessions
        WHERE access_token_h = $1
          AND revoked_at IS NULL
          AND access_expires_at > $2
          AND expires_at > $2`,
      [accessTokenH, now],
    );
    return rows[0] ?? null;
  }

  /** Live session for a presented refresh token (current hash). */
  async findLiveByRefreshHash(refreshTokenH: Buffer, now: Date): Promise<SessionRow | null> {
    const rows = await this.db.query<SessionRow>(
      `SELECT id, user_id, mfa_level, stepup_expires_at
         FROM sessions
        WHERE refresh_token_h = $1
          AND revoked_at IS NULL
          AND expires_at > $2`,
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
      `SELECT id, user_id, mfa_level, stepup_expires_at
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

  async grantStepUp(sessionId: string, stepupExpiresAt: Date): Promise<void> {
    await this.db.query(
      `UPDATE sessions
          SET mfa_level = 'stepup', stepup_expires_at = $2
        WHERE id = $1`,
      [sessionId, stepupExpiresAt],
    );
  }
}
