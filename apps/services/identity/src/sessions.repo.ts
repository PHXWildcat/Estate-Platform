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

/** A row of the paired-devices surface (M16). Ids, audience, timestamps. */
export interface LiveSessionRow {
  id: string;
  audience: SessionAudience;
  created_at: Date;
  expires_at: Date;
}

@Injectable()
export class SessionsRepo {
  constructor(private readonly db: Db) {}

  /**
   * Mint a session row.
   *
   * `audience` IS REQUIRED, and that is the whole point of this comment. It was
   * `audience?: SessionAudience` bound as `input.audience ?? 'account'` from
   * M15 until M16 — a FAIL-OPEN DEFAULT in the one function in the product that
   * decides what a session may be spent on, inside a codebase whose stated rule
   * is deny by default. It cost nothing while there were two mint paths and one
   * of them passed the argument; it costs everything the moment a third arrives
   * and forgets, because the session it mints is not refused anywhere — it is
   * an ORDINARY ACCOUNT SESSION, which is strictly the most powerful thing this
   * function can produce.
   *
   * Required rather than defaulted, so a new mint path cannot compile without
   * stating what it is minting. The DDL keeps its own `DEFAULT 'account'`,
   * which is a different question with a different answer: it exists so M15's
   * `ALTER TABLE` could populate rows that predate the column, and nothing
   * reaches it now that every INSERT names the value.
   */
  async create(input: {
    id: string;
    userId: string;
    refreshTokenH: Buffer;
    accessTokenH: Buffer;
    accessExpiresAt: Date;
    expiresAt: Date;
    audience: SessionAudience;
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
        input.audience,
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
   * Every live session for a user — the paired-devices surface (M16).
   *
   * The FIRST read of this kind in the product. Until M16 a session was a
   * cookie in one browser and the only thing anyone could do to it was present
   * it, so there was nothing to list; an extension credential that outlives the
   * browser and appears on no screen is what makes the list a precondition
   * rather than a feature.
   *
   * Deliberately NARROW. It returns ids, the audience, and timestamps — no
   * token hashes, obviously, but also no IP and no device: `sessions` has
   * `ip_ct` and `device_id` columns and neither is written by anything today,
   * so returning them would be a promise the data cannot keep. What a user
   * needs here is "which of these is my extension, and when did it appear".
   */
  async listLiveForUser(userId: string, now: Date): Promise<LiveSessionRow[]> {
    return this.db.query<LiveSessionRow>(
      `SELECT id, audience, created_at, expires_at
         FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
        ORDER BY created_at DESC`,
      [userId, now],
    );
  }

  /**
   * Revoke ONE session, and only if it belongs to this user.
   *
   * THE OWNER PREDICATE IS IN THE STATEMENT, and that is the whole point of
   * this method existing beside `revoke`. `revoke(sessionId, …)` takes an id and
   * no owner — correct for its callers, which are logout (already holding a
   * verified session) and the settlement lock (a service credential acting on a
   * whole account) — and catastrophic for a user-facing route, where the id
   * comes from the request. A check-then-act in the service would be the M13
   * `contact_in_use` shape: a race between the check and the update. So the
   * predicate rides the UPDATE.
   *
   * Returns whether a row matched, so the route can answer a UNIFORM NOT-FOUND
   * for "no such session" and "someone else's session" alike. A 403 on the
   * second would confirm that the id names a real session belonging to somebody
   * — the enumeration oracle this codebase closes everywhere else.
   */
  async revokeOwned(sessionId: string, userId: string, reason: string, at: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE sessions
          SET revoked_at = $3, revoke_reason = $4
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
        RETURNING id`,
      [sessionId, userId, at, reason],
    );
    return rows.length > 0;
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
