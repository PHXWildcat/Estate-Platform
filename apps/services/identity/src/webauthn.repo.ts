import { Injectable } from '@nestjs/common';
import { Db } from './db';

/** A stored passkey. `sign_count` is BIGINT, so pg returns it as a string. */
export interface WebAuthnCredentialRow {
  id: string;
  user_id: string;
  credential_id: Buffer;
  public_key: Buffer;
  sign_count: string;
  transports: string[] | null;
  aaguid: string | null;
  nickname: string | null;
  is_hardware_key: boolean;
}

export type WebAuthnChallengeKind = 'registration' | 'authentication';

/**
 * Repository for the WebAuthn tables (docs/02 §1 `webauthn_credentials`, plus
 * the additive single-use `webauthn_challenges` store). Raw parameterized pg
 * through the shared `Db` provider — same pattern as the other repos.
 */
@Injectable()
export class WebAuthnRepo {
  constructor(private readonly db: Db) {}

  async insertCredential(input: {
    userId: string;
    credentialId: Buffer;
    publicKey: Buffer;
    signCount: number;
    transports: string[] | null;
    aaguid: string | null;
    nickname: string | null;
    isHardwareKey: boolean;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO webauthn_credentials
         (user_id, credential_id, public_key, sign_count, transports, aaguid, nickname, is_hardware_key)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        input.userId,
        input.credentialId,
        input.publicKey,
        input.signCount,
        input.transports,
        input.aaguid,
        input.nickname,
        input.isHardwareKey,
      ],
    );
  }

  /** All active (non-revoked) credentials for a user. */
  async findCredentialsByUser(userId: string): Promise<WebAuthnCredentialRow[]> {
    return this.db.query<WebAuthnCredentialRow>(
      `SELECT id, user_id, credential_id, public_key, sign_count, transports,
              aaguid, nickname, is_hardware_key
         FROM webauthn_credentials
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at ASC`,
      [userId],
    );
  }

  /** Active credential by its raw credential id (unique). */
  async findCredentialById(credentialId: Buffer): Promise<WebAuthnCredentialRow | null> {
    const rows = await this.db.query<WebAuthnCredentialRow>(
      `SELECT id, user_id, credential_id, public_key, sign_count, transports,
              aaguid, nickname, is_hardware_key
         FROM webauthn_credentials
        WHERE credential_id = $1 AND revoked_at IS NULL`,
      [credentialId],
    );
    return rows[0] ?? null;
  }

  /** Persist the post-authentication signature counter and touch last_used_at. */
  async updateSignCount(credentialId: Buffer, signCount: number, lastUsedAt: Date): Promise<void> {
    await this.db.query(
      `UPDATE webauthn_credentials
          SET sign_count = $2, last_used_at = $3
        WHERE credential_id = $1`,
      [credentialId, signCount, lastUsedAt],
    );
  }

  async insertChallenge(input: {
    userId: string | null;
    challenge: string;
    kind: WebAuthnChallengeKind;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO webauthn_challenges (user_id, challenge, kind, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [input.userId, input.challenge, input.kind, input.expiresAt],
    );
  }

  /**
   * Find-and-delete the most recent challenge for (user, kind): the delete is
   * the point — a challenge is single-use, so it is consumed whether or not it
   * had expired. Returns the challenge string only when it was still fresh;
   * an expired (but now deleted) challenge returns null.
   */
  async consumeChallenge(
    userId: string,
    kind: WebAuthnChallengeKind,
    now: Date,
  ): Promise<string | null> {
    const rows = await this.db.query<{ challenge: string; expires_at: Date }>(
      `DELETE FROM webauthn_challenges
        WHERE id IN (
          SELECT id FROM webauthn_challenges
           WHERE user_id = $1 AND kind = $2
           ORDER BY created_at DESC
           LIMIT 1
        )
      RETURNING challenge, expires_at`,
      [userId, kind],
    );
    const row = rows[0];
    if (!row || row.expires_at.getTime() <= now.getTime()) {
      return null;
    }
    return row.challenge;
  }
}
