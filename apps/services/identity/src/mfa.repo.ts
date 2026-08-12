import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface MfaMethodRow {
  id: string;
  secret_ct: Buffer;
  verified_at: Date | null;
}

@Injectable()
export class MfaRepo {
  constructor(private readonly db: Db) {}

  async insertTotp(input: { id: string; userId: string; secretCt: Buffer }): Promise<void> {
    await this.db.query(
      `INSERT INTO mfa_methods (id, user_id, kind, secret_ct)
       VALUES ($1, $2, 'totp', $3)`,
      [input.id, input.userId, input.secretCt],
    );
  }

  /** Re-enrollment supersedes any pending (unverified) TOTP secret. */
  async revokeUnverifiedTotp(userId: string, at: Date): Promise<void> {
    await this.db.query(
      `UPDATE mfa_methods
          SET revoked_at = $2
        WHERE user_id = $1 AND kind = 'totp' AND verified_at IS NULL AND revoked_at IS NULL`,
      [userId, at],
    );
  }

  /**
   * Does this account already hold a proof-carrying second factor?
   *
   * The question `AuthService.enrollTotp` asks to decide whether ADDING one is
   * step-up gated: the first factor cannot be, because there is nothing to
   * prove with, and every one after it must be. Deliberately a boolean rather
   * than a row — the caller needs the fact, not the secret, and returning a
   * method here would put a `secret_ct` on a path that has no business
   * decrypting one.
   */
  async hasVerifiedTotp(userId: string): Promise<boolean> {
    const rows = await this.db.query<{ present: boolean }>(
      `SELECT true AS present
         FROM mfa_methods
        WHERE user_id = $1 AND kind = 'totp'
          AND verified_at IS NOT NULL AND revoked_at IS NULL
        LIMIT 1`,
      [userId],
    );
    return rows.length > 0;
  }

  async findActiveTotp(
    userId: string,
    opts: { verifiedOnly: boolean },
  ): Promise<MfaMethodRow | null> {
    const rows = await this.db.query<MfaMethodRow>(
      `SELECT id, secret_ct, verified_at
         FROM mfa_methods
        WHERE user_id = $1 AND kind = 'totp' AND revoked_at IS NULL
          AND ($2 = false OR verified_at IS NOT NULL)
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId, opts.verifiedOnly],
    );
    return rows[0] ?? null;
  }

  async markVerified(id: string, at: Date): Promise<void> {
    await this.db.query(`UPDATE mfa_methods SET verified_at = $2 WHERE id = $1`, [id, at]);
  }
}
