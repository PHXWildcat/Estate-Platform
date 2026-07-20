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
