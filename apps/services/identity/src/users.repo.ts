import { Injectable } from '@nestjs/common';
import { Db, isUniqueViolation } from './db';

export interface UserRow {
  id: string;
  password_hash: string | null;
  status: string;
  dek_id: string;
}

@Injectable()
export class UsersRepo {
  constructor(private readonly db: Db) {}

  /**
   * Insert a new user. Returns 'duplicate' (instead of throwing) when the
   * email blind index collides with a live row — the register endpoint must
   * behave identically for new and existing emails (no account enumeration).
   */
  async insert(input: {
    id: string;
    emailCt: Buffer;
    emailBidx: Buffer;
    passwordHash: string;
    dekId: string;
  }): Promise<'inserted' | 'duplicate'> {
    try {
      await this.db.query(
        `INSERT INTO users (id, email_ct, email_bidx, password_hash, dek_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [input.id, input.emailCt, input.emailBidx, input.passwordHash, input.dekId],
      );
      return 'inserted';
    } catch (err) {
      if (isUniqueViolation(err)) {
        return 'duplicate';
      }
      throw err;
    }
  }

  async findByEmailBidx(emailBidx: Buffer): Promise<UserRow | null> {
    const rows = await this.db.query<UserRow>(
      `SELECT id, password_hash, status, dek_id
         FROM users
        WHERE email_bidx = $1 AND deleted_at IS NULL`,
      [emailBidx],
    );
    return rows[0] ?? null;
  }
}
