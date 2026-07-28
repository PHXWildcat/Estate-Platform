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

  async findById(userId: string): Promise<UserRow | null> {
    const rows = await this.db.query<UserRow>(
      `SELECT id, password_hash, status, dek_id
         FROM users
        WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Compare-and-set status transition (M7 settlement lock). The allowed `from`
   * set travels in the SQL so a concurrent transition cannot be overwritten:
   * zero rows updated means the row was missing OR its status had already
   * moved — the caller re-reads to tell the two apart.
   *
   * `notAfterStepUp` is the owner-liveness interlock (docs/03 §5.1: "any owner
   * sign-in with step-up MFA instantly voids the case"). Settlement re-reads
   * liveness before asking for the terminal `settlement` transition, but that
   * read and this write are separated by a network hop — so the predicate is
   * restated HERE, in the same single statement as the write, against the
   * append-only ledger that lives in this cluster. A step-up granted after
   * the watermark makes the UPDATE match zero rows: a living owner cannot be
   * locked out by a step-up that landed while the transition was in flight.
   */
  async updateStatusFrom(
    userId: string,
    from: readonly string[],
    to: string,
    notAfterStepUp?: Date,
  ): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE users
          SET status = $3
        WHERE id = $1 AND deleted_at IS NULL AND status = ANY($2)
          AND ($4::timestamptz IS NULL OR NOT EXISTS (
                SELECT 1 FROM auth_events
                 WHERE user_id = $1
                   AND kind = 'stepup.granted'
                   AND occurred_at > $4
              ))
        RETURNING id`,
      [userId, [...from], to, notAfterStepUp ?? null],
    );
    return rows.length > 0;
  }
}
