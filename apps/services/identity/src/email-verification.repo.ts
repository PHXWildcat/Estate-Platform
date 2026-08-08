import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface EmailVerificationRow {
  id: string;
  user_id: string;
  expires_at: Date;
  attempts: number;
}

/** How many wrong guesses a live code survives before it stops working. */
export const MAX_VERIFY_ATTEMPTS = 5;

/**
 * Raised when the "one live code per user" index refuses a concurrent mint.
 * The caller treats it as success-by-somebody-else: a code IS live, which is
 * the state the mint was trying to reach.
 */
export class VerificationRaceError extends Error {
  constructor() {
    super('a live verification code already exists');
    this.name = 'VerificationRaceError';
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

/**
 * The email-verification code store. Lookup is by DIGEST for redemption and by
 * user id for the mint decision — never by address, which this table does not
 * hold.
 */
@Injectable()
export class EmailVerificationRepo {
  constructor(private readonly db: Db) {}

  /**
   * The live code for a user, if any. `live` means unspent, unrevoked and
   * unexpired — an expired row is left in place as evidence rather than
   * cleaned up, so the predicate carries the clock rather than trusting a
   * background job that does not exist.
   */
  async findLive(userId: string, now: Date): Promise<{ createdAt: Date } | null> {
    const rows = await this.db.query<{ created_at: Date }>(
      `SELECT created_at
         FROM email_verifications
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND verified_at IS NULL
          AND expires_at > $2
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId, now],
    );
    return rows[0] ? { createdAt: rows[0].created_at } : null;
  }

  async insert(input: { userId: string; codeSha256: Buffer; expiresAt: Date }): Promise<string> {
    try {
      const rows = await this.db.query<{ id: string }>(
        `INSERT INTO email_verifications (user_id, code_sha256, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [input.userId, input.codeSha256, input.expiresAt],
      );
      if (!rows[0]) {
        throw new Error('email_verifications insert returned no row');
      }
      return rows[0].id;
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new VerificationRaceError();
      }
      throw err;
    }
  }

  /**
   * Resolve a code by its digest. THE DIGEST IS THE ONLY SELECTOR — there is no
   * variant of this taking a user id, because a lookup that took one would let
   * a caller ask "does user X have a code outstanding", and the route above it
   * would become an oracle about somebody else's account state.
   *
   * Returns the row whatever its state; the service decides what is live, so
   * every dead reason collapses to one refusal in one place.
   */
  async findByCode(codeSha256: Buffer): Promise<
    | (EmailVerificationRow & {
        revoked_at: Date | null;
        verified_at: Date | null;
      })
    | null
  > {
    const rows = await this.db.query<
      EmailVerificationRow & { revoked_at: Date | null; verified_at: Date | null }
    >(
      `SELECT id, user_id, expires_at, attempts, revoked_at, verified_at
         FROM email_verifications
        WHERE code_sha256 = $1`,
      [codeSha256],
    );
    return rows[0] ?? null;
  }

  /** Count one failed guess against a REAL code. */
  async countAttempt(id: string): Promise<void> {
    await this.db.query(`UPDATE email_verifications SET attempts = attempts + 1 WHERE id = $1`, [
      id,
    ]);
  }

  /**
   * Spend the code. Restates every liveness precondition in its own WHERE so
   * two concurrent redemptions of one code produce exactly one success — the
   * check-then-act shape the M13 round-3 review closed in profile, avoided
   * here rather than repeated.
   */
  async markVerified(id: string, now: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE email_verifications
          SET verified_at = $2
        WHERE id = $1
          AND revoked_at IS NULL
          AND verified_at IS NULL
          AND expires_at > $2
      RETURNING id`,
      [id, now],
    );
    return rows.length > 0;
  }

  /**
   * Retire whatever live code the user has. Used when a send fails (so the next
   * login re-mints rather than waiting out a TTL for a mail nobody received)
   * and when the user asks for a fresh one. Returns whether anything was
   * retired, so the caller can audit a real retirement and stay quiet otherwise.
   */
  async revokeLive(userId: string, now: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE email_verifications
          SET revoked_at = $2
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND verified_at IS NULL
      RETURNING id`,
      [userId, now],
    );
    return rows.length > 0;
  }
}
