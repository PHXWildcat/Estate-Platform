import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

/**
 * Raised when the "one live code per user" index refuses a concurrent mint.
 * The caller treats it as success-by-somebody-else: a code IS live, which is
 * the state the mint was trying to reach.
 */
export class ResetRaceError extends Error {
  constructor() {
    super('a live password-reset code already exists');
    this.name = 'ResetRaceError';
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

/**
 * The password-reset code store (M17 PR3). Lookup is by DIGEST for redemption
 * and by user id for the mint decision — never by address, which this table
 * does not hold.
 *
 * The shape is `EmailVerificationRepo`'s with two deliberate differences, both
 * following from the redeemer being UNAUTHENTICATED: there is no attempt
 * counter (a wrong guess resolves no row, so there is nothing to count — see
 * the migration), and the spend takes a `Queryable` so it can commit inside the
 * same transaction as the password write.
 */
@Injectable()
export class PasswordResetRepo {
  constructor(private readonly db: Db) {}

  /**
   * When this user was last MAILED a reset code, live or not.
   *
   * The re-issue floor keys on THIS rather than on a live-code read, which is
   * the M14 review's second finding applied before it can bite: a send that
   * fails retires its code, so in exactly the state where sends are failing
   * there is no live code, and a floor gated on one evaluates to "no floor".
   * On this route that would be worse than M14's — an unauthenticated caller
   * could drive unlimited mail at an address they do not own.
   */
  async lastMintedAt(userId: string): Promise<Date | null> {
    const rows = await this.db.query<{ created_at: Date }>(
      `SELECT created_at
         FROM password_resets
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId],
    );
    return rows[0]?.created_at ?? null;
  }

  async insert(input: { userId: string; codeSha256: Buffer; expiresAt: Date }): Promise<string> {
    try {
      const rows = await this.db.query<{ id: string }>(
        `INSERT INTO password_resets (user_id, code_sha256, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id`,
        [input.userId, input.codeSha256, input.expiresAt],
      );
      if (!rows[0]) {
        throw new Error('password_resets insert returned no row');
      }
      return rows[0].id;
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new ResetRaceError();
      }
      throw err;
    }
  }

  /**
   * Retire whatever code occupies the live slot — matching THE INDEX's notion of
   * live (`revoked_at IS NULL AND redeemed_at IS NULL`), never a clock-carrying
   * one.
   *
   * Called UNCONDITIONALLY before a mint. A partial unique index cannot
   * reference `now()`, so a lapsed row still occupies the slot; retiring only
   * when a *usable* code exists is what made M14's ceremony answer `too_soon`
   * forever after the first ignored email. Here that bug would mean an account
   * whose owner ignored one reset mail could never be recovered at all.
   */
  /* `tx` (M17 PR4): the address switch retires outstanding codes in the SAME
   * commit as the flip — a code mailed to the just-left mailbox must not
   * outlive the address it was mailed to, and a post-commit retirement would
   * leave a window where it does. */
  async revokeLive(userId: string, now: Date, tx?: Queryable): Promise<boolean> {
    const rows = await (tx ?? this.db).query<{ id: string }>(
      `UPDATE password_resets
          SET revoked_at = $2
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND redeemed_at IS NULL
      RETURNING id`,
      [userId, now],
    );
    return rows.length > 0;
  }

  /**
   * Resolve a code by its digest. THE DIGEST IS THE ONLY SELECTOR — there is
   * deliberately no variant taking a user id, because the route above this is
   * unauthenticated and a lookup that accepted one would let a caller ask "does
   * user X have a reset outstanding" about somebody else's account.
   *
   * Returns the row whatever its state; the service decides what is live, so
   * every dead reason collapses to one refusal in one place.
   */
  async findByCode(codeSha256: Buffer): Promise<{
    id: string;
    user_id: string;
    expires_at: Date;
    revoked_at: Date | null;
    redeemed_at: Date | null;
  } | null> {
    const rows = await this.db.query<{
      id: string;
      user_id: string;
      expires_at: Date;
      revoked_at: Date | null;
      redeemed_at: Date | null;
    }>(
      `SELECT id, user_id, expires_at, revoked_at, redeemed_at
         FROM password_resets
        WHERE code_sha256 = $1`,
      [codeSha256],
    );
    return rows[0] ?? null;
  }

  /**
   * SPEND the code, inside the caller's transaction.
   *
   * TAKES A `Queryable` BECAUSE ATOMICITY IS THE CONTROL — the M13 PR3 lesson
   * verbatim. Spending the code and writing the new password must both happen
   * or neither: a spend with no password write burns the user's one recovery
   * code and leaves them locked out with a code they cannot re-use, and a
   * password write with no spend leaves the code REPLAYABLE, so whoever read
   * that mailbox can take the account again later.
   *
   * Restates every liveness precondition in its own WHERE, so two concurrent
   * redemptions of one code produce exactly one success and the loser rolls
   * back — the check-then-act shape the M13 round-3 review closed in profile,
   * avoided here rather than repeated.
   */
  async markRedeemed(tx: Queryable, id: string, now: Date): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE password_resets
          SET redeemed_at = $2
        WHERE id = $1
          AND revoked_at IS NULL
          AND redeemed_at IS NULL
          AND expires_at > $2
      RETURNING id`,
      [id, now],
    );
    return rows.length > 0;
  }
}
