import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

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
   * The live code for a user, if any. `live` means USABLE: unspent, unrevoked,
   * unexpired, and not attempt-exhausted. An expired row is left in place as
   * evidence rather than cleaned up, so the predicate carries the clock rather
   * than trusting a background job that does not exist.
   *
   * THE PREDICATE MATCHES `verify()`'s, deliberately and exactly. The M14
   * security review found the ceremony had THREE disagreeing notions of
   * liveness — this method, `verify()`, and the partial unique index — and the
   * disagreement was fatal (see `revokeLive`). `attempts` is included here for
   * the same reason: a code that has burned its attempt cap is dead to
   * redemption, so it must not read as live to the mint decision either, or a
   * user who mistypes five times waits out the re-issue floor for nothing.
   */
  async findLive(userId: string, now: Date): Promise<{ createdAt: Date } | null> {
    const rows = await this.db.query<{ created_at: Date }>(
      `SELECT created_at
         FROM email_verifications
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND verified_at IS NULL
          AND expires_at > $2
          AND attempts < $3
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId, now, MAX_VERIFY_ATTEMPTS],
    );
    return rows[0] ? { createdAt: rows[0].created_at } : null;
  }

  /**
   * When this user was last MAILED a code, live or not.
   *
   * The re-issue floor keys on this rather than on `findLive`, and that is the
   * M14 review's second finding: the floor used to be checked only when a live
   * code existed, but a send that fails RETIRES its code — so in exactly the
   * state where sends are failing (no recipient row, SES refusing, the
   * verification route down) there was no live code, the floor was skipped
   * entirely, and `POST /v1/auth/email/verification/resend` had no rate limit
   * of any kind. Each iteration cost a real SES call and two append-only
   * `auth_events` rows.
   *
   * "How recently did we mail this address" is the question the floor was
   * always trying to ask; `created_at` answers it whatever became of the row.
   */
  async lastMintedAt(userId: string): Promise<Date | null> {
    const rows = await this.db.query<{ created_at: Date }>(
      `SELECT created_at
         FROM email_verifications
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

  /**
   * Count one failed guess against the user's LIVE code, if they have one.
   *
   * ROUND 2 OF THE M14 REVIEW FOUND THE ATTEMPT CAP WAS DECORATIVE. It used to
   * take a row id, and `verify()` only ever called it inside the branch that
   * had already decided the row was DEAD — so `attempts` could only ever
   * increment on a code that was already revoked, spent or expired. A wrong
   * guess produces a DIFFERENT DIGEST, so the lookup returned nothing and no
   * counter moved at all. Three comments claimed it "bounds guessing against a
   * LIVE code"; it bounded replay of a dead one, which nothing needed.
   *
   * Keyed on the USER now, so a failed redemption costs the caller's own live
   * code one attempt whatever they submitted. That is what makes
   * `findLive`'s `attempts` predicate reachable, and it is the only bound of
   * any kind on the redeem route — every failure there writes an append-only
   * `auth_events` row and an audit event, so an unbounded one is a cost
   * amplifier even though the 160-bit code is not guessable.
   *
   * Self-inflicted only: it moves a counter on the CALLER's own code, reached
   * only from their own session. It cannot be used against anybody else, and
   * the response stays the same uniform refusal either way.
   */
  async countAttempt(userId: string, now: Date): Promise<void> {
    await this.db.query(
      `UPDATE email_verifications
          SET attempts = attempts + 1
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND verified_at IS NULL
          AND expires_at > $2`,
      [userId, now],
    );
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
   * Retire whatever code the user has occupying the live slot — and note that
   * "the live slot" here means the PARTIAL UNIQUE INDEX's notion of live
   * (`revoked_at IS NULL AND verified_at IS NULL`), NOT `findLive`'s.
   *
   * THE DIFFERENCE IS THE M14 REVIEW'S WORST FINDING. A partial index cannot
   * reference `now()`, so `ux_email_verifications_live` cannot carry an expiry
   * predicate — it counts a LAPSED row as occupying the slot. `findLive` does
   * carry the clock. The caller used to invoke this only when `findLive`
   * returned a row, so once a code passed its TTL nothing ever retired it, the
   * next insert took the unique violation, and the ceremony answered
   * `too_soon` FOREVER. The most common user behaviour there is — ignoring the
   * first email — permanently locked the account out of verification, and with
   * it out of every M14 arming gate. Reproduced against a real database before
   * this comment was written.
   *
   * So this predicate deliberately MATCHES THE INDEX rather than `findLive`,
   * and the caller now invokes it unconditionally before minting. Returns
   * whether anything was retired, so the caller can audit a real retirement
   * and stay quiet otherwise.
   */
  /* `tx` (M17 PR4): the address switch retires outstanding codes in the SAME
   * commit as the flip — a code mailed to the just-left mailbox must not
   * outlive the address it was mailed to, and a post-commit retirement would
   * leave a window where it does. */
  async revokeLive(userId: string, now: Date, tx?: Queryable): Promise<boolean> {
    const rows = await (tx ?? this.db).query<{ id: string }>(
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
