import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

/**
 * Raised when the "one live change per user" index refuses a concurrent mint.
 * The caller treats it as won-by-somebody: a change IS staged, which is the
 * state the mint was trying to reach.
 */
export class ChangeRaceError extends Error {
  constructor() {
    super('a live email change already exists');
    this.name = 'ChangeRaceError';
  }
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === '23505';
}

export interface EmailChangeRow {
  id: string;
  user_id: string;
  new_email_ct: Buffer;
  new_email_bidx: Buffer;
  dek_id: string;
  code_sha256: Buffer;
  attempts: number;
  expires_at: Date;
  revoked_at: Date | null;
  completed_at: Date | null;
}

/** One failed redemption more than this and the live change is dead. */
export const MAX_CHANGE_ATTEMPTS = 5;

/**
 * The email-change staging store (M17 PR4). THE SELECTOR IS THE USER — the
 * redeemer is authenticated, so completion resolves this user's live row and
 * compares digests, which is what makes the attempt cap attributable (M14
 * round 2: a cap keyed on a resolved row was decorative, because the failures
 * a guesser actually produces resolve no row).
 */
@Injectable()
export class EmailChangeRepo {
  constructor(private readonly db: Db) {}

  /**
   * When this user last STAGED a change, live or not — the re-issue floor's
   * question. Keyed on the mint and never on a live row, because a failed send
   * retires its row, and a floor gated on a live row evaluates to "no floor"
   * in exactly the state where sends are failing (the M14 review's second
   * finding, applied here before it can bite).
   */
  async lastMintedAt(userId: string): Promise<Date | null> {
    const rows = await this.db.query<{ created_at: Date }>(
      `SELECT created_at
         FROM email_changes
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 1`,
      [userId],
    );
    return rows[0]?.created_at ?? null;
  }

  async insert(input: {
    userId: string;
    newEmailCt: Buffer;
    newEmailBidx: Buffer;
    dekId: string;
    codeSha256: Buffer;
    expiresAt: Date;
  }): Promise<string> {
    try {
      const rows = await this.db.query<{ id: string }>(
        `INSERT INTO email_changes (user_id, new_email_ct, new_email_bidx, dek_id, code_sha256, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [
          input.userId,
          input.newEmailCt,
          input.newEmailBidx,
          input.dekId,
          input.codeSha256,
          input.expiresAt,
        ],
      );
      if (!rows[0]) {
        throw new Error('email_changes insert returned no row');
      }
      return rows[0].id;
    } catch (err) {
      if (isUniqueViolation(err)) {
        throw new ChangeRaceError();
      }
      throw err;
    }
  }

  /**
   * Retire whatever change occupies the live slot — matching THE INDEX's
   * notion of live (`revoked_at IS NULL AND completed_at IS NULL`), never a
   * clock-carrying one. Called UNCONDITIONALLY before a mint, and by cancel.
   */
  async revokeLive(userId: string, now: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE email_changes
          SET revoked_at = $2
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND completed_at IS NULL
      RETURNING id`,
      [userId, now],
    );
    return rows.length > 0;
  }

  /**
   * The caller's live change, whatever its usability — the service decides
   * what is redeemable, so every dead reason collapses to one refusal in one
   * place. At most one row can match (the partial unique index).
   */
  async findLive(userId: string): Promise<EmailChangeRow | null> {
    const rows = await this.db.query<EmailChangeRow>(
      `SELECT id, user_id, new_email_ct, new_email_bidx, dek_id, code_sha256,
              attempts, expires_at, revoked_at, completed_at
         FROM email_changes
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND completed_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Burn one attempt on the caller's OWN live change, whatever they submitted
   * (M14 round 2: the failures a guesser actually produces must move the
   * counter). Self-inflicted only — reachable only from the caller's own
   * session, about their own pending change.
   */
  async countAttempt(userId: string, now: Date): Promise<void> {
    await this.db.query(
      `UPDATE email_changes
          SET attempts = attempts + 1
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND completed_at IS NULL
          AND expires_at > $2`,
      [userId, now],
    );
  }

  /**
   * SPEND the change, inside the caller's transaction. Restates every
   * precondition in its own WHERE, so two concurrent completions produce
   * exactly one success and the loser rolls back — and the spend commits with
   * the address flip or not at all (the M13 atomicity-is-the-control rule).
   */
  async markCompleted(tx: Queryable, id: string, now: Date): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE email_changes
          SET completed_at = $2
        WHERE id = $1
          AND revoked_at IS NULL
          AND completed_at IS NULL
          AND expires_at > $2
          AND attempts < ${MAX_CHANGE_ATTEMPTS}
      RETURNING id`,
      [id, now],
    );
    return rows.length > 0;
  }
}
