import { Injectable } from '@nestjs/common';
import { Db } from './db';

/**
 * Local auth_events ledger (docs/02 §1) — every sensitive auth action lands
 * here AND is mirrored to the audit cluster via Kafka. Append-only (the
 * migration REVOKEs UPDATE/DELETE).
 */
@Injectable()
export class AuthEventsRepo {
  constructor(private readonly db: Db) {}

  async insert(input: {
    userId: string | null;
    sessionId?: string | null;
    kind: string;
    decision?: string | null;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO auth_events (user_id, session_id, kind, decision)
       VALUES ($1, $2, $3, $4)`,
      [input.userId, input.sessionId ?? null, input.kind, input.decision ?? null],
    );
  }

  /**
   * Most recent occurrence of an event kind for a user. M7's owner-liveness
   * check reads the last 'stepup.granted': auth_events is append-only and
   * survives session revocation/expiry, so it is the durable record of "the
   * owner proved themselves with step-up MFA at time T".
   */
  async lastOccurredAt(userId: string, kind: string): Promise<Date | null> {
    const rows = await this.db.query<{ occurred_at: Date }>(
      `SELECT occurred_at
         FROM auth_events
        WHERE user_id = $1 AND kind = $2
        ORDER BY occurred_at DESC
        LIMIT 1`,
      [userId, kind],
    );
    return rows[0]?.occurred_at ?? null;
  }

  /**
   * FAILED ATTEMPTS since the last successful one, in a window — the count
   * every ledger-derived bound is built on.
   *
   * DERIVED FROM THE LEDGER rather than kept in a counter column, and that is
   * the design rather than a shortcut. This table is append-only (the migration
   * REVOKEs UPDATE and DELETE), so the count is one an attacker cannot reset;
   * a mutable counter would need its own reset path, its own concurrency story,
   * and its own row for every user who has never failed anything. M7's
   * owner-liveness interlock already reads this table as a control input, so
   * the precedent is set.
   *
   * IT COUNTS EVERY ROUTE THAT CHECKS THE SAME SECRET, and it did not until the
   * M16 review. `stepUp` and `verifyTotp` both resolve the newest active
   * `mfa_methods` row and both call `verifyTotpCode` against it, so a cap that
   * counted only `stepup.denied` left `POST /v1/auth/totp/verify` as an UNCAPPED
   * ORACLE on the very secret the cap exists to protect: guess there until a
   * 200 comes back, then spend that known-good code at `stepup` having burned
   * none of the five. Measured, not reasoned about — forty guesses, all 401,
   * counter still zero. A bound on guessing has to cover every place the guess
   * can be made, so the failure kinds and the success kinds are both sets, and
   * adding a third checker of a secret means adding it to that bound's sets.
   *
   * THE KIND SETS ARE PARAMETERS, NOT IMPORTS (M17), and that is a security
   * change rather than a tidy-up. They used to be module-level constants this
   * file imported directly, which was correct while one bound existed and
   * becomes a defect at two: the "since the last success" watermark below is a
   * SINGLE SHARED SUBQUERY, so a success of any kind in the set clears the
   * window for every kind in it. Folding login into the step-up sets was
   * measured to take a user with four `stepup.denied` rows plus one
   * `login.succeeded` row from four denials to ZERO — a plain password login,
   * proving no second factor at all, resetting the second-factor cap. Bounds
   * pass their own sets now and `test/rate-bounds.spec.ts` asserts they are
   * pairwise disjoint.
   *
   * TWO SCOPES, AND THE PAIR IS THE POINT (see `stepup.ts`). Passing a
   * `sessionId` counts only that session's failures; omitting it counts the
   * account's. The account-wide number is the real bound and stays keyed on the
   * USER for M14's reason — a wrong code resolves no row, so anything keyed on
   * a resolved row counts zero forever while looking healthy. The per-session
   * number is what stops ONE stolen credential spending the whole account's
   * budget and locking the owner out of their own step-up.
   *
   * A BOUND WITH NO CREDENTIAL TO SCOPE TO passes no `sessionId` and gets the
   * account count alone. Login is that case — the failure is recorded before
   * any session exists — and `LOGIN_BOUND` records what the missing scope
   * costs rather than leaving it to be inferred from this signature.
   *
   * KEYED ON THE USER MEANS BLIND TO CALLERS WITH NO USER. `login.failed` rows
   * carry a NULL user whenever the identifier did not resolve, and this
   * predicate's `user_id = $1` cannot see them. That is not a gap to be closed
   * here — see `AddressAttemptBound`, which is the half that covers it.
   *
   * SINCE THE LAST SUCCESS, so a user who fumbles twice and then succeeds does
   * not carry those failures forward. `COALESCE(..., '-infinity')` is what makes
   * the never-succeeded case count from the beginning of the window rather than
   * returning no rows at all. The success set is scoped the same way as the
   * failure set: a per-session count clears on that session's own success, so
   * one session's proof of possession cannot silently forgive another's
   * failures.
   *
   * Every branch hits `ix_auth_events_user_kind_time` (user_id, kind,
   * occurred_at DESC) — the index migration 005 added. `kind = ANY($3)` is a
   * bounded IN-list over that index, and `session_id` filters the rows it
   * returns rather than driving the lookup.
   */
  async failedAttempts(
    userId: string,
    since: Date,
    opts: {
      readonly failures: readonly string[];
      readonly successes: readonly string[];
      readonly sessionId?: string;
    },
  ): Promise<number> {
    const sessionId = opts.sessionId ?? null;
    const rows = await this.db.query<{ denials: string }>(
      `SELECT count(*)::text AS denials
         FROM auth_events
        WHERE user_id = $1
          AND kind = ANY($3)
          AND occurred_at >= $2
          AND ($5::uuid IS NULL OR session_id = $5::uuid)
          AND occurred_at > COALESCE(
                (SELECT max(occurred_at) FROM auth_events
                  WHERE user_id = $1 AND kind = ANY($4)
                    AND ($5::uuid IS NULL OR session_id = $5::uuid)),
                '-infinity'::timestamptz)`,
      [userId, since, [...opts.failures], [...opts.successes], sessionId],
    );
    // `count(*)` is bigint, which pg returns as a string to avoid a silent
    // precision loss at 2^53. Parsed here rather than left for a caller to
    // compare against a number and always find unequal.
    return Number(rows[0]?.denials ?? '0');
  }
}
