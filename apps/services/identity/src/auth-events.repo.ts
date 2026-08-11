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
   * Failed step-ups for a user since their last SUCCESSFUL one, within a window
   * — the count the M16 attempt cap is a bound on.
   *
   * DERIVED FROM THE LEDGER rather than kept in a counter column, and that is
   * the design rather than a shortcut. This table is append-only (the migration
   * REVOKEs UPDATE and DELETE), so the count is one an attacker cannot reset;
   * a mutable counter would need its own reset path, its own concurrency story,
   * and its own row for every user who has never failed anything. M7's
   * owner-liveness interlock already reads this table as a control input, so
   * the precedent is set.
   *
   * KEYED ON THE USER, not the session. A wrong TOTP code resolves nothing, so
   * anything keyed on a resolved row counts zero forever while looking healthy —
   * which is exactly how M14's email-verification cap turned out to be
   * decorative. Session-keying fails differently and just as badly: anyone able
   * to mint sessions would reset the window at will.
   *
   * SINCE THE LAST GRANT, so a user who fumbles twice and then succeeds does not
   * carry those failures forward. `COALESCE(..., '-infinity')` is what makes the
   * never-succeeded case count from the beginning of the window rather than
   * returning no rows at all.
   *
   * Both branches hit `ix_auth_events_user_kind_time` (user_id, kind,
   * occurred_at DESC) — the index migration 005 added.
   */
  async deniedSinceLastGrant(userId: string, since: Date): Promise<number> {
    const rows = await this.db.query<{ denials: string }>(
      `SELECT count(*)::text AS denials
         FROM auth_events
        WHERE user_id = $1
          AND kind = 'stepup.denied'
          AND occurred_at >= $2
          AND occurred_at > COALESCE(
                (SELECT max(occurred_at) FROM auth_events
                  WHERE user_id = $1 AND kind = 'stepup.granted'),
                '-infinity'::timestamptz)`,
      [userId, since],
    );
    // `count(*)` is bigint, which pg returns as a string to avoid a silent
    // precision loss at 2^53. Parsed here rather than left for a caller to
    // compare against a number and always find unequal.
    return Number(rows[0]?.denials ?? '0');
  }
}
