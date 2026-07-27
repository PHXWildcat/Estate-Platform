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
}
