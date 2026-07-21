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
}
