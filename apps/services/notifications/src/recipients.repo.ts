import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

export interface RecipientRow {
  user_id: string;
  email_ct: Buffer;
  dek_id: string;
}

/**
 * The recipient store. One row per user, upsert-in-place (history captured by
 * the versions trigger); a re-registration revives a soft-deleted row. Lookup
 * is by user_id ONLY — there is deliberately no email equality search here
 * (no blind index), because nothing legitimate asks "which user has this
 * address" of the notifications service.
 */
@Injectable()
export class RecipientsRepo {
  constructor(private readonly db: Db) {}

  async find(userId: string): Promise<RecipientRow | null> {
    const rows = await this.db.query<RecipientRow>(
      `SELECT user_id, email_ct, dek_id
         FROM notification_recipients
        WHERE user_id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  async upsert(
    tx: Queryable,
    input: { userId: string; emailCt: Buffer; dekId: string },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO notification_recipients (user_id, email_ct, dek_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id) DO UPDATE
         SET email_ct = EXCLUDED.email_ct,
             dek_id = EXCLUDED.dek_id,
             deleted_at = NULL`,
      [input.userId, input.emailCt, input.dekId],
    );
  }
}
