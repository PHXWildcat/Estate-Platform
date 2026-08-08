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

  /**
   * Whether this user's stored address has been proved (M14).
   *
   * `null` = no row at all, which is a different fact from a row that is not
   * yet verified: the first means nothing has ever been fed for this user, the
   * second that they have not finished the ceremony. The service collapses
   * both to `verified: false` on the wire — a caller's gate treats them the
   * same — but they are kept apart here because the send path already
   * distinguishes them (`no_recipient`) and a repo that merged them would make
   * that impossible to see.
   */
  async findStatus(userId: string): Promise<{ verifiedAt: Date | null } | null> {
    const rows = await this.db.query<{ verified_at: Date | null }>(
      `SELECT verified_at
         FROM notification_recipients
        WHERE user_id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ? { verifiedAt: rows[0].verified_at } : null;
  }

  /**
   * THE UPSERT DELIBERATELY DOES NOT TOUCH `verified_at`, and the reason is
   * load-bearing enough to sit next to the SQL rather than in a design doc.
   *
   * Identity feeds this store fire-and-forget at registration AND at every
   * login (`auth.service.ts`). If the login re-feed cleared the bit, the
   * ceremony would be undone by the very act that proves the user is still
   * using the account, and no address would ever stay verified. It is safe to
   * preserve the bit because login resolves the user by `email_bidx` BEFORE it
   * calls here, so the address a login carries is by construction the address
   * already on file: the re-feed cannot present a different one. That is also
   * what lets the bit sit beside the ciphertext with no digest to compare
   * against, which is what keeps M9's "NO blind index — lookup is by user id
   * only" decision intact.
   *
   * THE FORWARD COMMITMENT, because this assumption has an expiry date: THE
   * DAY AN ADDRESS-CHANGE ROUTE EXISTS, IT INHERITS THE OBLIGATION TO CLEAR
   * THIS BIT. No such route exists today — identity has sixteen and none of
   * them changes an email — so this is a commitment rather than a migration.
   * Whoever adds one must clear `verified_at` in the same statement, or the
   * platform will vouch for an address nobody proved.
   *
   * A revived soft-deleted row keeps `deleted_at = NULL` and whatever
   * `verified_at` it had, which is correct: soft-deleting a recipient does not
   * un-prove an address, and the row's own lifecycle is what the arming gates
   * key on.
   */
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

  /**
   * Record that the user proved ownership. Idempotent and NEVER re-stamped: a
   * second verification of an already-verified address leaves the original
   * timestamp, so `verified_at` answers "when was this first proved" rather
   * than "when did somebody last press the button". Returns false when no live
   * row exists — a shredded or soft-deleted recipient cannot be vouched for,
   * and identity turns that into a refusal rather than a silent success.
   */
  async markVerified(tx: Queryable, userId: string, now: Date): Promise<boolean> {
    const rows = await tx.query<{ user_id: string }>(
      `UPDATE notification_recipients
          SET verified_at = COALESCE(verified_at, $2)
        WHERE user_id = $1 AND deleted_at IS NULL
      RETURNING user_id`,
      [userId, now],
    );
    return rows.length > 0;
  }
}
