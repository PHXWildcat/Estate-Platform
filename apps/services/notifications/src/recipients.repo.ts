import { Injectable } from '@nestjs/common';
import { Db, type Queryable } from './db';

export interface RecipientRow {
  user_id: string;
  email_ct: Buffer;
  dek_id: string;
  /** Non-null once the user proved they receive mail there (M14). */
  verified_at: Date | null;
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
      `SELECT user_id, email_ct, dek_id, verified_at
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
   *
   * IT REQUIRES AN ACTIVE DEK, and that is the M14 review making a claim true
   * rather than deleting it. Migration 003 says a crypto-shredded recipient
   * "loses its verification along with its address and the arming gates then
   * refuse — fail-closed by construction". Crypto-shredding destroys the DEK,
   * NOT the row, so without this EXISTS the row survived with `verified_at`
   * set: the gates would ARM for an owner whose every alert then failed to
   * decrypt and recorded `carrier_failure`. Exactly the fail-open M14 exists to
   * remove, in the machinery that removes it. No in-repo caller destroys a
   * notifications DEK today (erasure is an operator action), which is why this
   * was latent rather than live — and why it had to be closed before the
   * erasure route lands and nobody re-reads the comment.
   */
  async findStatus(userId: string): Promise<{ verifiedAt: Date | null } | null> {
    const rows = await this.db.query<{ verified_at: Date | null }>(
      `SELECT r.verified_at
         FROM notification_recipients r
        WHERE r.user_id = $1
          AND r.deleted_at IS NULL
          AND EXISTS (
            SELECT 1 FROM notification_deks d
             WHERE d.dek_id = r.dek_id AND d.destroyed_at IS NULL
          )`,
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
   * on file AT THAT MOMENT: the re-feed cannot present one the user did not
   * just sign in with. That is also what lets the bit sit beside the
   * ciphertext with no digest to compare against, which is what keeps M9's
   * "NO blind index — lookup is by user id only" decision intact.
   *
   * THE FORWARD COMMITMENT THIS COMMENT CARRIED IS DISCHARGED (M17 PR4), one
   * step stronger than it asked. It said an address-change route "must clear
   * `verified_at` in the same statement, or the platform will vouch for an
   * address nobody proved". The route that now exists never puts an unproved
   * address here at all: the ceremony mails a challenge to the PROSPECTIVE
   * address and only after redemption does identity call `replace` below —
   * which swaps the address and stamps the proof in ONE statement. So every
   * address that can reach this store is either the one the user signed in
   * with (this upsert) or one the ceremony just proved (`replace`), and the
   * preserve-the-bit reasoning above SURVIVES the change route: if a login
   * re-feed ever races a change and lands last, the address it re-writes is
   * one that was on file and whose proof state the bit already describes.
   * The residual — a stale re-feed landing after a change repoints the store
   * to the just-left address until the next login — is recorded in docs/03
   * §6n, and it self-heals because the next login can only carry the NEW
   * address (the old bidx no longer resolves).
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
             deleted_at = NULL,
             -- A CHANGE OF KEY CLEARS THE PROOF. Round 2 of the M14 review
             -- found the crypto-shred fix good only until the next login:
             -- encryptField mints a fresh DEK once the old one is destroyed,
             -- and this upsert preserved verified_at, so the row came back
             -- with an active key and an untouched proof and every arming gate
             -- re-armed with nothing re-proved. dek_id changes ONLY when the
             -- key underneath changed (a shred, or a rotation when one lands),
             -- which is exactly when the old proof stops describing the
             -- current state; an ordinary login re-feed resolves to the same
             -- active DEK and leaves the bit alone.
             verified_at = CASE
               WHEN notification_recipients.dek_id = EXCLUDED.dek_id
                 THEN notification_recipients.verified_at
               ELSE NULL
             END`,
      [input.userId, input.emailCt, input.dekId],
    );
  }

  /**
   * REPLACE the address with one the ceremony just proved (M17 PR4) — the
   * discharge of the forward commitment above, in the one statement it asked
   * for. The old proof leaves with the old address and the new proof arrives
   * with the new one, so there is no moment when the store vouches for an
   * address nobody proved and no moment when a proven address reads
   * unverified. Only identity can reach this (the RECIPIENTS credential), and
   * identity only calls it after the challenge code was redeemed under the
   * account's current password and a fresh second factor.
   *
   * An INSERT arm exists for the row-less case (a user who somehow has no
   * recipient row completing a change), because refusing the repoint there
   * would leave alerts flowing to nothing at all.
   */
  async replace(
    tx: Queryable,
    input: { userId: string; emailCt: Buffer; dekId: string; provenAt: Date },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO notification_recipients (user_id, email_ct, dek_id, verified_at)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE
         SET email_ct = EXCLUDED.email_ct,
             dek_id = EXCLUDED.dek_id,
             deleted_at = NULL,
             verified_at = EXCLUDED.verified_at`,
      [input.userId, input.emailCt, input.dekId, input.provenAt],
    );
  }

  /**
   * Record that the user proved ownership. Idempotent and NEVER re-stamped: a
   * second verification of an already-verified address leaves the original
   * timestamp, so `verified_at` answers "when was this first proved" rather
   * than "when did somebody last press the button". Returns false when no live
   * row exists — a shredded or soft-deleted recipient cannot be vouched for,
   * and identity turns that into a refusal rather than a silent success.
   *
   * THE DEK PREDICATE IS HERE TOO, and round 2 of the M14 review is why. The
   * first fix put it only on `findStatus`, so a shredded recipient answered
   * `verified: false` to the gates while this still returned true and stamped
   * the row — the platform telling a user their address was verified in the
   * same breath as telling every gate it was not. A read and a write that
   * disagree about the same fact is worse than either answer.
   */
  async markVerified(tx: Queryable, userId: string, now: Date): Promise<boolean> {
    const rows = await tx.query<{ user_id: string }>(
      `UPDATE notification_recipients r
          SET verified_at = COALESCE(r.verified_at, $2)
        WHERE r.user_id = $1
          AND r.deleted_at IS NULL
          AND EXISTS (
            SELECT 1 FROM notification_deks d
             WHERE d.dek_id = r.dek_id AND d.destroyed_at IS NULL
          )
      RETURNING r.user_id`,
      [userId, now],
    );
    return rows.length > 0;
  }
}
