import { Injectable } from '@nestjs/common';
import { Db } from './db';

export interface ExtensionPairingRow {
  id: string;
  user_id: string;
  expires_at: Date;
  redeemed_at: Date | null;
  session_id: string | null;
  revoked_at: Date | null;
  created_at: Date;
}

/**
 * The extension-pairing store (M16). See migration 007 for the shape and the
 * reasoning; this file holds the two statements that carry the properties.
 */
@Injectable()
export class ExtensionPairingsRepo {
  constructor(private readonly db: Db) {}

  /**
   * Retire this user's outstanding pairing, if any.
   *
   * MATCHES THE INDEX PREDICATE, NOT THE CLOCK, and unconditionally. This is
   * M14's worst finding turned into a rule: there, the live-row index counted a
   * LAPSED code as occupying the slot while the code that decided whether to
   * retire carried the clock, so once a code passed its TTL nothing ever
   * cleared it — the next insert took the unique violation, the ceremony
   * answered "too soon" forever, and the account could never be paired again.
   * The predicate below is character-for-character the index's, so the two
   * notions of "live" cannot disagree.
   */
  async retireLive(userId: string, at: Date): Promise<boolean> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE extension_pairings
          SET revoked_at = $2, revoke_reason = 'superseded'
        WHERE user_id = $1 AND redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    return rows.length > 0;
  }

  async insert(input: {
    userId: string;
    codeSha256: Buffer;
    mintedFrom: string;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO extension_pairings (user_id, code_sha256, minted_from, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [input.userId, input.codeSha256, input.mintedFrom, input.expiresAt],
    );
  }

  /**
   * Spend a code — BURNED ON THE ATTEMPT, in one statement.
   *
   * The WHERE clause is the whole concurrency argument, and it is the handoff's
   * verbatim: a check-then-act pair passes every unit test and lets two
   * concurrent redemptions of one code both succeed, which here would mean two
   * extensions paired from a credential the owner authorised once. Expiry is
   * enforced IN SQL for the same reason it is there — so a lapsed code and an
   * unknown one are indistinguishable at the only place that could tell them
   * apart.
   */
  async claim(codeSha256: Buffer, now: Date): Promise<ExtensionPairingRow | null> {
    const rows = await this.db.query<ExtensionPairingRow>(
      `UPDATE extension_pairings
          SET redeemed_at = $2
        WHERE code_sha256 = $1
          AND redeemed_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > $2
        RETURNING id, user_id, expires_at, redeemed_at, session_id, revoked_at, created_at`,
      [codeSha256, now],
    );
    return rows[0] ?? null;
  }

  /** Record which session a spent pairing produced. */
  async recordSession(id: string, sessionId: string): Promise<void> {
    await this.db.query(`UPDATE extension_pairings SET session_id = $2 WHERE id = $1`, [
      id,
      sessionId,
    ]);
  }
}
