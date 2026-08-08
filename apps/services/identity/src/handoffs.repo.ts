import { Injectable } from '@nestjs/common';
import type { SessionAudience } from '@estate/auth-guard';
import { Db } from './db';

export interface HandoffRow {
  id: string;
  user_id: string;
  audience: SessionAudience;
  expires_at: Date;
  consumed_at: Date | null;
}

/**
 * The vault-origin handoff (M15). See migration 004 for the shape and the
 * reasoning; the load-bearing behaviour lives in `claim` below.
 */
@Injectable()
export class HandoffsRepo {
  constructor(private readonly db: Db) {}

  /**
   * Retire this user's outstanding handoff, if any.
   *
   * Called by the mint path BEFORE inserting, which is what makes the
   * `ux_auth_handoffs_live` partial index satisfiable — an index predicate
   * cannot say "and not expired", so the write path closes the invariant
   * instead. Re-issuing therefore kills the previous code, which is also the
   * behaviour it should have (M13/M14).
   */
  async retireLive(userId: string, at: Date): Promise<number> {
    const rows = await this.db.query<{ id: string }>(
      `UPDATE auth_handoffs
          SET consumed_at = $2
        WHERE user_id = $1 AND consumed_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    return rows.length;
  }

  async insert(input: {
    userId: string;
    codeSha256: Buffer;
    audience: SessionAudience;
    mintedFrom: string;
    expiresAt: Date;
  }): Promise<HandoffRow> {
    const rows = await this.db.query<HandoffRow>(
      `INSERT INTO auth_handoffs (user_id, code_sha256, audience, minted_from, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, user_id, audience, expires_at, consumed_at`,
      [input.userId, input.codeSha256, input.audience, input.mintedFrom, input.expiresAt],
    );
    return rows[0]!;
  }

  /**
   * Spend a code, atomically, BURNING IT ON THE ATTEMPT.
   *
   * The single UPDATE is the whole concurrency story: two simultaneous
   * redemptions of one code contend on the row and exactly one matches
   * `consumed_at IS NULL`, so the loser gets no row and the uniform refusal.
   * A check-then-act pair here would let both through.
   *
   * Expiry is enforced in SQL rather than compared afterwards, so a lapsed code
   * is indistinguishable from an unknown one at the only place that could tell
   * them apart — both return null, and the caller has one answer for every
   * failure (the M13 §6g rule: distinguishing them tells whoever holds a guess
   * that it named something real).
   *
   * Note what is NOT a selector: no user id, no session id. The code is the
   * only thing the redeem path can name, which is what keeps that route from
   * becoming an account oracle.
   */
  async claim(codeSha256: Buffer, now: Date): Promise<HandoffRow | null> {
    const rows = await this.db.query<HandoffRow>(
      `UPDATE auth_handoffs
          SET consumed_at = $2
        WHERE code_sha256 = $1
          AND consumed_at IS NULL
          AND expires_at > $2
        RETURNING id, user_id, audience, expires_at, consumed_at`,
      [codeSha256, now],
    );
    return rows[0] ?? null;
  }

  /** Link the spent handoff to the session it produced (the audit trail). */
  async recordSession(id: string, sessionId: string): Promise<void> {
    await this.db.query(`UPDATE auth_handoffs SET session_id = $2 WHERE id = $1`, [id, sessionId]);
  }
}
