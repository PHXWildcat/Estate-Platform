import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

export interface HandshakeRow {
  id: string;
  user_id: string;
  server_public: Buffer;
  server_secret: Buffer;
  created_at: Date;
  expires_at: Date;
  consumed_at: Date | null;
}

/** In-flight SRP exchanges. Single-use, short-lived, swept by age. */
@Injectable()
export class HandshakesRepo {
  async insert(
    q: Queryable | Db,
    input: {
      userId: string;
      serverPublic: Buffer;
      serverSecret: Buffer;
      expiresAt: Date;
    },
  ): Promise<HandshakeRow> {
    const rows = await q.query<HandshakeRow>(
      `INSERT INTO vault_srp_handshakes (user_id, server_public, server_secret, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING id, user_id, server_public, server_secret, created_at, expires_at, consumed_at`,
      [input.userId, input.serverPublic, input.serverSecret, input.expiresAt],
    );
    return rows[0]!;
  }

  /**
   * Claim a handshake for a verification attempt.
   *
   * Consumption happens on the ATTEMPT, not on success: with rate limiting
   * still a documented follow-up, burning the handshake either way means every
   * password guess costs a fresh round trip and leaves its own
   * `vault.open.failed` audit event, instead of letting an attacker grind
   * guesses against one challenge. The UPDATE ... WHERE consumed_at IS NULL is
   * what makes "single use" atomic under concurrency.
   */
  async claim(
    q: Queryable | Db,
    input: { id: string; userId: string; now: Date },
  ): Promise<HandshakeRow | null> {
    const rows = await q.query<HandshakeRow>(
      `UPDATE vault_srp_handshakes
          SET consumed_at = $3
        WHERE id = $1 AND user_id = $2 AND consumed_at IS NULL AND expires_at > $3
        RETURNING id, user_id, server_public, server_secret, created_at, expires_at, consumed_at`,
      [input.id, input.userId, input.now],
    );
    return rows[0] ?? null;
  }

  /** Opportunistic sweep of expired rows; cheap and keeps the table small. */
  async deleteExpired(q: Queryable | Db, now: Date): Promise<void> {
    await q.query(`DELETE FROM vault_srp_handshakes WHERE expires_at <= $1`, [now]);
  }
}
