import { Injectable } from '@nestjs/common';
import { isUniqueViolation, type Db, type Queryable } from './db';

/**
 * The interim human-review allowlist (decision log: managed ONLY by the ops
 * CLI — there is deliberately NO runtime grant API, so a compromised operator
 * session cannot mint operators. Replaced by the TB7 operator platform).
 */
@Injectable()
export class OperatorsRepo {
  async isOperator(q: Queryable | Db, userId: string): Promise<boolean> {
    const rows = await q.query<{ ok: number }>(
      `SELECT 1 AS ok
         FROM settlement_operators
        WHERE user_id = $1 AND revoked_at IS NULL
        LIMIT 1`,
      [userId],
    );
    return rows.length > 0;
  }

  /** CLI-only write path. Idempotent: an already-active grant is a no-op. */
  async grant(q: Queryable | Db, userId: string): Promise<'granted' | 'already_granted'> {
    try {
      await q.query(`INSERT INTO settlement_operators (user_id) VALUES ($1)`, [userId]);
      return 'granted';
    } catch (err) {
      if (isUniqueViolation(err)) {
        return 'already_granted';
      }
      throw err;
    }
  }

  /** CLI-only write path. */
  async revoke(q: Queryable | Db, userId: string, at: Date): Promise<boolean> {
    const rows = await q.query<{ id: string }>(
      `UPDATE settlement_operators
          SET revoked_at = $2
        WHERE user_id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    return rows.length > 0;
  }

  async listActive(q: Queryable | Db): Promise<Array<{ user_id: string; created_at: Date }>> {
    return q.query<{ user_id: string; created_at: Date }>(
      `SELECT user_id, created_at
         FROM settlement_operators
        WHERE revoked_at IS NULL
        ORDER BY created_at, id`,
    );
  }
}
