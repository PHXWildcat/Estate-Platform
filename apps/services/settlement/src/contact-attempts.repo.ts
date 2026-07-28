import { Injectable } from '@nestjs/common';
import { isUniqueViolation, type Db, type Queryable } from './db';

export type ContactChannel = 'push' | 'email' | 'sms' | 'voice';

export interface ContactAttemptRow {
  id: string;
  case_id: string;
  seq: number;
  channel: ContactChannel;
  attempted_at: Date;
}

/**
 * The append-only owner-contact trail (docs/03 §5.1 control 3). UNIQUE
 * (case_id, seq) is the idempotency key: a concurrent driver sweep loses the
 * insert race, sees the unique violation, and skips — one recorded attempt
 * per schedule slot, ever.
 */
@Injectable()
export class ContactAttemptsRepo {
  /** Returns false when this seq was already recorded (lost race / rerun). */
  async insert(
    tx: Queryable,
    input: { caseId: string; seq: number; channel: ContactChannel; attemptedAt: Date },
  ): Promise<boolean> {
    try {
      await tx.query(
        `INSERT INTO settlement_contact_attempts (case_id, seq, channel, attempted_at)
         VALUES ($1, $2, $3, $4)`,
        [input.caseId, input.seq, input.channel, input.attemptedAt],
      );
      return true;
    } catch (err) {
      if (isUniqueViolation(err)) {
        return false;
      }
      throw err;
    }
  }

  async maxSeq(q: Queryable | Db, caseId: string): Promise<number | null> {
    const rows = await q.query<{ max: number | null }>(
      `SELECT MAX(seq) AS max FROM settlement_contact_attempts WHERE case_id = $1`,
      [caseId],
    );
    return rows[0]?.max ?? null;
  }

  async listByCase(q: Queryable | Db, caseId: string): Promise<ContactAttemptRow[]> {
    return q.query<ContactAttemptRow>(
      `SELECT id, case_id, seq, channel, attempted_at
         FROM settlement_contact_attempts
        WHERE case_id = $1
        ORDER BY seq`,
      [caseId],
    );
  }
}
