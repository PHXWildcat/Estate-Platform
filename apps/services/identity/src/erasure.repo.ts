import { Injectable } from '@nestjs/common';
import type { Queryable } from './db';

/** A live or historical erasure request, as the service hands it out. */
export interface ErasureRequestRow {
  id: string;
  user_id: string;
  status: 'pending' | 'cancelled';
  requested_at: Date;
  cancelled_at: Date | null;
}

/**
 * The erasure request record (M25 PR2).
 *
 * Every statement here carries its own precondition. The rule is the one
 * `.claude/rules/db-migrations.md` states for the settlement lock: a check that
 * must hold AT THE WRITE is restated inside the statement's own `WHERE`, never
 * read above it — a pre-transaction read and the write it guards are separated
 * by every commit that lands in between, and the whole point of this record is
 * that something irreversible reads it later.
 */
@Injectable()
export class ErasureRepo {
  /**
   * Record a request, but only for an account the status allowlist admits.
   *
   * THE ALLOWLIST TRAVELS IN THE STATEMENT. `INSERT ... SELECT ... WHERE
   * EXISTS` means a status change committing between the caller's session
   * lookup and this write cannot produce a request against an account that has
   * since been locked or moved into settlement. Zero rows back is "refused or
   * already requested" and the caller re-reads to tell those apart — it never
   * infers a reason from the row count.
   *
   * `ON CONFLICT DO NOTHING` inferred on the live partial index makes a second
   * concurrent request a no-op rather than a unique violation. Catching that
   * violation inside a transaction would abort it and refuse every subsequent
   * statement, which is the trap the repo's rules name explicitly.
   */
  async insertIfPermitted(
    tx: Queryable,
    userId: string,
    sessionId: string | null,
    permittedStatuses: readonly string[],
  ): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `INSERT INTO erasure_requests (user_id, requested_by_session)
       SELECT $1, $2
        WHERE EXISTS (
                SELECT 1 FROM users
                 WHERE id = $1
                   AND deleted_at IS NULL
                   AND status = ANY($3))
       ON CONFLICT (user_id) WHERE status = 'pending' AND deleted_at IS NULL
       DO NOTHING
       RETURNING id, user_id, status, requested_at, cancelled_at`,
      [userId, sessionId, [...permittedStatuses]],
    );
    return rows[0] ?? null;
  }

  /** The caller's live request, if there is one. */
  async findLive(tx: Queryable, userId: string): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `SELECT id, user_id, status, requested_at, cancelled_at
         FROM erasure_requests
        WHERE user_id = $1 AND status = 'pending' AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Cancel the live request. Returns null when there was nothing to cancel,
   * which is a normal answer and not an error: the protective verb must be
   * safe to press twice.
   *
   * NO STATUS ALLOWLIST HERE, deliberately. Cancelling is the de-escalating
   * direction, and an account that became ineligible to REQUEST erasure while a
   * request was live must still be able to withdraw it — refusing the
   * withdrawal because the account is now locked would strand the most
   * dangerous record in the system in its armed state.
   */
  async cancel(tx: Queryable, userId: string, at: Date): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `UPDATE erasure_requests
          SET status = 'cancelled', cancelled_at = $2
        WHERE user_id = $1 AND status = 'pending' AND deleted_at IS NULL
       RETURNING id, user_id, status, requested_at, cancelled_at`,
      [userId, at],
    );
    return rows[0] ?? null;
  }

  /** The account status the refusal message is derived from. */
  async statusOf(tx: Queryable, userId: string): Promise<string | null> {
    const rows = await tx.query<{ status: string }>(
      `SELECT status FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0]?.status ?? null;
  }
}
