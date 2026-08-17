import { Injectable } from '@nestjs/common';
import type { Db, Queryable } from './db';

/** What a grant attempt did. `already_granted` is the idempotent no-op. */
export type GrantOutcome =
  | { readonly result: 'granted'; readonly id: string }
  | { readonly result: 'already_granted'; readonly id: string };

/** What a revoke attempt did. `no_active_grant` is the idempotent no-op. */
export type RevokeOutcome =
  | { readonly result: 'revoked'; readonly id: string }
  | { readonly result: 'no_active_grant'; readonly id: null };

/**
 * The interim human-review allowlist.
 *
 * THE PROPERTY: no runtime session may mint an operator. The settlement
 * service reads this table on every operator action and never writes it — a
 * compromised operator session can act as the operator it already is and
 * cannot create another, which is the whole safety argument for an allowlist
 * standing in for the TB7 operator platform.
 *
 * Until M21 PR1 that property lived only in this docstring, and the docstring
 * was wrong about its own mechanism in the direction that matters: it said the
 * write methods below were "the CLI-only write path" while `operator-cli.ts`
 * reimplemented both in raw SQL and called neither. Two implementations of one
 * behaviour, one of them dead — the M8 PR2 shape, in the allowlist that
 * decides who may approve a death case. The CLI drives these now, and
 * `test/operator-write-path.spec.ts` asserts that nothing else does, so the
 * property is checked rather than asserted.
 *
 * Shape is `permission_grants`': append + revoke, no soft delete and no
 * `_versions` table, because the rows themselves are the history.
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

  /**
   * CLI-only write path (asserted by `test/operator-write-path.spec.ts`).
   *
   * `grantedBy` names the human who authorized this, and is REQUIRED — the
   * column has existed since M7 and nothing has ever written it, so every row
   * in the table says only that somebody with the database made a grant. It is
   * attribution, not authentication: the caller already holds the connection.
   *
   * Idempotent against `ux_settlement_operators_active`, the partial unique
   * index on the live row, so a repeat is a no-op rather than a second live
   * grant. The existing row's id comes back either way, because the audit event
   * that accompanies this needs a resource to name whichever branch was taken.
   *
   * WHY `ON CONFLICT` AND NOT catch-the-unique-violation, which is what this
   * did first and what the live drive of M21 PR1 refuted: **raising the error
   * makes the outcome depend on whether there is an enclosing transaction.**
   * Postgres aborts a transaction on a failed statement and refuses every
   * command until rollback, so the recovery re-read ran fine against a pool
   * (which is what every test used) and could not run at all inside the CLI's
   * own `BEGIN`/`COMMIT` (which is the only way this is ever really called).
   * A repeat grant therefore died with `current transaction is aborted` while
   * three green specs said it was a clean no-op. Never raising the error is
   * what makes the two contexts agree; the conflict target names the index's
   * own predicate so a REVOKED row is not treated as a conflict.
   */
  async grant(q: Queryable | Db, userId: string, grantedBy: string): Promise<GrantOutcome> {
    const inserted = await q.query<{ id: string }>(
      `INSERT INTO settlement_operators (user_id, granted_by) VALUES ($1, $2)
       ON CONFLICT (user_id) WHERE revoked_at IS NULL DO NOTHING
       RETURNING id`,
      [userId, grantedBy],
    );
    const row = inserted[0];
    if (row) {
      return { result: 'granted', id: row.id };
    }

    const existing = await q.query<{ id: string }>(
      `SELECT id FROM settlement_operators WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
    const active = existing[0];
    if (!active) {
      // DO NOTHING and the re-read disagree, which means the active grant was
      // revoked between the two statements. Reporting a no-op that did not
      // happen would be worse than refusing: the caller asked for a grant, and
      // after this there is none.
      throw new Error('operator grant raced a revoke; re-run');
    }
    return { result: 'already_granted', id: active.id };
  }

  /** CLI-only write path (asserted by `test/operator-write-path.spec.ts`). */
  async revoke(q: Queryable | Db, userId: string, at: Date): Promise<RevokeOutcome> {
    const rows = await q.query<{ id: string }>(
      `UPDATE settlement_operators
          SET revoked_at = $2
        WHERE user_id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [userId, at],
    );
    const row = rows[0];
    return row ? { result: 'revoked', id: row.id } : { result: 'no_active_grant', id: null };
  }

  async listActive(
    q: Queryable | Db,
  ): Promise<Array<{ user_id: string; created_at: Date; granted_by: string | null }>> {
    return q.query<{ user_id: string; created_at: Date; granted_by: string | null }>(
      `SELECT user_id, created_at, granted_by
         FROM settlement_operators
        WHERE revoked_at IS NULL
        ORDER BY created_at, id`,
    );
  }
}
