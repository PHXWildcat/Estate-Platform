import { Injectable } from '@nestjs/common';
import type { AccountKind } from '@estate/contracts';
import { Db, type Queryable } from './db';

export interface AccountRow {
  id: string;
  user_id: string;
  plaid_item_id: string | null;
  kind: AccountKind;
  name: string;
  mask: string | null;
  account_number_ct: Buffer | null;
  current_balance_ct: Buffer | null;
  balance_as_of: Date | null;
  is_liability: boolean;
  dek_id: string;
}

const COLUMNS = `id, user_id, plaid_item_id, kind, name, mask, account_number_ct,
                 current_balance_ct, balance_as_of, is_liability, dek_id`;

/**
 * accounts persistence (Plaid-linked rows only for now; manual accounts are a
 * future assets-service feature — docs/02 §3 `plaid_item_id NULL`).
 */
@Injectable()
export class AccountsRepo {
  constructor(private readonly db: Db) {}

  /**
   * Upsert one synced account. The row id is derived deterministically by the
   * caller from (plaid_item_id, Plaid's account_id), so re-syncs update in
   * place by primary key without persisting Plaid's account_id as an extra
   * plaintext column. A re-appearing account also clears any soft delete.
   */
  async upsert(
    tx: Queryable,
    input: {
      id: string;
      userId: string;
      plaidItemId: string;
      kind: AccountKind;
      name: string;
      mask: string | null;
      currentBalanceCt: Buffer | null;
      balanceAsOf: Date;
      isLiability: boolean;
      dekId: string;
    },
  ): Promise<void> {
    await tx.query(
      `INSERT INTO accounts
         (id, user_id, plaid_item_id, kind, name, mask, current_balance_ct,
          balance_as_of, is_liability, dek_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO UPDATE SET
         kind = EXCLUDED.kind,
         name = EXCLUDED.name,
         mask = EXCLUDED.mask,
         current_balance_ct = EXCLUDED.current_balance_ct,
         balance_as_of = EXCLUDED.balance_as_of,
         is_liability = EXCLUDED.is_liability,
         deleted_at = NULL`,
      [
        input.id,
        input.userId,
        input.plaidItemId,
        input.kind,
        input.name,
        input.mask,
        input.currentBalanceCt,
        input.balanceAsOf,
        input.isLiability,
        input.dekId,
      ],
    );
  }

  async listLiveByUser(userId: string): Promise<AccountRow[]> {
    return this.db.query<AccountRow>(
      `SELECT ${COLUMNS} FROM accounts
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY name, id`,
      [userId],
    );
  }

  /** Soft-delete every account behind a revoked item. */
  async softDeleteByItem(tx: Queryable, plaidItemId: string, at: Date): Promise<void> {
    await tx.query(
      `UPDATE accounts SET deleted_at = $2 WHERE plaid_item_id = $1 AND deleted_at IS NULL`,
      [plaidItemId, at],
    );
  }
}
