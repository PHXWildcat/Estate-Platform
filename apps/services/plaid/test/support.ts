import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import type { AccountRow } from '../src/accounts.repo';
import type { Db, Queryable } from '../src/db';
import { FieldCipher } from '../src/field-cipher';
import type { PlaidItemRow } from '../src/items.repo';
import type { PlaidItemStatus } from '@estate/contracts';

/** In-memory DekRepository for the real FieldCrypto (no Postgres needed). */
export class MemoryDeks implements DekRepository {
  private readonly rows = new Map<string, DekRecord>();
  findActiveByUser(userId: string): Promise<DekRecord | null> {
    for (const r of this.rows.values()) {
      if (r.userId === userId && r.destroyedAt === null) return Promise.resolve(r);
    }
    return Promise.resolve(null);
  }
  findById(dekId: string): Promise<DekRecord | null> {
    return Promise.resolve(this.rows.get(dekId) ?? null);
  }
  insert(record: DekRecord): Promise<void> {
    this.rows.set(record.dekId, record);
    return Promise.resolve();
  }
  markDestroyed(dekId: string, at: Date): Promise<void> {
    const r = this.rows.get(dekId);
    if (r) this.rows.set(dekId, { ...r, destroyedAt: at });
    return Promise.resolve();
  }
}

/** A real FieldCipher over a real FieldCrypto with an in-memory DEK store. */
export function buildCipher(): FieldCipher {
  const crypto = new FieldCrypto(LocalKmsProvider.generate(), new MemoryDeks(), () => undefined, {
    kekAlias: 'plaid/kek',
  });
  return new FieldCipher(crypto);
}

/** No-op events double (services under test don't assert on it). */
export const noopEvents = new Proxy(
  {},
  { get: () => (): Promise<void> => Promise.resolve() },
) as never;

/**
 * An events double that RECORDS each call — method name and the arguments the
 * service actually passed — for the drives that assert what the trail would
 * carry. Faithful about absences: a method never called is simply not in
 * `calls`, so "emits nothing" is an assertion over the whole list.
 */
export function recordingEvents(): {
  calls: Array<{ method: string; args: unknown[] }>;
  events: never;
} {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const events = new Proxy(
    {},
    {
      get:
        (_target, method) =>
        (...args: unknown[]): Promise<void> => {
          calls.push({ method: String(method), args });
          return Promise.resolve();
        },
    },
  ) as never;
  return { calls, events };
}

const rejectRawSql = (): Promise<never> =>
  Promise.reject(new Error('unit tests must not issue raw SQL'));

const DUMMY_TX: Queryable = { query: rejectRawSql };

/**
 * Db double: withTransaction just runs the callback (no rollback semantics —
 * transactional atomicity is integration-tested against real Postgres).
 */
export function fakeDb(): Db {
  return {
    query: rejectRawSql,
    withTransaction: async <T>(_actor: string, fn: (tx: Queryable) => Promise<T>): Promise<T> =>
      fn(DUMMY_TX),
    onModuleDestroy: () => Promise.resolve(),
  } as unknown as Db;
}

/** In-memory ItemsRepo faithful to soft-delete + blind-index semantics. */
export class FakeItems {
  readonly rows: Array<PlaidItemRow & { item_bidx: Buffer; deleted_at: Date | null }> = [];

  insert(input: {
    id: string;
    userId: string;
    accessTokenCt: Buffer;
    institutionId: string;
    institutionName: string | null;
    itemIdCt: Buffer;
    itemBidx: Buffer;
    dekId: string;
  }): Promise<void> {
    this.rows.push({
      id: input.id,
      user_id: input.userId,
      access_token_ct: input.accessTokenCt,
      institution_id: input.institutionId,
      institution_name: input.institutionName,
      sync_cursor: null,
      status: 'healthy',
      dek_id: input.dekId,
      created_at: new Date(),
      updated_at: new Date(),
      item_bidx: input.itemBidx,
      deleted_at: null,
    });
    return Promise.resolve();
  }

  /**
   * A SNAPSHOT, not the row. Postgres hands a caller the values as they were
   * when the SELECT ran; this double handed out the live object, so a later
   * `setStatus` mutated the caller's `item.status` too and the caller's STALE
   * PRE-READ was magically fresh. Three drives named for carrying "the prior
   * the WRITE found" could not tell the two apart, and M49 PR6's review proved
   * it: the mutation that passes `item.status` where the write's answer belongs
   * left them green. A double must be faithful about the SHAPE of what it
   * hands back, not only about values and refusals.
   */
  private static snapshot(row: PlaidItemRow): PlaidItemRow {
    return { ...row };
  }

  findLiveById(id: string): Promise<PlaidItemRow | null> {
    const row = this.rows.find((r) => r.id === id && r.deleted_at === null);
    return Promise.resolve(row ? FakeItems.snapshot(row) : null);
  }

  findLiveByItemBidx(itemBidx: Buffer): Promise<PlaidItemRow | null> {
    const row = this.rows.find((r) => r.deleted_at === null && r.item_bidx.equals(itemBidx));
    return Promise.resolve(row ? FakeItems.snapshot(row) : null);
  }

  listLiveByUser(userId: string): Promise<PlaidItemRow[]> {
    return Promise.resolve(
      this.rows
        .filter((r) => r.user_id === userId && r.deleted_at === null)
        .map((r) => FakeItems.snapshot(r)),
    );
  }

  /**
   * Faithful about the ABSENCE as well as the value: null when no live row
   * matched, which is what the real statement answers for a revoked item.
   */
  setStatus(_q: Queryable, id: string, status: PlaidItemStatus): Promise<PlaidItemStatus | null> {
    const row = this.rows.find((r) => r.id === id && r.deleted_at === null);
    if (!row) return Promise.resolve(null);
    const prior = row.status;
    row.status = status;
    return Promise.resolve(prior);
  }

  setCursor(_q: Queryable, id: string, cursor: string | null): Promise<void> {
    const row = this.rows.find((r) => r.id === id && r.deleted_at === null);
    if (row) row.sync_cursor = cursor;
    return Promise.resolve();
  }

  markRevoked(_q: Queryable, id: string, at: Date): Promise<PlaidItemStatus | null> {
    const row = this.rows.find((r) => r.id === id && r.deleted_at === null);
    if (!row) return Promise.resolve(null);
    const prior = row.status;
    row.status = 'revoked';
    row.deleted_at = at;
    return Promise.resolve(prior);
  }
}

/** In-memory AccountsRepo with primary-key upsert + soft-delete semantics. */
export class FakeAccounts {
  readonly rows = new Map<string, AccountRow & { deleted_at: Date | null }>();

  upsert(
    _q: Queryable,
    input: {
      id: string;
      userId: string;
      plaidItemId: string;
      kind: AccountRow['kind'];
      name: string;
      mask: string | null;
      currentBalanceCt: Buffer | null;
      balanceAsOf: Date;
      isLiability: boolean;
      dekId: string;
    },
  ): Promise<void> {
    this.rows.set(input.id, {
      id: input.id,
      user_id: input.userId,
      plaid_item_id: input.plaidItemId,
      kind: input.kind,
      name: input.name,
      mask: input.mask,
      account_number_ct: null,
      current_balance_ct: input.currentBalanceCt,
      balance_as_of: input.balanceAsOf,
      is_liability: input.isLiability,
      dek_id: input.dekId,
      deleted_at: null,
    });
    return Promise.resolve();
  }

  listLiveByUser(userId: string): Promise<AccountRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) => r.user_id === userId && r.deleted_at === null),
    );
  }

  softDeleteByItem(_q: Queryable, plaidItemId: string, at: Date): Promise<void> {
    for (const row of this.rows.values()) {
      if (row.plaid_item_id === plaidItemId && row.deleted_at === null) {
        row.deleted_at = at;
      }
    }
    return Promise.resolve();
  }
}
