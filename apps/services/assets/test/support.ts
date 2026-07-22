import { FieldCrypto, LocalKmsProvider, type DekRecord, type DekRepository } from '@estate/crypto';
import type { AssetViewRow } from '../src/assets-view.repo';
import type { BeneficiaryRow } from '../src/beneficiaries.repo';
import type { Db, Queryable } from '../src/db';
import { FieldCipher } from '../src/field-cipher';
import type { AppendInput, LedgerRow } from '../src/ledger.repo';
import { pctToSql } from '../src/money';
import type { AssetState } from '../src/projection';

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
    kekAlias: 'financial/kek',
  });
  return new FieldCipher(crypto);
}

/** No-op events double capturing nothing (services under test don't assert on it). */
export const noopEvents = new Proxy(
  {},
  { get: () => (): Promise<void> => Promise.resolve() },
) as never;

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

/** Mimics the ux_asset_events_event_id unique violation shape from pg. */
function eventIdConflict(): Error & { code: string; constraint: string } {
  return Object.assign(new Error('duplicate key'), {
    code: '23505',
    constraint: 'ux_asset_events_event_id',
  });
}

/** In-memory LedgerRepo faithful to append-only + idempotency semantics. */
export class FakeLedger {
  readonly rows: LedgerRow[] = [];
  private seq = 0;
  /** Fixed clock hook so as-of tests can plant events in the past. */
  nextOccurredAt: Date | null = null;

  append(_q: Queryable, input: AppendInput): Promise<{ seq: string; occurredAt: Date }> {
    if (this.rows.some((r) => r.event_id === input.eventId)) {
      return Promise.reject(eventIdConflict());
    }
    this.seq += 1;
    const occurredAt = this.nextOccurredAt ?? new Date();
    this.nextOccurredAt = null;
    const row: LedgerRow = {
      seq: String(this.seq),
      event_id: input.eventId,
      asset_id: input.assetId,
      user_id: input.userId,
      event_type: input.eventType,
      payload_ct: input.payloadCt,
      actor_id: input.actorId,
      actor_role: input.actorRole ?? null,
      occurred_at: occurredAt,
    };
    this.rows.push(row);
    return Promise.resolve({ seq: row.seq, occurredAt });
  }

  findByEventId(_q: Queryable, eventId: string): Promise<LedgerRow | null> {
    return Promise.resolve(this.rows.find((r) => r.event_id === eventId) ?? null);
  }

  latestSeq(_q: Queryable, assetId: string): Promise<string | null> {
    const rows = this.rows.filter((r) => r.asset_id === assetId);
    return Promise.resolve(rows.length > 0 ? rows[rows.length - 1]!.seq : null);
  }

  latestSeqByAssets(_q: Queryable, assetIds: readonly string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const id of assetIds) {
      const rows = this.rows.filter((r) => r.asset_id === id);
      if (rows.length > 0) out.set(id, rows[rows.length - 1]!.seq);
    }
    return Promise.resolve(out);
  }

  listByAsset(_q: Queryable, assetId: string): Promise<LedgerRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.asset_id === assetId));
  }

  listByUser(_q: Queryable, userId: string, upTo?: Date): Promise<LedgerRow[]> {
    const rows = this.rows
      .filter((r) => r.user_id === userId && (!upTo || r.occurred_at <= upTo))
      .sort((a, b) => a.asset_id.localeCompare(b.asset_id) || Number(a.seq) - Number(b.seq));
    return Promise.resolve(rows);
  }

  listAll(_q: Queryable): Promise<LedgerRow[]> {
    return Promise.resolve(
      [...this.rows].sort(
        (a, b) => a.asset_id.localeCompare(b.asset_id) || Number(a.seq) - Number(b.seq),
      ),
    );
  }
}

/** In-memory AssetsViewRepo mirroring upsertFromState's column mapping. */
export class FakeViews {
  readonly rows = new Map<string, AssetViewRow>();

  lockById(_q: Queryable, assetId: string): Promise<AssetViewRow | null> {
    return Promise.resolve(this.rows.get(assetId) ?? null);
  }
  getAny(_q: Queryable, assetId: string): Promise<AssetViewRow | null> {
    return Promise.resolve(this.rows.get(assetId) ?? null);
  }
  getLive(_q: Queryable, assetId: string): Promise<AssetViewRow | null> {
    const row = this.rows.get(assetId);
    return Promise.resolve(row && row.deleted_at === null ? row : null);
  }
  listLiveByUser(_q: Queryable, userId: string): Promise<AssetViewRow[]> {
    return Promise.resolve(
      [...this.rows.values()].filter((r) => r.user_id === userId && r.deleted_at === null),
    );
  }
  listAll(_q: Queryable): Promise<AssetViewRow[]> {
    return Promise.resolve([...this.rows.values()]);
  }
  upsertFromState(
    _q: Queryable,
    state: AssetState<Buffer | null>,
    dekId: string,
    updatedAt: Date,
  ): Promise<void> {
    this.rows.set(state.assetId, {
      asset_id: state.assetId,
      user_id: state.userId,
      category: state.category,
      title: state.title,
      est_value_ct: state.estValue,
      valuation_as_of: state.valuationAsOf,
      valuation_source: state.valuationSource,
      ownership_pct: pctToSql(state.ownershipPct),
      cost_basis_ct: state.costBasis,
      location_ct: state.location,
      notes_ct: state.notes,
      in_trust: state.inTrust,
      funding_status: state.fundingStatus,
      dek_id: dekId,
      updated_at: updatedAt,
      deleted_at: state.retiredAt,
    });
    return Promise.resolve();
  }
}

/** In-memory BeneficiariesRepo with live/soft-deleted semantics. */
export class FakeBens {
  readonly rows: BeneficiaryRow[] = [];
  private nextId = 0;

  listLive(_q: Queryable, assetId: string): Promise<BeneficiaryRow[]> {
    return Promise.resolve(
      this.rows.filter((r) => r.asset_id === assetId && r.deleted_at === null),
    );
  }
  listAllLive(_q: Queryable): Promise<BeneficiaryRow[]> {
    return Promise.resolve(this.rows.filter((r) => r.deleted_at === null));
  }
  upsertDesignation(
    _q: Queryable,
    input: { assetId: string; contactId: string; designation: string; sharePct: number },
  ): Promise<void> {
    const live = this.rows.find(
      (r) =>
        r.asset_id === input.assetId &&
        r.contact_id === input.contactId &&
        r.designation === input.designation &&
        r.deleted_at === null,
    );
    if (live) {
      live.share_pct = pctToSql(input.sharePct);
      live.updated_at = new Date();
    } else {
      this.nextId += 1;
      this.rows.push({
        id: `00000000-0000-4000-8000-${String(this.nextId).padStart(12, '0')}`,
        asset_id: input.assetId,
        contact_id: input.contactId,
        designation: input.designation,
        share_pct: pctToSql(input.sharePct),
        created_at: new Date(),
        updated_at: new Date(),
        deleted_at: null,
      });
    }
    return Promise.resolve();
  }
  softRemove(
    _q: Queryable,
    input: { assetId: string; contactId: string; designation: string },
  ): Promise<boolean> {
    const live = this.rows.find(
      (r) =>
        r.asset_id === input.assetId &&
        r.contact_id === input.contactId &&
        r.designation === input.designation &&
        r.deleted_at === null,
    );
    if (!live) return Promise.resolve(false);
    live.deleted_at = new Date();
    return Promise.resolve(true);
  }
}
