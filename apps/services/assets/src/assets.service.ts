import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import type { AssetCategory } from '@estate/contracts';
import { deserializePayload, serializePayload, type AssetEventPayload } from './asset-events';
import { AssetsViewRepo, type AssetViewRow } from './assets-view.repo';
import { AssetsAuthz, assetResource } from './authz.service';
import { BeneficiariesRepo } from './beneficiaries.repo';
import { Db, isUniqueViolation, type Queryable } from './db';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { LedgerRepo, type LedgerRow } from './ledger.repo';
import { centsToMoney, moneyToCents, ownedShareCents, sqlToPct } from './money';
import { applyAssetEvent, shareSum, type AssetState, type EncryptedField } from './projection';
import type {
  ChangeOwnershipInput,
  CreateAssetInput,
  DesignateBeneficiaryInput,
  RecordValuationInput,
  RemoveBeneficiaryInput,
  RetireAssetInput,
  UpdateDetailsInput,
} from './schemas';

/** AAD field string for a ledger event's encrypted payload. */
export function payloadField(eventId: string): string {
  return `asset_event.payload.${eventId}`;
}

/** AAD field string for an encrypted assets_view column. */
export function viewField(field: EncryptedField): string {
  return `asset.${field}`;
}

/** Decrypted, API-facing asset representation. */
export interface AssetDto {
  assetId: string;
  category: string;
  title: string;
  estValue: string | null;
  valuationAsOf: string | null;
  valuationSource: string | null;
  ownershipPct: number;
  costBasis: string | null;
  location: string | null;
  notes: string | null;
  inTrust: boolean;
  fundingStatus: string | null;
  /** Optimistic-concurrency token: the asset's latest ledger seq. */
  version: string;
}

/** Thin command acknowledgement (CQRS: reads come from the queries). */
export interface CommandResult {
  assetId: string;
  eventId: string;
  version: string;
  occurredAt: string;
  /** True when this call was an idempotent retry of an earlier command. */
  replayed: boolean;
}

export interface HistoryEntryDto {
  version: string;
  eventId: string;
  eventType: string;
  occurredAt: string;
  actorId: string;
  payload: AssetEventPayload;
}

export interface BeneficiariesDto {
  assetId: string;
  beneficiaries: Array<{
    contactId: string;
    designation: string;
    sharePct: number;
  }>;
  totals: Array<{ designation: string; sharePct: number; designationComplete: boolean }>;
}

export interface NetWorthDto {
  asOf: string | null;
  /** Σ estValue × ownership%, over assets with a known value. */
  totalValue: string;
  assetCount: number;
  valuedAssetCount: number;
  byCategory: Array<{ category: string; count: number; value: string }>;
  /** Value-weighted share of known value held in trust ("estate funding %"). */
  inTrustValue: string;
  inTrustPct: number | null;
}

interface CommandSpec {
  actor: string;
  assetId: string;
  eventId: string | undefined;
  payload: AssetEventPayload;
  ifMatch: bigint | undefined;
  /** Extra in-transaction validation/projection (beneficiary designations). */
  project?: (tx: Queryable, row: AssetViewRow) => Promise<void>;
  expectExisting: boolean;
}

@Injectable()
export class AssetsService {
  constructor(
    private readonly db: Db,
    private readonly ledger: LedgerRepo,
    private readonly views: AssetsViewRepo,
    private readonly beneficiaries: BeneficiariesRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: AssetsAuthz,
    private readonly events: EventsService,
  ) {}

  // ------------------------------------------------------------------ commands

  async createAsset(actor: string, input: CreateAssetInput): Promise<CommandResult> {
    const assetId = randomUUID();
    this.authz.assertCan(actor, 'create', assetResource(assetId, actor));
    const payload: AssetEventPayload = {
      v: 1,
      type: 'AssetCreated',
      category: input.category,
      title: input.title,
      ownershipPct: input.ownershipPct ?? 100,
      inTrust: input.inTrust ?? false,
      ...(input.fundingStatus !== undefined ? { fundingStatus: input.fundingStatus } : {}),
      ...(input.estValue !== undefined ? { estValue: input.estValue } : {}),
      ...(input.valuationAsOf !== undefined ? { valuationAsOf: input.valuationAsOf } : {}),
      ...(input.valuationSource !== undefined ? { valuationSource: input.valuationSource } : {}),
      ...(input.costBasis !== undefined ? { costBasis: input.costBasis } : {}),
      ...(input.location !== undefined ? { location: input.location } : {}),
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch: undefined,
      expectExisting: false,
    });
    if (!result.replayed) {
      await this.events.assetCreated(actor, result.assetId, input.category);
      await this.emitLedgerAppended(actor, result, payload, input.category);
    }
    return result;
  }

  async updateDetails(
    actor: string,
    assetId: string,
    input: UpdateDetailsInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'AssetDetailsUpdated',
      ...(input.title !== undefined ? { title: input.title } : {}),
      ...(input.location !== undefined ? { location: input.location } : {}),
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
      ...(input.inTrust !== undefined ? { inTrust: input.inTrust } : {}),
      ...(input.fundingStatus !== undefined ? { fundingStatus: input.fundingStatus } : {}),
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
    });
    if (!result.replayed) {
      await this.events.assetUpdated(actor, assetId);
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  async recordValuation(
    actor: string,
    assetId: string,
    input: RecordValuationInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'ValuationRecorded',
      estValue: input.estValue,
      valuationAsOf: input.valuationAsOf,
      valuationSource: input.valuationSource,
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
    });
    if (!result.replayed) {
      await this.events.valuationRecorded(actor, assetId, input.valuationSource);
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  async changeOwnership(
    actor: string,
    assetId: string,
    input: ChangeOwnershipInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'OwnershipChanged',
      ownershipPct: input.ownershipPct,
      ...(input.costBasis !== undefined ? { costBasis: input.costBasis } : {}),
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
    });
    if (!result.replayed) {
      await this.events.ownershipChanged(actor, assetId);
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  async designateBeneficiary(
    actor: string,
    assetId: string,
    input: DesignateBeneficiaryInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'BeneficiaryDesignated',
      contactId: input.contactId,
      designation: input.designation,
      sharePct: input.sharePct,
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
      project: async (tx): Promise<void> => {
        // Share-sum invariant (app layer; the DB constraint trigger backs it):
        // live shares for this designation class, replacing any existing row
        // for this contact, must stay ≤ 100.
        const live = await this.beneficiaries.listLive(tx, assetId);
        const states = live
          .filter((r) => !(r.contact_id === input.contactId && r.designation === input.designation))
          .map((r) => ({
            contactId: r.contact_id,
            designation: r.designation as 'primary' | 'contingent',
            sharePct: sqlToPct(r.share_pct),
          }));
        const total = shareSum(
          [
            ...states,
            {
              contactId: input.contactId,
              designation: input.designation,
              sharePct: input.sharePct,
            },
          ],
          input.designation,
        );
        if (total > 100) {
          throw new UnprocessableEntityException({ error: 'share_sum_exceeded' });
        }
        await this.beneficiaries.upsertDesignation(tx, {
          assetId,
          contactId: input.contactId,
          designation: input.designation,
          sharePct: input.sharePct,
        });
      },
    });
    if (!result.replayed) {
      await this.events.beneficiaryDesignated(actor, assetId, {
        contactId: input.contactId,
        designation: input.designation,
      });
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  async removeBeneficiary(
    actor: string,
    assetId: string,
    contactId: string,
    input: RemoveBeneficiaryInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'BeneficiaryRemoved',
      contactId,
      designation: input.designation,
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
      project: async (tx): Promise<void> => {
        const removed = await this.beneficiaries.softRemove(tx, {
          assetId,
          contactId,
          designation: input.designation,
        });
        if (!removed) {
          throw new NotFoundException({ error: 'not_found' });
        }
      },
    });
    if (!result.replayed) {
      await this.events.beneficiaryRemoved(actor, assetId, {
        contactId,
        designation: input.designation,
      });
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  async retireAsset(
    actor: string,
    assetId: string,
    input: RetireAssetInput,
    ifMatch?: bigint,
  ): Promise<CommandResult> {
    const payload: AssetEventPayload = {
      v: 1,
      type: 'AssetRetired',
      ...(input.reason !== undefined ? { reason: input.reason } : {}),
    };
    const result = await this.runCommand({
      actor,
      assetId,
      eventId: input.eventId,
      payload,
      ifMatch,
      expectExisting: true,
    });
    if (!result.replayed) {
      await this.events.assetRetired(actor, assetId, input.reason);
      await this.emitLedgerAppended(actor, result, payload);
    }
    return result;
  }

  // ------------------------------------------------------------------- queries

  async getAsset(actor: string, assetId: string): Promise<AssetDto> {
    const row = await this.views.getLive(this.db, assetId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    this.authz.assertCan(actor, 'read', assetResource(assetId, row.user_id));
    const version = (await this.ledger.latestSeq(this.db, assetId)) ?? '0';
    return this.toDto(row, actor, 'asset_read', version);
  }

  async listAssets(actor: string, asOf?: string): Promise<AssetDto[]> {
    if (asOf) {
      const replayed = await this.replayForUser(actor, endOfDayUtc(asOf), 'asset_list_asof');
      return replayed.map((r) => plainStateToDto(r.state, r.version));
    }
    const rows = await this.views.listLiveByUser(this.db, actor);
    const versions = await this.ledger.latestSeqByAssets(
      this.db,
      rows.map((r) => r.asset_id),
    );
    const dtos: AssetDto[] = [];
    for (const row of rows) {
      if (!this.authz.can(actor, 'read', assetResource(row.asset_id, row.user_id))) {
        continue; // owner-only in M3; defensive per-item check like profile
      }
      dtos.push(await this.toDto(row, actor, 'asset_list', versions.get(row.asset_id) ?? '0'));
    }
    return dtos;
  }

  async getHistory(actor: string, assetId: string): Promise<HistoryEntryDto[]> {
    // History of a retired asset stays readable — asset history is the product.
    const row = await this.views.getAny(this.db, assetId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    this.authz.assertCan(actor, 'read', assetResource(assetId, row.user_id));
    const events = await this.ledger.listByAsset(this.db, assetId);
    const entries: HistoryEntryDto[] = [];
    for (const evt of events) {
      const payload = await this.decryptPayload(evt, actor, 'asset_history');
      entries.push({
        version: evt.seq,
        eventId: evt.event_id,
        eventType: evt.event_type,
        occurredAt: evt.occurred_at.toISOString(),
        actorId: evt.actor_id,
        payload,
      });
    }
    return entries;
  }

  async getBeneficiaries(actor: string, assetId: string): Promise<BeneficiariesDto> {
    const row = await this.views.getAny(this.db, assetId);
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    this.authz.assertCan(actor, 'read', assetResource(assetId, row.user_id));
    const live = await this.beneficiaries.listLive(this.db, assetId);
    const states = live.map((r) => ({
      contactId: r.contact_id,
      designation: r.designation as 'primary' | 'contingent',
      sharePct: sqlToPct(r.share_pct),
    }));
    const totals = (['primary', 'contingent'] as const)
      .map((designation) => ({ designation, sharePct: shareSum(states, designation) }))
      .filter((t) => t.sharePct > 0)
      .map((t) => ({ ...t, designationComplete: t.sharePct === 100 }));
    return {
      assetId,
      beneficiaries: states,
      totals,
    };
  }

  async getNetWorth(actor: string, asOf?: string): Promise<NetWorthDto> {
    const holdings: Array<{
      category: string;
      estValue: string | null;
      ownershipPct: number;
      inTrust: boolean;
    }> = [];
    if (asOf) {
      const replayed = await this.replayForUser(actor, endOfDayUtc(asOf), 'net_worth_asof');
      for (const r of replayed) {
        holdings.push({
          category: r.state.category,
          estValue: r.state.estValue,
          ownershipPct: r.state.ownershipPct,
          inTrust: r.state.inTrust,
        });
      }
    } else {
      const rows = await this.views.listLiveByUser(this.db, actor);
      for (const row of rows) {
        if (!this.authz.can(actor, 'read', assetResource(row.asset_id, row.user_id))) {
          continue;
        }
        holdings.push({
          category: row.category,
          estValue: await this.cipher.decrypt({
            ownerUserId: row.user_id,
            dekId: row.dek_id,
            field: viewField('est_value'),
            ciphertext: row.est_value_ct,
            actorId: actor,
            purpose: 'net_worth',
          }),
          ownershipPct: sqlToPct(row.ownership_pct),
          inTrust: row.in_trust,
        });
      }
    }
    let total = 0n;
    let inTrustTotal = 0n;
    let valued = 0;
    const byCategory = new Map<string, { count: number; value: bigint }>();
    for (const h of holdings) {
      const entry = byCategory.get(h.category) ?? { count: 0, value: 0n };
      entry.count += 1;
      if (h.estValue !== null) {
        const owned = ownedShareCents(moneyToCents(h.estValue), h.ownershipPct);
        entry.value += owned;
        total += owned;
        valued += 1;
        if (h.inTrust) {
          inTrustTotal += owned;
        }
      }
      byCategory.set(h.category, entry);
    }
    return {
      asOf: asOf ?? null,
      totalValue: centsToMoney(total),
      assetCount: holdings.length,
      valuedAssetCount: valued,
      byCategory: [...byCategory.entries()]
        .map(([category, v]) => ({ category, count: v.count, value: centsToMoney(v.value) }))
        .sort((a, b) => a.category.localeCompare(b.category)),
      inTrustValue: centsToMoney(inTrustTotal),
      inTrustPct: total > 0n ? Number((inTrustTotal * 1000n + total / 2n) / total) / 10 : null,
    };
  }

  // ------------------------------------------------------------ command engine

  /**
   * The single command pipeline: encrypt outside the transaction, then
   * atomically (lock → authz → concurrency check → append → reduce →
   * project). A unique violation on event_id is an idempotent retry and
   * returns the original append's acknowledgement.
   */
  private async runCommand(spec: CommandSpec): Promise<CommandResult> {
    const eventId = spec.eventId ?? randomUUID();
    // Pre-materialize the owner's DEK once so parallel field encrypts can
    // never race a first-write mint (M2 pattern), then encrypt outside the
    // transaction to keep KMS latency out of the lock window.
    const dekId = await this.cipher.getOrCreateDek(spec.actor);
    const payloadCt = await this.mustEncrypt(
      spec.actor,
      payloadField(eventId),
      serializePayload(spec.payload),
    );
    const encrypted = await this.encryptSettableFields(spec.actor, spec.payload);
    try {
      return await this.db.withTransaction(spec.actor, async (tx) => {
        const row = await this.views.lockById(tx, spec.assetId);
        if (spec.expectExisting) {
          if (!row || row.deleted_at !== null) {
            // Retired assets refuse further commands; their history remains.
            throw new NotFoundException({ error: 'not_found' });
          }
          this.authz.assertCan(spec.actor, 'update', assetResource(spec.assetId, row.user_id));
        } else if (row) {
          // Fresh random UUID collided with an existing asset — treat as a
          // conflict rather than corrupting another asset's stream.
          throw new ConflictException({ error: 'version_conflict' });
        }
        if (spec.ifMatch !== undefined) {
          const latest = await this.ledger.latestSeq(tx, spec.assetId);
          if (latest !== spec.ifMatch.toString()) {
            throw new ConflictException({ error: 'version_conflict' });
          }
        }
        if (spec.project) {
          await this.projectWithRow(tx, spec, row);
        }
        const { seq, occurredAt } = await this.ledger.append(tx, {
          eventId,
          assetId: spec.assetId,
          userId: spec.expectExisting ? row!.user_id : spec.actor,
          eventType: spec.payload.type,
          payloadCt,
          actorId: spec.actor,
          actorRole: 'owner',
        });
        const state = applyAssetEvent<Buffer | null>(
          row ? rowToState(row, dekId) : null,
          {
            assetId: spec.assetId,
            userId: spec.expectExisting ? row!.user_id : spec.actor,
            occurredAt,
            payload: spec.payload,
          },
          (field) => encrypted.get(field) ?? null,
        );
        await this.views.upsertFromState(tx, state, dekId, occurredAt);
        return {
          assetId: spec.assetId,
          eventId,
          version: seq,
          occurredAt: occurredAt.toISOString(),
          replayed: false,
        };
      });
    } catch (err) {
      if (isUniqueViolation(err) && isEventIdConflict(err)) {
        return this.replayAck(spec.actor, spec.assetId, eventId, spec.expectExisting);
      }
      throw err;
    }
  }

  private async projectWithRow(
    tx: Queryable,
    spec: CommandSpec,
    row: AssetViewRow | null,
  ): Promise<void> {
    if (!row) {
      throw new NotFoundException({ error: 'not_found' });
    }
    await spec.project!(tx, row);
  }

  /** Resolve an idempotent retry to the original command's acknowledgement. */
  private async replayAck(
    actor: string,
    assetId: string,
    eventId: string,
    expectExisting: boolean,
  ): Promise<CommandResult> {
    const original = await this.ledger.findByEventId(this.db, eventId);
    if (!original || original.user_id !== actor) {
      // The eventId belongs to someone else (or vanished): do not leak
      // whether it exists — a generic conflict is all a client learns.
      throw new ConflictException({ error: 'version_conflict' });
    }
    if (expectExisting && original.asset_id !== assetId) {
      throw new ConflictException({ error: 'version_conflict' });
    }
    return {
      assetId: original.asset_id,
      eventId,
      version: original.seq,
      occurredAt: original.occurred_at.toISOString(),
      replayed: true,
    };
  }

  // ------------------------------------------------------------------- helpers

  private async emitLedgerAppended(
    actor: string,
    result: CommandResult,
    payload: AssetEventPayload,
    category?: AssetCategory,
  ): Promise<void> {
    await this.events.ledgerAppended({
      actorId: actor,
      assetId: result.assetId,
      ledgerEventId: result.eventId,
      eventType: payload.type,
      ...(category !== undefined ? { category } : {}),
    });
  }

  /** Encrypt the encrypted-capable view fields this payload sets. */
  private async encryptSettableFields(
    owner: string,
    payload: AssetEventPayload,
  ): Promise<Map<EncryptedField, Buffer>> {
    const values = new Map<EncryptedField, string>();
    if (payload.type === 'AssetCreated') {
      if (payload.estValue !== undefined) values.set('est_value', payload.estValue);
      if (payload.costBasis !== undefined) values.set('cost_basis', payload.costBasis);
      if (payload.location !== undefined) values.set('location', payload.location);
      if (payload.notes !== undefined) values.set('notes', payload.notes);
    } else if (payload.type === 'AssetDetailsUpdated') {
      if (typeof payload.location === 'string') values.set('location', payload.location);
      if (typeof payload.notes === 'string') values.set('notes', payload.notes);
    } else if (payload.type === 'ValuationRecorded') {
      values.set('est_value', payload.estValue);
    } else if (payload.type === 'OwnershipChanged') {
      if (typeof payload.costBasis === 'string') values.set('cost_basis', payload.costBasis);
    }
    const out = new Map<EncryptedField, Buffer>();
    for (const [field, value] of values) {
      out.set(field, await this.mustEncrypt(owner, viewField(field), value));
    }
    return out;
  }

  private async mustEncrypt(owner: string, field: string, value: string): Promise<Buffer> {
    const { ciphertext } = await this.cipher.encrypt(owner, field, value);
    if (!ciphertext) {
      // encrypt() only returns null ciphertext for null input; value is a string.
      throw new Error('encryption returned no ciphertext');
    }
    return ciphertext;
  }

  private async decryptPayload(
    evt: LedgerRow,
    actorId: string,
    purpose: string,
  ): Promise<AssetEventPayload> {
    const json = await this.cipher.decrypt({
      ownerUserId: evt.user_id,
      dekId: await this.dekIdForEvent(evt),
      field: payloadField(evt.event_id),
      ciphertext: evt.payload_ct,
      actorId,
      purpose,
    });
    return deserializePayload(json!);
  }

  /**
   * Ledger rows do not carry a dek_id column (docs/02 §3 DDL); payloads are
   * encrypted under the owner's active DEK at append time. With at most one
   * active DEK per user (DB-enforced here) that is the owner's current DEK;
   * after a crypto-shred the payloads are unrecoverable by design.
   */
  private async dekIdForEvent(evt: LedgerRow): Promise<string> {
    return this.cipher.getOrCreateDek(evt.user_id);
  }

  /** Replay an owner's ledger to plaintext states (as-of queries). */
  private async replayForUser(
    actor: string,
    upTo: Date,
    purpose: string,
  ): Promise<Array<{ state: AssetState<string>; version: string }>> {
    const rows = await this.ledger.listByUser(this.db, actor, upTo);
    const results: Array<{ state: AssetState<string>; version: string }> = [];
    let current: AssetState<string> | null = null;
    let lastSeq = '0';
    const flush = (): void => {
      if (current && current.retiredAt === null) {
        results.push({ state: current, version: lastSeq });
      }
      current = null;
      lastSeq = '0';
    };
    let currentAssetId: string | null = null;
    for (const row of rows) {
      if (row.asset_id !== currentAssetId) {
        flush();
        currentAssetId = row.asset_id;
      }
      const payload = await this.decryptPayload(row, actor, purpose);
      current = applyAssetEvent<string>(
        current,
        { assetId: row.asset_id, userId: row.user_id, occurredAt: row.occurred_at, payload },
        (_field, plaintext) => plaintext,
      );
      lastSeq = row.seq;
    }
    flush();
    return results;
  }

  private async toDto(
    row: AssetViewRow,
    actor: string,
    purpose: string,
    version: string,
  ): Promise<AssetDto> {
    const decrypt = (field: EncryptedField, ciphertext: Buffer | null): Promise<string | null> =>
      this.cipher.decrypt({
        ownerUserId: row.user_id,
        dekId: row.dek_id,
        field: viewField(field),
        ciphertext,
        actorId: actor,
        purpose,
      });
    return {
      assetId: row.asset_id,
      category: row.category,
      title: row.title,
      estValue: await decrypt('est_value', row.est_value_ct),
      valuationAsOf: row.valuation_as_of,
      valuationSource: row.valuation_source,
      ownershipPct: sqlToPct(row.ownership_pct),
      costBasis: await decrypt('cost_basis', row.cost_basis_ct),
      location: await decrypt('location', row.location_ct),
      notes: await decrypt('notes', row.notes_ct),
      inTrust: row.in_trust,
      fundingStatus: row.funding_status,
      version,
    };
  }
}

/** Convert a projection row back into reducer state (ciphertext-valued). */
function rowToState(row: AssetViewRow, activeDekId: string): AssetState<Buffer | null> {
  // If the row's DEK is no longer the owner's active DEK, the old DEK was
  // crypto-shredded: its ciphertext is unrecoverable BY DESIGN. The untouched
  // encrypted fields are therefore erased, not carried forward.
  const erased = row.dek_id !== activeDekId;
  return {
    assetId: row.asset_id,
    userId: row.user_id,
    category: row.category as AssetState<Buffer | null>['category'],
    title: row.title,
    estValue: erased ? null : row.est_value_ct,
    valuationAsOf: row.valuation_as_of,
    valuationSource: row.valuation_source as AssetState<Buffer | null>['valuationSource'],
    ownershipPct: sqlToPct(row.ownership_pct),
    costBasis: erased ? null : row.cost_basis_ct,
    location: erased ? null : row.location_ct,
    notes: erased ? null : row.notes_ct,
    inTrust: row.in_trust,
    fundingStatus: row.funding_status as AssetState<Buffer | null>['fundingStatus'],
    retiredAt: row.deleted_at,
  };
}

function plainStateToDto(state: AssetState<string>, version: string): AssetDto {
  return {
    assetId: state.assetId,
    category: state.category,
    title: state.title,
    estValue: state.estValue,
    valuationAsOf: state.valuationAsOf,
    valuationSource: state.valuationSource,
    ownershipPct: state.ownershipPct,
    costBasis: state.costBasis,
    location: state.location,
    notes: state.notes,
    inTrust: state.inTrust,
    fundingStatus: state.fundingStatus,
    version,
  };
}

function endOfDayUtc(isoDate: string): Date {
  return new Date(`${isoDate}T23:59:59.999Z`);
}

/** Whether a 23505 came from the event-id idempotency index specifically. */
function isEventIdConflict(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === 'ux_asset_events_event_id'
  );
}
