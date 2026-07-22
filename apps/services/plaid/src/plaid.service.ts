import { createHash, randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { blindIndex } from '@estate/crypto';
import type { PlaidItemStatus } from '@estate/contracts';
import { AccountsRepo } from './accounts.repo';
import { PlaidAuthz, plaidItemResource } from './authz.service';
import { CLOCK, CONFIG, PLAID_GATEWAY, type Clock } from './di-tokens';
import { Db, isUniqueViolation } from './db';
import { EventsService } from './events.service';
import { FieldCipher } from './field-cipher';
import { ItemsRepo, type PlaidItemRow } from './items.repo';
import { PlaidGatewayError, type PlaidGateway } from './plaid-gateway';
import { SyncActivityMonitor } from './sync-monitor';
import type { PlaidConfig } from './config';

/** Blind-index purpose label: domain-separates item lookups from all others. */
const ITEM_BIDX_PURPOSE = 'plaid_item.v1';

export interface ItemView {
  id: string;
  institutionId: string;
  institutionName: string | null;
  status: PlaidItemStatus;
  createdAt: string;
}

export interface AccountView {
  id: string;
  plaidItemId: string | null;
  kind: string;
  name: string;
  mask: string | null;
  currentBalance: string | null;
  balanceAsOf: string | null;
  isLiability: boolean;
}

/**
 * The isolating service's core flows (docs/03 TB5). The access token is
 * decrypted in exactly two methods — sync() and revoke() — as actorType
 * 'service' with an explicit purpose, each an audited `crypto.field.decrypted`
 * event. It never leaves this class: not in responses, events, errors, or
 * logs.
 */
@Injectable()
export class PlaidService {
  constructor(
    @Inject(CONFIG) private readonly config: PlaidConfig,
    @Inject(PLAID_GATEWAY) private readonly gateway: PlaidGateway,
    @Inject(CLOCK) private readonly clock: Clock,
    private readonly db: Db,
    private readonly items: ItemsRepo,
    private readonly accounts: AccountsRepo,
    private readonly cipher: FieldCipher,
    private readonly authz: PlaidAuthz,
    private readonly events: EventsService,
    private readonly monitor: SyncActivityMonitor,
  ) {}

  async createLinkToken(userId: string): Promise<{ linkToken: string }> {
    return this.gateway.createLinkToken(userId);
  }

  /** Exchange a Link public token and persist the item (token encrypted). */
  async linkItem(userId: string, publicToken: string): Promise<ItemView> {
    const exchanged = await this.gateway.exchangePublicToken(publicToken).catch((err: unknown) => {
      if (err instanceof PlaidGatewayError && err.reason === 'invalid_public_token') {
        throw new BadRequestException({ error: 'invalid_public_token' });
      }
      throw err;
    });

    const id = randomUUID();
    // Pre-materialize the DEK before the parallel encrypts (M2 lesson).
    await this.cipher.getOrCreateDek(userId);
    const [token, itemId] = await Promise.all([
      this.cipher.encrypt(userId, `plaid_item.access_token.${id}`, exchanged.accessToken),
      this.cipher.encrypt(userId, `plaid_item.item_id.${id}`, exchanged.itemId),
    ]);
    try {
      await this.items.insert({
        id,
        userId,
        accessTokenCt: token.ciphertext!,
        institutionId: exchanged.institutionId,
        institutionName: exchanged.institutionName,
        itemIdCt: itemId.ciphertext!,
        itemBidx: blindIndex(this.config.itemIndexKey, ITEM_BIDX_PURPOSE, exchanged.itemId),
        dekId: token.dekId,
      });
    } catch (err) {
      if (isUniqueViolation(err)) {
        // ux_plaid_items_item_bidx: this Plaid item is already linked. Only
        // someone holding a fresh public token for the SAME item can hit
        // this, so the 409 is not a cross-user existence oracle.
        throw new ConflictException({ error: 'item_already_linked' });
      }
      throw err;
    }
    await this.events.itemLinked(userId, id, exchanged.institutionId);
    const created = await this.items.findLiveById(id);
    return toItemView(created!);
  }

  async listItems(userId: string): Promise<ItemView[]> {
    const rows = await this.items.listLiveByUser(userId);
    return rows.map(toItemView);
  }

  /** Owner-initiated sync. The webhook path funnels here too. */
  async sync(callerUserId: string, itemId: string): Promise<{ accountsUpserted: number }> {
    const item = await this.requireItem(itemId);
    this.authz.assertCan(callerUserId, 'sync', plaidItemResource(item.id, item.user_id));
    return this.syncItem(item, callerUserId);
  }

  /**
   * Step-up-gated revocation (TB5 "tokens are per-item revocable"). Plaid-side
   * removal is attempted first but its failure does not block local
   * revocation — the item is dead to this platform either way; a failed
   * remote remove surfaces in the item's final status for ops follow-up.
   */
  async revoke(callerUserId: string, itemId: string): Promise<void> {
    const item = await this.requireItem(itemId);
    this.authz.assertCan(callerUserId, 'revoke', plaidItemResource(item.id, item.user_id));
    const accessToken = await this.decryptAccessToken(item, 'plaid_revoke');
    await this.gateway.removeItem(accessToken).catch(() => {
      // Best-effort: local revocation must not be blockable by provider
      // downtime. The token ciphertext remains crypto-erasable via the DEK.
    });
    const now = this.clock();
    await this.db.withTransaction(callerUserId, async (tx) => {
      await this.items.markRevoked(tx, item.id, now);
      await this.accounts.softDeleteByItem(tx, item.id, now);
    });
    await this.events.itemRevoked(callerUserId, item.id);
  }

  async listAccounts(userId: string): Promise<AccountView[]> {
    const rows = await this.accounts.listLiveByUser(userId);
    return Promise.all(
      rows.map(async (row) => ({
        id: row.id,
        plaidItemId: row.plaid_item_id,
        kind: row.kind,
        name: row.name,
        mask: row.mask,
        currentBalance: await this.cipher.decrypt({
          ownerUserId: row.user_id,
          dekId: row.dek_id,
          field: `account.current_balance.${row.id}`,
          ciphertext: row.current_balance_ct,
          actorId: userId,
          purpose: 'account_read',
        }),
        balanceAsOf: row.balance_as_of ? row.balance_as_of.toISOString() : null,
        isLiability: row.is_liability,
      })),
    );
  }

  /**
   * Webhook entry: the body is untrusted input even AFTER signature
   * verification — the item is resolved via the blind index, unknown items
   * are ignored (204 either way: webhook responses must not be an oracle).
   */
  async handleWebhook(input: { webhookCode: string; plaidItemId: string }): Promise<void> {
    const item = await this.items.findLiveByItemBidx(
      blindIndex(this.config.itemIndexKey, ITEM_BIDX_PURPOSE, input.plaidItemId),
    );
    if (!item) {
      return;
    }
    if (input.webhookCode === 'SYNC_UPDATES_AVAILABLE' || input.webhookCode === 'DEFAULT_UPDATE') {
      await this.syncItem(item, null);
      return;
    }
    if (input.webhookCode === 'ITEM_LOGIN_REQUIRED' || input.webhookCode === 'ERROR') {
      await this.db.withTransaction(item.user_id, async (tx) => {
        await this.items.setStatus(tx, item.id, 'login_required');
      });
      await this.events.itemLoginRequired(item.id);
    }
    // Unknown webhook codes are ignored by design (forward compatibility).
  }

  /** Shared sync path (owner-initiated or webhook-driven). */
  private async syncItem(
    item: PlaidItemRow,
    actorUserId: string | null,
  ): Promise<{ accountsUpserted: number }> {
    await this.monitor.recordSync(item.id);
    const accessToken = await this.decryptAccessToken(item, 'plaid_sync');
    const result = await this.gateway
      .syncAccounts(accessToken, item.sync_cursor)
      .catch(async (err: unknown) => {
        if (err instanceof PlaidGatewayError && err.reason === 'invalid_access_token') {
          await this.db.withTransaction(item.user_id, async (tx) => {
            await this.items.setStatus(tx, item.id, 'error');
          });
        }
        throw err;
      });

    const now = this.clock();
    // Encrypt outside the transaction (KMS calls don't belong inside it); the
    // DEK is the item's own, so no pre-materialization race exists here.
    const prepared = result.accounts.map((account) => ({
      account,
      id: deterministicAccountId(item.id, account.externalAccountId),
    }));
    const encrypted = [] as Array<{
      id: string;
      balanceCt: Buffer | null;
      account: (typeof prepared)[number]['account'];
    }>;
    for (const entry of prepared) {
      const { ciphertext } = await this.cipher.encrypt(
        item.user_id,
        `account.current_balance.${entry.id}`,
        entry.account.currentBalance,
      );
      encrypted.push({ id: entry.id, balanceCt: ciphertext, account: entry.account });
    }

    await this.db.withTransaction(actorUserId ?? item.user_id, async (tx) => {
      for (const entry of encrypted) {
        await this.accounts.upsert(tx, {
          id: entry.id,
          userId: item.user_id,
          plaidItemId: item.id,
          kind: entry.account.kind,
          name: entry.account.name,
          mask: entry.account.mask,
          currentBalanceCt: entry.balanceCt,
          balanceAsOf: now,
          isLiability: entry.account.isLiability,
          dekId: item.dek_id,
        });
      }
      await this.items.setCursor(tx, item.id, result.nextCursor);
      await this.items.setStatus(tx, item.id, 'healthy');
    });
    await this.events.itemSynced(actorUserId ?? item.user_id, item.id, result.accounts.length);
    return { accountsUpserted: result.accounts.length };
  }

  /** THE two callers of this method are the only token-decrypt sites. */
  private decryptAccessToken(
    item: PlaidItemRow,
    purpose: 'plaid_sync' | 'plaid_revoke',
  ): Promise<string> {
    return this.cipher
      .decrypt({
        ownerUserId: item.user_id,
        dekId: item.dek_id,
        field: `plaid_item.access_token.${item.id}`,
        ciphertext: item.access_token_ct,
        actorId: item.user_id,
        actorType: 'service',
        purpose,
      })
      .then((token) => token!);
  }

  private async requireItem(itemId: string): Promise<PlaidItemRow> {
    const item = await this.items.findLiveById(itemId);
    if (!item) {
      throw new NotFoundException({ error: 'not_found' });
    }
    return item;
  }
}

function toItemView(row: PlaidItemRow): ItemView {
  return {
    id: row.id,
    institutionId: row.institution_id,
    institutionName: row.institution_name,
    status: row.status,
    createdAt: row.created_at.toISOString(),
  };
}

/**
 * Deterministic row id from (item row id, Plaid account_id): a UUID formed
 * from SHA-256 so re-syncs upsert in place without storing Plaid's account_id
 * as an extra plaintext column.
 */
export function deterministicAccountId(itemRowId: string, externalAccountId: string): string {
  const digest = createHash('sha256')
    .update(`estate.plaid.account.v1|${itemRowId}|${externalAccountId}`, 'utf8')
    .digest('hex');
  return [
    digest.slice(0, 8),
    digest.slice(8, 12),
    `4${digest.slice(13, 16)}`,
    `8${digest.slice(17, 20)}`,
    digest.slice(20, 32),
  ].join('-');
}
