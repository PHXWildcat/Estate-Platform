import { randomBytes, randomUUID } from 'node:crypto';
import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { loadBundledPolicies, PolicyDecisionPoint } from '@estate/authz';
import type { AccountsRepo } from '../src/accounts.repo';
import { PlaidAuthz } from '../src/authz.service';
import type { Db } from '../src/db';
import type { ItemsRepo } from '../src/items.repo';
import type { PlaidConfig } from '../src/config';
import { deterministicAccountId, PlaidService } from '../src/plaid.service';
import { PlaidGatewayError } from '../src/plaid-gateway';
import { StubPlaidGateway } from '../src/stub-plaid-gateway';
import { SyncActivityMonitor } from '../src/sync-monitor';
import { buildCipher, fakeDb, FakeAccounts, FakeItems, noopEvents } from './support';

const OWNER = randomUUID();
const STRANGER = randomUUID();

function buildService(overrides: { db?: Db } = {}): {
  service: PlaidService;
  items: FakeItems;
  accounts: FakeAccounts;
  gateway: StubPlaidGateway;
} {
  const items = new FakeItems();
  const accounts = new FakeAccounts();
  const gateway = new StubPlaidGateway();
  const authz = new PlaidAuthz(new PolicyDecisionPoint(loadBundledPolicies()));
  const config = { itemIndexKey: randomBytes(32) } as PlaidConfig;
  const service = new PlaidService(
    config,
    gateway,
    () => new Date(),
    overrides.db ?? fakeDb(),
    items as unknown as ItemsRepo,
    accounts as unknown as AccountsRepo,
    buildCipher(),
    authz,
    noopEvents,
    new SyncActivityMonitor(noopEvents, () => new Date()),
  );
  return { service, items, accounts, gateway };
}

describe('PlaidService', () => {
  it('links an item: token encrypted at rest, view carries no token', async () => {
    const { service, items } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    expect(view.institutionId).toBe('ins_stub_109508');
    expect(view.status).toBe('healthy');
    expect(JSON.stringify(view)).not.toContain('access-stub');

    const row = items.rows[0]!;
    expect(row.access_token_ct.toString('utf8')).not.toContain('access-stub');
    expect(row.item_bidx.length).toBe(32); // HMAC-SHA-256 blind index
  });

  it('rejects an invalid public token with a generic 400', async () => {
    const { service } = buildService();
    await expect(service.linkItem(OWNER, 'public-evil')).rejects.toThrow(BadRequestException);
  });

  it('sync decrypts the token internally, upserts accounts, advances the cursor', async () => {
    const { service, items, accounts } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    const result = await service.sync(OWNER, view.id);
    expect(result.accountsUpserted).toBe(2);
    expect(items.rows[0]!.sync_cursor).toBe('cursor-1');
    expect(accounts.rows.size).toBe(2);
    // Balances are ciphertext at rest.
    for (const row of accounts.rows.values()) {
      expect(row.current_balance_ct!.toString('utf8')).not.toContain('1240.55');
    }
    // Owner reads them back decrypted.
    const listed = await service.listAccounts(OWNER);
    expect(listed.map((a) => a.currentBalance).sort()).toEqual(['1240.55', '98230.10']);
  });

  it('re-sync upserts in place (deterministic account ids)', async () => {
    const { service } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    await service.sync(OWNER, view.id);
    await service.sync(OWNER, view.id);
    expect((await service.listAccounts(OWNER)).length).toBe(2);
  });

  it('denies sync and revoke to a non-owner (Cedar deny-by-default)', async () => {
    const { service } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    await expect(service.sync(STRANGER, view.id)).rejects.toThrow(ForbiddenException);
    await expect(service.revoke(STRANGER, view.id)).rejects.toThrow(ForbiddenException);
  });

  it('revoke removes the item at Plaid, soft-deletes locally, and hides accounts', async () => {
    const { service, items, gateway } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    await service.sync(OWNER, view.id);
    await service.revoke(OWNER, view.id);

    expect(items.rows[0]!.status).toBe('revoked');
    expect(items.rows[0]!.deleted_at).not.toBeNull();
    expect(await service.listItems(OWNER)).toEqual([]);
    expect(await service.listAccounts(OWNER)).toEqual([]);
    await expect(service.sync(OWNER, view.id)).rejects.toThrow(NotFoundException);
    // The token is dead at the provider too: the stub refuses a re-sync of it.
    await expect(
      gateway.syncAccounts(items.rows[0]!.access_token_ct.toString('utf8'), null),
    ).rejects.toThrow(PlaidGatewayError);
  });

  it('revoke succeeds even when the provider-side remove fails (local revocation is not blockable)', async () => {
    const { service, items, gateway } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    jest.spyOn(gateway, 'removeItem').mockRejectedValue(new Error('plaid down'));
    await service.revoke(OWNER, view.id);
    expect(items.rows[0]!.status).toBe('revoked');
  });

  it('webhook routes by blind index; unknown items are ignored', async () => {
    const { service, items, gateway } = buildService();
    await service.linkItem(OWNER, 'public-stub-alpha');
    const exchanged = await gateway.exchangePublicToken('public-stub-alpha'); // same itemId
    await service.handleWebhook({
      webhookCode: 'ITEM_LOGIN_REQUIRED',
      plaidItemId: exchanged.itemId,
    });
    expect(items.rows[0]!.status).toBe('login_required');

    // Unknown item id: silently ignored, nothing changes.
    await service.handleWebhook({ webhookCode: 'ITEM_LOGIN_REQUIRED', plaidItemId: 'item-ghost' });
    expect(items.rows.filter((r) => r.status === 'login_required')).toHaveLength(1);
  });

  it('webhook SYNC_UPDATES_AVAILABLE triggers a sync as the system', async () => {
    const { service, accounts, gateway } = buildService();
    await service.linkItem(OWNER, 'public-stub-alpha');
    const exchanged = await gateway.exchangePublicToken('public-stub-alpha');
    await service.handleWebhook({
      webhookCode: 'SYNC_UPDATES_AVAILABLE',
      plaidItemId: exchanged.itemId,
    });
    expect(accounts.rows.size).toBe(2);
  });

  it('marks the item status error when the provider rejects the access token', async () => {
    const { service, items, gateway } = buildService();
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    // Simulate Plaid-side revocation out from under us.
    jest
      .spyOn(gateway, 'syncAccounts')
      .mockRejectedValue(new PlaidGatewayError('invalid_access_token'));
    await expect(service.sync(OWNER, view.id)).rejects.toThrow();
    expect(items.rows[0]!.status).toBe('error');
  });
});

describe('deterministicAccountId', () => {
  it('is stable per (item, external id) and shaped like a UUID', () => {
    const a = deterministicAccountId('item-row-1', 'acct-1');
    expect(a).toBe(deterministicAccountId('item-row-1', 'acct-1'));
    expect(a).not.toBe(deterministicAccountId('item-row-1', 'acct-2'));
    expect(a).not.toBe(deterministicAccountId('item-row-2', 'acct-1'));
    expect(a).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe('SyncActivityMonitor (TB5 anomaly hook)', () => {
  it('emits plaid.sync.anomalous once the window threshold is crossed', async () => {
    const alerts: Array<{ itemId: string; syncsInWindow: number }> = [];
    const events = {
      syncAnomalous: (itemId: string, detail: { syncsInWindow: number }): Promise<void> => {
        alerts.push({ itemId, ...detail });
        return Promise.resolve();
      },
    } as never;
    let now = Date.parse('2026-07-22T00:00:00Z');
    const monitor = new SyncActivityMonitor(events, () => new Date(now));
    for (let i = 0; i < 31; i += 1) {
      await monitor.recordSync('item-1');
    }
    expect(alerts).toEqual([{ itemId: 'item-1', syncsInWindow: 31 }]);

    // Outside the window the counter resets — no more alerts.
    now += 2 * 60 * 60 * 1000;
    await monitor.recordSync('item-1');
    expect(alerts).toHaveLength(1);
  });
});
