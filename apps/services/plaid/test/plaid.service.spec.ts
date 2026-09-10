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
import {
  buildCipher,
  fakeDb,
  FakeAccounts,
  FakeItems,
  noopEvents,
  recordingEvents,
} from './support';

const OWNER = randomUUID();
const STRANGER = randomUUID();

function buildService(overrides: { db?: Db; events?: never } = {}): {
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
    overrides.events ?? noopEvents,
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

/**
 * THE GUARD LAYER (M49 PR6). Each status write now answers the prior it found,
 * or null when no live row matched, and the service is supposed to pass the
 * former to the emitter and file nothing on the latter. These drives prove the
 * WIRING with the repo double forced to each answer; the integration spec
 * proves the statement that answers it. A test at one layer must say which.
 */
describe('the item ladder records the prior each write found (M49 PR6)', () => {
  /** A double that answers null and COUNTS, so a drive can prove it was reached. */
  const loseTheWrite = (
    items: FakeItems,
    method: 'setStatus' | 'markRevoked',
  ): { reached: () => number } => {
    let n = 0;
    items[method] = (): Promise<null> => {
      n += 1;
      return Promise.resolve(null);
    };
    return { reached: () => n };
  };

  it('the webhook flip carries the prior the WRITE found, and files NOTHING when the write matched no live row', async () => {
    const { calls, events } = recordingEvents();
    const { service, items, gateway } = buildService({ events });
    await service.linkItem(OWNER, 'public-stub-alpha');
    const exchanged = await gateway.exchangePublicToken('public-stub-alpha');
    await service.handleWebhook({
      webhookCode: 'ITEM_LOGIN_REQUIRED',
      plaidItemId: exchanged.itemId,
    });
    expect(calls.filter((c) => c.method === 'itemLoginRequired').map((c) => c.args)).toEqual([
      [OWNER, items.rows[0]!.id, 'healthy'],
    ]);

    // The row was revoked between the blind-index lookup and the write.
    const lost = loseTheWrite(items, 'setStatus');
    await service.handleWebhook({
      webhookCode: 'ITEM_LOGIN_REQUIRED',
      plaidItemId: exchanged.itemId,
    });
    expect(lost.reached()).toBe(1);
    expect(calls.filter((c) => c.method === 'itemLoginRequired')).toHaveLength(1);
  });

  it('the error arm files `errored` with the prior and the sync’s actor — the owner on the route, the platform on the webhook', async () => {
    const { calls, events } = recordingEvents();
    const { service, items, gateway } = buildService({ events });
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    const exchanged = await gateway.exchangePublicToken('public-stub-alpha');
    const spy = jest
      .spyOn(gateway, 'syncAccounts')
      .mockRejectedValue(new PlaidGatewayError('invalid_access_token'));

    await expect(service.sync(OWNER, view.id)).rejects.toThrow(PlaidGatewayError);
    expect(items.rows[0]!.status).toBe('error');
    await expect(
      service.handleWebhook({
        webhookCode: 'SYNC_UPDATES_AVAILABLE',
        plaidItemId: exchanged.itemId,
      }),
    ).rejects.toThrow(PlaidGatewayError);

    // Second argument: the OWNER, for `onBehalfOf` on the platform arm.
    expect(calls.filter((c) => c.method === 'itemErrored').map((c) => c.args)).toEqual([
      [OWNER, OWNER, view.id, 'healthy'],
      [null, OWNER, view.id, 'error'],
    ]);
    spy.mockRestore();
  });

  it('EMITS NOTHING for `errored` when the write lost its compare-and-set — and still rethrows', async () => {
    const { calls, events } = recordingEvents();
    const { service, items, gateway } = buildService({ events });
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    jest
      .spyOn(gateway, 'syncAccounts')
      .mockRejectedValue(new PlaidGatewayError('invalid_access_token'));
    const lost = loseTheWrite(items, 'setStatus');
    await expect(service.sync(OWNER, view.id)).rejects.toThrow(PlaidGatewayError);
    expect(lost.reached()).toBe(1);
    expect(calls.map((c) => c.method)).not.toContain('itemErrored');
  });

  it('`synced` carries the prior; a sync that finds its item revoked under the lock upserts NOTHING and files NOTHING', async () => {
    const { calls, events } = recordingEvents();
    const { service, items, accounts } = buildService({ events });
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    await service.sync(OWNER, view.id);
    expect(calls.filter((c) => c.method === 'itemSynced').map((c) => c.args)).toEqual([
      [OWNER, view.id, 2, 'healthy'],
    ]);

    // A rival revoke committed after `requireItem` read the row. The `healthy`
    // write is the transaction's FIRST statement, so it answers null before any
    // account row is touched, and the sync stops there. The accounts double is
    // WATCHED, so "nothing was upserted" is an observation rather than an
    // inference from a row count that would not have changed either way.
    const upserts = jest.spyOn(accounts, 'upsert');
    const lost = loseTheWrite(items, 'setStatus');
    await expect(service.sync(OWNER, view.id)).resolves.toEqual({ accountsUpserted: 0 });
    expect(lost.reached()).toBe(1);
    expect(upserts).not.toHaveBeenCalled();
    expect(calls.filter((c) => c.method === 'itemSynced')).toHaveLength(1);
  });

  it("`synced` carries the WRITE's answer, not the row the caller read — proven where the two DISAGREE", async () => {
    // The one fixture where a stale pre-read and the write's answer differ, and
    // therefore the only unit drive that can tell them apart. The gateway call
    // sits between `requireItem` and the transaction, so flipping the row from
    // inside the stub reproduces exactly the window the compare-and-set exists
    // for: the caller holds `healthy`, the write finds `login_required`.
    const { calls, events } = recordingEvents();
    const { service, items, gateway } = buildService({ events });
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    const row = items.rows[0]!;
    const realSync = gateway.syncAccounts.bind(gateway);
    jest.spyOn(gateway, 'syncAccounts').mockImplementation(async (token, cursor) => {
      row.status = 'login_required';
      return realSync(token, cursor);
    });

    await service.sync(OWNER, view.id);
    expect(calls.filter((c) => c.method === 'itemSynced').map((c) => c.args)).toEqual([
      [OWNER, view.id, 2, 'login_required'],
    ]);
  });

  it('revoke files the prior, and NOTHING when a rival revoke got there first', async () => {
    const { calls, events } = recordingEvents();
    const { service, items } = buildService({ events });
    const view = await service.linkItem(OWNER, 'public-stub-alpha');
    await service.revoke(OWNER, view.id);
    expect(calls.filter((c) => c.method === 'itemRevoked').map((c) => c.args)).toEqual([
      [OWNER, view.id, 'healthy'],
    ]);

    const second = await service.linkItem(OWNER, 'public-stub-beta');
    const lost = loseTheWrite(items, 'markRevoked');
    await service.revoke(OWNER, second.id);
    expect(lost.reached()).toBe(1);
    expect(calls.filter((c) => c.method === 'itemRevoked')).toHaveLength(1);
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
    const alerts: Array<{ itemId: string; owner: string; syncsInWindow: number }> = [];
    const events = {
      syncAnomalous: (
        itemId: string,
        owner: string,
        detail: { syncsInWindow: number },
      ): Promise<void> => {
        alerts.push({ itemId, owner, ...detail });
        return Promise.resolve();
      },
    } as never;
    let now = Date.parse('2026-07-22T00:00:00Z');
    const monitor = new SyncActivityMonitor(events, () => new Date(now));
    for (let i = 0; i < 31; i += 1) {
      await monitor.recordSync('item-1', OWNER);
    }
    // The OWNER travels with the alert: it is the platform acting on one
    // person's item, and the audit row says whose (M49 PR6).
    expect(alerts).toEqual([{ itemId: 'item-1', owner: OWNER, syncsInWindow: 31 }]);

    // Outside the window the counter resets — no more alerts.
    now += 2 * 60 * 60 * 1000;
    await monitor.recordSync('item-1', OWNER);
    expect(alerts).toHaveLength(1);
  });
});
