import { LivePlaidGateway, type FetchLike } from '../src/live-plaid-gateway';
import { PlaidGatewayError } from '../src/plaid-gateway';
import { StubPlaidGateway } from '../src/stub-plaid-gateway';

describe('StubPlaidGateway (deterministic sandbox)', () => {
  it('exchanges only stub public tokens and issues revocable access tokens', async () => {
    const stub = new StubPlaidGateway();
    await expect(stub.exchangePublicToken('public-real-thing')).rejects.toThrow(
      new PlaidGatewayError('invalid_public_token'),
    );
    const exchanged = await stub.exchangePublicToken('public-stub-alpha');
    expect(exchanged.itemId).toMatch(/^item-stub-/);

    const synced = await stub.syncAccounts(exchanged.accessToken, null);
    expect(synced.accounts.map((a) => a.kind)).toEqual(['checking', 'savings']);
    expect(synced.nextCursor).toBe('cursor-1');

    await stub.removeItem(exchanged.accessToken);
    await expect(stub.syncAccounts(exchanged.accessToken, null)).rejects.toThrow(
      new PlaidGatewayError('invalid_access_token'),
    );
  });

  it('re-exchanging the same public token yields the same item id (idempotent link)', async () => {
    const stub = new StubPlaidGateway();
    const a = await stub.exchangePublicToken('public-stub-same');
    const b = await stub.exchangePublicToken('public-stub-same');
    expect(a.itemId).toBe(b.itemId);
    expect(a.accessToken).not.toBe(b.accessToken); // tokens rotate per exchange
  });
});

describe('LivePlaidGateway (mocked transport)', () => {
  const OPTIONS = { env: 'sandbox' as const, clientId: 'cid', secret: 's3cr3t' };

  function fetchReturning(
    bodies: Record<string, unknown>,
    status = 200,
  ): {
    calls: Array<{ url: string; body: Record<string, unknown> }>;
    fetchImpl: FetchLike;
  } {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchImpl: FetchLike = (url, init) => {
      calls.push({ url, body: JSON.parse(init.body) as Record<string, unknown> });
      const path = new URL(url).pathname;
      return Promise.resolve({
        ok: status < 400,
        status,
        json: () => Promise.resolve(bodies[path] ?? {}),
      });
    };
    return { calls, fetchImpl };
  }

  it('exchanges a public token and normalizes the item', async () => {
    const { calls, fetchImpl } = fetchReturning({
      '/item/public_token/exchange': { access_token: 'access-1', item_id: 'item-1' },
      '/item/get': { item: { institution_id: 'ins_9' } },
    });
    const gateway = new LivePlaidGateway(OPTIONS, fetchImpl);
    const result = await gateway.exchangePublicToken('public-x');
    expect(result).toEqual({
      itemId: 'item-1',
      accessToken: 'access-1',
      institutionId: 'ins_9',
      institutionName: null,
    });
    // Credentials travel in the body to Plaid's host — and only there.
    expect(calls[0]!.url).toBe('https://sandbox.plaid.com/item/public_token/exchange');
    expect(calls[0]!.body['client_id']).toBe('cid');
    expect(calls[0]!.body['secret']).toBe('s3cr3t');
  });

  it('maps accounts onto the docs/02 kind vocabulary and fixes balances to strings', async () => {
    const { fetchImpl } = fetchReturning({
      '/accounts/balance/get': {
        accounts: [
          {
            account_id: 'a1',
            name: 'Everyday',
            mask: '4321',
            type: 'depository',
            subtype: 'savings',
            balances: { current: 1500.5 },
          },
          {
            account_id: 'a2',
            name: 'Card',
            mask: null,
            type: 'credit',
            subtype: 'credit card',
            balances: { current: null },
          },
        ],
      },
    });
    const gateway = new LivePlaidGateway(OPTIONS, fetchImpl);
    const result = await gateway.syncAccounts('access-1', 'cursor-9');
    expect(result.accounts).toEqual([
      {
        externalAccountId: 'a1',
        kind: 'savings',
        name: 'Everyday',
        mask: '4321',
        currentBalance: '1500.50',
        isLiability: false,
      },
      {
        externalAccountId: 'a2',
        kind: 'credit_card',
        name: 'Card',
        mask: null,
        currentBalance: null,
        isLiability: true,
      },
    ]);
    expect(result.nextCursor).toBe('cursor-9');
  });

  it('translates provider 400s into typed gateway errors, 500s into provider_error', async () => {
    const bad = new LivePlaidGateway(OPTIONS, fetchReturning({}, 400).fetchImpl);
    await expect(bad.exchangePublicToken('public-x')).rejects.toThrow(
      new PlaidGatewayError('invalid_public_token'),
    );
    await expect(bad.syncAccounts('access-1', null)).rejects.toThrow(
      new PlaidGatewayError('invalid_access_token'),
    );
    const down = new LivePlaidGateway(OPTIONS, fetchReturning({}, 500).fetchImpl);
    await expect(down.createLinkToken('u')).rejects.toThrow(
      new PlaidGatewayError('provider_error'),
    );
  });

  it('rejects malformed provider payloads (third-party responses are untrusted)', async () => {
    const gateway = new LivePlaidGateway(
      OPTIONS,
      fetchReturning({ '/item/public_token/exchange': { access_token: 42 } }).fetchImpl,
    );
    await expect(gateway.exchangePublicToken('public-x')).rejects.toThrow();
  });

  it('returns null for an unknown webhook verification key', async () => {
    const gateway = new LivePlaidGateway(OPTIONS, fetchReturning({}, 400).fetchImpl);
    await expect(gateway.getWebhookVerificationKey('kid-x')).resolves.toBeNull();
  });
});
