import { AccountKindSchema, type AccountKind } from '@estate/contracts';
import { z } from 'zod';
import {
  PlaidGatewayError,
  type ExchangeResult,
  type PlaidGateway,
  type SyncResult,
  type WebhookJwk,
} from './plaid-gateway';

const BASE_URLS = {
  sandbox: 'https://sandbox.plaid.com',
  development: 'https://development.plaid.com',
  production: 'https://production.plaid.com',
} as const;

/** Minimal fetch shape so tests inject a double without network access. */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

// Responses are validated before use — Plaid is a third party, and its
// payloads are untrusted input like any other (CLAUDE.md).
const LinkTokenResponse = z.object({ link_token: z.string().min(1) });
const ExchangeResponse = z.object({ access_token: z.string().min(1), item_id: z.string().min(1) });
const ItemGetResponse = z.object({
  item: z.object({ institution_id: z.string().nullable().optional() }),
});
const AccountsResponse = z.object({
  accounts: z.array(
    z.object({
      account_id: z.string().min(1),
      name: z.string().min(1),
      mask: z.string().nullable().optional(),
      type: z.string(),
      subtype: z.string().nullable().optional(),
      balances: z.object({ current: z.number().nullable() }),
    }),
  ),
});
const WebhookKeyResponse = z.object({
  key: z.object({
    kty: z.literal('EC'),
    crv: z.literal('P-256'),
    x: z.string().min(1),
    y: z.string().min(1),
    kid: z.string().min(1),
  }),
});

export interface LivePlaidOptions {
  env: 'sandbox' | 'development' | 'production';
  clientId: string;
  secret: string;
}

/**
 * Plaid REST gateway. Credentials travel only in request bodies to Plaid's
 * host (Plaid's API convention) and never appear in errors or logs; response
 * bodies are schema-validated and reduced to the exact fields this service
 * needs. Constructed only when PLAID_MODE=live (required in production).
 */
export class LivePlaidGateway implements PlaidGateway {
  constructor(
    private readonly options: LivePlaidOptions,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
  ) {}

  async createLinkToken(userId: string): Promise<{ linkToken: string }> {
    const body = await this.post('/link/token/create', {
      user: { client_user_id: userId },
      client_name: 'Estate Platform',
      products: ['transactions'],
      country_codes: ['US'],
      language: 'en',
    });
    return { linkToken: LinkTokenResponse.parse(body).link_token };
  }

  async exchangePublicToken(publicToken: string): Promise<ExchangeResult> {
    const exchanged = ExchangeResponse.parse(
      await this.post('/item/public_token/exchange', { public_token: publicToken }, [400]),
    );
    const item = ItemGetResponse.parse(
      await this.post('/item/get', { access_token: exchanged.access_token }),
    );
    return {
      itemId: exchanged.item_id,
      accessToken: exchanged.access_token,
      institutionId: item.item.institution_id ?? 'unknown',
      institutionName: null, // institutions/get_by_id is a later enrichment
    };
  }

  async syncAccounts(accessToken: string, cursor: string | null): Promise<SyncResult> {
    const body = AccountsResponse.parse(
      await this.post('/accounts/balance/get', { access_token: accessToken }, [400]),
    );
    return {
      accounts: body.accounts.map((a) => ({
        externalAccountId: a.account_id,
        kind: toKind(a.type, a.subtype ?? null),
        name: a.name,
        mask: a.mask ?? null,
        currentBalance: a.balances.current === null ? null : a.balances.current.toFixed(2),
        isLiability: a.type === 'credit' || a.type === 'loan',
      })),
      // Balance reads are snapshot-style; the cursor becomes meaningful when
      // transactions/sync lands. Preserved verbatim for that upgrade.
      nextCursor: cursor,
    };
  }

  async removeItem(accessToken: string): Promise<void> {
    await this.post('/item/remove', { access_token: accessToken }, [400]);
  }

  async getWebhookVerificationKey(kid: string): Promise<WebhookJwk | null> {
    const body = await this.post('/webhook_verification_key/get', { key_id: kid }, [400]).catch(
      () => null,
    );
    if (body === null) {
      return null;
    }
    const parsed = WebhookKeyResponse.safeParse(body);
    return parsed.success ? parsed.data.key : null;
  }

  /** POST JSON to Plaid; `clientErrorStatuses` map to typed gateway errors. */
  private async post(
    path: string,
    payload: Record<string, unknown>,
    clientErrorStatuses: number[] = [],
  ): Promise<unknown> {
    const response = await this.fetchImpl(`${BASE_URLS[this.options.env]}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_id: this.options.clientId,
        secret: this.options.secret,
        ...payload,
      }),
    });
    if (!response.ok) {
      if (clientErrorStatuses.includes(response.status)) {
        throw new PlaidGatewayError(
          path === '/item/public_token/exchange' ? 'invalid_public_token' : 'invalid_access_token',
        );
      }
      throw new PlaidGatewayError('provider_error');
    }
    return response.json();
  }
}

/** Map Plaid's type/subtype vocabulary onto docs/02 §3 `accounts.kind`. */
function toKind(type: string, subtype: string | null): AccountKind {
  const candidate =
    subtype !== null && AccountKindSchema.safeParse(subtype).success
      ? (subtype as AccountKind)
      : null;
  if (candidate) {
    return candidate;
  }
  switch (type) {
    case 'depository':
      return 'checking';
    case 'investment':
      return 'investment';
    case 'credit':
      return 'credit_card';
    case 'loan':
      return subtype === 'mortgage' ? 'mortgage' : 'loan';
    default:
      return 'other';
  }
}
