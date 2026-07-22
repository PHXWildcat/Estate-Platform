import type { AccountKind } from '@estate/contracts';

/** An account as reported by Plaid, normalized to this service's vocabulary. */
export interface GatewayAccount {
  /** Plaid's stable account_id within the item. */
  externalAccountId: string;
  kind: AccountKind;
  name: string;
  /** Last 2–4 digits, as Plaid reports them (display-safe). */
  mask: string | null;
  /** Decimal string, e.g. '1234.56'. Null when the institution reports none. */
  currentBalance: string | null;
  isLiability: boolean;
}

export interface ExchangeResult {
  /** Plaid's item_id — stored encrypted + blind-indexed, never plaintext. */
  itemId: string;
  /** The item access token — the TB5 crown jewel; encrypted at rest. */
  accessToken: string;
  institutionId: string;
  institutionName: string | null;
}

export interface SyncResult {
  accounts: GatewayAccount[];
  nextCursor: string | null;
}

/** A JWK public key for webhook JWT verification (ES256 / P-256). */
export interface WebhookJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  kid: string;
}

/**
 * The boundary to Plaid. Exactly two implementations: StubPlaidGateway
 * (deterministic in-process sandbox — no credentials exist yet) and
 * LivePlaidGateway (Plaid REST). Everything this service knows about Plaid
 * flows through here, so swapping in real credentials later touches nothing
 * but configuration.
 */
export interface PlaidGateway {
  /** Create a Link token for the user's client-side Link flow. */
  createLinkToken(userId: string): Promise<{ linkToken: string }>;
  /** Exchange a Link public_token for the item's access token. */
  exchangePublicToken(publicToken: string): Promise<ExchangeResult>;
  /** Pull the item's accounts + balances. Cursor enables incremental sync. */
  syncAccounts(accessToken: string, cursor: string | null): Promise<SyncResult>;
  /** Revoke the item at Plaid (invalidates the access token server-side). */
  removeItem(accessToken: string): Promise<void>;
  /** Fetch the JWK for a webhook JWT `kid` (verification key rotation-safe). */
  getWebhookVerificationKey(kid: string): Promise<WebhookJwk | null>;
}

/** Thrown when the gateway rejects an exchange/sync (invalid or revoked token). */
export class PlaidGatewayError extends Error {
  constructor(readonly reason: 'invalid_public_token' | 'invalid_access_token' | 'provider_error') {
    // Reason token only — never provider response bodies (they can carry PII).
    super(reason);
    this.name = 'PlaidGatewayError';
  }
}
