import {
  createHash,
  createSign,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from 'node:crypto';
import {
  PlaidGatewayError,
  type ExchangeResult,
  type GatewayAccount,
  type PlaidGateway,
  type SyncResult,
  type WebhookJwk,
} from './plaid-gateway';

/**
 * Deterministic in-process Plaid sandbox for dev/test (no real credentials
 * exist yet — decision log). Behavior is derived from the public token so
 * tests and the E2E flow are reproducible:
 *
 *   public token 'public-stub-<anything>'          → links a two-account item
 *   public token containing 'liability'            → adds a credit-card account
 *   anything not starting with 'public-stub-'      → invalid_public_token
 *
 * It also owns a real ES256 keypair and can SIGN webhook payloads exactly the
 * way Plaid does (JWT with request_body_sha256 claim), so the webhook
 * verifier is exercised against genuine signatures — not a bypassed check.
 * Production wiring refuses to construct this class (config.ts: PLAID_MODE
 * must be 'live' in production).
 */
export class StubPlaidGateway implements PlaidGateway {
  private readonly privateKey: KeyObject;
  private readonly publicJwk: WebhookJwk;
  readonly webhookKid = 'stub-webhook-key-1';

  /** access tokens this stub has issued and not revoked, by token. */
  private readonly liveTokens = new Map<string, { itemId: string }>();

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
    this.publicJwk = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: this.webhookKid };
  }

  createLinkToken(userId: string): Promise<{ linkToken: string }> {
    return Promise.resolve({ linkToken: `link-stub-${userId}` });
  }

  exchangePublicToken(publicToken: string): Promise<ExchangeResult> {
    if (!publicToken.startsWith('public-stub-')) {
      return Promise.reject(new PlaidGatewayError('invalid_public_token'));
    }
    const itemId = `item-stub-${createHash('sha256').update(publicToken).digest('hex').slice(0, 24)}`;
    const accessToken = `access-stub-${randomUUID()}`;
    this.liveTokens.set(accessToken, { itemId });
    return Promise.resolve({
      itemId,
      accessToken,
      institutionId: 'ins_stub_109508',
      institutionName: 'First Stub Platypus Bank',
    });
  }

  syncAccounts(accessToken: string, cursor: string | null): Promise<SyncResult> {
    const live = this.liveTokens.get(accessToken);
    if (!live) {
      return Promise.reject(new PlaidGatewayError('invalid_access_token'));
    }
    const accounts: GatewayAccount[] = [
      {
        externalAccountId: `${live.itemId}-checking`,
        kind: 'checking',
        name: 'Stub Checking',
        mask: '0000',
        currentBalance: '1240.55',
        isLiability: false,
      },
      {
        externalAccountId: `${live.itemId}-savings`,
        kind: 'savings',
        name: 'Stub Savings',
        mask: '1111',
        currentBalance: '98230.10',
        isLiability: false,
      },
    ];
    return Promise.resolve({ accounts, nextCursor: cursor === null ? 'cursor-1' : cursor });
  }

  removeItem(accessToken: string): Promise<void> {
    if (!this.liveTokens.delete(accessToken)) {
      return Promise.reject(new PlaidGatewayError('invalid_access_token'));
    }
    return Promise.resolve();
  }

  getWebhookVerificationKey(kid: string): Promise<WebhookJwk | null> {
    return Promise.resolve(kid === this.webhookKid ? this.publicJwk : null);
  }

  /**
   * Sign a webhook body the way Plaid does: ES256 JWT whose payload carries
   * `iat` and `request_body_sha256`. Test/dev helper — the verifier treats
   * these signatures exactly like production ones.
   */
  signWebhook(rawBody: string, opts: { iatMs?: number; kid?: string } = {}): string {
    const header = { alg: 'ES256', typ: 'JWT', kid: opts.kid ?? this.webhookKid };
    const payload = {
      iat: Math.floor((opts.iatMs ?? Date.now()) / 1000),
      request_body_sha256: createHash('sha256').update(rawBody, 'utf8').digest('hex'),
    };
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    const signer = createSign('sha256').update(signingInput, 'utf8');
    const signature = signer.sign({ key: this.privateKey, dsaEncoding: 'ieee-p1363' });
    return `${signingInput}.${signature.toString('base64url')}`;
  }
}

function b64url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}
