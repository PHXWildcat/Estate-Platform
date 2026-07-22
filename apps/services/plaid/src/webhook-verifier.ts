import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { z } from 'zod';
import { CLOCK, PLAID_GATEWAY, type Clock } from './di-tokens';
import type { PlaidGateway, WebhookJwk } from './plaid-gateway';

/** Plaid signs webhooks with ES256 JWTs no older than 5 minutes. */
const MAX_AGE_SECONDS = 5 * 60;
/** Verification keys cache briefly; rotation is handled by unknown-kid refetch. */
const KEY_CACHE_TTL_MS = 60 * 60 * 1000;
/**
 * The webhook route is UNAUTHENTICATED and the kid is attacker-controlled, so
 * key resolution runs before any signature check. Without a negative cache an
 * attacker could POST a stream of JWTs with novel kids and drive one outbound
 * Plaid key-fetch each — burning the service's Plaid rate-limit budget. A
 * miss is remembered briefly so repeated/rotating unknown kids collapse to at
 * most one fetch per kid per window (legitimate rotation still refetches once
 * this expires).
 */
const NEGATIVE_CACHE_TTL_MS = 5 * 60 * 1000;

const HeaderSchema = z.object({
  alg: z.literal('ES256'), // pinned: anything else (esp. 'none', HS256) is rejected
  kid: z.string().min(1),
});

const PayloadSchema = z.object({
  iat: z.number().int().positive(),
  request_body_sha256: z.string().regex(/^[0-9a-f]{64}$/),
});

export type WebhookVerdict = { valid: true } | { valid: false; reason: string };

/**
 * Full verification of Plaid's `Plaid-Verification` webhook JWT (docs/03 TB5:
 * "webhook signatures verified"), implemented on node:crypto — no new
 * dependency for a security-critical path (supply-chain rule).
 *
 * Checks, all of which must pass — the webhook body is untrusted input until
 * every one holds:
 *   1. structural JWT (three base64url segments, JSON header/payload);
 *   2. header alg pinned to ES256 (algorithm-confusion hardening) + kid known;
 *   3. ES256 signature over `header.payload` with the kid's JWK;
 *   4. iat within the 5-minute freshness window (replay hardening);
 *   5. payload.request_body_sha256 equals sha256(exact raw request body) —
 *      compared in constant time.
 */
@Injectable()
export class WebhookVerifier {
  private readonly keyCache = new Map<string, { jwk: WebhookJwk; expiresAt: number }>();
  /** kid → epoch-ms until which a prior lookup miss is remembered. */
  private readonly missCache = new Map<string, number>();

  constructor(
    @Inject(PLAID_GATEWAY) private readonly gateway: PlaidGateway,
    @Inject(CLOCK) private readonly clock: Clock,
  ) {}

  async verify(jwt: string | undefined, rawBody: Buffer): Promise<WebhookVerdict> {
    if (!jwt) {
      return { valid: false, reason: 'missing_jwt' };
    }
    const segments = jwt.split('.');
    if (segments.length !== 3) {
      return { valid: false, reason: 'malformed_jwt' };
    }
    const [headerB64, payloadB64, signatureB64] = segments as [string, string, string];

    const header = decodeJson(headerB64, HeaderSchema);
    if (!header) {
      return { valid: false, reason: 'bad_header' };
    }
    const payload = decodeJson(payloadB64, PayloadSchema);
    if (!payload) {
      return { valid: false, reason: 'bad_payload' };
    }

    const jwk = await this.keyFor(header.kid);
    if (!jwk) {
      return { valid: false, reason: 'unknown_kid' };
    }

    let signatureOk = false;
    try {
      const key = createPublicKey({
        key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        format: 'jwk',
      });
      signatureOk = verifySignature(
        'sha256',
        Buffer.from(`${headerB64}.${payloadB64}`, 'utf8'),
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signatureB64, 'base64url'),
      );
    } catch {
      signatureOk = false;
    }
    if (!signatureOk) {
      return { valid: false, reason: 'bad_signature' };
    }

    const nowSeconds = Math.floor(this.clock().getTime() / 1000);
    if (Math.abs(nowSeconds - payload.iat) > MAX_AGE_SECONDS) {
      return { valid: false, reason: 'stale_iat' };
    }

    const bodyHash = createHash('sha256').update(rawBody).digest();
    const claimed = Buffer.from(payload.request_body_sha256, 'hex');
    if (claimed.length !== bodyHash.length || !timingSafeEqual(bodyHash, claimed)) {
      return { valid: false, reason: 'body_hash_mismatch' };
    }

    return { valid: true };
  }

  private async keyFor(kid: string): Promise<WebhookJwk | null> {
    const now = this.clock().getTime();
    const cached = this.keyCache.get(kid);
    if (cached && cached.expiresAt > now) {
      return cached.jwk;
    }
    // Suppress repeated outbound fetches for a kid we recently failed to
    // resolve — the anti-amplification guard for this unauthenticated route.
    const missUntil = this.missCache.get(kid);
    if (missUntil !== undefined && missUntil > now) {
      return null;
    }
    const jwk = await this.gateway.getWebhookVerificationKey(kid);
    if (jwk) {
      this.missCache.delete(kid);
      this.keyCache.set(kid, { jwk, expiresAt: now + KEY_CACHE_TTL_MS });
    } else {
      this.missCache.set(kid, now + NEGATIVE_CACHE_TTL_MS);
    }
    return jwk;
  }
}

function decodeJson<T extends z.ZodTypeAny>(segment: string, schema: T): z.infer<T> | null {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    const result = schema.safeParse(parsed);
    return result.success ? (result.data as z.infer<T>) : null;
  } catch {
    return null;
  }
}
