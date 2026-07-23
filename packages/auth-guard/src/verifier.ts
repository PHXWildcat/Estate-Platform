import { createHash } from 'node:crypto';
import { z } from 'zod';
import { MfaLevelSchema } from '@estate/contracts';
import type { Clock, SessionContext } from './session';

/** DI token for the SessionVerifier a service wires into the guards. */
export const SESSION_VERIFIER = Symbol('SESSION_VERIFIER');
/** DI token for the guards' clock (optional; defaults to `() => new Date()`). */
export const SESSION_CLOCK = Symbol('SESSION_CLOCK');

/**
 * Verifies a caller's bearer access token and resolves the session behind it.
 * Returns null when the token is missing/invalid/expired/revoked (⇒ 401). This
 * interface is the seam: today it is HTTP introspection against identity; the
 * documented OIDC/JWT end-state swaps in a local-verify implementation here
 * without touching the guards or any service.
 */
export interface SessionVerifier {
  verify(bearerToken: string): Promise<SessionContext | null>;
}

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** identity `GET /v1/auth/session` response (mirrors the BFF's SessionSchema). */
const SessionResponseSchema = z.object({
  userId: z.string().uuid(),
  sessionId: z.string().uuid(),
  mfaLevel: MfaLevelSchema,
  stepupExpiresAt: z.string().datetime().nullable(),
});

export interface HttpSessionVerifierOptions {
  /** Base URL of the identity service (e.g. http://identity:3001). */
  identityUrl: string;
  /**
   * Positive-cache TTL. Short by design: a cached verification keeps a revoked
   * token accepted until it lapses, so this bounds revocation latency. Redis
   * with pub/sub invalidation is the eventual home; an in-memory Map is fine
   * per-instance for now.
   */
  cacheTtlMs?: number;
  fetchImpl?: FetchLike;
}

interface CacheEntry {
  context: SessionContext;
  expiresAt: number;
}

const DEFAULT_CACHE_TTL_MS = 30 * 1000;

/**
 * SessionVerifier that introspects the token against identity's existing
 * `GET /v1/auth/session` route (the mechanism the service READMEs name). Fails
 * CLOSED: a 401, a non-2xx, a malformed body, or a network error all resolve to
 * null so the caller is treated as unauthenticated rather than trusted.
 *
 * Only POSITIVE results are cached (keyed by the token's SHA-256, never the raw
 * token) — negatives are never cached, so a transient identity outage cannot
 * lock out an otherwise-valid token beyond the request that saw it.
 */
export class HttpSessionVerifier implements SessionVerifier {
  private readonly identityUrl: string;
  private readonly cacheTtlMs: number;
  private readonly fetchImpl: FetchLike;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(
    options: HttpSessionVerifierOptions,
    private readonly clock: Clock = () => new Date(),
  ) {
    this.identityUrl = options.identityUrl.replace(/\/$/, '');
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  async verify(bearerToken: string): Promise<SessionContext | null> {
    if (!bearerToken) {
      return null;
    }
    const now = this.clock().getTime();
    const key = createHash('sha256').update(bearerToken, 'utf8').digest('hex');
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt > now) {
      return cached.context;
    }

    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.identityUrl}/v1/auth/session`, {
        method: 'GET',
        headers: { authorization: `Bearer ${bearerToken}` },
      });
    } catch {
      return null; // network/DNS failure ⇒ unauthenticated (fail closed)
    }
    if (!response.ok) {
      return null; // 401 (invalid/expired/revoked) or any non-2xx
    }

    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return null;
    }
    const parsed = SessionResponseSchema.safeParse(body);
    if (!parsed.success) {
      return null; // identity contract drift ⇒ fail closed, never guess
    }
    const context: SessionContext = {
      userId: parsed.data.userId,
      sessionId: parsed.data.sessionId,
      mfaLevel: parsed.data.mfaLevel,
      stepupExpiresAt: parsed.data.stepupExpiresAt ? new Date(parsed.data.stepupExpiresAt) : null,
    };
    this.cache.set(key, { context, expiresAt: now + this.cacheTtlMs });
    return context;
  }
}
