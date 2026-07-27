import { z } from 'zod';

/** DI token consumers use to inject the client (or a test double). */
export const SETTLEMENT_AUTHORITY = Symbol('SETTLEMENT_AUTHORITY');

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Answer to "may this caller read this document version as case evidence?".
 * `caseId` accompanies an allow so the consumer can audit which case the
 * authority derives from.
 */
export type EvidenceReadAuthority =
  { allowed: true; caseId: string; ownerUserId: string } | { allowed: false };

const EvidenceReadResponseSchema = z.object({
  allowed: z.boolean(),
  caseId: z.string().uuid().nullable(),
  ownerUserId: z.string().uuid().nullable(),
});

/**
 * The authority questions settlement answers for other services. The seam is
 * an interface (SessionVerifier precedent) so services can wire a test double
 * and a later transport change (mesh, mTLS) touches only the implementation.
 */
export interface SettlementAuthority {
  /**
   * May the caller behind `bearerToken` read version `version` of document
   * `documentId` as evidence on a live settlement case? The caller's own
   * bearer is forwarded — settlement introspects it and applies its operator
   * allowlist + evidence registry; the consuming service never learns more
   * than the yes/no and the case id.
   */
  checkEvidenceRead(input: {
    bearerToken: string;
    documentId: string;
    version: number;
  }): Promise<EvidenceReadAuthority>;
}

export interface HttpSettlementAuthorityOptions {
  /** Base URL of the settlement service (e.g. http://settlement:3007). */
  settlementUrl: string;
  fetchImpl?: FetchLike;
}

const REFUSED: EvidenceReadAuthority = { allowed: false };

/**
 * HTTP implementation against settlement's authority endpoints. Fails CLOSED:
 * a non-2xx, a malformed body, or a network error is a refusal — an
 * unreachable settlement service must never widen access (the
 * HttpSessionVerifier and notification-gate precedents). Deliberately no
 * cache: authority answers gate rare, sensitive actions where freshness is
 * worth a round trip.
 */
export class HttpSettlementAuthority implements SettlementAuthority {
  private readonly settlementUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpSettlementAuthorityOptions) {
    this.settlementUrl = options.settlementUrl.replace(/\/$/, '');
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  async checkEvidenceRead(input: {
    bearerToken: string;
    documentId: string;
    version: number;
  }): Promise<EvidenceReadAuthority> {
    if (!input.bearerToken) {
      return REFUSED;
    }
    const query = new URLSearchParams({
      documentId: input.documentId,
      version: String(input.version),
    });
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(
        `${this.settlementUrl}/v1/settlement/authority/evidence-read?${query.toString()}`,
        { method: 'GET', headers: { authorization: `Bearer ${input.bearerToken}` } },
      );
    } catch {
      return REFUSED; // network/DNS failure ⇒ refusal (fail closed)
    }
    if (!response.ok) {
      return REFUSED;
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return REFUSED;
    }
    const parsed = EvidenceReadResponseSchema.safeParse(body);
    if (!parsed.success) {
      return REFUSED; // contract drift ⇒ fail closed, never guess
    }
    if (!parsed.data.allowed || !parsed.data.caseId || !parsed.data.ownerUserId) {
      return REFUSED;
    }
    return { allowed: true, caseId: parsed.data.caseId, ownerUserId: parsed.data.ownerUserId };
  }
}
