import { z } from 'zod';
import { bffError } from './identity-client';

/**
 * Client for the assets service (apps/services/assets) — the BFF's FIRST
 * non-identity downstream, and the point where the 2026-07-23 decision's
 * stated end-state becomes real: the BFF FORWARDS THE CALLER'S OWN BEARER
 * TOKEN, and assets verifies it against identity through the same
 * introspection every service uses. The BFF injects no identity headers,
 * holds no assets credential, and cannot mint authority it was not handed —
 * a compromised BFF can replay the sessions it is currently serving, never
 * conjure new ones.
 *
 * Same error contract as the identity client: downstream response text is
 * NEVER forwarded to GraphQL clients; recognized machine tokens map to stable
 * codes and everything else becomes a masked generic error.
 *
 * TWO ASSET SHAPES, deliberately (M19): the LIST shape has no
 * costBasis/location/notes because the service's list decrypts exactly
 * est_value (one audited decrypt per row — the M18 decrypt-rate budget), and
 * the DETAIL shape carries everything. Sharing one nullable type would make
 * "the list doesn't carry notes" indistinguishable from "this asset has no
 * notes", which is the M11 missing-field-is-NO-DATA rule violated at the
 * type level.
 */

export const AssetSchema = z.object({
  assetId: z.string().min(1),
  category: z.string().min(1),
  title: z.string(),
  estValue: z.string().nullable(),
  valuationAsOf: z.string().nullable(),
  valuationSource: z.string().nullable(),
  ownershipPct: z.number(),
  inTrust: z.boolean(),
  fundingStatus: z.string().nullable(),
  status: z.enum(['live', 'retired']),
  retiredAt: z.string().nullable(),
  version: z.string().min(1),
});
export type Asset = z.infer<typeof AssetSchema>;

export const AssetDetailSchema = AssetSchema.extend({
  costBasis: z.string().nullable(),
  location: z.string().nullable(),
  notes: z.string().nullable(),
});
export type AssetDetail = z.infer<typeof AssetDetailSchema>;

export const NetWorthSchema = z.object({
  totalValue: z.string(),
  assetCount: z.number().int(),
  valuedAssetCount: z.number().int(),
  inTrustValue: z.string(),
});
export type NetWorth = z.infer<typeof NetWorthSchema>;

/**
 * Every command acknowledgement, create included. `replayed` is the
 * idempotency signal: a retry carrying the same clientEventId is a no-op
 * that returns the ORIGINAL append's ack.
 */
const CommandAckSchema = z.object({
  assetId: z.string().min(1),
  eventId: z.string().min(1),
  version: z.string().min(1),
  occurredAt: z.string().min(1),
  replayed: z.boolean(),
});
export type CommandAck = z.infer<typeof CommandAckSchema>;

/**
 * One ledger event. The payload is the service's own validated event body
 * (deserialized through its zod union before it ever reaches the wire), so
 * it crosses here as an object the web surface renders defensively — the
 * same OUTPUT-of-validated-data reasoning as the readiness JSON scalar.
 */
const HistoryEntrySchema = z.object({
  version: z.string().min(1),
  eventId: z.string().min(1),
  eventType: z.string().min(1),
  occurredAt: z.string().min(1),
  actorId: z.string().min(1),
  payload: z.record(z.unknown()),
});
export type HistoryEntry = z.infer<typeof HistoryEntrySchema>;

/**
 * Beneficiary designations for one asset, exactly as the service shapes them:
 * CONTACT IDS, never names — the financial cluster cannot dereference a core-
 * cluster contact (docs/02 §8), so name composition happens in the BFF
 * resolver on the caller's own bearer, and only when designations exist.
 */
const BeneficiariesSchema = z.object({
  assetId: z.string().min(1),
  beneficiaries: z.array(
    z.object({
      contactId: z.string().min(1),
      designation: z.string().min(1),
      sharePct: z.number(),
    }),
  ),
  totals: z.array(
    z.object({
      designation: z.string().min(1),
      sharePct: z.number(),
      designationComplete: z.boolean(),
    }),
  ),
});
export type Beneficiaries = z.infer<typeof BeneficiariesSchema>;

/**
 * A valuation is not a bare number: the ledger requires `estValue`,
 * `valuationAsOf` and `valuationSource` TOGETHER, or none of them (a
 * `.refine` on CreateAssetSchema). An amount with no date and no provenance
 * is not a claim anyone could later audit, so the API refuses it — and this
 * type makes that all-or-nothing rule impossible to get wrong from here.
 */
export type Valuation = {
  readonly estValue: string;
  readonly valuationAsOf: string;
  readonly valuationSource: string;
};

/**
 * `clientEventId` is the idempotency key, minted by the TRUE client (the
 * browser form) and held across retries so a resend after a lost response
 * is a no-op. The BFF forwards it verbatim; the service validates it — one
 * validator, never a second opinion here (the M12 upload-client rule).
 */
export type CreateAssetInput = {
  readonly category: string;
  readonly title: string;
  readonly ownershipPct?: number;
  readonly inTrust?: boolean;
  readonly fundingStatus?: string;
  readonly valuation?: Valuation;
  readonly costBasis?: string;
  readonly location?: string;
  readonly notes?: string;
  readonly clientEventId?: string;
};

/** Absent = unchanged; explicit null = clear (the service's own semantics). */
export type UpdateDetailsInput = {
  readonly title?: string;
  readonly location?: string | null;
  readonly notes?: string | null;
  readonly inTrust?: boolean;
  readonly fundingStatus?: string | null;
  readonly clientEventId?: string;
};

export type RecordValuationInput = Valuation & {
  readonly clientEventId?: string;
};

export type ChangeOwnershipInput = {
  readonly ownershipPct: number;
  readonly costBasis?: string | null;
  readonly clientEventId?: string;
};

export type RetireAssetInput = {
  readonly reason?: string;
  readonly clientEventId?: string;
};

export type DesignateBeneficiaryInput = {
  readonly contactId: string;
  readonly designation: string;
  readonly sharePct: number;
  readonly clientEventId?: string;
};

export interface AssetsClient {
  list(accessToken: string, includeRetired?: boolean): Promise<Asset[]>;
  netWorth(accessToken: string): Promise<NetWorth>;
  get(accessToken: string, assetId: string): Promise<AssetDetail>;
  history(accessToken: string, assetId: string): Promise<HistoryEntry[]>;
  create(accessToken: string, input: CreateAssetInput): Promise<CommandAck>;
  updateDetails(
    accessToken: string,
    assetId: string,
    input: UpdateDetailsInput,
    expectedVersion?: string,
  ): Promise<CommandAck>;
  recordValuation(
    accessToken: string,
    assetId: string,
    input: RecordValuationInput,
    expectedVersion?: string,
  ): Promise<CommandAck>;
  changeOwnership(
    accessToken: string,
    assetId: string,
    input: ChangeOwnershipInput,
    expectedVersion?: string,
  ): Promise<CommandAck>;
  retire(
    accessToken: string,
    assetId: string,
    input: RetireAssetInput,
    expectedVersion?: string,
  ): Promise<CommandAck>;
  beneficiaries(accessToken: string, assetId: string): Promise<Beneficiaries>;
  designateBeneficiary(
    accessToken: string,
    assetId: string,
    input: DesignateBeneficiaryInput,
    expectedVersion?: string,
  ): Promise<CommandAck>;
  removeBeneficiary(
    accessToken: string,
    assetId: string,
    contactId: string,
    designation: string,
    clientEventId?: string,
    expectedVersion?: string,
  ): Promise<CommandAck>;
}

type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export class FetchAssetsClient implements AssetsClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  async list(accessToken: string, includeRetired = false): Promise<Asset[]> {
    const path = includeRetired ? '/v1/assets?includeRetired=true' : '/v1/assets';
    const res = await this.request('GET', path, accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(AssetSchema));
  }

  async netWorth(accessToken: string): Promise<NetWorth> {
    const res = await this.request('GET', '/v1/net-worth', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, NetWorthSchema);
  }

  async get(accessToken: string, assetId: string): Promise<AssetDetail> {
    const res = await this.request('GET', `/v1/assets/${encodeURIComponent(assetId)}`, accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, AssetDetailSchema);
  }

  async history(accessToken: string, assetId: string): Promise<HistoryEntry[]> {
    const res = await this.request(
      'GET',
      `/v1/assets/${encodeURIComponent(assetId)}/events`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(HistoryEntrySchema));
  }

  async create(accessToken: string, input: CreateAssetInput): Promise<CommandAck> {
    const { valuation, clientEventId, ...rest } = input;
    const res = await this.request('POST', '/v1/assets', accessToken, {
      ...rest,
      // All three or none — never a partial valuation.
      ...(valuation ?? {}),
      ...(clientEventId !== undefined ? { eventId: clientEventId } : {}),
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, CommandAckSchema);
  }

  async updateDetails(
    accessToken: string,
    assetId: string,
    input: UpdateDetailsInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command(
      'PATCH',
      `/v1/assets/${encodeURIComponent(assetId)}`,
      accessToken,
      input,
      expectedVersion,
    );
  }

  async recordValuation(
    accessToken: string,
    assetId: string,
    input: RecordValuationInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command(
      'POST',
      `/v1/assets/${encodeURIComponent(assetId)}/valuations`,
      accessToken,
      input,
      expectedVersion,
    );
  }

  async changeOwnership(
    accessToken: string,
    assetId: string,
    input: ChangeOwnershipInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command(
      'POST',
      `/v1/assets/${encodeURIComponent(assetId)}/ownership`,
      accessToken,
      input,
      expectedVersion,
    );
  }

  async retire(
    accessToken: string,
    assetId: string,
    input: RetireAssetInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command(
      'POST',
      `/v1/assets/${encodeURIComponent(assetId)}/retire`,
      accessToken,
      input,
      expectedVersion,
    );
  }

  async beneficiaries(accessToken: string, assetId: string): Promise<Beneficiaries> {
    const res = await this.request(
      'GET',
      `/v1/assets/${encodeURIComponent(assetId)}/beneficiaries`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, BeneficiariesSchema);
  }

  async designateBeneficiary(
    accessToken: string,
    assetId: string,
    input: DesignateBeneficiaryInput,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    return this.command(
      'POST',
      `/v1/assets/${encodeURIComponent(assetId)}/beneficiaries`,
      accessToken,
      input,
      expectedVersion,
    );
  }

  async removeBeneficiary(
    accessToken: string,
    assetId: string,
    contactId: string,
    designation: string,
    clientEventId?: string,
    expectedVersion?: string,
  ): Promise<CommandAck> {
    // A DELETE carries no body: designation and the idempotency key ride the
    // query string, which is what the service route reads.
    const query = new URLSearchParams({ designation });
    if (clientEventId !== undefined) {
      query.set('eventId', clientEventId);
    }
    const path =
      `/v1/assets/${encodeURIComponent(assetId)}/beneficiaries/` +
      `${encodeURIComponent(contactId)}?${query.toString()}`;
    const res = await this.request('DELETE', path, accessToken, undefined, expectedVersion);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, CommandAckSchema);
  }

  private async command(
    method: 'POST' | 'PATCH',
    path: string,
    accessToken: string,
    input: { readonly clientEventId?: string | undefined; readonly [key: string]: unknown },
    expectedVersion?: string,
  ): Promise<CommandAck> {
    const { clientEventId, ...rest } = input;
    const body = {
      ...rest,
      ...(clientEventId !== undefined ? { eventId: clientEventId } : {}),
    };
    // JSON.stringify keeps explicit nulls (= clear) and drops undefined
    // (= unchanged) — exactly the service's UpdateDetails wire semantics.
    const res = await this.request(method, path, accessToken, body, expectedVersion);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, CommandAckSchema);
  }

  private async request(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    path: string,
    accessToken: string,
    body?: Record<string, unknown>,
    expectedVersion?: string,
  ): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` };
    if (expectedVersion !== undefined) {
      // The optimistic-concurrency token: the version the caller last READ.
      headers['if-match'] = expectedVersion;
    }
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    try {
      return await this.fetchFn(`${this.baseUrl}${path}`, init);
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('assets service unreachable');
    }
  }

  private async mapError(res: Response): Promise<Error> {
    let token = '';
    try {
      const body: unknown = await res.json();
      const parsed = z.object({ error: z.string() }).safeParse(body);
      if (parsed.success) {
        token = parsed.data.error;
      }
    } catch {
      // Non-JSON body: fall through to status-based mapping.
    }
    if (res.status === 401) {
      return bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    if (res.status === 404) {
      // The service's UNIFORM 404 (M19 PR1): "no such asset", "not yours" and
      // "retired refuses commands" are one answer, and the BFF keeps them one.
      return bffError('NOT_FOUND');
    }
    if (res.status === 409 && token === 'version_conflict') {
      // Stale If-Match. The remedy is RE-READ, never blind-retry — the UI
      // reloads the asset and shows what changed before asking again.
      return bffError('VERSION_CONFLICT');
    }
    if (res.status === 422 && token === 'share_sum_exceeded') {
      // Checked BEFORE the generic 422: "those shares add past 100%" is the
      // one refusal the owner fixes by choosing a different number, and
      // folding it into INVALID_REQUEST would hide the only actionable fact.
      return bffError('SHARE_SUM_EXCEEDED');
    }
    if (res.status === 400 || res.status === 422) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`assets responded with status ${res.status}`);
  }

  private async parseBody<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('assets response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Field paths only — never response values.
      throw new Error('assets response failed validation');
    }
    return parsed.data as z.infer<T>;
  }
}
