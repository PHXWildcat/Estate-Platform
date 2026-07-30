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
 */

export const AssetSchema = z.object({
  assetId: z.string().min(1),
  category: z.string().min(1),
  title: z.string(),
  estValue: z.string().nullable(),
  valuationAsOf: z.string().nullable(),
  ownershipPct: z.number(),
  inTrust: z.boolean(),
  version: z.string().min(1),
});
export type Asset = z.infer<typeof AssetSchema>;

export const NetWorthSchema = z.object({
  totalValue: z.string(),
  assetCount: z.number().int(),
  valuedAssetCount: z.number().int(),
  inTrustValue: z.string(),
});
export type NetWorth = z.infer<typeof NetWorthSchema>;

const CreateResultSchema = z.object({
  assetId: z.string().min(1),
  version: z.string().min(1),
});
export type CreateResult = z.infer<typeof CreateResultSchema>;

/**
 * A valuation is not a bare number: the ledger requires `estValue`,
 * `valuationAsOf` and `valuationSource` TOGETHER, or none of them (a
 * `.refine` on CreateAssetSchema). An amount with no date and no provenance
 * is not a claim anyone could later audit, so the API refuses it — and this
 * type makes that all-or-nothing rule impossible to get wrong from here.
 */
export interface Valuation {
  readonly estValue: string;
  readonly valuationAsOf: string;
  readonly valuationSource: string;
}

export interface CreateAssetInput {
  readonly category: string;
  readonly title: string;
  readonly valuation?: Valuation;
}

export interface AssetsClient {
  list(accessToken: string): Promise<Asset[]>;
  netWorth(accessToken: string): Promise<NetWorth>;
  create(accessToken: string, input: CreateAssetInput): Promise<CreateResult>;
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

  async list(accessToken: string): Promise<Asset[]> {
    const res = await this.request('GET', '/v1/assets', accessToken);
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

  async create(accessToken: string, input: CreateAssetInput): Promise<CreateResult> {
    const res = await this.request('POST', '/v1/assets', accessToken, {
      category: input.category,
      title: input.title,
      // All three or none — never a partial valuation.
      ...(input.valuation ?? {}),
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, CreateResultSchema);
  }

  private async request(
    method: 'GET' | 'POST',
    path: string,
    accessToken: string,
    body?: Record<string, string>,
  ): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` };
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
