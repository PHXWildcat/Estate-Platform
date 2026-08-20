import { z } from 'zod';
import { bffError } from './identity-client';

/**
 * Client for the settlement service (apps/services/settlement) — the BFF's
 * FIFTH non-identity downstream, and the first edge to it that has ever
 * existed. Until M22 PR3 the reporter/owner half of settlement had no consumer
 * at any layer: `route-consumers.spec.ts` carried seven routes under
 * `EXEMPT_SETTLEMENT_REPORTING`, and the only way for a real person to reach
 * any of them was curl.
 *
 * Same posture as every client here: the BFF FORWARDS THE CALLER'S OWN BEARER
 * TOKEN and holds no settlement credential of its own. That matters more on
 * this edge than on most, and `identity-client.ts` already says why in prose —
 * whether a caller may act on a settlement case is decided by
 * `settlement_operators`, inside the transaction that would act. This client
 * cannot widen that decision because it cannot ask it.
 *
 * FOUR OF THE SEVEN, deliberately. PR3 consumes the OWNER's half — the list, the
 * kill switch, and the waiting-period setting. The reporter's three
 * (`reportable-estates`, `POST /cases`, evidence attach) land in PR4, and the
 * order is the repo's own rule rather than a scheduling accident: filing a
 * death report is already one tap by design, so shipping the reporting screen
 * first would put the permissive capability in front of ten million people
 * while the protective one still required a terminal.
 *
 * WHAT IS DELIBERATELY NOT MODELLED HERE: evidence CONTENTS. `CaseDto.evidence`
 * carries document ids, versions, provider match ids and the id of whoever
 * attached them, and the owner's surface needs exactly one fact about it — how
 * many. So the schema below counts the array and never looks inside it. That is
 * the absence-over-filter rule: a field the BFF never parses is a field it
 * cannot leak through a resolver someone adds later.
 */

/**
 * One case as the OWNER'S SURFACE needs it, not as the service shapes it.
 *
 * `CaseDto` crosses the wire with `decedentUserId` and `reportedBy` — raw
 * user UUIDs. Neither is projected into GraphQL. `decedentUserId` becomes the
 * boolean `aboutMe` (see the resolver), and `reportedBy` is dropped outright:
 * a bare UUID tells a person nothing they can act on, and resolving it to a
 * NAME would mean a cross-cluster read this edge has no business making. The
 * one question the surface actually asks — "is this case about me, or one I
 * filed?" — is answerable without either id leaving the BFF.
 */
const CaseSchema = z.object({
  caseId: z.string().min(1),
  decedentUserId: z.string().min(1),
  reportedBy: z.string().min(1),
  status: z.string().min(1),
  reportSource: z.string().min(1),
  /**
   * Counted, never inspected. `z.unknown()` is the point: the BFF asserts the
   * shape it USES (an array) and declines to model evidence entries at all.
   */
  evidence: z.array(z.unknown()),
  waitingPeriodEnds: z.string().nullable(),
  resolution: z.string().nullable(),
  resolvedAt: z.string().nullable(),
  createdAt: z.string().min(1),
});
export type SettlementCase = z.infer<typeof CaseSchema>;

const SettingsSchema = z.object({
  waitingPeriodDays: z.number().int(),
});
export type SettlementSettings = z.infer<typeof SettingsSchema>;

export interface SettlementClient {
  /**
   * Every case this caller can see: one about them, one they filed, or both.
   * `cases.repo.ts#listForUser` selects
   * `WHERE decedent_user_id = $1 OR reported_by = $1`, so a single list serves
   * both audiences and the caller's relationship to each row is a fact the
   * resolver derives rather than a second request.
   */
  listMyCases(accessToken: string): Promise<SettlementCase[]>;
  voidCase(accessToken: string, caseId: string): Promise<SettlementCase>;
  getSettings(accessToken: string): Promise<SettlementSettings>;
  updateSettings(accessToken: string, waitingPeriodDays: number): Promise<SettlementSettings>;
}

type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export class FetchSettlementClient implements SettlementClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  async listMyCases(accessToken: string): Promise<SettlementCase[]> {
    const res = await this.request('GET', '/v1/settlement/cases', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(CaseSchema));
  }

  async voidCase(accessToken: string, caseId: string): Promise<SettlementCase> {
    const res = await this.request(
      'POST',
      `/v1/settlement/cases/${encodeURIComponent(caseId)}/void`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, CaseSchema);
  }

  async getSettings(accessToken: string): Promise<SettlementSettings> {
    const res = await this.request('GET', '/v1/settlement/settings', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, SettingsSchema);
  }

  async updateSettings(
    accessToken: string,
    waitingPeriodDays: number,
  ): Promise<SettlementSettings> {
    const res = await this.request('PUT', '/v1/settlement/settings', accessToken, {
      waitingPeriodDays,
    });
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, SettingsSchema);
  }

  private async request(
    method: 'GET' | 'POST' | 'PUT',
    path: string,
    accessToken: string,
    body?: Record<string, unknown>,
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
      throw new Error('settlement service unreachable');
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
      /*
       * THE SERVICE'S UNIFORM 404, AND THE BFF KEEPS IT ONE. On the void route
       * this covers "no such case" and "a real case that is not yours"
       * identically — which it did NOT until M22 PR3, when `void` answered 403
       * for the second and any account able to step up on itself could ask
       * whether a death case existed for a given UUID. Mapping both to
       * NOT_FOUND here is not the fix (a service is reachable without going
       * through a BFF); it is this layer declining to reintroduce the
       * distinction the service just stopped making.
       */
      return bffError('NOT_FOUND');
    }
    if (res.status === 409 && token === 'case_open') {
      /*
       * The waiting period is FROZEN while a case about this owner is open —
       * otherwise a step-up-fresh stolen session could shorten the very window
       * designed to catch it. Its own code because its remedy is its own: void
       * the case (or wait for it to resolve), then change the setting. Folding
       * it into INVALID_REQUEST would tell an owner their input was wrong when
       * their input was fine.
       */
      return bffError('CASE_OPEN');
    }
    if (res.status === 409 && token === 'invalid_transition') {
      /*
       * NOT the document `INVALID_TRANSITION`, whose copy names a document and
       * whose remedy is a different next step. This one means the case has
       * passed verification, so self-rescue has become an operator ceremony —
       * a different fact needing a different sentence, and the repo's rule is
       * that two failures with different remedies never share a token.
       */
      return bffError('CASE_NOT_VOIDABLE');
    }
    if (res.status === 503) {
      /*
       * A settlement transition whose identity-lock or legal-hold effect could
       * not be confirmed ROLLS BACK — nothing moved and a retry is the remedy.
       * On the kill switch that distinction is the whole thing: an owner told
       * "we could not do that right now" tries again, where an owner told
       * "that is not allowed" stops. WHICH downstream was unreachable
       * (`identity_unavailable` vs `documents_unavailable`) is deliberately
       * collapsed — the remedy is identical and the difference is an internal
       * topology detail, the same reasoning as VAULT/PAIRING/OPERATOR.
       */
      return bffError('SETTLEMENT_UNAVAILABLE');
    }
    if (res.status === 400 || res.status === 422) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`settlement responded with status ${res.status}`);
  }

  private async parseBody<T extends z.ZodTypeAny>(res: Response, schema: T): Promise<z.infer<T>> {
    let body: unknown;
    try {
      body = await res.json();
    } catch {
      throw new Error('settlement response was not JSON');
    }
    const parsed = schema.safeParse(body);
    if (!parsed.success) {
      // Field paths only — never response values.
      throw new Error('settlement response failed validation');
    }
    return parsed.data as z.infer<T>;
  }
}
