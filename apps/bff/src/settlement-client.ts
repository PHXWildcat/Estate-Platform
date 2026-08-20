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
 * ALL SEVEN NOW (M22 PR4c completed what PR3 began), and the ORDER was the
 * repo's own rule rather than a scheduling accident: filing a death report is
 * already one tap by design, so the owner's kill switch shipped first rather
 * than putting the permissive capability in front of ten million people while
 * the protective one still required a terminal. `EXEMPT_SETTLEMENT_REPORTING`
 * is gone from `route-consumers.spec.ts` with its last entry.
 *
 * INTAKE IS NOT STEP-UP GATED and that is deliberate — see the settlement
 * controller's own docstring. Filing ADDS scrutiny rather than authority: the
 * case locks nothing, the owner is notified on every channel we have, and they
 * void it with one ungated click. A gate here would fall on a grieving contact
 * on a borrowed device while stopping nothing a token thief wants, and the
 * protective action must never be the harder one.
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

/**
 * ONE ESTATE THIS CALLER MAY REPORT ON.
 *
 * `decedentUserId` is kept, and it is the only place in this file where a raw
 * user id survives into the resolver layer — because it is the argument the
 * reporting mutation must send back, and settlement identifies an estate by
 * nothing else. It is NOT projected into GraphQL: the resolver joins it to a
 * name and exposes an opaque handle, and the schema comment there says why.
 *
 * SETTLEMENT IS THE AUTHORITATIVE SET, not profile's `linkedEstates`, even
 * though the two queries read the same `contacts` rows today. `report()`
 * re-checks `isLinkedContact` under its own transaction and answers a uniform
 * 404 otherwise, so this is the list that predicts what the server will accept.
 * Building the picker from the other read would be offering an action the
 * server might refuse the moment the two drift — the M12 rule.
 */
const ReportableEstateSchema = z.object({
  decedentUserId: z.string().min(1),
  contactId: z.string().min(1),
  roles: z.array(z.string()),
});
export type ReportableEstate = z.infer<typeof ReportableEstateSchema>;

/**
 * What a reporter may attach, at intake or afterwards. DOCUMENTS ONLY, and the
 * type has no other arm on purpose: settlement refuses a non-operator's
 * `provider_match` (M22 PR4b, 403 `document_evidence_only`), and a field the
 * BFF cannot express is a refusal the UI cannot walk into. Absence over filter.
 */
export interface DocumentEvidence {
  readonly documentId: string;
  readonly version: number;
}

export type ReportSource = 'trusted_contact' | 'death_certificate_upload';

/**
 * ONE ESTATE THIS CALLER IS SETTLING (M23 PR2).
 *
 * Two ids, and only one of them ever leaves the BFF. `contactId` is the handle
 * GraphQL exposes — the same handle `ReportableEstate` uses, so an estate has
 * ONE name across the reporter's surface and the executor's. `decedentUserId`
 * stays here because assets and profile identify an estate by nothing else,
 * and the resolver's job is to turn a contact id back into it by re-reading
 * THIS list: an argument the browser supplies is a claim, and a row on this
 * list is settlement's answer.
 */
const ExecutorCaseSchema = z.object({
  caseId: z.string().min(1),
  contactId: z.string().min(1),
  decedentUserId: z.string().min(1),
  status: z.string().min(1),
  verifiedAt: z.string().nullable(),
  createdAt: z.string().min(1),
});
export type ExecutorCase = z.infer<typeof ExecutorCaseSchema>;

/**
 * One rung of the staged-access ladder.
 *
 * `requestedBy` and `decidedBy` are on the wire and are NOT modelled: both are
 * raw user UUIDs, the executor cannot act on either, and naming the operator
 * who decided a stage would put a staff member's id in a grieving family
 * member's browser. What the surface needs is which stage, what state, and
 * when — the same absence-over-filter rule the evidence array is under.
 */
const StageSchema = z.object({
  stageId: z.string().min(1),
  caseId: z.string().min(1),
  stage: z.string().min(1),
  status: z.string().min(1),
  requestedAt: z.string().min(1),
  decidedAt: z.string().nullable(),
});
export type SettlementStage = z.infer<typeof StageSchema>;

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
  /** The estates whose death this caller is entitled to report — the picker's spine. */
  reportableEstates(accessToken: string): Promise<ReportableEstate[]>;
  reportCase(
    accessToken: string,
    input: {
      decedentUserId: string;
      source: ReportSource;
      evidence: readonly DocumentEvidence[];
    },
  ): Promise<SettlementCase>;
  addEvidence(
    accessToken: string,
    caseId: string,
    evidence: DocumentEvidence,
  ): Promise<SettlementCase>;
  voidCase(accessToken: string, caseId: string): Promise<SettlementCase>;
  /** The estates this caller is settling — the executor surface's spine. */
  executorCases(accessToken: string): Promise<ExecutorCase[]>;
  /** The staged-access ladder on one case, requested and decided rungs alike. */
  listStages(accessToken: string, caseId: string): Promise<SettlementStage[]>;
  /** Ask an operator for one rung. Step-up gated at the service. */
  requestStage(accessToken: string, caseId: string, stage: string): Promise<SettlementStage>;
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

  async reportableEstates(accessToken: string): Promise<ReportableEstate[]> {
    const res = await this.request('GET', '/v1/settlement/reportable-estates', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(ReportableEstateSchema));
  }

  async reportCase(
    accessToken: string,
    input: {
      decedentUserId: string;
      source: ReportSource;
      evidence: readonly DocumentEvidence[];
    },
  ): Promise<SettlementCase> {
    const res = await this.request('POST', '/v1/settlement/cases', accessToken, {
      decedentUserId: input.decedentUserId,
      source: input.source,
      // `type` is added HERE rather than carried on the input, so the one
      // evidence kind a reporter may file is a property of this edge and not
      // of a caller's argument.
      evidence: input.evidence.map((e) => ({
        type: 'document',
        documentId: e.documentId,
        version: e.version,
      })),
    });
    if (!res.ok) {
      throw await this.mapError(res, { caseExists: 'CASE_ALREADY_REPORTED' });
    }
    return this.parseBody(res, CaseSchema);
  }

  async addEvidence(
    accessToken: string,
    caseId: string,
    evidence: DocumentEvidence,
  ): Promise<SettlementCase> {
    const res = await this.request(
      'POST',
      `/v1/settlement/cases/${encodeURIComponent(caseId)}/evidence`,
      accessToken,
      {
        evidence: { type: 'document', documentId: evidence.documentId, version: evidence.version },
      },
    );
    if (!res.ok) {
      throw await this.mapError(res, { invalidTransition: 'EVIDENCE_WINDOW_CLOSED' });
    }
    return this.parseBody(res, CaseSchema);
  }

  async voidCase(accessToken: string, caseId: string): Promise<SettlementCase> {
    const res = await this.request(
      'POST',
      `/v1/settlement/cases/${encodeURIComponent(caseId)}/void`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res, { invalidTransition: 'CASE_NOT_VOIDABLE' });
    }
    return this.parseBody(res, CaseSchema);
  }

  async executorCases(accessToken: string): Promise<ExecutorCase[]> {
    const res = await this.request('GET', '/v1/settlement/executor-cases', accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(ExecutorCaseSchema));
  }

  async listStages(accessToken: string, caseId: string): Promise<SettlementStage[]> {
    const res = await this.request(
      'GET',
      `/v1/settlement/cases/${encodeURIComponent(caseId)}/stages`,
      accessToken,
    );
    if (!res.ok) {
      throw await this.mapError(res);
    }
    return this.parseBody(res, z.array(StageSchema));
  }

  async requestStage(accessToken: string, caseId: string, stage: string): Promise<SettlementStage> {
    const res = await this.request(
      'POST',
      `/v1/settlement/cases/${encodeURIComponent(caseId)}/stages`,
      accessToken,
      { stage },
    );
    if (!res.ok) {
      // BOTH of settlement's 409s on this route are named. `case_not_verified`
      // reaches only the estate's own executor (M23 PR1), so mapping it is not
      // a leak — and leaving it unmapped would render the one refusal whose
      // remedy is "wait" as the generic failure whose remedy is "retry".
      throw await this.mapError(res, {
        stageOutOfOrder: 'STAGE_OUT_OF_ORDER',
        stageExists: 'STAGE_ALREADY_REQUESTED',
        caseNotVerified: 'CASE_NOT_VERIFIED',
      });
    }
    return this.parseBody(res, StageSchema);
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

  /**
   * WHAT A REUSED TOKEN MEANS ON THIS ROUTE.
   *
   * Settlement spends one `invalid_transition` on two routes with opposite
   * remedies: on `void` it means self-rescue has become an operator ceremony,
   * and on the evidence attach it means the case has passed the window where
   * anything more can be added. One sentence cannot serve both — "this case
   * has moved past the point where you can close it yourself" is simply false
   * when the caller was trying to attach a death certificate — and the repo's
   * rule is that two failures needing different remedies never share a token.
   *
   * A ROUTE THAT DECLARES NOTHING GETS NOTHING. There is deliberately no
   * default: an unmapped 409 falls through to the generic status error rather
   * than borrowing whichever sentence happened to be written first. That is
   * the fail-closed direction — a new route added without thinking about this
   * says something vague, not something confidently wrong.
   */
  private async mapError(
    res: Response,
    meaning: {
      readonly invalidTransition?: 'CASE_NOT_VOIDABLE' | 'EVIDENCE_WINDOW_CLOSED';
      readonly caseExists?: 'CASE_ALREADY_REPORTED';
      readonly stageOutOfOrder?: 'STAGE_OUT_OF_ORDER';
      readonly stageExists?: 'STAGE_ALREADY_REQUESTED';
      readonly caseNotVerified?: 'CASE_NOT_VERIFIED';
    } = {},
  ): Promise<Error> {
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
    if (res.status === 409 && token === 'case_exists' && meaning.caseExists !== undefined) {
      /*
       * ONE OPEN CASE PER DECEDENT, enforced by a partial unique index. It is
       * NOT `CASE_OPEN`, which is about a case on the CALLER'S OWN account
       * freezing their waiting period: this one says somebody has already
       * reported this estate and the reporter's next step is to do nothing.
       * Two facts, two audiences, two sentences.
       *
       * It is also NOT a leak. Settlement answers this only to a caller who
       * has already passed the linked-contact check on that estate, so the
       * existence it confirms is one they were entitled to ask about.
       */
      return bffError(meaning.caseExists);
    }
    if (res.status === 409 && token === 'stage_exists' && meaning.stageExists) {
      return bffError(meaning.stageExists);
    }
    if (res.status === 409 && token === 'stage_out_of_order' && meaning.stageOutOfOrder) {
      return bffError(meaning.stageOutOfOrder);
    }
    if (res.status === 409 && token === 'case_not_verified' && meaning.caseNotVerified) {
      return bffError(meaning.caseNotVerified);
    }
    if (res.status === 409 && token === 'invalid_transition' && meaning.invalidTransition) {
      /*
       * NOT the document `INVALID_TRANSITION`, whose copy names a document and
       * whose remedy is a different next step. Which sentence this becomes is
       * the calling route's decision — see `mapError`'s own docstring.
       */
      return bffError(meaning.invalidTransition);
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
