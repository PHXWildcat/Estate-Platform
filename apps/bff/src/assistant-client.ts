import { z } from 'zod';
import { bffError } from './identity-client';

/**
 * Client for the AI assistant service (apps/services/ai-assistant) — the BFF's
 * second non-identity downstream, on exactly the assets-client terms: THE BFF
 * FORWARDS THE CALLER'S OWN BEARER TOKEN, injects no identity header, and holds
 * no credential for the assistant. That matters twice over here, because the
 * assistant itself holds no credential either (M10 PR1): the whole chain from
 * browser to analyser runs on one session's authority, so a compromised BFF
 * replays the sessions it is currently serving and can never widen them.
 *
 * ONLY THE READ ROUTES AND THE CONSENT SURFACE ARE REACHED FROM HERE. There is
 * no conversation call in this file: PR4 ships the readiness UI, and the
 * analysis routes send nothing to a model provider (M10 PR3) — they fetch on the
 * caller's bearer, compute in-process, and return the result. So this client
 * cannot cause estate content to leave the platform, whatever a caller asks of
 * it.
 *
 * Same error contract as the other clients: downstream response text is NEVER
 * forwarded to GraphQL clients. Recognized machine tokens become stable codes
 * or statuses; everything else is a masked generic error.
 */

/**
 * One analyser finding. The shape mirrors `Finding` in the service, minus the
 * detail's type freedom: `detail` is validated as a record of scalars rather
 * than passed through as `unknown`, so a peer that started returning nested
 * objects (or prose) fails the parse instead of reaching a browser.
 */
export const FindingSchema = z.object({
  code: z.string().min(1),
  severity: z.enum(['high', 'medium', 'info']),
  subject: z.object({
    kind: z.enum(['asset', 'document', 'estate']),
    ref: z.string().nullable(),
    label: z.string().nullable(),
  }),
  detail: z.record(z.union([z.string(), z.number(), z.boolean(), z.null()])),
});
export type Finding = z.infer<typeof FindingSchema>;

/** The service's own three-state result (analysis/findings.ts). */
export const AnalysisSchema = z.union([
  z.object({
    status: z.literal('ok'),
    findings: z.array(FindingSchema),
    summary: z.record(z.unknown()),
    disclaimer: z.string().min(1),
  }),
  z.object({
    status: z.literal('unavailable'),
    reason: z.string().min(1),
    disclaimer: z.string().min(1),
  }),
  z.object({
    status: z.literal('refused'),
    reason: z.string().min(1),
    disclaimer: z.string().min(1),
  }),
]);
export type Analysis = z.infer<typeof AnalysisSchema>;

/**
 * What the GraphQL layer sees. FOUR statuses where the service has three: the
 * assistant being switched off is a 403 rather than a result, and the UI has to
 * tell "you have this turned off" (actionable: turn it on) from "we could not
 * compute this" (not actionable) from "this analysis does not run here" (the
 * unreviewed-reference-data gate). Collapsing any two would make the page lie
 * about which of them happened.
 */
export type AnalysisStatus = 'OK' | 'UNAVAILABLE' | 'REFUSED' | 'DISABLED';

export interface AnalysisView {
  readonly status: AnalysisStatus;
  /** Enum token from the service ('upstream_unavailable', …); never prose. */
  readonly reason: string | null;
  readonly findings: readonly Finding[];
  /** docs/01 §2.8's non-legal-advice watermark. Always present, every status. */
  readonly disclaimer: string;
}

/** The four analyses the readiness surface renders. */
export type AnalysisName = 'funding' | 'missing-documents' | 'beneficiary-conflicts' | 'estate-tax';

const ConsentsSchema = z.object({ granted: z.array(z.string().min(1)) });

export interface AssistantClient {
  analysis(accessToken: string, name: AnalysisName): Promise<AnalysisView>;
  consents(accessToken: string): Promise<string[]>;
  grantConsent(accessToken: string, scope: string): Promise<string[]>;
  revokeConsent(accessToken: string, scope: string): Promise<string[]>;
}

type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

/**
 * The disclaimer shown when the service could not supply its own.
 *
 * Only reachable when a non-ok response carries no body we can parse — the
 * analysers always send theirs. It exists because the watermark is a REQUIRED
 * field all the way to the screen (docs/01 §2.8), and a fallback that says less
 * than the service's own text is better than a UI that renders none.
 */
const FALLBACK_DISCLAIMER =
  'This is an automated analysis for education only. It is not legal or tax advice.';

export class FetchAssistantClient implements AssistantClient {
  private readonly fetchFn: FetchFn;

  constructor(
    private readonly baseUrl: string,
    fetchFn?: FetchFn,
  ) {
    this.fetchFn = fetchFn ?? ((input, init): Promise<Response> => globalThis.fetch(input, init));
  }

  /**
   * Run one analysis.
   *
   * A NON-OK RESPONSE BECOMES A STATUS, NOT A THROWN ERROR, and this is the one
   * place this client differs from the assets one. The readiness page asks for
   * all four analyses in a single GraphQL query; if one 503s because a peer
   * blinked, the other three must still render. A thrown error would null the
   * whole field set and turn a partial outage into a blank page.
   *
   * It is not a softening of the service's rule. M10 PR3 refuses to answer 200
   * with an empty finding list precisely so "nothing found" cannot be confused
   * with "could not look" — and that distinction is exactly what these statuses
   * carry forward. What never happens, at any layer, is a failure rendering as
   * an empty result.
   *
   * A 401 still throws: an expired session is a fact about the whole request,
   * not about one analysis, and the client needs to re-authenticate rather than
   * read four "unavailable" cards.
   */
  async analysis(accessToken: string, name: AnalysisName): Promise<AnalysisView> {
    const res = await this.request('GET', `/v1/analysis/${name}`, accessToken);
    if (res.status === 401) {
      throw bffError('UNAUTHENTICATED');
    }
    const body = await this.readJson(res);
    if (!res.ok) {
      const token = errorToken(body);
      return {
        // 403 from these routes means one thing: the master consent switch is
        // off (the routes require nothing else — see the service's controller).
        status: res.status === 403 ? 'DISABLED' : statusForToken(token),
        reason: token,
        findings: [],
        disclaimer: FALLBACK_DISCLAIMER,
      };
    }
    const parsed = AnalysisSchema.safeParse(body);
    if (!parsed.success) {
      // Contract drift ⇒ no data, never a guess. Field paths only, never values.
      throw new Error('assistant analysis response failed validation');
    }
    const analysis = parsed.data;
    if (analysis.status === 'ok') {
      return {
        status: 'OK',
        reason: null,
        findings: analysis.findings,
        disclaimer: analysis.disclaimer,
      };
    }
    // A 200 carrying a non-ok status is not a shape the service produces today
    // (it 503s instead), but the union admits it and honouring it costs one
    // branch — the alternative is a status silently rendered as OK with no
    // findings, which is the one outcome this whole layer exists to prevent.
    return {
      status: analysis.status === 'refused' ? 'REFUSED' : 'UNAVAILABLE',
      reason: analysis.reason,
      findings: [],
      disclaimer: analysis.disclaimer,
    };
  }

  async consents(accessToken: string): Promise<string[]> {
    return this.consentRequest('GET', '/v1/consents', accessToken);
  }

  /** Step-up gated downstream: a 403 `stepup_required` maps to STEPUP_REQUIRED. */
  async grantConsent(accessToken: string, scope: string): Promise<string[]> {
    return this.consentRequest('PUT', `/v1/consents/${encodeURIComponent(scope)}`, accessToken);
  }

  /** Deliberately NOT step-up gated: the protective action must never be harder. */
  async revokeConsent(accessToken: string, scope: string): Promise<string[]> {
    return this.consentRequest('DELETE', `/v1/consents/${encodeURIComponent(scope)}`, accessToken);
  }

  private async consentRequest(
    method: 'GET' | 'PUT' | 'DELETE',
    path: string,
    accessToken: string,
  ): Promise<string[]> {
    const res = await this.request(method, path, accessToken);
    if (!res.ok) {
      throw await this.mapError(res);
    }
    const parsed = ConsentsSchema.safeParse(await this.readJson(res));
    if (!parsed.success) {
      throw new Error('assistant consents response failed validation');
    }
    return parsed.data.granted;
  }

  private async request(
    method: 'GET' | 'PUT' | 'DELETE',
    path: string,
    accessToken: string,
  ): Promise<Response> {
    try {
      return await this.fetchFn(`${this.baseUrl}${path}`, {
        method,
        headers: { authorization: `Bearer ${accessToken}` },
      });
    } catch {
      // Network/DNS failure. Plain Error ⇒ masked by yoga; cause never exposed.
      throw new Error('assistant service unreachable');
    }
  }

  private async readJson(res: Response): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  private async mapError(res: Response): Promise<Error> {
    const token = errorToken(await this.readJson(res));
    if (res.status === 401) {
      return bffError('UNAUTHENTICATED');
    }
    if (res.status === 403 && token === 'stepup_required') {
      return bffError('STEPUP_REQUIRED');
    }
    if (res.status === 400 || res.status === 422) {
      return bffError('INVALID_REQUEST');
    }
    return new Error(`assistant responded with status ${res.status}`);
  }
}

/** The peer's machine token, or null. Never its message. */
function errorToken(body: unknown): string | null {
  const parsed = z.object({ error: z.string().min(1) }).safeParse(body);
  return parsed.success ? parsed.data.error : null;
}

/**
 * `reference_unreviewed` is a CONTROL FIRING, not an outage: the estate-tax
 * table has no professional sign-off, so production refuses to state it (M10
 * PR3). Keeping it distinct is what lets the UI say "we don't publish this
 * here" rather than "try again later", which would be a lie the user would act
 * on by retrying forever.
 */
function statusForToken(token: string | null): AnalysisStatus {
  return token === 'reference_unreviewed' ? 'REFUSED' : 'UNAVAILABLE';
}
