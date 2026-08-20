/**
 * THE SETTLEMENT SURFACE, in the console's own vocabulary.
 *
 * Every call goes through `request` from `api.ts` — the one module on this
 * origin that touches the network, which `test/fences.spec.ts` asserts. That
 * fence makes a claim about ESTATE CONTENT here rather than about key material:
 * a death case an operator reads has exactly one route off this page.
 *
 * WHAT THIS MODULE ADDS TO `request` IS PARSING AND A VOCABULARY, never
 * authority. It holds no credential (the cookie is `HttpOnly` and this code
 * cannot read it), takes no authorization decision, and its refusals are the
 * service's own — `settlement_operators` decides who may act, read inside the
 * transaction that would act (M21 PR2). The console is role-BLIND by
 * construction, so a caller who is not an operator gets here and is refused
 * there, which is why `FORBIDDEN` has the copy it has.
 *
 * A ROW THAT CANNOT BE READ FAILS THE WHOLE LIST. The alternative — skip it and
 * render the rest — hides a death case from the worklist that exists to make
 * somebody work it, and a shorter queue looks exactly like a quieter week. A
 * response missing its fields is NO DATA, never data (M11/M12/M15).
 */
import { request, type ApiResult } from './api.js';

export interface CaseSummary {
  readonly caseId: string;
  readonly decedentUserId: string;
  readonly status: string;
  readonly reportSource: string;
  readonly reportedBy: string;
  readonly claimedBy: string | null;
  readonly claimedAt: string | null;
  readonly humanReviewBy: string | null;
  readonly waitingPeriodEnds: string | null;
  readonly verifiedAt: string | null;
  readonly resolution: string | null;
  readonly createdAt: string;
  readonly eligibleForVerification: boolean;
  readonly evidence: readonly EvidenceView[];
}

/**
 * AN EVIDENCE ENTRY, widened on purpose (M22 PR4b).
 *
 * Settlement's own `EvidenceEntry` is a discriminated union — `document` with
 * a documentId and version, `provider_match` with a matchId — and mirroring it
 * as a union here would mean an entry of a type this build predates fails to
 * parse. Every path out of that is wrong on a review screen: fail the ROW and a
 * death case vanishes from the worklist because of an evidence kind added last
 * week; drop the ENTRY and the reviewer is told there are two when there are
 * three, which is the affirmative statement about what does not exist that this
 * file's docstring exists to forbid.
 *
 * So the shape is flat and the discriminant is carried as settlement's own
 * token, unrecognised values included: `screens.ts` renders an unknown token as
 * ITSELF, and `addedBy`/`addedAt` are on every arm, so an entry this console
 * cannot fully describe still reports that it exists, who attached it and when.
 * That is the M15 `parseTimeline` posture — say what is not understood rather
 * than discard it — applied to the field a human review turns on.
 */
export interface EvidenceView {
  readonly type: string;
  readonly documentId: string | null;
  readonly version: number | null;
  readonly matchId: string | null;
  readonly addedBy: string;
  readonly addedAt: string;
}

export interface StageView {
  readonly stageId: string;
  readonly stage: string;
  readonly status: string;
  readonly requestedBy: string;
  readonly requestedAt: string;
  readonly decidedBy: string | null;
  readonly decidedAt: string | null;
}

export interface DistributionView {
  readonly distributionId: string;
  readonly beneficiaryContactId: string;
  readonly assetId: string | null;
  readonly status: string;
  readonly createdBy: string;
  readonly approvedBy: string | null;
  readonly hasAmount: boolean;
  readonly createdAt: string;
}

export interface TimelineEvent {
  readonly at: string;
  readonly kind: string;
  readonly detail: Readonly<Record<string, string>>;
}

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function nullableStr(value: unknown): string | null | undefined {
  if (value === null) return null;
  return typeof value === 'string' ? value : undefined;
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * A row this parser cannot read fails the CASE, exactly as one bad worklist row
 * fails the list. The alternative is a case screen whose evidence panel is
 * shorter than the case's evidence, and short is the direction that reads as
 * "there was not much to go on".
 *
 * The three fields required are the three every arm of settlement's union
 * carries. `documentId` / `version` / `matchId` are per-arm and absent by
 * design on the other one, so they are read WHEN PRESENT and are null
 * otherwise — never a reason to reject the entry.
 */
function parseEvidence(payload: unknown): EvidenceView | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const raw = payload as Record<string, unknown>;
  const type = str(raw['type']);
  const addedBy = str(raw['addedBy']);
  const addedAt = str(raw['addedAt']);
  if (type === null || addedBy === null || addedAt === null) return null;
  return {
    type,
    documentId: str(raw['documentId']),
    version: num(raw['version']),
    matchId: str(raw['matchId']),
    addedBy,
    addedAt,
  };
}

function parseEvidenceList(payload: unknown): EvidenceView[] | null {
  if (!Array.isArray(payload)) return null;
  const rows: EvidenceView[] = [];
  for (const row of payload) {
    const parsed = parseEvidence(row);
    if (parsed === null) return null;
    rows.push(parsed);
  }
  return rows;
}

function parseCase(payload: unknown): CaseSummary | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const raw = payload as Record<string, unknown>;
  const caseId = str(raw['caseId']);
  const decedentUserId = str(raw['decedentUserId']);
  const status = str(raw['status']);
  const reportSource = str(raw['reportSource']);
  const reportedBy = str(raw['reportedBy']);
  const createdAt = str(raw['createdAt']);
  const claimedBy = nullableStr(raw['claimedBy']);
  const claimedAt = nullableStr(raw['claimedAt']);
  const humanReviewBy = nullableStr(raw['humanReviewBy']);
  const waitingPeriodEnds = nullableStr(raw['waitingPeriodEnds']);
  const verifiedAt = nullableStr(raw['verifiedAt']);
  const resolution = nullableStr(raw['resolution']);
  const eligible = raw['eligibleForVerification'];
  // A CASE WITH NO `evidence` FIELD IS NOT A CASE WITH NO EVIDENCE. A peer that
  // stopped sending it must not render as an empty panel on the screen where
  // somebody decides whether to lock a living person's account.
  const evidence = parseEvidenceList(raw['evidence']);
  if (
    evidence === null ||
    caseId === null ||
    decedentUserId === null ||
    status === null ||
    reportSource === null ||
    reportedBy === null ||
    createdAt === null ||
    claimedBy === undefined ||
    claimedAt === undefined ||
    humanReviewBy === undefined ||
    waitingPeriodEnds === undefined ||
    verifiedAt === undefined ||
    resolution === undefined ||
    typeof eligible !== 'boolean'
  ) {
    return null;
  }
  return {
    caseId,
    decedentUserId,
    status,
    reportSource,
    reportedBy,
    claimedBy,
    claimedAt,
    humanReviewBy,
    waitingPeriodEnds,
    verifiedAt,
    resolution,
    createdAt,
    eligibleForVerification: eligible,
    evidence,
  };
}

function parseStage(payload: unknown): StageView | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const raw = payload as Record<string, unknown>;
  const stageId = str(raw['stageId']);
  const stage = str(raw['stage']);
  const status = str(raw['status']);
  const requestedBy = str(raw['requestedBy']);
  const requestedAt = str(raw['requestedAt']);
  const decidedBy = nullableStr(raw['decidedBy']);
  const decidedAt = nullableStr(raw['decidedAt']);
  if (
    stageId === null ||
    stage === null ||
    status === null ||
    requestedBy === null ||
    requestedAt === null ||
    decidedBy === undefined ||
    decidedAt === undefined
  ) {
    return null;
  }
  return { stageId, stage, status, requestedBy, requestedAt, decidedBy, decidedAt };
}

function parseDistribution(payload: unknown): DistributionView | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const raw = payload as Record<string, unknown>;
  const distributionId = str(raw['distributionId']);
  const beneficiaryContactId = str(raw['beneficiaryContactId']);
  const status = str(raw['status']);
  const createdBy = str(raw['createdBy']);
  const createdAt = str(raw['createdAt']);
  const assetId = nullableStr(raw['assetId']);
  const approvedBy = nullableStr(raw['approvedBy']);
  const hasAmount = raw['hasAmount'];
  if (
    distributionId === null ||
    beneficiaryContactId === null ||
    status === null ||
    createdBy === null ||
    createdAt === null ||
    assetId === undefined ||
    approvedBy === undefined ||
    typeof hasAmount !== 'boolean'
  ) {
    return null;
  }
  return {
    distributionId,
    beneficiaryContactId,
    assetId,
    status,
    createdBy,
    approvedBy,
    hasAmount,
    createdAt,
  };
}

/**
 * A timeline entry's `detail` is IDS AND ENUMS by construction (the audit PII
 * firewall), and every value is rendered as text.
 *
 * SCALARS ONLY, and a non-scalar is SAID rather than stringified. `String({})`
 * is `'[object Object]'`, which on an audit surface is a sentence that looks
 * like a value and is not one — the M16 PR2b rule that "a record with no title"
 * and "content this build cannot read" are different facts and a person acts on
 * them differently. A nested shape here would mean settlement started emitting
 * something this client predates, and the honest answer is to name that.
 */
function parseTimeline(payload: unknown): TimelineEvent | null {
  if (typeof payload !== 'object' || payload === null) return null;
  const raw = payload as Record<string, unknown>;
  const at = str(raw['at']);
  const kind = str(raw['kind']);
  if (at === null || kind === null) return null;
  const detail: Record<string, string> = {};
  const source = raw['detail'];
  if (typeof source === 'object' && source !== null) {
    for (const [key, value] of Object.entries(source as Record<string, unknown>)) {
      if (value === null || value === undefined) continue;
      detail[key] =
        typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
          ? String(value)
          : '(not shown — this console does not understand this value)';
    }
  }
  return { at, kind, detail };
}

function list<T>(result: ApiResult<unknown>, parse: (row: unknown) => T | null): ApiResult<T[]> {
  if (!result.ok) return result;
  if (!Array.isArray(result.data)) return { ok: false, code: 'UNKNOWN' };
  const rows: T[] = [];
  for (const row of result.data) {
    const parsed = parse(row);
    // One unreadable row fails the list. See the module docstring: a short
    // worklist is indistinguishable from a quiet week.
    if (parsed === null) return { ok: false, code: 'UNKNOWN' };
    rows.push(parsed);
  }
  return { ok: true, data: rows };
}

function one<T>(result: ApiResult<unknown>, parse: (row: unknown) => T | null): ApiResult<T> {
  if (!result.ok) return result;
  const parsed = parse(result.data);
  return parsed === null ? { ok: false, code: 'UNKNOWN' } : { ok: true, data: parsed };
}

const CASES = '/api/settlement/cases';

export async function reviewQueue(): Promise<ApiResult<CaseSummary[]>> {
  return list(await request<unknown>('/api/settlement/queue'), parseCase);
}

export async function administrable(): Promise<ApiResult<CaseSummary[]>> {
  return list(await request<unknown>('/api/settlement/administrable'), parseCase);
}

export async function getCase(caseId: string): Promise<ApiResult<CaseSummary>> {
  return one(await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}`), parseCase);
}

export async function timeline(caseId: string): Promise<ApiResult<TimelineEvent[]>> {
  return list(
    await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/timeline`),
    parseTimeline,
  );
}

export async function stages(caseId: string): Promise<ApiResult<StageView[]>> {
  return list(await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/stages`), parseStage);
}

export async function distributions(caseId: string): Promise<ApiResult<DistributionView[]>> {
  return list(
    await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/distributions`),
    parseDistribution,
  );
}

// --------------------------------------------------------------------- verbs

export async function startReview(caseId: string): Promise<ApiResult<CaseSummary>> {
  return one(
    await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/review/start`, {
      method: 'POST',
    }),
    parseCase,
  );
}

/** The closed reason vocabulary a rejection must carry (settlement's schema). */
export const REJECTION_REASONS = [
  'insufficient_evidence',
  'fraud_suspected',
  'duplicate_report',
  'other',
] as const;
export type RejectionReason = (typeof REJECTION_REASONS)[number];

export async function decideReview(
  caseId: string,
  decision: 'approve' | 'reject',
  reason?: RejectionReason,
): Promise<ApiResult<CaseSummary>> {
  return one(
    await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/review`, {
      method: 'POST',
      body: decision === 'reject' ? { decision, reason } : { decision },
    }),
    parseCase,
  );
}

export async function confirmVerification(caseId: string): Promise<ApiResult<CaseSummary>> {
  return one(
    await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/verify`, { method: 'POST' }),
    parseCase,
  );
}

export async function closeCase(caseId: string): Promise<ApiResult<{ status: string }>> {
  const result = await request<unknown>(`${CASES}/${encodeURIComponent(caseId)}/close`, {
    method: 'POST',
  });
  if (!result.ok) return result;
  const status = str((result.data as Record<string, unknown>)['status']);
  return status === null ? { ok: false, code: 'UNKNOWN' } : { ok: true, data: { status } };
}

export async function decideStage(
  stageId: string,
  decision: 'approve' | 'deny',
): Promise<ApiResult<StageView>> {
  return one(
    await request<unknown>(`/api/settlement/stages/${encodeURIComponent(stageId)}/decision`, {
      method: 'POST',
      body: { decision },
    }),
    parseStage,
  );
}

export async function revokeStage(stageId: string): Promise<ApiResult<StageView>> {
  return one(
    await request<unknown>(`/api/settlement/stages/${encodeURIComponent(stageId)}/revoke`, {
      method: 'POST',
    }),
    parseStage,
  );
}

export async function approveDistribution(
  distributionId: string,
): Promise<ApiResult<DistributionView>> {
  return one(
    await request<unknown>(
      `/api/settlement/distributions/${encodeURIComponent(distributionId)}/approval`,
      { method: 'POST' },
    ),
    parseDistribution,
  );
}
