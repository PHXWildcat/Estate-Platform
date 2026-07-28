import { z } from 'zod';

/** DI token consumers use to inject the client (or a test double). */
export const SETTLEMENT_AUTHORITY = Symbol('SETTLEMENT_AUTHORITY');

/** Header carrying the service credential on state questions that have no
 * user bearer to forward. Mirrors @estate/auth-guard's constant; duplicated
 * rather than imported so this package keeps a zero-workspace-dependency tree
 * (it is consumed by four services, including Zone A's vault). */
export const SERVICE_CREDENTIAL_HEADER = 'x-estate-service-credential';

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string> },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** The staged-access ladder (docs/03 §5.1 control 5). Vault is LAST by design. */
export const ACCESS_STAGES = ['inventory', 'documents', 'vault'] as const;
export type AccessStage = (typeof ACCESS_STAGES)[number];

/**
 * Answer to "may this caller read this document version as case evidence?".
 * `caseId` accompanies an allow so the consumer can audit which case the
 * authority derives from.
 */
export type EvidenceReadAuthority =
  { allowed: true; caseId: string; ownerUserId: string } | { allowed: false };

/** Answer to "may this caller act on this estate at this stage?". */
export type StageAccessAuthority = { allowed: true; caseId: string } | { allowed: false };

/**
 * Answer to "may vault emergency access proceed for this owner?".
 * NOT caller-scoped: this is a question about the OWNER's settlement state, so
 * it is authenticated by the service credential rather than by a grantee's
 * bearer token — a grantee must never be able to mint their own authority.
 */
export type VaultReleaseAuthority = { permitted: boolean; caseId: string | null };

const EvidenceReadResponseSchema = z.object({
  allowed: z.boolean(),
  caseId: z.string().uuid().nullable(),
  ownerUserId: z.string().uuid().nullable(),
});

const StageAccessResponseSchema = z.object({
  allowed: z.boolean(),
  caseId: z.string().uuid().nullable(),
});

const VaultReleaseResponseSchema = z.object({
  permitted: z.boolean(),
  caseId: z.string().uuid().nullable(),
});

/**
 * The evidence question (documents service). Split from the other two so each
 * consumer depends only on the question it asks — a vault test double should
 * not have to stub document authority, and vice versa.
 */
export interface SettlementEvidenceAuthority {
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

/** The staged-access question (assets service, and any later data service). */
export interface SettlementStageAuthority {
  /**
   * May the caller behind `bearerToken` act on `ownerUserId`'s estate at
   * `stage`? True only when a verified case exists, the caller is its
   * executor, and that stage has been separately approved by an operator.
   */
  checkStageAccess(input: {
    bearerToken: string;
    ownerUserId: string;
    stage: AccessStage;
  }): Promise<StageAccessAuthority>;
}

/** The Zone A gate (vault service) — docs/03 §6a's M7 integration point. */
export interface SettlementVaultGate {
  /**
   * May vault emergency access proceed for `ownerUserId`? Permitted when the
   * owner has no non-terminal settlement case at all, or has one whose `vault`
   * stage is approved. A pending case with an unapproved vault stage BLOCKS —
   * a death report must make emergency access harder, never easier.
   */
  checkVaultRelease(input: { ownerUserId: string }): Promise<VaultReleaseAuthority>;
}

export interface SettlementAuthority
  extends SettlementEvidenceAuthority, SettlementStageAuthority, SettlementVaultGate {}

export interface HttpSettlementAuthorityOptions {
  /** Base URL of the settlement service (e.g. http://settlement:3007). */
  settlementUrl: string;
  /** Shared service credential for the non-caller-scoped vault gate. Absent
   * ⇒ that question fails closed (settlement refuses, so release is blocked). */
  serviceCredential?: string;
  fetchImpl?: FetchLike;
}

const REFUSED_EVIDENCE: EvidenceReadAuthority = { allowed: false };
const REFUSED_STAGE: StageAccessAuthority = { allowed: false };
/** The fail-closed vault answer: NOT permitted, no case attributed. */
const BLOCKED_RELEASE: VaultReleaseAuthority = { permitted: false, caseId: null };

/**
 * HTTP implementation against settlement's authority endpoints. Fails CLOSED
 * on every path: a non-2xx, a malformed body, or a network error is a refusal
 * — an unreachable settlement service must never widen access (the
 * HttpSessionVerifier and notification-gate precedents). Deliberately no
 * cache: authority answers gate rare, sensitive actions where freshness is
 * worth a round trip.
 */
export class HttpSettlementAuthority implements SettlementAuthority {
  private readonly settlementUrl: string;
  private readonly serviceCredential: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpSettlementAuthorityOptions) {
    this.settlementUrl = options.settlementUrl.replace(/\/$/, '');
    this.serviceCredential = options.serviceCredential ?? '';
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /** GET + parse, or null on ANY failure. The callers turn null into their own
   * fail-closed answer. */
  private async getJson(path: string, headers: Record<string, string>): Promise<unknown> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.settlementUrl}${path}`, { method: 'GET', headers });
    } catch {
      return null; // network/DNS failure ⇒ refusal (fail closed)
    }
    if (!response.ok) {
      return null;
    }
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  async checkEvidenceRead(input: {
    bearerToken: string;
    documentId: string;
    version: number;
  }): Promise<EvidenceReadAuthority> {
    if (!input.bearerToken) {
      return REFUSED_EVIDENCE;
    }
    const query = new URLSearchParams({
      documentId: input.documentId,
      version: String(input.version),
    });
    const body = await this.getJson(`/v1/settlement/authority/evidence-read?${query.toString()}`, {
      authorization: `Bearer ${input.bearerToken}`,
    });
    const parsed = EvidenceReadResponseSchema.safeParse(body);
    if (!parsed.success) {
      return REFUSED_EVIDENCE; // contract drift ⇒ fail closed, never guess
    }
    if (!parsed.data.allowed || !parsed.data.caseId || !parsed.data.ownerUserId) {
      return REFUSED_EVIDENCE;
    }
    return { allowed: true, caseId: parsed.data.caseId, ownerUserId: parsed.data.ownerUserId };
  }

  async checkStageAccess(input: {
    bearerToken: string;
    ownerUserId: string;
    stage: AccessStage;
  }): Promise<StageAccessAuthority> {
    if (!input.bearerToken) {
      return REFUSED_STAGE;
    }
    const query = new URLSearchParams({ ownerUserId: input.ownerUserId, stage: input.stage });
    const body = await this.getJson(`/v1/settlement/authority/stage-access?${query.toString()}`, {
      authorization: `Bearer ${input.bearerToken}`,
    });
    const parsed = StageAccessResponseSchema.safeParse(body);
    if (!parsed.success || !parsed.data.allowed || !parsed.data.caseId) {
      return REFUSED_STAGE;
    }
    return { allowed: true, caseId: parsed.data.caseId };
  }

  async checkVaultRelease(input: { ownerUserId: string }): Promise<VaultReleaseAuthority> {
    if (!this.serviceCredential) {
      // Unwired credential ⇒ settlement would refuse anyway; block locally and
      // save the round trip. Emergency release stays closed until both sides
      // are provisioned, which is the safe direction for Zone A.
      return BLOCKED_RELEASE;
    }
    const query = new URLSearchParams({ ownerUserId: input.ownerUserId });
    const body = await this.getJson(`/v1/settlement/authority/vault-release?${query.toString()}`, {
      [SERVICE_CREDENTIAL_HEADER]: this.serviceCredential,
    });
    const parsed = VaultReleaseResponseSchema.safeParse(body);
    if (!parsed.success) {
      return BLOCKED_RELEASE;
    }
    return { permitted: parsed.data.permitted, caseId: parsed.data.caseId };
  }
}
