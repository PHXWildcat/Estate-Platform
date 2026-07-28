import { SERVICE_CREDENTIAL_HEADER } from '@estate/auth-guard';
import { z } from 'zod';

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export type LockState = 'deceased_pending' | 'settlement' | 'active';

export interface LivenessAnswer {
  status: string;
  lastStepUpAt: Date | null;
}

/** Thrown on ANY failure — network, non-2xx, contract drift. The service maps
 * it to 503 identity_unavailable and the surrounding transaction rolls back:
 * a case transition whose account-lock effect cannot be confirmed does not
 * happen (docs/03 §5.1 control 4, fail closed). */
export class IdentityLockError extends Error {
  constructor() {
    super('identity settlement-lock call failed');
    this.name = 'IdentityLockError';
  }
}

/**
 * Identity refused the terminal transition because the owner proved liveness
 * after the case opened — the docs/03 §5.1 interlock firing atomically with
 * the status write, catching a step-up that landed after settlement's own
 * liveness read. Distinct from IdentityLockError: this is an ANSWER (the owner
 * is alive), not a failure, and the case must be voided.
 */
export class OwnerAliveError extends Error {
  constructor() {
    super('identity refused: owner proved liveness after the case opened');
    this.name = 'OwnerAliveError';
  }
}

/**
 * The identity half of the cross-service account lock, as settlement sees it.
 * Two operations: put the account into a settlement lock state, and read the
 * owner-liveness answer (last step-up grant) for the verification re-check.
 * Authenticated by the shared service credential — there is no user bearer
 * token for these calls by construction (the decedent cannot present one).
 */
export interface IdentityLockPort {
  /**
   * `livenessNotAfter` (the case's opening instant) makes identity re-evaluate
   * owner liveness in the SAME statement as the status write; it throws
   * OwnerAliveError instead of locking out an owner who just proved they are
   * alive. Passed on the terminal `settlement` transition.
   */
  setState(
    userId: string,
    state: LockState,
    caseId: string,
    livenessNotAfter?: Date,
  ): Promise<void>;
  liveness(userId: string): Promise<LivenessAnswer>;
}

const SetStateResponseSchema = z.object({ status: z.string() });

const LivenessResponseSchema = z.object({
  status: z.string(),
  lastStepUpAt: z.string().datetime().nullable(),
});

export interface HttpIdentityLockOptions {
  identityUrl: string;
  /** The shared service credential ('' ⇒ identity refuses; calls fail closed). */
  credential: string;
  fetchImpl?: FetchLike;
}

export class HttpIdentityLock implements IdentityLockPort {
  private readonly identityUrl: string;
  private readonly credential: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpIdentityLockOptions) {
    this.identityUrl = options.identityUrl.replace(/\/$/, '');
    this.credential = options.credential;
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  async setState(
    userId: string,
    state: LockState,
    caseId: string,
    livenessNotAfter?: Date,
  ): Promise<void> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.identityUrl}/internal/v1/settlement-lock/${userId}`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          [SERVICE_CREDENTIAL_HEADER]: this.credential,
        },
        body: JSON.stringify({
          state,
          caseId,
          ...(livenessNotAfter ? { livenessNotAfter: livenessNotAfter.toISOString() } : {}),
        }),
      });
    } catch {
      throw new IdentityLockError();
    }
    if (!response.ok) {
      // 409 owner_alive is an ANSWER, not an outage: the liveness interlock
      // fired atomically with the write, so the case must be voided instead.
      if (response.status === 409) {
        let refusal: unknown;
        try {
          refusal = await response.json();
        } catch {
          throw new IdentityLockError();
        }
        if (
          typeof refusal === 'object' &&
          refusal !== null &&
          (refusal as { error?: unknown }).error === 'owner_alive'
        ) {
          throw new OwnerAliveError();
        }
      }
      throw new IdentityLockError();
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new IdentityLockError();
    }
    if (!SetStateResponseSchema.safeParse(body).success) {
      throw new IdentityLockError(); // contract drift ⇒ fail closed, never guess
    }
  }

  async liveness(userId: string): Promise<LivenessAnswer> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(
        `${this.identityUrl}/internal/v1/settlement-lock/${userId}/liveness`,
        {
          method: 'GET',
          headers: { [SERVICE_CREDENTIAL_HEADER]: this.credential },
        },
      );
    } catch {
      throw new IdentityLockError();
    }
    if (!response.ok) {
      throw new IdentityLockError();
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new IdentityLockError();
    }
    const parsed = LivenessResponseSchema.safeParse(body);
    if (!parsed.success) {
      throw new IdentityLockError();
    }
    return {
      status: parsed.data.status,
      lastStepUpAt: parsed.data.lastStepUpAt ? new Date(parsed.data.lastStepUpAt) : null,
    };
  }
}
