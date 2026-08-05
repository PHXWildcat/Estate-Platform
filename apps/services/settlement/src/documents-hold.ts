import { SERVICE_CREDENTIAL_HEADER } from '@estate/auth-guard';
import { z } from 'zod';
import type { FetchLike } from './identity-lock';

/** Thrown on ANY failure — network, non-2xx, contract drift. The service maps
 * it to 503 documents_unavailable and the surrounding transaction rolls back:
 * a case transition whose legal-hold effect cannot be confirmed does not
 * happen. Fail closed — an estate entering administration must not silently
 * keep its documents deletable, and a case resolving as not-a-death must not
 * silently leave a hold behind. */
export class DocumentsHoldError extends Error {
  constructor() {
    super('documents legal-hold call failed');
    this.name = 'DocumentsHoldError';
  }
}

/**
 * The documents half of the estate-wide legal hold, as settlement sees it
 * (M9 PR2 — the caller that closes the M4 zero-callers gap). One operation:
 * set or clear the hold on every live document the decedent owns.
 * Authenticated by the documents service credential — there is no user bearer
 * for this call by construction (the decedent cannot present one, and an
 * operator's token must not carry hold power). The documents side is
 * idempotent, so settlement can re-drive it after a commit failure.
 */
export interface DocumentsHoldPort {
  setHold(ownerUserId: string, hold: boolean, caseId: string): Promise<void>;
}

const SetHoldResponseSchema = z.object({ changed: z.number() });

export interface HttpDocumentsHoldOptions {
  documentsUrl: string;
  /** The documents service credential ('' ⇒ documents refuses; calls fail closed). */
  credential: string;
  fetchImpl?: FetchLike;
}

export class HttpDocumentsHold implements DocumentsHoldPort {
  private readonly documentsUrl: string;
  private readonly credential: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpDocumentsHoldOptions) {
    this.documentsUrl = options.documentsUrl.replace(/\/$/, '');
    this.credential = options.credential;
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  async setHold(ownerUserId: string, hold: boolean, caseId: string): Promise<void> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.documentsUrl}/internal/v1/legal-hold`, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          [SERVICE_CREDENTIAL_HEADER]: this.credential,
        },
        body: JSON.stringify({ ownerUserId, hold, caseId }),
      });
    } catch {
      throw new DocumentsHoldError();
    }
    if (!response.ok) {
      throw new DocumentsHoldError();
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new DocumentsHoldError();
    }
    if (!SetHoldResponseSchema.safeParse(body).success) {
      throw new DocumentsHoldError(); // contract drift ⇒ fail closed, never guess
    }
  }
}
