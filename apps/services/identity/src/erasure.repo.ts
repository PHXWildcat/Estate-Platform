import { Injectable } from '@nestjs/common';
import type { ErasureDomain, ErasureRequestStatus } from '@estate/contracts';
import type { Queryable } from './db';

/** A live or historical erasure request, as the service hands it out. */
export interface ErasureRequestRow {
  id: string;
  user_id: string;
  status: ErasureRequestStatus;
  requested_at: Date;
  cancelled_at: Date | null;
}

/** The columns every statement here returns, so the shape cannot drift. */
const REQUEST_COLUMNS = 'id, user_id, status, requested_at, cancelled_at';

/**
 * The erasure request record (M25 PR2).
 *
 * Every statement here carries its own precondition. The rule is the one
 * `.claude/rules/db-migrations.md` states for the settlement lock: a check that
 * must hold AT THE WRITE is restated inside the statement's own `WHERE`, never
 * read above it — a pre-transaction read and the write it guards are separated
 * by every commit that lands in between, and the whole point of this record is
 * that something irreversible reads it later.
 */
@Injectable()
export class ErasureRepo {
  /**
   * Record a request, but only for an account the status allowlist admits.
   *
   * THE ALLOWLIST TRAVELS IN THE STATEMENT. `INSERT ... SELECT ... WHERE
   * EXISTS` means a status change committing between the caller's session
   * lookup and this write cannot produce a request against an account that has
   * since been locked or moved into settlement. Zero rows back is "refused or
   * already requested" and the caller re-reads to tell those apart — it never
   * infers a reason from the row count.
   *
   * `ON CONFLICT DO NOTHING` inferred on the live partial index makes a second
   * concurrent request a no-op rather than a unique violation. Catching that
   * violation inside a transaction would abort it and refuse every subsequent
   * statement, which is the trap the repo's rules name explicitly.
   */
  async insertIfPermitted(
    tx: Queryable,
    userId: string,
    sessionId: string | null,
    permittedStatuses: readonly string[],
  ): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `INSERT INTO erasure_requests (user_id, requested_by_session)
       SELECT $1, $2
        WHERE EXISTS (
                SELECT 1 FROM users
                 WHERE id = $1
                   AND deleted_at IS NULL
                   AND status = ANY($3))
       ON CONFLICT (user_id) WHERE status IN ('pending','executing') AND deleted_at IS NULL
       DO NOTHING
       RETURNING ${REQUEST_COLUMNS}`,
      [userId, sessionId, [...permittedStatuses]],
    );
    return rows[0] ?? null;
  }

  /**
   * The caller's live request, if there is one.
   *
   * LIVE IS TWO STATES SINCE M25 PR3, and this predicate must stay the same
   * one the partial unique index uses. They answer the same question — is a
   * request already outstanding for this owner — from opposite ends: the index
   * refuses a second insert, this read tells the first one apart from a
   * refusal. If they disagree, `request()` reports a conflict nobody can see.
   */
  async findLive(tx: Queryable, userId: string): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `SELECT ${REQUEST_COLUMNS}
         FROM erasure_requests
        WHERE user_id = $1 AND status IN ('pending','executing') AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0] ?? null;
  }

  /**
   * Cancel the live request. Returns null when there was nothing to cancel,
   * which is a normal answer and not an error: the protective verb must be
   * safe to press twice.
   *
   * ONLY 'pending' IS CANCELLABLE, and the narrowing is the M25 PR3 boundary
   * rather than an oversight. Once the driver has claimed a request it is
   * destroying keys, and a cancel that answered "withdrawn" while a DEK was
   * being shredded would be the worst lie this product could tell. The caller
   * re-reads and reports the live state instead, so "too late" and "there was
   * nothing to cancel" never share an answer — two outcomes, two remedies.
   *
   * NO STATUS ALLOWLIST ON THE ACCOUNT, deliberately. Cancelling is the de-escalating
   * direction, and an account that became ineligible to REQUEST erasure while a
   * request was live must still be able to withdraw it — refusing the
   * withdrawal because the account is now locked would strand the most
   * dangerous record in the system in its armed state.
   */
  async cancel(tx: Queryable, userId: string, at: Date): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `UPDATE erasure_requests
          SET status = 'cancelled', cancelled_at = $2
        WHERE user_id = $1 AND status = 'pending' AND deleted_at IS NULL
       RETURNING ${REQUEST_COLUMNS}`,
      [userId, at],
    );
    return rows[0] ?? null;
  }

  /**
   * Claim ONE request that is due for execution, moving it 'pending' →
   * 'executing'. Returns null when nothing is due.
   *
   * THE GRACE PERIOD IS WHAT MAKES CANCEL MEAN ANYTHING. `requested_at <= $1`
   * is the whole waiting period: without it the driver would execute a request
   * the instant it was made and PR2's ungated cancel would be a button that can
   * never be pressed in time. The protective action must never be harder than
   * the permissive one, and a window too short to use is the same as no window.
   *
   * ELIGIBILITY IS RESTATED HERE because the request may be days old. An
   * account that moved to `deceased_pending` or `settlement` since the owner
   * asked must not be erased on the strength of a check made before that
   * happened — the pre-transaction-read rule, with an unusually long gap.
   *
   * `FOR UPDATE SKIP LOCKED` so two drivers cannot claim the same request and
   * neither blocks on the other. `ORDER BY requested_at` so the oldest request
   * is not starved by a steady arrival of newer ones.
   */
  async claimDue(
    tx: Queryable,
    cutoff: Date,
    at: Date,
    permittedStatuses: readonly string[],
  ): Promise<ErasureRequestRow | null> {
    const rows = await tx.query<ErasureRequestRow>(
      `UPDATE erasure_requests
          SET status = 'executing', started_at = $2
        WHERE id = (
                SELECT r.id
                  FROM erasure_requests r
                  JOIN users u ON u.id = r.user_id
                 WHERE r.status = 'pending'
                   AND r.deleted_at IS NULL
                   AND r.requested_at <= $1
                   AND u.deleted_at IS NULL
                   AND u.status = ANY($3)
                 ORDER BY r.requested_at
                   FOR UPDATE OF r SKIP LOCKED
                 LIMIT 1)
       RETURNING ${REQUEST_COLUMNS}`,
      [cutoff, at, [...permittedStatuses]],
    );
    return rows[0] ?? null;
  }

  /**
   * Hand a claim back. The account became ineligible between the claim and the
   * work, so nothing was destroyed and the request returns to 'pending'.
   *
   * RELEASING RATHER THAN FAILING is the choice that keeps the owner in
   * control. A request wedged in 'executing' would be uncancellable (see
   * `cancel`) AND would block a new one through the live index — the erasure
   * feature locked shut for that account, by a race. Back on 'pending' it is
   * cancellable, retried on the next tick, and self-heals if the account
   * returns to an eligible status.
   */
  async releaseClaim(tx: Queryable, requestId: string): Promise<void> {
    await tx.query(
      `UPDATE erasure_requests
          SET status = 'pending', started_at = NULL
        WHERE id = $1 AND status = 'executing'`,
      [requestId],
    );
  }

  /**
   * Open a ledger row for every participant domain. Idempotent, because the
   * driver is resumable: a crash after the claim re-runs this, and a domain
   * already marked done must not be reset to 'pending' by the retry.
   */
  async seedDomains(
    tx: Queryable,
    requestId: string,
    domains: readonly ErasureDomain[],
  ): Promise<void> {
    await tx.query(
      `INSERT INTO erasure_domain_progress (request_id, domain)
       SELECT $1, d FROM unnest($2::text[]) AS d
       ON CONFLICT (request_id, domain) DO NOTHING`,
      [requestId, [...domains]],
    );
  }

  /** Record that a domain finished. Idempotent for the same reason. */
  async markDomainDone(tx: Queryable, requestId: string, domain: ErasureDomain): Promise<void> {
    await tx.query(
      `UPDATE erasure_domain_progress
          SET state = 'done'
        WHERE request_id = $1 AND domain = $2 AND state <> 'done'`,
      [requestId, domain],
    );
  }

  /**
   * Finish the request, but ONLY when the ledger says every domain is done.
   *
   * THE COMPLETENESS TEST TRAVELS IN THE STATEMENT — a `NOT EXISTS` over the
   * ledger rather than a count compared in TypeScript. A count would have to
   * know how many domains there are, which is the hand-list this whole design
   * avoids; and a count read before the write is a check-then-act against a
   * table another domain's worker will one day be writing to.
   *
   * Returns false in M25 for every request, because seven domains have no
   * transport to report. That is the honest answer, not a bug: `completed`
   * means every domain, and the reach is what grows.
   */
  async completeIfAllDone(tx: Queryable, requestId: string, at: Date): Promise<boolean> {
    const rows = await tx.query<{ id: string }>(
      `UPDATE erasure_requests
          SET status = 'completed', completed_at = $2
        WHERE id = $1
          AND status = 'executing'
          AND NOT EXISTS (
                SELECT 1 FROM erasure_domain_progress
                 WHERE request_id = $1 AND state <> 'done')
       RETURNING id`,
      [requestId, at],
    );
    return rows.length > 0;
  }

  /** The account status the refusal message is derived from. */
  async statusOf(tx: Queryable, userId: string): Promise<string | null> {
    const rows = await tx.query<{ status: string }>(
      `SELECT status FROM users WHERE id = $1 AND deleted_at IS NULL`,
      [userId],
    );
    return rows[0]?.status ?? null;
  }
}
