/**
 * Sign-off metadata for LEGAL AND TAX REFERENCE DATA, and the gate that keeps
 * unreviewed exemplars out of production (M10 PR3).
 *
 * This is the M4 template rule applied one domain over. Templates are "versioned
 * like code" with a schema-mandatory `legalReview` block, and the publish CLI
 * refuses placeholder sign-off when `NODE_ENV=production` — because a will
 * generated from an attorney-unreviewed template is a legal instrument nobody
 * signed off. The federal exemption, a state's estate-tax threshold and the list
 * of instruments a married parent in Texas is expected to hold are the same kind
 * of fact: they are law, they change, and they are wrong to state on the
 * platform's authority without someone qualified having said so.
 *
 * WHAT THIS SHIPS WITH IS EXEMPLARS. No attorney and no CPA has reviewed
 * anything in this repository, so every dataset below carries
 * `reviewedBy: UNREVIEWED_EXEMPLAR` and every analyser built on one REFUSES in
 * production — the M6/M7 pattern where a capability that cannot be exercised
 * safely answers with a control firing rather than with a plausible number. In
 * development the analysers run fully, which is what makes them testable, and
 * docs/05 says plainly that a green analyser in the stack is not evidence of a
 * reviewed tax table.
 *
 * The alternative — ship the numbers, add a disclaimer, hope — is worse in a
 * specific way: a user reading "your estate is $2.1M under the federal
 * exemption" does not experience that as a hypothesis. Estate-tax exposure is
 * the finding most likely to change what someone actually does.
 */

/** Who signed off on one reference dataset, when, and against what. */
export interface ReferenceReview {
  /** A person or firm, or `UNREVIEWED_EXEMPLAR`. Never a bare "TODO". */
  readonly reviewedBy: string;
  /** ISO date of the review. Reference data goes stale on a schedule. */
  readonly reviewedAt: string;
  /** What was consulted — a statute, a revenue procedure, an agency page. */
  readonly source: string;
  /**
   * The tax year or effective year the figures state. Distinct from
   * `reviewedAt`: a table reviewed in March 2026 may state 2026 figures, and a
   * table reviewed in 2024 stating 2024 figures is stale even though somebody
   * qualified did look at it.
   */
  readonly effectiveYear: number;
}

/**
 * The sentinel that marks a dataset nobody qualified has approved. A distinct
 * constant rather than an empty string so a half-filled block ("reviewedBy: ''")
 * reads as unreviewed too — `isReviewed` below treats anything falsy the same
 * way, because the failure mode to defend against is a well-meaning edit that
 * clears the sentinel without adding a reviewer.
 */
export const UNREVIEWED_EXEMPLAR = 'unreviewed-exemplar';

/** True only when a named reviewer, a date and a source are all present. */
export function isReviewed(review: ReferenceReview): boolean {
  return (
    review.reviewedBy.trim().length > 0 &&
    review.reviewedBy !== UNREVIEWED_EXEMPLAR &&
    review.reviewedAt.trim().length > 0 &&
    review.source.trim().length > 0
  );
}

/**
 * Whether an analyser built on this dataset may run in this environment.
 *
 * Production requires review. Everywhere else runs, deliberately: an exemplar
 * that never executes is an exemplar nobody tests, and the analysers' logic —
 * which is what PR3 is actually shipping — is worth exercising against numbers
 * whose exact values will be replaced.
 */
export function referenceUsable(
  review: ReferenceReview,
  nodeEnv: 'development' | 'test' | 'production',
): boolean {
  return nodeEnv !== 'production' || isReviewed(review);
}
