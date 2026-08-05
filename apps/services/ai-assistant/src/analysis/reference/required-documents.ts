import type { DocumentKind, ExecutionStatus } from '@estate/contracts';

/**
 * Which instruments an estate is EXPECTED to hold, and what triggers each
 * expectation (M10 PR3).
 *
 * WHY THIS ONE CARRIES NO REVIEW GATE, unlike `estate-tax.ts`. The tax table
 * states the law — a threshold, a rate — on the platform's authority, so an
 * unreviewed copy of it is a wrong claim about a statute. This file states
 * something weaker and checkable: that a person with minor children has no
 * guardian designation ON FILE HERE, that a will exists but has never been
 * executed. Those are facts about the user's own account, and the finding is
 * phrased as one. The expectation itself is the ordinary content of any
 * estate-planning checklist, and the analyser never asserts a legal requirement
 * or a deadline.
 *
 * The line to hold, then: a rule may condition on structure the platform can
 * see (household, asset categories, an existing trust). A rule that would need a
 * statute to justify it — a state-specific execution formality, a filing
 * deadline, a community-property characterization — belongs in reviewed data
 * with the tax table's gate, not here. `execution_requirements` already lives in
 * the M4 templates, sha256-pinned and legal-review-gated, and is the right home
 * for the first such rule.
 */

/** What makes an instrument expected for this particular estate. */
export type ExpectationTrigger =
  /** Everyone. The baseline of any estate plan. */
  | 'always'
  /** There is at least one family member recorded as a minor. */
  | 'minor_child'
  /** A revocable or irrevocable trust exists in the document set. */
  | 'trust_exists'
  /** A trust exists AND there is at least one asset not titled into it. */
  | 'trust_with_unfunded_assets';

export interface DocumentExpectation {
  /** The instrument kind, from the shared DOCUMENT_KINDS vocabulary. */
  readonly kind: DocumentKind;
  readonly trigger: ExpectationTrigger;
  /**
   * How much its absence matters. `high` is reserved for the instruments whose
   * absence has an immediate, concrete consequence: dying intestate, or nobody
   * being able to act for you while you are alive but incapacitated.
   */
  readonly severity: 'high' | 'medium';
  /**
   * Instruments that satisfy this expectation INSTEAD of `kind` — the reason a
   * trust-based plan does not get nagged about a standalone will. A will is
   * satisfied by a revocable trust paired with a pour-over will, and a financial
   * POA by a durable POA, because those are the same instrument under two names
   * in different states' vocabulary.
   */
  readonly satisfiedAlsoBy: readonly DocumentKind[];
}

/**
 * The matrix. Ordered by how much the absence matters, because the analyser
 * emits findings in this order and a list that opens with "no HIPAA
 * authorization" while the user has no will is a list nobody reads twice.
 */
export const DOCUMENT_EXPECTATIONS: readonly DocumentExpectation[] = [
  {
    kind: 'will',
    trigger: 'always',
    severity: 'high',
    // A funded revocable trust plus a pour-over will is the other standard
    // shape; either satisfies "something directs what happens to the estate".
    satisfiedAlsoBy: ['revocable_trust', 'pour_over_will'],
  },
  {
    kind: 'durable_poa',
    trigger: 'always',
    severity: 'high',
    satisfiedAlsoBy: ['financial_poa'],
  },
  {
    kind: 'medical_poa',
    trigger: 'always',
    severity: 'high',
    satisfiedAlsoBy: ['mental_health_poa'],
  },
  {
    // The one instrument whose absence is felt by someone else entirely: with
    // no designation on file, who raises a minor child is decided by a court.
    kind: 'guardian_designation',
    trigger: 'minor_child',
    severity: 'high',
    satisfiedAlsoBy: [],
  },
  {
    kind: 'living_will',
    trigger: 'always',
    severity: 'medium',
    satisfiedAlsoBy: [],
  },
  {
    kind: 'hipaa_auth',
    trigger: 'always',
    severity: 'medium',
    satisfiedAlsoBy: [],
  },
  {
    // A trust nobody can prove exists is a trust that gets argued with at a
    // bank counter.
    kind: 'certification_of_trust',
    trigger: 'trust_exists',
    severity: 'medium',
    satisfiedAlsoBy: [],
  },
  {
    // The paperwork that actually moves an asset into the trust. Expected only
    // when there is something left to move — otherwise the checklist nags a
    // user whose funding is complete.
    kind: 'funding_letter',
    trigger: 'trust_with_unfunded_assets',
    severity: 'medium',
    satisfiedAlsoBy: ['property_assignment'],
  },
];

/**
 * Document kinds that are, or contain, a trust.
 *
 * Declared through `DocumentKind` so a typo is a compile error, but exposed as a
 * `Set<string>` because every consumer tests it against `DocumentView.docType`,
 * which is a peer service's string — the client deliberately does not narrow it
 * to an enum, so that a kind documents adds later reads as an unfamiliar type
 * rather than failing the whole read closed.
 */
export const TRUST_KINDS: ReadonlySet<string> = new Set<DocumentKind>([
  'revocable_trust',
  'irrevocable_trust',
]);

/**
 * Execution states that mean an instrument is NOT yet operative.
 *
 * A generated-but-unsigned will is the most dangerous document in the vault: it
 * looks like a plan and directs nothing. `revoked` and `superseded` are not here
 * because a document in either state is deliberately out of force — the analyser
 * treats it as absent instead, which is what it is.
 */
export const UNEXECUTED_STATUSES: ReadonlySet<string> = new Set<ExecutionStatus>([
  'draft',
  'generated',
  'signed',
  'witnessed',
  'notarized',
]);

/** Execution states that mean the document no longer counts as present at all. */
export const RETIRED_STATUSES: ReadonlySet<string> = new Set<ExecutionStatus>([
  'revoked',
  'superseded',
]);
