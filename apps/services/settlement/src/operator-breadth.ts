/**
 * THE OPERATOR BREADTH BOUND, declared as data.
 *
 * ═══ WHAT IT MODELS, AND WHY IT IS NOT A VOLUME CAP ═══
 *
 * The threat is a compromised or rogue operator moving ACROSS estates: fifty
 * cases touched once each in an hour. The naive framing — cap the number of
 * privileged actions per operator — measures the opposite population. A
 * legitimate reviewer working one complicated estate can fire thirty actions on
 * it in a morning and would hit a volume cap first, while the attacker above
 * sits comfortably under it. So the bound counts DISTINCT CASES, and an
 * operator may do as much work as they like on an estate they are genuinely
 * administering.
 *
 * ═══ WHY IT WARNS AND DOES NOT REFUSE (this slice) ═══
 *
 * Settlement's human review is mandatory and time-sensitive: docs/03 §5.1 makes
 * a person the control, not a formality. Refusing a reviewer mid-case on a
 * ceiling nobody has production data for can do more harm than the operator it
 * models — the failure mode is a family waiting on a death case while the
 * platform declines to let anybody act.
 *
 * So this slice ships the LEDGER and the DETECTION, and the action proceeds.
 * The warning is an append-only audit event, which is the surface that already
 * carries every other operator action. Turning it into a refusal is a change to
 * `onExceeded` here, once there are real numbers behind the ceiling.
 *
 * This is deliberately NOT a disabled control pretending to be an enabled one:
 * `settlement.operator.breadth_exceeded` fires, is asserted by tests, and is a
 * closed-vocabulary audit action like every other. A silent counter would be
 * the thing worth objecting to.
 *
 * ═══ WHAT IS COUNTED, AND WHAT MUST NEVER BE ═══
 *
 * Only PERMISSIVE actions — the ones that grant, approve, verify or advance.
 * `revokeStage` and every deny arm are absent BY CONSTRUCTION, not by
 * filtering: they never call `record`. CLAUDE.md's rule is that the protective
 * action must never be harder than the permissive one, and a bound that counted
 * revocations would make withdrawing access the thing that runs out first —
 * precisely inverted, and exactly the defect identity's step-up cap hit when
 * its refusal blocked the one action that would have helped.
 *
 * The constants are REVIEWED, not configuration. A ceiling that can be raised
 * by an environment variable is a ceiling an attacker who reaches the
 * environment can raise (the `stepup.ts` precedent).
 */

/** How far back the bound looks. */
export const OPERATOR_BREADTH_WINDOW_MS = 60 * 60 * 1000;

/**
 * Distinct estates one operator may touch inside the window before the warning
 * fires. Set from the shape of the work rather than from data, and said plainly
 * so the first person with real numbers knows it is a guess: an operator
 * genuinely administering estates handles a handful concurrently, not dozens.
 */
export const OPERATOR_BREADTH_MAX_CASES = 12;

/**
 * The permissive operator actions, and the ONE spelling of that set.
 *
 * Every member records to the ledger. `operator-breadth-fence.spec.ts` derives
 * the operator-gated verbs from the source and asserts this list covers them,
 * so a seventh permissive verb cannot be added without either recording or
 * being declared as deliberately exempt. A hand-maintained list beside a thing
 * that grows is this repo's most repeated defect; this one is checked.
 */
export const PERMISSIVE_OPERATOR_ACTIONS = [
  'review.started',
  'review.approved',
  'verification.confirmed',
  'stage.approved',
  'distribution.approved',
  'case.closed',
] as const;

export type PermissiveOperatorAction = (typeof PERMISSIVE_OPERATOR_ACTIONS)[number];

/**
 * PROTECTIVE actions, named here so the exclusion is a DECLARATION rather than
 * an absence somebody has to notice. Nothing reads this list at runtime — it
 * exists so the fence can assert that none of these ever reaches `record`.
 */
export const PROTECTIVE_OPERATOR_ACTIONS = [
  'stage.revoked',
  'review.rejected',
  'stage.denied',
] as const;

/** Did this operator's breadth cross the ceiling? */
export function breadthExceeded(distinctCases: number): boolean {
  return distinctCases > OPERATOR_BREADTH_MAX_CASES;
}
