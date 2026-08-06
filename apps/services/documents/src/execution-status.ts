import type { ExecutionStatus } from '@estate/contracts';
import type { ExecutionRequirements } from './template-model';

/**
 * The execution-status state machine (docs/02 §4 lifecycle), parameterized by
 * the template's per-state execution requirements: the attestation ladder
 * only contains the steps THIS state's law requires for THIS instrument.
 * A required step can never be skipped; an unrequired step never appears.
 *
 * Manual transitions (owner attests real-world acts; the platform records,
 * it does not witness):
 *   draft/generated → signed → [witnessed] → [notarized] → executed
 *   signed|witnessed|notarized|executed → revoked
 *   executed → superseded
 * `draft → generated` is NOT here: it happens only through the generation
 * pipeline. Terminal statuses (revoked, superseded) allow nothing further.
 */

/** The attestation ladder for a given requirements profile. */
export function attestationLadder(requirements: ExecutionRequirements): ExecutionStatus[] {
  const ladder: ExecutionStatus[] = ['signed'];
  if (requirements.witnesses > 0) {
    ladder.push('witnessed');
  }
  if (requirements.notarization) {
    ladder.push('notarized');
  }
  ladder.push('executed');
  return ladder;
}

export function allowedTransitions(
  current: ExecutionStatus,
  requirements: ExecutionRequirements,
): ExecutionStatus[] {
  const ladder = attestationLadder(requirements);
  switch (current) {
    case 'draft':
    case 'generated':
      return ['signed'];
    case 'signed':
    case 'witnessed':
    case 'notarized': {
      const index = ladder.indexOf(current);
      // `current` can be absent from the ladder when requirements changed
      // between template versions; the only way forward then is revocation.
      const next = index >= 0 ? ladder.slice(index + 1, index + 2) : [];
      return [...next, 'revoked'];
    }
    case 'executed':
      return ['revoked', 'superseded'];
    case 'revoked':
    case 'superseded':
      return [];
  }
}

/**
 * What remains available when the template's formalities CANNOT BE VERIFIED —
 * de-escalation, and nothing else.
 *
 * WHY THIS EXISTS. `requirementsFor` fails closed when the ladder cannot be
 * read from a sha256-verified template (a soft-deleted row, a body_sha256
 * mismatch), and M12 PR2 first read that as "offer nothing at all". But
 * `allowedTransitions` computes `revoked` — from every attested status — and
 * `superseded` WITHOUT EVER READING `requirements`. Withdrawing those meant an
 * unverifiable template stripped the owner's only way back out of an attested
 * status, permanently, since nothing re-verifies a template that is gone. That
 * inverts the M6 rule that THE PROTECTIVE ACTION MUST NEVER BE HARDER THAN THE
 * PERMISSIVE ONE: an owner who cannot prove a witness requirement must still
 * be able to revoke.
 *
 * THE LINE IS ADVANCE vs DE-ESCALATE, not requirement-dependent vs not.
 * `signed` is technically requirement-independent — it is the first rung of
 * every profile — but permitting it would still let the ladder MOVE FORWARD on
 * a template nobody can verify, which is what the M4 review closed. Advancing
 * asserts something about the real world; revoking and superseding assert
 * nothing that the formalities govern. So only the latter survive.
 *
 * The set is a strict subset of `allowedTransitions(current, R)` for every R —
 * asserted exhaustively in the spec — so permitting it can never grant
 * something the real ladder would have withheld.
 */
export function deEscalationTransitions(current: ExecutionStatus): ExecutionStatus[] {
  switch (current) {
    case 'draft':
    case 'generated':
      // Nothing to step back from, and advancing is exactly what is withheld.
      // An unwanted draft is deleted, not revoked.
      return [];
    case 'signed':
    case 'witnessed':
    case 'notarized':
      return ['revoked'];
    case 'executed':
      return ['revoked', 'superseded'];
    case 'revoked':
    case 'superseded':
      return [];
  }
}

export function isTransitionAllowed(
  current: ExecutionStatus,
  next: ExecutionStatus,
  requirements: ExecutionRequirements,
): boolean {
  return allowedTransitions(current, requirements).includes(next);
}

/** Statuses from which the content may still be regenerated (new versions). */
export function allowsNewVersion(current: ExecutionStatus): boolean {
  // Once signing starts, the paper trail is legally meaningful: regenerating
  // content out from under a signed/executed instrument is forbidden. The
  // owner revokes (or supersedes) first, then generates a fresh document.
  return current === 'draft' || current === 'generated';
}
