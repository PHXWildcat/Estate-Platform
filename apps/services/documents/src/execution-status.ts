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
