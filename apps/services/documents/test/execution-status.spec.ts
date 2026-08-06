import type { ExecutionStatus } from '@estate/contracts';
import {
  allowedTransitions,
  allowsNewVersion,
  attestationLadder,
  deEscalationTransitions,
  isTransitionAllowed,
} from '../src/execution-status';
import type { ExecutionRequirements } from '../src/template-model';

const FULL: ExecutionRequirements = {
  witnesses: 2,
  notarization: true,
  selfProvingAffidavit: false,
};
const WITNESS_ONLY: ExecutionRequirements = {
  witnesses: 2,
  notarization: false,
  selfProvingAffidavit: false,
};
const NOTARY_ONLY: ExecutionRequirements = {
  witnesses: 0,
  notarization: true,
  selfProvingAffidavit: false,
};
const BARE: ExecutionRequirements = {
  witnesses: 0,
  notarization: false,
  selfProvingAffidavit: false,
};

describe('attestationLadder', () => {
  it('contains exactly the steps the requirements demand, in order', () => {
    expect(attestationLadder(FULL)).toEqual(['signed', 'witnessed', 'notarized', 'executed']);
    expect(attestationLadder(WITNESS_ONLY)).toEqual(['signed', 'witnessed', 'executed']);
    expect(attestationLadder(NOTARY_ONLY)).toEqual(['signed', 'notarized', 'executed']);
    expect(attestationLadder(BARE)).toEqual(['signed', 'executed']);
  });
});

describe('allowedTransitions', () => {
  it('walks the ladder one required step at a time', () => {
    expect(allowedTransitions('generated', FULL)).toEqual(['signed']);
    expect(allowedTransitions('signed', FULL)).toEqual(['witnessed', 'revoked']);
    expect(allowedTransitions('witnessed', FULL)).toEqual(['notarized', 'revoked']);
    expect(allowedTransitions('notarized', FULL)).toEqual(['executed', 'revoked']);
  });

  it('never offers an unrequired step and never skips a required one', () => {
    expect(allowedTransitions('signed', WITNESS_ONLY)).toEqual(['witnessed', 'revoked']);
    expect(allowedTransitions('signed', NOTARY_ONLY)).toEqual(['notarized', 'revoked']);
    expect(allowedTransitions('signed', BARE)).toEqual(['executed', 'revoked']);
    expect(isTransitionAllowed('signed', 'executed', FULL)).toBe(false);
    expect(isTransitionAllowed('signed', 'notarized', WITNESS_ONLY)).toBe(false);
  });

  it('handles executed and terminal statuses', () => {
    expect(allowedTransitions('executed', BARE)).toEqual(['revoked', 'superseded']);
    expect(allowedTransitions('revoked', BARE)).toEqual([]);
    expect(allowedTransitions('superseded', FULL)).toEqual([]);
  });

  it('draft behaves like generated (uploads attest the same ladder)', () => {
    expect(allowedTransitions('draft', BARE)).toEqual(['signed']);
  });

  it('an off-ladder current status can only be revoked', () => {
    // e.g. notarized under requirements that no longer include notarization
    expect(allowedTransitions('notarized', BARE)).toEqual(['revoked']);
  });

  it('never allows moving backward', () => {
    expect(isTransitionAllowed('executed', 'signed', FULL)).toBe(false);
    expect(isTransitionAllowed('witnessed', 'signed', FULL)).toBe(false);
    expect(isTransitionAllowed('signed', 'generated', FULL)).toBe(false);
  });
});

describe('allowsNewVersion', () => {
  it('permits regeneration only before signing starts', () => {
    expect(allowsNewVersion('draft')).toBe(true);
    expect(allowsNewVersion('generated')).toBe(true);
    for (const status of [
      'signed',
      'witnessed',
      'notarized',
      'executed',
      'revoked',
      'superseded',
    ] as const) {
      expect(allowsNewVersion(status)).toBe(false);
    }
  });
});

describe('deEscalationTransitions', () => {
  const EVERY_STATUS: ExecutionStatus[] = [
    'draft',
    'generated',
    'signed',
    'witnessed',
    'notarized',
    'executed',
    'revoked',
    'superseded',
  ];

  it('is a STRICT SUBSET of the real ladder under every requirements profile', () => {
    // The safety property. This set is what survives when the template cannot
    // be verified, so it must never contain a transition the real ladder would
    // have withheld — for ANY profile, since the whole point is that we do not
    // know which profile applies.
    for (const status of EVERY_STATUS) {
      for (const requirements of [FULL, WITNESS_ONLY, NOTARY_ONLY, BARE]) {
        const real = allowedTransitions(status, requirements);
        for (const fallback of deEscalationTransitions(status)) {
          expect(real).toContain(fallback);
        }
      }
    }
  });

  it('leaves an attested document a way back out', () => {
    // The M12-review defect: withdrawing everything meant an unverifiable
    // template stripped the owner's only de-escalation, permanently — which
    // inverts the M6 rule that the protective action must never be harder than
    // the permissive one.
    expect(deEscalationTransitions('signed')).toEqual(['revoked']);
    expect(deEscalationTransitions('witnessed')).toEqual(['revoked']);
    expect(deEscalationTransitions('notarized')).toEqual(['revoked']);
    expect(deEscalationTransitions('executed')).toEqual(['revoked', 'superseded']);
  });

  it('never ADVANCES the ladder, not even by one rung', () => {
    // `signed` is technically requirement-independent (it heads every ladder),
    // and is still withheld: advancing asserts something about the real world
    // on a template nobody can verify, which is what the M4 review closed.
    for (const status of EVERY_STATUS) {
      expect(deEscalationTransitions(status)).not.toContain('signed');
      expect(deEscalationTransitions(status)).not.toContain('witnessed');
      expect(deEscalationTransitions(status)).not.toContain('notarized');
      expect(deEscalationTransitions(status)).not.toContain('executed');
    }
  });

  it('offers nothing from a draft or a terminal status', () => {
    expect(deEscalationTransitions('draft')).toEqual([]);
    expect(deEscalationTransitions('generated')).toEqual([]);
    expect(deEscalationTransitions('revoked')).toEqual([]);
    expect(deEscalationTransitions('superseded')).toEqual([]);
  });
});
