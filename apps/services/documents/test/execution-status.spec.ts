import {
  allowedTransitions,
  allowsNewVersion,
  attestationLadder,
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
