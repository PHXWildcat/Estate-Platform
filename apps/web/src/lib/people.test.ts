import {
  conditionLabel,
  conditionMeaning,
  maritalLabel,
  onFileSummary,
  professionalLabel,
  relationLabel,
  roleLabel,
  EFFECTIVE_CONDITIONS,
  RELATIONS,
  ROLES,
} from './people';

/**
 * The vocabulary maps are TOTAL over their closed unions, so a new token without
 * wording is a compile error. What these tests pin is the other half: an UNKNOWN
 * token still renders something readable, because a service deployed ahead of the
 * app must not blank a page — and the fallbacks must never read as a claim.
 */

describe('every declared token has real wording', () => {
  it.each(ROLES)('role %s', (role) => {
    const label = roleLabel(role);
    expect(label.length).toBeGreaterThan(0);
    // Never the raw token: `agent_financial` is not a sentence.
    expect(label).not.toContain('_');
  });

  it.each(EFFECTIVE_CONDITIONS)('condition %s', (condition) => {
    expect(conditionLabel(condition)).not.toContain('_');
    expect(conditionMeaning(condition).length).toBeGreaterThan(20);
  });

  it.each(RELATIONS)('relation %s', (relation) => {
    expect(relationLabel(relation)).not.toContain('_');
  });
});

describe('a condition never reads as access', () => {
  it('says the deferred ones grant nothing today', () => {
    expect(conditionMeaning('on_death_verified')).toMatch(/grants no access today/);
    expect(conditionMeaning('on_incapacity')).toMatch(/grants no access today/);
  });

  it('and the immediate one is still conditional on a permission', () => {
    expect(conditionMeaning('immediate')).toMatch(/only for what you separately allow/);
  });
});

describe('unknown tokens degrade readably', () => {
  it('humanizes a role the app has never heard of', () => {
    expect(roleLabel('estate_custodian')).toBe('Estate custodian');
  });

  it('falls back to the safest possible meaning for an unknown condition', () => {
    // Not "takes effect when…": an unknown condition must never be described as
    // conferring something.
    expect(conditionMeaning('on_full_moon')).toMatch(/grants no access on its own/);
    expect(conditionLabel('on_full_moon')).toBe('On full moon');
  });

  it('humanizes unknown relations, professions and marital statuses', () => {
    expect(relationLabel('step_child')).toBe('Step child');
    expect(professionalLabel('estate_agent')).toBe('Estate agent');
    expect(maritalLabel('civil_union')).toBe('Civil union');
  });
});

describe('onFileSummary says what is held without holding it', () => {
  it('lists only what is present', () => {
    expect(
      onFileSummary({ hasEmail: true, hasPhone: false, hasAddress: true, hasNotes: false }),
    ).toBe('On file: email, address');
  });

  it('says so plainly when nothing is', () => {
    expect(
      onFileSummary({ hasEmail: false, hasPhone: false, hasAddress: false, hasNotes: false }),
    ).toBe('No contact details on file');
  });

  it('lists all four when all four are held', () => {
    expect(
      onFileSummary({ hasEmail: true, hasPhone: true, hasAddress: true, hasNotes: true }),
    ).toBe('On file: email, phone, address, notes');
  });
});
