import { isStepUpFresh, STEPUP_WINDOW_MS } from '../src/stepup';

describe('step-up freshness math', () => {
  const now = new Date('2026-07-20T12:00:00Z');

  it('window constant is exactly 5 minutes (docs/01 §5)', () => {
    expect(STEPUP_WINDOW_MS).toBe(5 * 60 * 1000);
  });

  it('fresh: stepup level with expiry in the future', () => {
    expect(isStepUpFresh('stepup', new Date(now.getTime() + 1), now)).toBe(true);
    expect(isStepUpFresh('stepup', new Date(now.getTime() + STEPUP_WINDOW_MS), now)).toBe(true);
  });

  it('stale: expiry exactly now or in the past', () => {
    expect(isStepUpFresh('stepup', now, now)).toBe(false);
    expect(isStepUpFresh('stepup', new Date(now.getTime() - 1), now)).toBe(false);
  });

  it('never fresh without the stepup level, regardless of expiry', () => {
    const future = new Date(now.getTime() + STEPUP_WINDOW_MS);
    expect(isStepUpFresh('none', future, now)).toBe(false);
    expect(isStepUpFresh('mfa', future, now)).toBe(false);
  });

  it('never fresh with a null expiry', () => {
    expect(isStepUpFresh('stepup', null, now)).toBe(false);
  });
});
