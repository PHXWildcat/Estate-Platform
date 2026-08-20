import type { SettlementCaseInfo } from '../graphql/client';
import { caseDetail, caseHeadline, formatDate, isOpen, reportSourceLabel } from './settlement';

/**
 * The case vocabulary (M22 PR3).
 *
 * These are pure functions and the temptation is to skip them. They are the
 * ones worth pinning: every sentence here is read by somebody who has just been
 * told a stranger reported them dead, and the two failure modes are printing a
 * database token at them and telling them fraud was found against them when
 * they closed the case themselves.
 */

function settlementCase(over: Partial<SettlementCaseInfo> = {}): SettlementCaseInfo {
  return {
    caseId: 'case-1',
    status: 'reported',
    reportSource: 'trusted_contact',
    evidenceCount: 0,
    waitingPeriodEnds: null,
    resolution: null,
    resolvedAt: null,
    createdAt: '2026-08-01T00:00:00.000Z',
    aboutMe: true,
    voidable: true,
    ...over,
  };
}

describe('resolution outranks status', () => {
  /**
   * BOTH TERMINAL OUTCOMES CARRY `status: 'rejected_fraud'` — the DDL CHECK
   * forces it. So the status alone cannot tell an owner's own void from an
   * operator's rejection, and reading it first would describe the protective
   * action as a finding of fraud against the person who took it.
   */
  it.each([
    ['owner_voided', /you confirmed you’re alive/i],
    ['operator_rejected', /we reviewed this and rejected it/i],
  ])('describes %s from the resolution, not the status', (resolution, expected) => {
    const headline = caseHeadline(settlementCase({ status: 'rejected_fraud', resolution }));
    expect(headline).toMatch(expected);
    expect(headline).not.toMatch(/fraud/i);
  });

  it('says the same reassuring thing about both, because both released nothing', () => {
    for (const resolution of ['owner_voided', 'operator_rejected']) {
      expect(caseDetail(settlementCase({ status: 'rejected_fraud', resolution }))).toMatch(
        /nothing was released/i,
      );
    }
  });
});

describe('open statuses', () => {
  it.each(['reported', 'verifying', 'waiting_period'])('%s is open', (status) => {
    expect(isOpen(settlementCase({ status }))).toBe(true);
    expect(caseDetail(settlementCase({ status }))).toMatch(/close it right now/i);
  });

  it.each(['verified', 'active', 'distributing', 'closed', 'rejected_fraud'])(
    '%s is not open',
    (status) => {
      expect(isOpen(settlementCase({ status }))).toBe(false);
    },
  );

  it('gives each open status its own sentence', () => {
    expect(caseHeadline(settlementCase({ status: 'reported' }))).toMatch(/waiting for our review/i);
    expect(caseHeadline(settlementCase({ status: 'verifying' }))).toMatch(/under review/i);
    expect(caseHeadline(settlementCase({ status: 'waiting_period' }))).toMatch(/waiting period/i);
  });
});

describe('the ended-but-not-closed statuses', () => {
  it.each(['verified', 'active', 'distributing', 'closed'])(
    'tells the owner plainly that %s means the estate was opened',
    (status) => {
      expect(caseHeadline(settlementCase({ status }))).toMatch(/estate has been opened/i);
      expect(caseDetail(settlementCase({ status }))).toMatch(/contact us immediately/i);
    },
  );
});

describe('a vocabulary that grows', () => {
  /**
   * The service's status list has grown twice already. An unrecognised value
   * must degrade to a vague sentence — never `deceased_pending` printed at
   * somebody about themselves.
   */
  it('falls back rather than printing an unknown token', () => {
    const headline = caseHeadline(settlementCase({ status: 'some_future_status' }));
    expect(headline).toBe('In progress');
    expect(headline).not.toMatch(/some_future_status/);
  });

  it('does the same for an unknown report source', () => {
    const label = reportSourceLabel('some_future_source');
    expect(label).toBe('Reported');
    expect(label).not.toMatch(/some_future_source/);
  });
});

describe('report sources read as sentences', () => {
  it.each([
    ['trusted_contact', /someone linked to your estate/i],
    ['death_certificate_upload', /death certificate/i],
    ['data_provider', /external records check/i],
  ])('%s', (source, expected) => {
    expect(reportSourceLabel(source)).toMatch(expected);
  });
});

describe('dates', () => {
  it('formats a wire timestamp', () => {
    expect(formatDate('2026-08-01T00:00:00.000Z')).toMatch(/2026/);
  });

  it('answers null for an absent date, so a caller can choose its own words', () => {
    expect(formatDate(null)).toBeNull();
  });

  it('answers null for an unparseable one rather than rendering "Invalid Date"', () => {
    // A peer that starts sending a different shape must not put the literal
    // string "Invalid Date" on this page.
    expect(formatDate('not-a-date')).toBeNull();
  });
});
