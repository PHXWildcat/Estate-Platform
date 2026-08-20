import { render, screen, waitFor } from '@testing-library/react';
import type { SettlementCaseInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { OpenSettlementCaseBanner } from './OpenSettlementCaseBanner';

/**
 * The app-wide banner (M22 PR3) — THE REASON THIS SURFACE NEEDS NO NAV ENTRY.
 *
 * It has to be silent for almost everybody and impossible to miss for the few
 * people it concerns, so the assertions here are mostly about when it does NOT
 * appear: for a reporter looking at their own filed case, for a case that has
 * already ended, and on a read that failed.
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

function handlers(cases: SettlementCaseInfo[]): Record<string, OperationHandler> {
  return { SettlementCases: () => jsonResponse({ data: { settlementCases: cases } }) };
}

it('shouts when a case naming this person is open', async () => {
  installGraphqlFetchMock(handlers([settlementCase()]));
  render(<OpenSettlementCaseBanner />);
  expect(await screen.findByText(/reported you as deceased/i)).toBeInTheDocument();
  expect(screen.getByRole('link', { name: /close it now/i })).toHaveAttribute(
    'href',
    '/security/cases',
  );
});

it('counts more than one', async () => {
  installGraphqlFetchMock(
    handlers([settlementCase(), settlementCase({ caseId: 'case-2', status: 'verifying' })]),
  );
  render(<OpenSettlementCaseBanner />);
  expect(await screen.findByText(/2 open reports/i)).toBeInTheDocument();
});

it('says NOTHING to a reporter about a case they filed', async () => {
  // The same query answers both audiences. A reporter's own case is not a
  // threat to them, and alarming them on every page would be simply wrong.
  installGraphqlFetchMock(handlers([settlementCase({ aboutMe: false })]));
  const { container } = render(<OpenSettlementCaseBanner />);
  await waitFor(() => {
    expect(container).toBeEmptyDOMElement();
  });
});

it('says nothing once the case has ended', async () => {
  installGraphqlFetchMock(
    handlers([settlementCase({ status: 'rejected_fraud', resolution: 'owner_voided' })]),
  );
  const { container } = render(<OpenSettlementCaseBanner />);
  await waitFor(() => {
    expect(container).toBeEmptyDOMElement();
  });
});

it('stays silent on a failed read rather than alarming somebody wrongly', async () => {
  // The page behind it reports the failure properly. A page-wide alarm the
  // reader cannot act on is the wrong place to surface an outage.
  installGraphqlFetchMock({ SettlementCases: () => graphqlError('UNKNOWN') });
  const { container } = render(<OpenSettlementCaseBanner />);
  await waitFor(() => {
    expect(container).toBeEmptyDOMElement();
  });
});

it('offers no way to dismiss it', async () => {
  // Deliberate: a dismissed banner hides a live case from the only person
  // entitled to kill it, and the case keeps advancing regardless.
  installGraphqlFetchMock(handlers([settlementCase()]));
  render(<OpenSettlementCaseBanner />);
  await screen.findByText(/reported you as deceased/i);
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});
