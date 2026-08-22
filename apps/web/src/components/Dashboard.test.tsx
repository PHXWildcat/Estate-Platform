import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import type {
  AnalysisInfo,
  AssetInfo,
  DocumentInfo,
  FindingInfo,
  LiveSessionInfo,
} from '../graphql/client';
import { resetSharedReadsForTests } from '../graphql/read-cache';
import { Dashboard } from './Dashboard';

/**
 * The dashboard, tested through the REAL client against the fetch mock.
 *
 * The two claims that anchor this suite:
 * 1. A FAILED READ MUST NOT RENDER AS ZERO (docs/04 M24 PR3 — the M25 PR4
 *    rule). The named assertion is `renders no dollar figure on a failed
 *    NetWorth read`; its POSITIVE CONTROL is the happy-path test proving the
 *    same matcher sees a rendered dollar figure when one exists.
 * 2. READS ARE ON THE OWNER'S TERMS: the session gate fires first and alone
 *    when signed out, each backing is asked exactly once per mount, and the
 *    readiness analyses run zero times until the owner presses the button.
 */

// Fixture vocabularies are PINNED to their owners: categories to the
// assets_view DDL CHECK (categories.test.ts derives it), executionStatus to
// docs/02 §4, mfaLevel/AnalysisStatus to the BFF SDL enums (UPPERCASE names).

const SESSION = { userId: 'u-1', mfaLevel: 'MFA', stepUpFresh: false };

const NET_WORTH = {
  totalValue: '739700.00',
  assetCount: 3,
  valuedAssetCount: 2,
  inTrustValue: '150000.00',
};

function asset(overrides: Partial<AssetInfo>): AssetInfo {
  return {
    assetId: 'a-1',
    category: 'cash',
    title: 'Checking',
    estValue: '100.00',
    valuationAsOf: null,
    valuationSource: null,
    ownershipPct: 100,
    inTrust: false,
    fundingStatus: null,
    status: 'live',
    retiredAt: null,
    version: '1',
    ...overrides,
  };
}

function doc(overrides: Partial<DocumentInfo>): DocumentInfo {
  return {
    documentId: 'd-1',
    docType: 'will',
    source: 'generated',
    title: 'My will',
    currentVersion: 1,
    executionStatus: 'executed',
    executedAt: null,
    legalHold: false,
    sealed: false,
    templateId: null,
    createdAt: '2026-08-01T00:00:00Z',
    updatedAt: '2026-08-01T00:00:00Z',
    ...overrides,
  };
}

const SESSION_ROW: LiveSessionInfo = {
  sessionId: 's-1',
  audience: 'ACCOUNT',
  createdAt: '2026-08-01T00:00:00Z',
  expiresAt: '2026-09-01T00:00:00Z',
  current: true,
};

const DISCLAIMER = 'General information, not legal advice — the server’s own sentence.';

function analysis(overrides: Partial<AnalysisInfo> = {}): AnalysisInfo {
  return { status: 'OK', reason: null, findings: [], disclaimer: DISCLAIMER, ...overrides };
}

function finding(overrides: Partial<FindingInfo> = {}): FindingInfo {
  return {
    code: 'asset_not_titled_in_trust',
    severity: 'high',
    subject: { kind: 'asset', ref: 'a-1', label: 'House' },
    detail: {},
    ...overrides,
  };
}

const READINESS_CLEAN = {
  funding: analysis(),
  missingDocuments: analysis(),
  beneficiaryConflicts: analysis(),
  estateTax: analysis(),
};

function handlers(
  overrides: Record<string, OperationHandler> = {},
): Record<string, OperationHandler> {
  return {
    Session: () => jsonResponse({ data: { session: SESSION } }),
    ExecutorCases: () => jsonResponse({ data: { executorCases: [] } }),
    NetWorth: () => jsonResponse({ data: { netWorth: NET_WORTH } }),
    Assets: () => jsonResponse({ data: { assets: [asset({})] } }),
    Documents: () => jsonResponse({ data: { documents: [doc({})] } }),
    Sessions: () => jsonResponse({ data: { sessions: [SESSION_ROW] } }),
    Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
    EmailVerification: () => jsonResponse({ data: { emailVerification: 'VERIFIED' } }),
    ...overrides,
  };
}

function asksOf(requests: RecordedRequest[], name: string): number {
  return requests.filter((r) => r.body.query?.split(/[\s({]+/)[1] === name).length;
}

beforeEach(() => {
  resetSharedReadsForTests();
});

describe('the session gate', () => {
  it('signed out: hero plus get-started, and NOT ONE estate read fires', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ Session: () => jsonResponse({ data: { session: null } }) }),
    );
    render(<Dashboard />);

    await screen.findByRole('link', { name: 'Create account' });
    expect(screen.getByText(/Your estate, in order/)).toBeInTheDocument();
    // The gate is the point: a visitor's landing spends no asset decrypts.
    for (const name of ['NetWorth', 'Assets', 'Documents', 'Sessions', 'Passkeys']) {
      expect(asksOf(requests, name)).toBe(0);
    }
  });

  it('a failed session read is its own arm — not signed-out, not a blank page', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ Session: () => jsonResponse({}, false) }),
    );
    render(<Dashboard />);

    await screen.findByText(/couldn’t check your session/);
    expect(asksOf(requests, 'NetWorth')).toBe(0);
  });
});

describe('the tiles', () => {
  it('renders every tile from ONE read per operation (positive control for the money matcher)', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<Dashboard />);

    // Staged waits (the 2026-08-19 lesson): land on one tile's datum first.
    await screen.findByText('$739,700.00');
    expect(screen.getByText('2 of 3 assets valued')).toBeInTheDocument();
    // Funding: trustFundingPct('150000.00','739700.00') = 20.3, formatted.
    expect(screen.getByText('20.3%')).toBeInTheDocument();
    expect(screen.getByText('$150,000.00 of $739,700.00 held in trust')).toBeInTheDocument();
    // Documents: 1 of 1 executed.
    expect(screen.getByText('100%')).toBeInTheDocument();
    expect(screen.getByText('Every document on file has been executed.')).toBeInTheDocument();
    await screen.findByText('Active sessions: 1');

    // One read, many tiles: NetWorth feeds three figures, asked once.
    for (const name of [
      'Session',
      'NetWorth',
      'Assets',
      'Documents',
      'Sessions',
      'Passkeys',
      'EmailVerification',
    ]) {
      expect(asksOf(requests, name)).toBe(1);
    }
  });

  it('renders NO dollar figure on a failed NetWorth read — the failed-read-is-not-zero rule', async () => {
    installGraphqlFetchMock(handlers({ NetWorth: () => jsonResponse({}, false) }));
    render(<Dashboard />);

    // Both NetWorth consumers (estate tile, funding tile) show the
    // non-statement…
    await waitFor(() =>
      expect(screen.getAllByText(/This is not a statement about your estate/).length).toBe(3),
    );
    // …and no dollar renders ANYWHERE: "we could not ask" must never wear
    // "nothing is here"'s face. (The happy-path test above proves this
    // matcher sees dollars when they exist.)
    expect(screen.queryByText(/\$/)).toBeNull();
  });

  it('one backing failing costs its own tile, never the page', async () => {
    installGraphqlFetchMock(handlers({ Documents: () => jsonResponse({}, false) }));
    render(<Dashboard />);

    // The documents tile shows its failure…
    await screen.findByText(/couldn’t load your documents/);
    // …while the money tiles render normally.
    await screen.findByText('$739,700.00');
    expect(screen.queryByText('Nothing on file yet.')).toBeNull();
  });

  it('assets with no recorded values render “—”, never “$0.00”', async () => {
    installGraphqlFetchMock(
      handlers({
        NetWorth: () =>
          jsonResponse({
            data: {
              netWorth: {
                totalValue: '0.00',
                assetCount: 3,
                valuedAssetCount: 0,
                inTrustValue: '0.00',
              },
            },
          }),
      }),
    );
    render(<Dashboard />);

    await screen.findByText('None of your 3 assets has a recorded value yet.');
    expect(screen.queryByText('$0.00')).toBeNull();
    // Funding has nothing to measure either — the service's own null case.
    expect(screen.getByText('No valued estate to measure yet.')).toBeInTheDocument();
  });

  it('a tile read answering UNAUTHENTICATED collapses the PAGE to signed-out — one mechanism, no outage face', async () => {
    // The session died between the gate read and the tile reads (revoked
    // from another device; the client's silent refresh already failed). The
    // review found the alternative — per-tile session-end sentences — left
    // half the surfaces wearing an outage's face with the real remedy
    // withheld. The honest state is the page's, not a tile's.
    installGraphqlFetchMock(handlers({ NetWorth: () => graphqlError('UNAUTHENTICATED') }));
    render(<Dashboard />);

    await screen.findByRole('link', { name: 'Create account' });
    // No stale tile survives the collapse, and no failure copy renders — the
    // page IS the signed-out page now.
    expect(screen.queryByText(/\$/)).toBeNull();
    expect(screen.queryByText(/could not load/)).toBeNull();
    expect(screen.queryByText(/This is not a statement/)).toBeNull();
    // …and it SAYS SO (M24 PR4). The collapse used to hand this person the
    // anonymous first-visit hero, which states nothing about what happened to
    // their credential — the likeliest causes being a revocation they
    // performed elsewhere and an expiry, i.e. the controls working.
    expect(screen.getByRole('status')).toHaveTextContent(/Your session has ended/);
  });

  it('a FIRST-TIME visitor is not told a session ended — the two are different facts', async () => {
    // The other arm, and the reason `ended` exists rather than a bare flag on
    // the signed-out state: at mount, "no session" and "never had one" are
    // indistinguishable, and announcing an event that did not happen would be
    // its own false statement.
    installGraphqlFetchMock(handlers({ Session: () => jsonResponse({ data: { session: null } }) }));
    render(<Dashboard />);

    await screen.findByRole('link', { name: 'Create account' });
    expect(screen.queryByText(/session has ended/)).toBeNull();
  });

  it('an EMPTY estate is a real answer, distinct from a failed read', async () => {
    installGraphqlFetchMock(
      handlers({
        NetWorth: () =>
          jsonResponse({
            data: {
              netWorth: {
                totalValue: '0.00',
                assetCount: 0,
                valuedAssetCount: 0,
                inTrustValue: '0.00',
              },
            },
          }),
        Assets: () => jsonResponse({ data: { assets: [] } }),
        Documents: () => jsonResponse({ data: { documents: [] } }),
      }),
    );
    render(<Dashboard />);

    await screen.findByText('Nothing recorded yet.');
    expect(screen.getByText('Nothing on file yet.')).toBeInTheDocument();
    expect(screen.queryByText(/This is not a statement/)).toBeNull();
  });

  it('counts the insurance categories by the DDL vocabulary, labels included', async () => {
    installGraphqlFetchMock(
      handlers({
        Assets: () =>
          jsonResponse({
            data: {
              assets: [
                asset({ assetId: 'a-1', category: 'life_insurance' }),
                asset({ assetId: 'a-2', category: 'ltc_insurance' }),
                asset({ assetId: 'a-3', category: 'annuity' }),
                asset({ assetId: 'a-4', category: 'annuity' }),
                asset({ assetId: 'a-5', category: 'cash' }),
              ],
            },
          }),
      }),
    );
    render(<Dashboard />);

    await screen.findByText(
      'On file: Life insurance (1), Long-term-care insurance (1), Annuity (2).',
    );
  });

  it('says so when no insurance is recorded — an empty facet is an answer', async () => {
    installGraphqlFetchMock(handlers());
    render(<Dashboard />);

    await screen.findByText(/None recorded\. Life insurance, long-term-care insurance/);
  });

  it('document completion uses the /documents denominator: revoked stays counted', async () => {
    installGraphqlFetchMock(
      handlers({
        Documents: () =>
          jsonResponse({
            data: {
              documents: [
                doc({ documentId: 'd-1', executionStatus: 'executed' }),
                doc({ documentId: 'd-2', executionStatus: 'executed' }),
                doc({ documentId: 'd-3', executionStatus: 'generated' }),
                doc({ documentId: 'd-4', executionStatus: 'revoked' }),
              ],
            },
          }),
      }),
    );
    render(<Dashboard />);

    // 2 of 4 — the revoked document is in the denominator, exactly as the
    // /documents page counts (lib/documents.ts inForceCount); the two
    // surfaces must not disagree about the same estate. "Not in force", not
    // "not executed yet" — a revoked will is not pending future execution.
    await screen.findByText('50%');
    expect(
      screen.getByText('2 of 4 are not in force, so they direct nothing.'),
    ).toBeInTheDocument();
  });
});

describe('the security tile', () => {
  it('renders the facts and keeps failure distinct from absence', async () => {
    installGraphqlFetchMock(
      handlers({
        Passkeys: () => jsonResponse({}, false),
        EmailVerification: () => jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }),
      }),
    );
    render(<Dashboard />);

    await screen.findByText('Active sessions: 1');
    // Session semantics, not enrollment: mfaLevel says what THIS session
    // proved. The fixture's session carried a second factor.
    expect(screen.getByText('Second factor verified')).toBeInTheDocument();
    expect(screen.getByText('Step-up not fresh')).toBeInTheDocument();
    // A failed passkey read is withheld, never shown as "none yet".
    expect(screen.getByText('Passkeys: could not load just now')).toBeInTheDocument();
    expect(screen.queryByText('Passkeys: none yet')).toBeNull();
    await screen.findByText('Email address not verified yet');
  });

  it('UNAVAILABLE email verification is a platform fact, never rendered as unverified', async () => {
    installGraphqlFetchMock(
      handlers({
        EmailVerification: () => jsonResponse({ data: { emailVerification: 'UNAVAILABLE' } }),
      }),
    );
    render(<Dashboard />);

    await screen.findByText('Email: verification could not be checked just now');
    expect(screen.queryByText(/not verified yet/)).toBeNull();
  });
});

describe('the estate checks', () => {
  it('run ZERO times on mount and once per press — the analyses are on the owner’s terms', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ Readiness: () => jsonResponse({ data: { readiness: READINESS_CLEAN } }) }),
    );
    render(<Dashboard />);

    await screen.findByText('$739,700.00');
    // The load-bearing zero: a mount must not spend the four-analyser fan.
    expect(asksOf(requests, 'Readiness')).toBe(0);

    fireEvent.click(screen.getByRole('button', { name: 'Run the checks' }));
    await waitFor(() => expect(screen.getAllByText('Nothing found').length).toBe(4));
    expect(asksOf(requests, 'Readiness')).toBe(1);
    // The watermark is the SERVER's sentence.
    expect(screen.getByText(DISCLAIMER)).toBeInTheDocument();

    // A second press is a second run — once per press, never a poll.
    fireEvent.click(screen.getByRole('button', { name: 'Run again' }));
    await waitFor(() => expect(asksOf(requests, 'Readiness')).toBe(2));
  });

  it('renders findings as counts and non-OK statuses in words — never as a clean bill', async () => {
    installGraphqlFetchMock(
      handlers({
        Readiness: () =>
          jsonResponse({
            data: {
              readiness: {
                funding: analysis({ status: 'UNAVAILABLE' }),
                missingDocuments: analysis({
                  findings: [
                    finding({ code: 'instrument_missing', severity: 'high' }),
                    finding({ code: 'instrument_not_executed', severity: 'high' }),
                  ],
                }),
                beneficiaryConflicts: analysis({
                  findings: [finding({ code: 'no_designations_on_file', severity: 'info' })],
                }),
                estateTax: analysis({ status: 'REFUSED', reason: 'reference_unreviewed' }),
              },
            },
          }),
      }),
    );
    render(<Dashboard />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run the checks' }));

    await screen.findByText('2 items need attention');
    // UNAVAILABLE must never read as clean — it says what happened.
    expect(screen.getByText('Could not run')).toBeInTheDocument();
    // REFUSED is a control firing, not an outage, and keeps its own words.
    expect(screen.getByText('Not published here')).toBeInTheDocument();
    // An info finding is counted, not summarised into reassurance.
    expect(screen.getByText('1 note')).toBeInTheDocument();
    expect(screen.queryByText('Nothing found')).toBeNull();
  });

  it('DISABLED is the actionable status: its own words, linking to the assistant page', async () => {
    installGraphqlFetchMock(
      handlers({
        Readiness: () =>
          jsonResponse({
            data: {
              readiness: {
                funding: analysis({ status: 'DISABLED' }),
                missingDocuments: analysis({ status: 'DISABLED' }),
                beneficiaryConflicts: analysis({ status: 'DISABLED' }),
                estateTax: analysis({ status: 'DISABLED' }),
              },
            },
          }),
      }),
    );
    render(<Dashboard />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run the checks' }));

    await waitFor(() => expect(screen.getAllByText('Assistant off').length).toBe(4));
    expect(screen.getByText(/nothing is analysed while it is off/)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'assistant page' });
    expect(link).toHaveAttribute('href', '/assistant');
  });

  it('a status this build has no words for renders neutrally — never as an affirmative claim', async () => {
    // A server deployed ahead of this app: isReadiness deliberately admits
    // any string status, and the chip must fall back neutrally (the
    // lib/findings unknown-code rule) — not to 'Assistant off', which would
    // be a false statement about the user's own configuration.
    installGraphqlFetchMock(
      handlers({
        Readiness: () =>
          jsonResponse({
            data: {
              readiness: {
                ...READINESS_CLEAN,
                estateTax: { ...analysis(), status: 'TIMEOUT' },
              },
            },
          }),
      }),
    );
    render(<Dashboard />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run the checks' }));

    await screen.findByText('Unknown status');
    expect(screen.queryByText('Assistant off')).toBeNull();
    expect(screen.getAllByText('Nothing found').length).toBe(3);
  });

  it('the landing outcome takes keyboard focus — the run leaves nobody stranded at the top of the page', async () => {
    // The review demonstrated the defect live: a natively disabled button
    // blurs to <body> the moment the attribute lands, so the button uses
    // aria-disabled and the outcome region receives focus when a run lands
    // (the M24 PR2 lesson's second half).
    installGraphqlFetchMock(
      handlers({ Readiness: () => jsonResponse({ data: { readiness: READINESS_CLEAN } }) }),
    );
    render(<Dashboard />);

    await screen.findByText('$739,700.00');
    const button = screen.getByRole('button', { name: 'Run the checks' });
    button.focus();
    fireEvent.click(button);
    await waitFor(() => expect(screen.getAllByText('Nothing found').length).toBe(4));
    expect(document.activeElement).toBe(screen.getByRole('status'));
  });

  it('a failed run is a non-statement with a way to try again', async () => {
    installGraphqlFetchMock(handlers({ Readiness: () => jsonResponse({}, false) }));
    render(<Dashboard />);

    fireEvent.click(await screen.findByRole('button', { name: 'Run the checks' }));

    await screen.findByText(/couldn’t run these checks/);
    expect(screen.getByRole('button', { name: 'Run again' })).toBeEnabled();
  });
});
