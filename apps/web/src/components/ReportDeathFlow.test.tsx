import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { ReportDeathFlow } from './ReportDeathFlow';

/**
 * FILING A DEATH REPORT (M22 PR4c).
 *
 * Two properties carry this file. The first is that NOTHING IS FILED BY THE
 * FIRST CLICK — the review step is what stands in for the step-up gate this
 * route deliberately does not have, and a regression that skipped it would
 * turn a list of names into a one-misclick death report. The second is that a
 * failed read never renders as an empty one, in either direction: "nobody has
 * linked you" and "we could not check" are different facts, and so are "you
 * have no documents" and "we could not read your documents".
 */

const ESTATES = [
  { contactId: 'contact-1', ownerName: 'Ada Lovelace', roles: ['executor', 'viewer'] },
  { contactId: 'contact-9', ownerName: null, roles: [] },
];

const DOCUMENTS = [
  {
    documentId: 'doc-1',
    docType: 'other',
    source: 'uploaded',
    title: 'Death certificate',
    currentVersion: 3,
    executionStatus: 'none',
    executedAt: null,
    legalHold: false,
    sealed: false,
    templateId: null,
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt: '2026-08-01T00:00:00.000Z',
  },
  {
    documentId: 'doc-sealed',
    docType: 'other',
    source: 'uploaded',
    title: 'Sealed letter',
    currentVersion: 1,
    executionStatus: 'none',
    executedAt: null,
    legalHold: false,
    sealed: true,
    templateId: null,
    createdAt: '2026-08-01T00:00:00.000Z',
    updatedAt: '2026-08-01T00:00:00.000Z',
  },
];

const CASE = {
  caseId: 'case-1',
  status: 'reported',
  reportSource: 'trusted_contact',
  evidenceCount: 0,
  waitingPeriodEnds: null,
  resolution: null,
  resolvedAt: null,
  createdAt: '2026-08-20T00:00:00.000Z',
  aboutMe: false,
  voidable: false,
};

function handlers(
  options: {
    estates?: OperationHandler;
    documents?: OperationHandler;
    report?: OperationHandler;
  } = {},
): Record<string, OperationHandler> {
  return {
    ReportableEstates:
      options.estates ?? (() => jsonResponse({ data: { reportableEstates: ESTATES } })),
    Documents: options.documents ?? (() => jsonResponse({ data: { documents: DOCUMENTS } })),
    ReportDeath: options.report ?? (() => jsonResponse({ data: { reportDeath: CASE } })),
  };
}

const pickFirst = async (): Promise<void> => {
  const buttons = await screen.findAllByRole('button', { name: /report a death/i });
  fireEvent.click(buttons[0] as HTMLElement);
};

describe('reading the estates you may report on', () => {
  it('names each one, and says in words when an owner has no name', async () => {
    installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
    expect(screen.getByText(/hasn’t added their name yet/i)).toBeInTheDocument();
    // Never the literal word: a null name is the server declining to say one,
    // not a value this layer gets to invent.
    expect(screen.queryByText(/unknown/i)).not.toBeInTheDocument();
  });

  it('shows a failed read as a failure, never as "nobody has linked you"', async () => {
    installGraphqlFetchMock(handlers({ estates: () => graphqlError('UNKNOWN') }));
    render(<ReportDeathFlow />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/nobody has linked you/i)).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as no data', async () => {
    installGraphqlFetchMock(handlers({ estates: () => jsonResponse({ data: {} }) }));
    render(<ReportDeathFlow />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('an empty list is a real answer and says what to do instead', async () => {
    installGraphqlFetchMock(
      handlers({ estates: () => jsonResponse({ data: { reportableEstates: [] } }) }),
    );
    render(<ReportDeathFlow />);
    expect(await screen.findByText(/nobody has linked you to their plan/i)).toBeInTheDocument();
  });
});

describe('the review step', () => {
  /**
   * THE ASSERTION THIS FILE EXISTS FOR. Intake is deliberately not step-up
   * gated, so the review screen is the only thing between a list of names and
   * a death report. It must be reached, and reaching it must file NOTHING.
   */
  it('files nothing on the first click', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    expect(await screen.findByText(/report the death of ada lovelace/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(requests.filter((r) => r.body.query?.includes('ReportDeath'))).toHaveLength(0);
    });
  });

  it('says what will actually happen, including that they can undo it', async () => {
    installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    expect(await screen.findByText(/every channel we have/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing in their estate is unlocked/i)).toBeInTheDocument();
    expect(screen.getByText(/they can close the case themselves/i)).toBeInTheDocument();
    // The reporter is told they are named on it, before they file rather than
    // after — it is the one consequence that lands on THEM.
    expect(screen.getByText(/your name is recorded on the case/i)).toBeInTheDocument();
  });

  it('going back files nothing and returns the list', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    fireEvent.click(await screen.findByRole('button', { name: /go back/i }));
    expect(await screen.findByText(/whose death are you reporting/i)).toBeInTheDocument();
    expect(requests.filter((r) => r.body.query?.includes('ReportDeath'))).toHaveLength(0);
  });
});

describe('filing', () => {
  it('sends the CONTACT id and no user id at all', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    fireEvent.click(await screen.findByRole('button', { name: /confirm and report/i }));
    await screen.findByText(/we’ve opened a case/i);
    const sent = requests.filter((r) => r.body.query?.includes('ReportDeath'));
    expect(sent[0]?.body.variables).toEqual({ contactId: 'contact-1' });
  });

  it('attaches the document at the version that exists now', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    fireEvent.change(await screen.findByLabelText(/document to attach/i), {
      target: { value: 'doc-1' },
    });
    fireEvent.click(screen.getByRole('button', { name: /confirm and report/i }));
    await screen.findByText(/we’ve opened a case/i);
    const sent = requests.filter((r) => r.body.query?.includes('ReportDeath'));
    // BOTH FIELDS. A document id without its version names no document, and
    // `currentVersion` is what pins evidence to the file that was meant
    // rather than to whatever replaces it later.
    expect(sent[0]?.body.variables).toEqual({
      contactId: 'contact-1',
      documentId: 'doc-1',
      documentVersion: 3,
    });
  });

  it('does not offer a sealed document, which no reviewer could ever read', async () => {
    installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    const select = await screen.findByLabelText(/document to attach/i);
    expect(select).toHaveTextContent('Death certificate');
    expect(select).not.toHaveTextContent('Sealed letter');
  });

  it('points somebody with no documents at the UPLOAD page, not the generator', async () => {
    /*
     * FOUND BY DRIVING THE APP, not by a test. This link read `/documents/new`
     * — which is the TEMPLATE GENERATOR, a page that offers a state and a
     * reviewed will template. Somebody holding a scanned death certificate
     * would have arrived there and found nothing that could take it. Upload
     * lives inside `DocumentsPanel` on `/documents`.
     */
    installGraphqlFetchMock(
      handlers({ documents: () => jsonResponse({ data: { documents: [] } }) }),
    );
    render(<ReportDeathFlow />);
    await pickFirst();
    const link = await screen.findByRole('link', { name: /you can upload one/i });
    expect(link).toHaveAttribute('href', '/documents');
  });

  it('a failed documents read still lets the report be filed', async () => {
    // The certificate is optional, so an unreadable document list must not
    // block the report — and must not claim the person has no documents.
    const { requests } = installGraphqlFetchMock(
      handlers({ documents: () => graphqlError('UNKNOWN') }),
    );
    render(<ReportDeathFlow />);
    await pickFirst();
    expect(await screen.findByText(/couldn’t load your documents/i)).toBeInTheDocument();
    expect(screen.queryByText(/haven’t uploaded any documents/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /confirm and report/i }));
    await screen.findByText(/we’ve opened a case/i);
    expect(requests.filter((r) => r.body.query?.includes('ReportDeath'))).toHaveLength(1);
  });

  it('tells a reporter somebody got there first, and not that their own case is open', async () => {
    /*
     * CASE_ALREADY_REPORTED and CASE_OPEN are one word apart and mean opposite
     * things to opposite people: this one says the work is done and there is
     * nothing more to do, where CASE_OPEN is about the reader's own account
     * having its waiting period frozen. Rendering the wrong one at a bereaved
     * person tells them their own estate is under a death report.
     */
    installGraphqlFetchMock(handlers({ report: () => graphqlError('CASE_ALREADY_REPORTED') }));
    render(<ReportDeathFlow />);
    await pickFirst();
    fireEvent.click(await screen.findByRole('button', { name: /confirm and report/i }));
    expect(await screen.findByText(/already reported this/i)).toBeInTheDocument();
    // Anchored on the sentence CASE_OPEN would have put here — "a case about
    // YOU is open" — rather than on a word the review screen legitimately
    // uses in its own explanation.
    expect(screen.queryByText(/a case about you is open/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/this setting is frozen/i)).not.toBeInTheDocument();
    // Still on the review screen, not the confirmation.
    expect(screen.queryByText(/we’ve opened a case/i)).not.toBeInTheDocument();
  });

  it('confirms without promising anything was released', async () => {
    installGraphqlFetchMock(handlers());
    render(<ReportDeathFlow />);
    await pickFirst();
    fireEvent.click(await screen.findByRole('button', { name: /confirm and report/i }));
    expect(await screen.findByText(/we’ve opened a case/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing in the estate is released/i)).toBeInTheDocument();
  });
});
