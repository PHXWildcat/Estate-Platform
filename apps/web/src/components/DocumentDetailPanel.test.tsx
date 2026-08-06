import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { DocumentDetailPanel } from './DocumentDetailPanel';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const DOCUMENT_ID = 'd0000000-0000-4000-8000-00000000000a';

const DOCUMENT = {
  documentId: DOCUMENT_ID,
  docType: 'will',
  source: 'generated',
  title: 'Last Will and Testament',
  currentVersion: 2,
  executionStatus: 'generated',
  executedAt: null,
  legalHold: false,
  sealed: false,
  templateId: 't0000000-0000-4000-8000-00000000000a',
  createdAt: '2026-08-01T10:00:00.000Z',
  updatedAt: '2026-08-04T10:00:00.000Z',
  // CA's will template: two witnesses, no notary — so from `generated` the
  // only rung is `signed`. Computed by the service, carried by this app.
  allowedTransitions: ['signed'],
};

const VERSIONS = [
  {
    version: 1,
    contentSha256: 'a'.repeat(64),
    sizeBytes: 800,
    mime: 'text/html',
    createdAt: '2026-08-01T10:00:00.000Z',
  },
  {
    version: 2,
    contentSha256: 'b'.repeat(64),
    sizeBytes: 900,
    mime: 'text/html',
    createdAt: '2026-08-04T10:00:00.000Z',
  },
];

const CONTENT = {
  documentId: DOCUMENT_ID,
  version: 2,
  mime: 'text/html',
  contentSha256: 'b'.repeat(64),
  encoding: 'utf8',
  content: '<!doctype html><html><body><h1>Will</h1></body></html>',
};

function mount(
  overrides: Partial<Record<string, OperationHandler>> = {},
  document: unknown = DOCUMENT,
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    Document: () => jsonResponse({ data: { document } }),
    DocumentVersions: () => jsonResponse({ data: { documentVersions: VERSIONS } }),
    DocumentContent: () => jsonResponse({ data: { documentContent: CONTENT } }),
    ...overrides,
  });
  render(<DocumentDetailPanel documentId={DOCUMENT_ID} />);
  return requests;
}

function operations(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '');
}

describe('reading a version is a deliberate act', () => {
  it('loads metadata and history, and no content, on mount', async () => {
    const requests = mount();
    await screen.findByText('Last Will and Testament');
    // Each content read is an audited decrypt. Nothing opens by itself, not
    // even the current version.
    expect(operations(requests).sort()).toEqual(['Document', 'DocumentVersions']);
    expect(screen.queryByTitle(/Document version/)).not.toBeInTheDocument();
  });

  it('fetches exactly the version whose Read was pressed', async () => {
    const requests = mount();
    const rows = await screen.findAllByRole('button', { name: 'Read' });
    fireEvent.click(rows[0] as HTMLElement);
    await waitFor(() => {
      expect(operations(requests)).toContain('DocumentContent');
    });
    const read = requests.find((request) => request.body.query?.includes('DocumentContent'));
    expect(read?.body.variables).toEqual({ documentId: DOCUMENT_ID, version: 1 });
  });

  it('shows the opened version inside the sandboxed frame', async () => {
    const { container } = (() => {
      installGraphqlFetchMock({
        Document: () => jsonResponse({ data: { document: DOCUMENT } }),
        DocumentVersions: () => jsonResponse({ data: { documentVersions: VERSIONS } }),
        DocumentContent: () => jsonResponse({ data: { documentContent: CONTENT } }),
      });
      return render(<DocumentDetailPanel documentId={DOCUMENT_ID} />);
    })();
    const rows = await screen.findAllByRole('button', { name: 'Read' });
    fireEvent.click(rows[1] as HTMLElement);
    await waitFor(() => {
      expect(container.querySelectorAll('iframe')).toHaveLength(1);
    });
    expect(container.querySelector('iframe')?.getAttribute('sandbox')).toBe('');
    // The instrument's own markup never entered this page.
    expect(container.querySelector('h1')?.textContent).not.toBe('Will');
  });

  it('offers no retry for a crypto-shredded version', async () => {
    mount({ DocumentContent: () => graphqlError('CONTENT_ERASED') });
    const rows = await screen.findAllByRole('button', { name: 'Read' });
    fireEvent.click(rows[0] as HTMLElement);
    // Permanent, and said as such: a "try again" affordance here would have
    // someone pressing it forever against a key destroyed on purpose.
    expect(await screen.findByText(/permanently erased/i)).toBeVisible();
  });
});

describe('what the page offers matches what the server would allow', () => {
  it('offers a new version for a generated, unsigned document', async () => {
    mount();
    expect(await screen.findByRole('link', { name: 'Create a new version' })).toHaveAttribute(
      'href',
      `/documents/${DOCUMENT_ID}/revise`,
    );
  });

  it.each([
    ['a signed document', { executionStatus: 'signed' }],
    ['an executed document', { executionStatus: 'executed', executedAt: '2026-07-04' }],
    ['an uploaded document', { source: 'uploaded', templateId: null }],
  ])('offers no new version for %s', async (_name, overrides) => {
    mount({}, { ...DOCUMENT, ...overrides });
    await screen.findByText('Last Will and Testament');
    // Offering an action the server would refuse is how a UI teaches people to
    // distrust it.
    expect(screen.queryByRole('link', { name: 'Create a new version' })).not.toBeInTheDocument();
  });

  it('explains a legal hold rather than showing an unexplained badge', async () => {
    mount({}, { ...DOCUMENT, legalHold: true });
    expect(await screen.findByText('Legal hold')).toBeInTheDocument();
    expect(screen.getByText(/cannot be deleted while that is in place/i)).toBeVisible();
  });
});

describe('the execution ladder is the server’s, not this page’s', () => {
  it('offers exactly the rungs the service returned', async () => {
    mount(
      {},
      { ...DOCUMENT, executionStatus: 'signed', allowedTransitions: ['witnessed', 'revoked'] },
    );
    expect(await screen.findByRole('button', { name: 'It was witnessed' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Revoke it' })).toBeInTheDocument();
    // CA's will template needs no notary, so that rung does not exist here —
    // and this page derives nothing, so it cannot invent one.
    expect(screen.queryByRole('button', { name: 'It was notarized' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Record it as executed' })).not.toBeInTheDocument();
  });

  it('reveals the date field for the executed attestation ONLY', async () => {
    mount(
      {},
      { ...DOCUMENT, executionStatus: 'witnessed', allowedTransitions: ['executed', 'revoked'] },
    );
    expect(await screen.findByLabelText('Date signed')).toBeInTheDocument();
  });

  it('hides the date field for every other rung', async () => {
    mount();
    await screen.findByRole('button', { name: 'I signed it' });
    expect(screen.queryByLabelText('Date signed')).not.toBeInTheDocument();
  });

  it('refuses to record "executed" with no date, without calling the server', async () => {
    // executedAt accompanies exactly that attestation; the service refuses the
    // pairing either way round, and saying so here beats a masked 422.
    const requests = mount(
      {},
      { ...DOCUMENT, executionStatus: 'witnessed', allowedTransitions: ['executed'] },
    );
    fireEvent.click(await screen.findByRole('button', { name: 'Record it as executed' }));
    expect(await screen.findByText(/Enter the date it was signed/i)).toBeVisible();
    expect(operations(requests)).not.toContain('SetDocumentStatus');
  });

  it('sends the attestation and re-reads rather than patching locally', async () => {
    const requests = mount({
      SetDocumentStatus: () =>
        jsonResponse({
          data: {
            setDocumentStatus: {
              documentId: DOCUMENT_ID,
              executionStatus: 'signed',
              executedAt: null,
              allowedTransitions: ['witnessed', 'revoked'],
            },
          },
        }),
    });
    fireEvent.click(await screen.findByRole('button', { name: 'I signed it' }));
    await waitFor(() => {
      expect(operations(requests).filter((op) => op === 'Document')).toHaveLength(2);
    });
    const sent = requests.find((r) => r.body.query?.includes('SetDocumentStatus'));
    expect(sent?.body.variables).toEqual({ documentId: DOCUMENT_ID, status: 'signed' });
  });

  it('says why an EMPTY ladder is empty, without pretending it is finished', async () => {
    // The service answers an empty list when it cannot resolve the formalities
    // from a verified template — fail closed. That is not the same as a
    // finished document, and the page must not say it is.
    mount({}, { ...DOCUMENT, allowedTransitions: [] });
    expect(await screen.findByText(/can’t confirm the signing steps/i)).toBeVisible();
  });

  it('says a terminal document is finished', async () => {
    mount({}, { ...DOCUMENT, executionStatus: 'revoked', allowedTransitions: [] });
    expect(await screen.findByText(/nothing further to record/i)).toBeVisible();
  });
});

describe('deletion', () => {
  it('collects a step-up code inline and retries the same deletion', async () => {
    let attempts = 0;
    mount({
      DeleteDocument: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { deleteDocument: { ok: true } } });
      },
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    fireEvent.click(await screen.findByRole('button', { name: 'Delete this document' }));
    const code = await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and delete' }));
    await waitFor(() => {
      expect(attempts).toBe(2);
    });
  });

  it('does not OFFER deletion at all for a held document', async () => {
    /*
     * Found by driving the real app. The service runs its step-up guard at the
     * controller and checks the hold inside the handler, so a stale session
     * gets `stepup_required` first and the hold only after — and the page
     * dutifully walked someone through finding their authenticator to be told
     * the document could not be deleted anyway. The page already knows it is
     * held, so it must not ask.
     */
    mount({}, { ...DOCUMENT, legalHold: true });
    await screen.findByText('Last Will and Testament');
    expect(screen.queryByRole('button', { name: 'Delete this document' })).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    // Explained where the button was, not only as a badge at the top.
    expect(screen.getAllByText(/preserved as part of an estate matter/i).length).toBeGreaterThan(0);
    // Everything else on the page still works — a hold is not a freeze.
    expect(screen.getByRole('button', { name: 'I signed it' })).toBeInTheDocument();
  });

  it('still handles a hold applied between page load and the click', async () => {
    // The hold can arrive from settlement at any moment, so the code path
    // stays: a 409 answers with its own sentence and no code prompt.
    mount({ DeleteDocument: () => graphqlError('LEGAL_HOLD') });
    fireEvent.click(await screen.findByRole('button', { name: 'Delete this document' }));
    expect(await screen.findByText(/preserved as part of an estate matter/i)).toBeVisible();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });
});

describe('failure states', () => {
  it('answers a not-found uniformly, with no hint about whose it is', async () => {
    mount({ Document: () => graphqlError('NOT_FOUND') });
    expect(await screen.findByText('That isn’t available.')).toBeVisible();
  });

  it('treats a response missing its fields as NO DATA', async () => {
    // The M11 defect in the shape it took there: an ordinary version skew
    // arrives as {"data":{}} and must not white-screen or read as a document
    // with no history.
    mount({ Document: () => jsonResponse({ data: {} }) });
    expect(await screen.findByText(/couldn’t load this document/i)).toBeVisible();
  });

  it('treats a MISSING LADDER as no data, not as a fail-closed empty one', async () => {
    // Found by this suite: the page dereferenced allowedTransitions before it
    // was checked, and a peer that predates the field white-screened it — the
    // same shape for the third time. Reading it as an empty list would be
    // worse than the crash: empty is a REAL answer (the service cannot resolve
    // the formalities), so a skew would be indistinguishable from it.
    const { allowedTransitions: _omitted, ...withoutLadder } = DOCUMENT;
    mount({}, withoutLadder);
    expect(await screen.findByText(/couldn’t load this document/i)).toBeVisible();
  });

  it('offers sign-in when the session has ended', async () => {
    mount({ Document: () => graphqlError('UNAUTHENTICATED') });
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });
});
