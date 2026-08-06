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

  it('offers sign-in when the session has ended', async () => {
    mount({ Document: () => graphqlError('UNAUTHENTICATED') });
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });
});
