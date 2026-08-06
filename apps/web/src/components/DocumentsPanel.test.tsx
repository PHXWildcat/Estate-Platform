import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { DocumentsPanel } from './DocumentsPanel';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const WILL = {
  documentId: 'd0000000-0000-4000-8000-00000000000a',
  docType: 'will',
  source: 'generated',
  title: 'Last Will and Testament',
  currentVersion: 1,
  executionStatus: 'generated',
  executedAt: null,
  legalHold: false,
  sealed: false,
  templateId: 't0000000-0000-4000-8000-00000000000a',
  createdAt: '2026-08-01T10:00:00.000Z',
  updatedAt: '2026-08-01T10:00:00.000Z',
};

const POA = {
  ...WILL,
  documentId: 'd0000000-0000-4000-8000-00000000000b',
  docType: 'durable_poa',
  title: 'Durable power of attorney',
  executionStatus: 'executed',
  executedAt: '2026-07-04',
  updatedAt: '2026-08-04T10:00:00.000Z',
};

function mount(
  documents: unknown,
  overrides: Partial<Record<string, OperationHandler>> = {},
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    Documents: () => jsonResponse({ data: { documents } }),
    DocumentSearch: () => jsonResponse({ data: { documentSearch: [POA] } }),
    ...overrides,
  });
  render(<DocumentsPanel />);
  return requests;
}

function runSearch(term: string): void {
  fireEvent.change(screen.getByLabelText('Search your documents'), { target: { value: term } });
  fireEvent.click(screen.getByRole('button', { name: 'Search' }));
}

describe('the list is metadata only', () => {
  it('never asks for content while listing', async () => {
    const requests = mount([WILL, POA]);
    await screen.findByText('Last Will and Testament');
    // The load-bearing assertion of this surface. Every content read is an
    // audited decrypt on the user's own trail, so a list that fetched content
    // would turn one page load into one such event per document.
    const operations = requests.map((request) => request.body.query?.split(/[\s({]+/)[1]);
    expect(operations).toEqual(['Documents']);
  });

  it('shows what each status MEANS, not just its name', async () => {
    mount([WILL]);
    // "Generated" read as "done" is the misunderstanding this surface exists to
    // stop — it is the same fact the readiness page reports as
    // `instrument_not_executed`.
    expect(await screen.findByText(/does not direct anything yet/i)).toBeInTheDocument();
  });

  it('counts what is actually in force', async () => {
    mount([WILL, POA]);
    expect(await screen.findByText('In force')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 not executed yet, so it directs nothing.')).toBeInTheDocument();
  });

  it('flags a legal hold, because it changes what the owner can do', async () => {
    mount([{ ...WILL, legalHold: true }]);
    expect(await screen.findByText('Legal hold')).toBeInTheDocument();
  });

  it('renders a user-authored title as text, never as markup', async () => {
    const { container } = (() => {
      installGraphqlFetchMock({
        Documents: () =>
          jsonResponse({
            data: { documents: [{ ...WILL, title: '<img src=x onerror=alert(1)>My will' }] },
          }),
      });
      return render(<DocumentsPanel />);
    })();
    await screen.findByText('<img src=x onerror=alert(1)>My will');
    expect(container.querySelectorAll('img')).toHaveLength(0);
  });
});

describe('encrypted search', () => {
  it('sends the trimmed query and shows only the matches', async () => {
    const requests = mount([WILL, POA]);
    await screen.findByText('Last Will and Testament');
    runSearch('  power  ');
    await waitFor(() => {
      expect(screen.getByText(/Matches for/)).toBeInTheDocument();
    });
    const sent = requests.find((r) => r.body.query?.includes('DocumentSearch'));
    expect(sent?.body.variables).toEqual({ query: 'power' });
    // By LINK, not by text: the upload form's kind picker also contains the
    // words "Durable power of attorney" as an option.
    expect(screen.getByRole('link', { name: 'Durable power of attorney' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Last Will and Testament' })).not.toBeInTheDocument();
  });

  it('refuses a too-short query with the server’s own bound, before sending', async () => {
    const requests = mount([WILL]);
    await screen.findByText('Last Will and Testament');
    runSearch('ab');
    expect(await screen.findByText(/at least 3 characters/i)).toBeVisible();
    expect(requests.filter((r) => r.body.query?.includes('DocumentSearch'))).toHaveLength(0);
  });

  it('says a search matched nothing WITHOUT the empty-estate copy', async () => {
    // "You have no documents" is a claim about the account; "nothing matched"
    // is a fact about the query. Conflating them would tell someone their
    // estate is empty because they misspelled a word.
    mount([WILL], { DocumentSearch: () => jsonResponse({ data: { documentSearch: [] } }) });
    await screen.findByText('Last Will and Testament');
    runSearch('lake');
    expect(await screen.findByText(/Nothing matched/i)).toBeVisible();
    expect(screen.queryByText(/Nothing on file yet/i)).not.toBeInTheDocument();
  });

  it('restores the full list when the search is cleared', async () => {
    mount([WILL, POA]);
    await screen.findByText('Last Will and Testament');
    runSearch('power');
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(await screen.findByText('Last Will and Testament')).toBeInTheDocument();
  });

  it('explains why a partial word finds nothing, where the user meets it', async () => {
    // The accepted cost of matching ciphertext-side: whole indexed words only.
    mount([WILL]);
    expect(await screen.findByText(/matches encrypted keywords/i)).toBeVisible();
  });
});

describe('failure states', () => {
  it('says nothing about the account when the read fails', async () => {
    installGraphqlFetchMock({ Documents: () => graphqlError('UNKNOWN') });
    render(<DocumentsPanel />);
    // An empty list would read as "you have no documents", which is a claim.
    expect(await screen.findByText(/not a statement about what you have on file/i)).toBeVisible();
  });

  it('offers sign-in rather than an error when the session has ended', async () => {
    installGraphqlFetchMock({ Documents: () => graphqlError('UNAUTHENTICATED') });
    render(<DocumentsPanel />);
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('treats a response missing its field as NO DATA, not as an empty estate', async () => {
    // The M11 defect, in the shape it took there: an ordinary version skew
    // arrives as {"data":{}} and must not white-screen or read as "none".
    mount(undefined);
    expect(await screen.findByText(/couldn’t load your documents/i)).toBeVisible();
  });
});
