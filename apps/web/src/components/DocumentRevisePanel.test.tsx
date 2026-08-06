import { render, screen } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { DocumentRevisePanel } from './DocumentRevisePanel';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const DOCUMENT_ID = 'd0000000-0000-4000-8000-00000000000a';

const DOCUMENT = {
  documentId: DOCUMENT_ID,
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

function mount(document: unknown, overrides: Partial<Record<string, OperationHandler>> = {}): void {
  installGraphqlFetchMock({
    Document: () => jsonResponse({ data: { document } }),
    DocumentTemplates: () => jsonResponse({ data: { documentTemplates: [] } }),
    ...overrides,
  });
  render(<DocumentRevisePanel documentId={DOCUMENT_ID} />);
}

describe('refusing before the form rather than after', () => {
  it('opens the generator for a generated, unsigned document', async () => {
    mount(DOCUMENT);
    expect(await screen.findByLabelText('State')).toBeInTheDocument();
  });

  it.each([['signed'], ['witnessed'], ['executed'], ['revoked']])(
    'explains rather than asking, for a %s document',
    async (executionStatus) => {
      mount({ ...DOCUMENT, executionStatus });
      // A filled-in questionnaire followed by a 409 is the worse answer: the
      // wording of a signed instrument is a legal record.
      expect(await screen.findByText('This document can’t be revised')).toBeVisible();
      expect(screen.getByText(/Revoke or supersede it/i)).toBeVisible();
      expect(screen.queryByLabelText('State')).not.toBeInTheDocument();
    },
  );

  it('explains that an uploaded document has no template to re-render from', async () => {
    mount({ ...DOCUMENT, source: 'uploaded', templateId: null });
    expect(await screen.findByText(/no template to re-render it from/i)).toBeVisible();
  });
});

describe('failure states', () => {
  it('answers a not-found uniformly', async () => {
    mount(DOCUMENT, { Document: () => graphqlError('NOT_FOUND') });
    expect(await screen.findByText('That isn’t available.')).toBeVisible();
  });

  it('treats a response missing its field as NO DATA', async () => {
    mount(DOCUMENT, { Document: () => jsonResponse({ data: {} }) });
    expect(await screen.findByText(/Something went wrong/i)).toBeVisible();
  });
});
