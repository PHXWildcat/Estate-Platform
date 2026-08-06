import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { DocumentGenerator } from './DocumentGenerator';

const pushMock = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock, refresh: jest.fn() }),
}));

const TEMPLATE = {
  templateId: 't0000000-0000-4000-8000-00000000000a',
  docType: 'will',
  state: 'CA',
  version: 1,
  legalReviewAt: '2026-07-23T00:00:00.000Z',
  executionRequirements: { witnesses: 2, notarization: false, selfProvingAffidavit: false },
  variables: [
    {
      name: 'testatorName',
      kind: 'text',
      label: 'Full legal name',
      required: true,
      maxLength: 200,
      options: null,
    },
    {
      name: 'alternateExecutorName',
      kind: 'text',
      label: 'Alternate executor',
      required: false,
      maxLength: 200,
      options: null,
    },
    {
      name: 'hasMinorChildren',
      kind: 'boolean',
      label: 'Do you have minor children?',
      required: true,
      maxLength: null,
      options: null,
    },
  ],
};

const POA_TEMPLATE = {
  ...TEMPLATE,
  templateId: 't0000000-0000-4000-8000-00000000000b',
  docType: 'durable_poa',
  variables: [],
};

const GENERATED = {
  documentId: 'd0000000-0000-4000-8000-00000000000a',
  version: 1,
  contentSha256: 'a'.repeat(64),
  executionStatus: 'generated',
};

function mount(
  overrides: Partial<Record<string, OperationHandler>> = {},
  props: Parameters<typeof DocumentGenerator>[0] = {},
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    DocumentTemplates: () =>
      jsonResponse({ data: { documentTemplates: [TEMPLATE, POA_TEMPLATE] } }),
    GenerateDocument: () => jsonResponse({ data: { generateDocument: GENERATED } }),
    RegenerateDocument: () =>
      jsonResponse({ data: { regenerateDocument: { ...GENERATED, version: 2 } } }),
    StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    ...overrides,
  });
  render(<DocumentGenerator {...props} />);
  return requests;
}

function selectState(value = 'CA'): void {
  fireEvent.change(screen.getByLabelText('State'), { target: { value } });
}

async function chooseWill(): Promise<void> {
  selectState();
  const buttons = await screen.findAllByRole('button', { name: 'Choose' });
  fireEvent.click(buttons[0] as HTMLElement);
}

function lastVariablesSent(requests: readonly RecordedRequest[], operation: string): unknown {
  const sent = requests.filter((request) => request.body.query?.includes(operation));
  return (sent[sent.length - 1]?.body.variables as { variables?: unknown } | undefined)?.variables;
}

describe('the questionnaire comes from the template', () => {
  it('asks nothing until a state is chosen', () => {
    const requests = mount();
    expect(screen.queryByRole('button', { name: 'Choose' })).not.toBeInTheDocument();
    expect(requests).toHaveLength(0);
  });

  it('builds the form from the template’s declared variables, not a local list', async () => {
    mount();
    await chooseWill();
    // Labels, kinds and the template's own length cap all come from the
    // reviewed source; nothing here is hand-written per instrument.
    expect(screen.getByLabelText('Full legal name')).toHaveAttribute('maxlength', '200');
    expect(screen.getByLabelText('Alternate executor (optional)')).toBeInTheDocument();
    expect(screen.getByLabelText('Do you have minor children?')).toHaveAttribute(
      'type',
      'checkbox',
    );
  });

  it('reads back the template’s execution formalities', async () => {
    mount();
    selectState();
    // A fact about what the reviewed template records — never a claim of law.
    const readbacks = await screen.findAllByText(/signing needs 2 witnesses/i);
    expect(readbacks.length).toBeGreaterThan(0);
  });

  it('says plainly when a state has no reviewed template', async () => {
    mount({ DocumentTemplates: () => jsonResponse({ data: { documentTemplates: [] } }) });
    selectState('WY');
    expect(await screen.findByText(/No attorney-reviewed templates for WY/i)).toBeVisible();
  });

  it('treats a response missing its field as NO DATA', async () => {
    mount({ DocumentTemplates: () => jsonResponse({ data: {} }) });
    selectState();
    // Not "no templates for this state", which is a different, actionable fact.
    expect(await screen.findByText(/Something went wrong/i)).toBeVisible();
  });
});

describe('what gets submitted', () => {
  it('sends the answers with the chosen template, and navigates on success', async () => {
    const requests = mount();
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), {
      target: { value: '  Ada Lovelace  ' },
    });
    fireEvent.click(screen.getByLabelText('Do you have minor children?'));
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(`/documents/${GENERATED.documentId}`);
    });
    expect(lastVariablesSent(requests, 'GenerateDocument')).toEqual([
      { name: 'testatorName', text: 'Ada Lovelace' },
      { name: 'hasMinorChildren', boolean: true },
    ]);
  });

  it('omits an empty OPTIONAL answer rather than sending an empty string', async () => {
    // The template's intake schema types an optional variable as
    // absent-or-non-empty, so '' would be refused as invalid rather than
    // understood as "not applicable".
    const requests = mount();
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    await waitFor(() => {
      expect(pushMock).toHaveBeenCalled();
    });
    const sent = lastVariablesSent(requests, 'GenerateDocument') as Array<{ name: string }>;
    expect(sent.map((entry) => entry.name)).not.toContain('alternateExecutorName');
  });

  it('says the document EXISTS when the reply is not understood, rather than going quiet', async () => {
    /*
     * The M12-review defect: a write path with no "a response missing its
     * field is not data" guard. A version skew arrives as {"data":{}}, the
     * dereference threw inside a void-ed handler after busy had cleared, and
     * the form sat idle with no error and no navigation — for a document that
     * HAD been generated. The next thing a user does is press the button
     * again, which mints a second legal instrument.
     */
    mount({ GenerateDocument: () => jsonResponse({ data: {} }) });
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    expect(await screen.findByText(/don’t create it again/i)).toBeVisible();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it('names the missing required answers instead of submitting a blank one', async () => {
    const requests = mount();
    await chooseWill();
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    // The service withholds WHICH variable failed (values are PII), so a
    // submitted-and-refused round trip would name nothing.
    expect(await screen.findByText(/Still needed: Full legal name/i)).toBeVisible();
    expect(requests.filter((r) => r.body.query?.includes('GenerateDocument'))).toHaveLength(0);
  });
});

describe('step-up', () => {
  it('collects a code inline and retries the SAME submission', async () => {
    let generateCalls = 0;
    const requests = mount({
      GenerateDocument: () => {
        generateCalls += 1;
        return generateCalls === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { generateDocument: GENERATED } });
      },
    });
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));

    const code = await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and generate' }));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(`/documents/${GENERATED.documentId}`);
    });
    // Nobody loses a filled-in form to an authentication round trip: the same
    // answers are re-sent unchanged.
    expect(lastVariablesSent(requests, 'GenerateDocument')).toEqual([
      { name: 'testatorName', text: 'Ada' },
      { name: 'hasMinorChildren', boolean: false },
    ]);
  });

  it('says a REJECTED code was rejected, not that a password was wrong', async () => {
    // Found by driving the real app: identity answers `invalid_credentials` for
    // a bad TOTP code exactly as for a bad password, so the shared copy table
    // told someone "that email and password combination didn't work" about a
    // form carrying neither.
    installGraphqlFetchMock({
      DocumentTemplates: () => jsonResponse({ data: { documentTemplates: [TEMPLATE] } }),
      GenerateDocument: () => graphqlError('STEPUP_REQUIRED'),
      StepUp: () => graphqlError('INVALID_CREDENTIALS'),
    });
    render(<DocumentGenerator />);
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and generate' }));
    expect(await screen.findByText(/Codes change every 30 seconds/i)).toBeVisible();
    expect(screen.queryByText(/email and password/i)).not.toBeInTheDocument();
  });

  it('rejects a malformed code without calling the server', async () => {
    const requests = mount({ GenerateDocument: () => graphqlError('STEPUP_REQUIRED') });
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Generate document' }));
    await screen.findByLabelText('Confirm it’s you');
    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '12' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and generate' }));
    expect(await screen.findByText(/6 digits, numbers only/i)).toBeVisible();
    expect(requests.filter((r) => r.body.query?.includes('StepUp'))).toHaveLength(0);
  });
});

describe('revising an existing document', () => {
  const REVISE = {
    documentId: 'd0000000-0000-4000-8000-00000000000a',
    docType: 'will',
    title: 'Last Will and Testament',
  };

  it('offers only templates that could produce a new version of THIS instrument', async () => {
    mount({}, { revise: REVISE });
    selectState();
    // The catalog carries a will and a POA; the service would refuse a
    // mismatched template, so the picker must not offer one.
    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: 'Choose' })).toHaveLength(1);
    });
    expect(screen.getByText('Will')).toBeInTheDocument();
    expect(screen.queryByText('Durable power of attorney')).not.toBeInTheDocument();
  });

  it('sends a regeneration against the document, keeping its title', async () => {
    const requests = mount({}, { revise: REVISE });
    await chooseWill();
    fireEvent.change(screen.getByLabelText('Full legal name'), { target: { value: 'Ada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create new version' }));
    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith(`/documents/${REVISE.documentId}`);
    });
    const sent = requests.find((request) => request.body.query?.includes('RegenerateDocument'));
    expect(sent?.body.variables).toMatchObject({
      documentId: REVISE.documentId,
      title: REVISE.title,
      templateId: TEMPLATE.templateId,
    });
  });
});
