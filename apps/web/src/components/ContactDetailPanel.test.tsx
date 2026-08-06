import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { ContactDetailPanel } from './ContactDetailPanel';

const push = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, refresh: jest.fn() }),
}));

const CONTACT_ID = 'f0000000-0000-4000-8000-00000000000a';

const DETAIL = {
  id: CONTACT_ID,
  name: 'Bob Brother',
  email: 'bob@example.com',
  phone: '555-0100',
  address: null,
  relationship: 'brother',
  professionalKind: null,
  notes: null,
};

const SUMMARY = {
  id: CONTACT_ID,
  name: 'Bob Brother',
  relationship: 'brother',
  professionalKind: null,
  hasEmail: true,
  hasPhone: true,
  hasAddress: false,
  hasNotes: false,
  linked: true,
};

function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(overrides: Partial<Record<string, OperationHandler>> = {}): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    Contact: () => jsonResponse({ data: { contact: DETAIL } }),
    Contacts: () => jsonResponse({ data: { contacts: [SUMMARY] } }),
    RoleAssignments: () => jsonResponse({ data: { roleAssignments: [] } }),
    ...overrides,
  });
  render(<ContactDetailPanel contactId={CONTACT_ID} />);
  return requests;
}

beforeEach(() => {
  push.mockReset();
});

describe('opening a person is what spends the decrypts', () => {
  it('reads the one contact, exactly once', async () => {
    const requests = mount();
    await screen.findByText('bob@example.com');
    // One read per opening: no prefetch, no second call, no cache that would
    // make a repeat read invisible on the owner's own audit trail.
    expect(opNames(requests).filter((n) => n === 'Contact')).toHaveLength(1);
  });

  it('tells the owner the read is on their trail', async () => {
    mount();
    expect(
      await screen.findByText(/the read is recorded on your own activity trail/),
    ).toBeInTheDocument();
  });

  it('omits fields that are not on file rather than showing empties', async () => {
    mount();
    await screen.findByText('bob@example.com');
    expect(screen.queryByText('Address')).not.toBeInTheDocument();
    expect(screen.queryByText('Notes')).not.toBeInTheDocument();
  });
});

describe('the uniform not-found', () => {
  it('says the same thing for someone else’s id as for one that does not exist', async () => {
    mount({ Contact: () => graphqlError('NOT_FOUND') });
    expect(await screen.findByText('That isn’t available.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to people' })).toBeInTheDocument();
  });

  it('offers a sign-in when the session has ended', async () => {
    mount({ Contact: () => graphqlError('UNAUTHENTICATED') });
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });
});

describe('a failed list read costs the badge, not the page', () => {
  it('still renders the contact when the summary read fails', async () => {
    mount({ Contacts: () => graphqlError('UNKNOWN') });
    // The detail is the page; `linked` is a badge on it.
    expect(await screen.findByText('bob@example.com')).toBeInTheDocument();
  });

  /**
   * The version-skew shape M11 and M12 each found by running the real app: a
   * response without the row must read as "we do not know", never as "no
   * account", which is a claim about someone's estate.
   */
  it('says nothing about accounts when the row is absent from the list', async () => {
    mount({ Contacts: () => jsonResponse({ data: { contacts: [] } }) });
    await screen.findByText('bob@example.com');
    await waitFor(() => {
      expect(screen.getByText('Their role in your estate')).toBeInTheDocument();
    });
    expect(screen.queryByText(/does not have an account/)).not.toBeInTheDocument();
  });
});

describe('editing', () => {
  async function openEditor(): Promise<void> {
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
  }

  it('prefills from the stored record and renders what the server saved', async () => {
    mount({
      UpdateContact: () =>
        jsonResponse({ data: { updateContact: { ...DETAIL, phone: '555-0199' } } }),
    });
    await openEditor();
    expect(screen.getByLabelText('Phone')).toHaveValue('555-0100');

    fireEvent.change(screen.getByLabelText('Phone'), { target: { value: 'ignored locally' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

    // The panel shows the SERVER's row, not what was typed.
    expect(await screen.findByText('555-0199')).toBeInTheDocument();
    expect(screen.queryByText('ignored locally')).not.toBeInTheDocument();
  });

  it('cancelling restores the stored values rather than keeping edits', async () => {
    mount();
    await openEditor();
    fireEvent.change(screen.getByLabelText('Phone'), { target: { value: '555-9999' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.getByLabelText('Phone')).toHaveValue('555-0100');
  });
});

describe('deleting', () => {
  it('says what to do when a role still names this person', async () => {
    mount({ DeleteContact: () => graphqlError('CONTACT_IN_USE') });
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));

    // Actionable, and never softened into a generic conflict: deleting used to
    // retire the person's fiduciary roles silently (fixed in M13 PR1).
    expect(await screen.findByText(/Remove their roles first/)).toBeInTheDocument();
    expect(push).not.toHaveBeenCalled();
  });

  it('returns to the list once the person is gone', async () => {
    mount({ DeleteContact: () => jsonResponse({ data: { deleteContact: [] } }) });
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => {
      expect(push).toHaveBeenCalledWith('/people');
    });
  });
});

describe('the remaining paths', () => {
  it('sends only the non-empty fields on an edit', async () => {
    const requests = mount({
      UpdateContact: () => jsonResponse({ data: { updateContact: DETAIL } }),
    });
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Notes'), { target: { value: 'lead contact' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => {
      expect(opNames(requests)).toContain('UpdateContact');
    });
    const sent = requests.find((r) => r.body.query?.includes('UpdateContact'));
    // `address` and `professionalKind` stay out: the service requires a non-empty
    // value for every optional field it accepts.
    expect(sent?.body.variables).toEqual({
      contactId: CONTACT_ID,
      name: 'Bob Brother',
      email: 'bob@example.com',
      phone: '555-0100',
      relationship: 'brother',
      notes: 'lead contact',
    });
  });

  it('refuses an empty name locally', async () => {
    const requests = mount();
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: ' ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('A name is needed.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('UpdateContact');
  });

  it('surfaces a refused edit without closing the form', async () => {
    mount({ UpdateContact: () => graphqlError('INVALID_REQUEST') });
    await screen.findByText('bob@example.com');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toBeInTheDocument();
  });

  it('shows an error rather than a person when the detail read fails outright', async () => {
    mount({ Contact: () => graphqlError('UNKNOWN') });
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
  });

  it('passes the account status through to the role controls when it knows', async () => {
    mount({
      Contacts: () => jsonResponse({ data: { contacts: [{ ...SUMMARY, linked: false }] } }),
    });
    expect(
      await screen.findByText(/does not have an account on this platform yet/),
    ).toBeInTheDocument();
  });

  it('shows a professional role when one is recorded', async () => {
    mount({
      Contact: () =>
        jsonResponse({ data: { contact: { ...DETAIL, professionalKind: 'attorney' } } }),
    });
    expect(await screen.findByText('Attorney')).toBeInTheDocument();
  });
});
