import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { PeoplePanel } from './PeoplePanel';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const ALICE = {
  id: 'f0000000-0000-4000-8000-00000000000a',
  name: 'Alice Attorney',
  relationship: 'friend',
  professionalKind: 'attorney',
  hasEmail: true,
  hasPhone: true,
  hasAddress: false,
  hasNotes: false,
  linked: false,
};

const BOB = {
  id: 'f0000000-0000-4000-8000-00000000000b',
  name: 'Bob Brother',
  relationship: 'brother',
  professionalKind: null,
  hasEmail: false,
  hasPhone: false,
  hasAddress: false,
  hasNotes: false,
  linked: true,
};

const EXECUTOR_ROLE = {
  id: 'e0000000-0000-4000-8000-00000000000a',
  contactId: BOB.id,
  role: 'executor',
  scopeType: 'estate',
  scopeId: null,
  effectiveCondition: 'on_death_verified',
  startsAt: null,
  endsAt: null,
};

/** The operation names actually sent, in the mock's own derivation. */
function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(
  contacts: unknown,
  roles: unknown = [],
  overrides: Partial<Record<string, OperationHandler>> = {},
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    Contacts: () => jsonResponse({ data: { contacts } }),
    RoleAssignments: () => jsonResponse({ data: { roleAssignments: roles } }),
    ...overrides,
  });
  render(<PeoplePanel />);
  return requests;
}

describe('the list decrypts as little as it can', () => {
  it('never asks for a contact’s details while listing', async () => {
    const requests = mount([ALICE, BOB], [EXECUTOR_ROLE]);
    await screen.findByText('Alice Attorney');
    // Every field of a contact is an audited decrypt downstream (docs/03 §6f).
    // The list asks for summaries and the per-person read only when someone
    // opens that person.
    expect(opNames(requests).sort()).toEqual(['Contacts', 'RoleAssignments']);
    expect(opNames(requests)).not.toContain('Contact');
  });

  it('says WHAT is on file without having read it', async () => {
    mount([ALICE]);
    expect(await screen.findByText(/On file: email, phone/)).toBeInTheDocument();
    // ...and the values themselves are nowhere on the page.
    expect(screen.queryByText(/@/)).not.toBeInTheDocument();
  });
});

describe('a row shows whether a designation can actually be used', () => {
  it('marks a linked contact as having an account and an unlinked one as not', async () => {
    mount([ALICE, BOB]);
    await screen.findByText('Bob Brother');
    expect(screen.getByText('Has an account')).toBeInTheDocument();
    expect(screen.getByText('No account yet')).toBeInTheDocument();
  });

  it('shows the roles a person holds', async () => {
    mount([ALICE, BOB], [EXECUTOR_ROLE]);
    expect(await screen.findByText('Executor')).toBeInTheDocument();
  });
});

describe('the summary line', () => {
  it('counts people and role-holders', async () => {
    mount([ALICE, BOB], [EXECUTOR_ROLE]);
    expect(
      await screen.findByText('2 people on file, 1 holding a role in your estate.'),
    ).toBeInTheDocument();
  });

  it('says so plainly when nobody holds a role', async () => {
    mount([ALICE, BOB]);
    expect(
      await screen.findByText('2 people on file, none holding a role in your estate yet.'),
    ).toBeInTheDocument();
  });

  /**
   * A role can outlive the contact row a client can see (a §5.5 grant-holder
   * sees only the contacts a grant names). Counting role rows rather than
   * matched contacts would then report more role-holders than people.
   */
  it('ignores roles whose contact is not in the list', async () => {
    mount([ALICE], [EXECUTOR_ROLE]);
    expect(
      await screen.findByText('1 person on file, none holding a role in your estate yet.'),
    ).toBeInTheDocument();
  });

  it('invites a first contact when there are none', async () => {
    mount([]);
    expect(await screen.findByText('Nobody on file yet.')).toBeInTheDocument();
  });
});

describe('adding a person', () => {
  function openForm(): void {
    fireEvent.click(screen.getByRole('button', { name: 'Add a person' }));
  }

  it('omits blank optional fields rather than sending them empty', async () => {
    const requests = mount([], [], {
      AddContact: () => jsonResponse({ data: { addContact: [ALICE] } }),
    });
    await screen.findByText('Nobody on file yet.');
    openForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Alice Attorney' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));

    await waitFor(() => {
      expect(opNames(requests)).toContain('AddContact');
    });
    const add = requests.find((r) => r.body.query?.includes('AddContact'));
    // The service requires a non-empty value for each optional field it accepts,
    // so an empty string would be a 400 for something the user left out.
    expect(add?.body.variables).toEqual({ name: 'Alice Attorney' });
  });

  it('renders the server’s list rather than appending locally', async () => {
    mount([], [], {
      AddContact: () => jsonResponse({ data: { addContact: [ALICE, BOB] } }),
    });
    await screen.findByText('Nobody on file yet.');
    openForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Ignored locally' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));

    // Both names come back from the server; the typed one is not shown at all.
    expect(await screen.findByText('Alice Attorney')).toBeInTheDocument();
    expect(screen.getByText('Bob Brother')).toBeInTheDocument();
    expect(screen.queryByText('Ignored locally')).not.toBeInTheDocument();
  });

  it('surfaces a refusal without clearing the form', async () => {
    mount([], [], {
      AddContact: () => graphqlError('INVALID_REQUEST'),
    });
    await screen.findByText('Nobody on file yet.');
    openForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Alice Attorney' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));

    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.getByLabelText('Name')).toHaveValue('Alice Attorney');
  });
});

describe('load failures', () => {
  it('offers a sign-in link when the session has ended', async () => {
    mount([], [], { Contacts: () => graphqlError('UNAUTHENTICATED') });
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('shows an error rather than an empty estate when a read fails', async () => {
    mount([], [], { RoleAssignments: () => graphqlError('UNKNOWN') });
    // Never "nobody on file" for a failed request — that is a claim about
    // someone's estate made on the strength of an outage.
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
    expect(screen.queryByText('Nobody on file yet.')).not.toBeInTheDocument();
  });
});

describe('the add form’s remaining paths', () => {
  it('refuses an empty name locally, without a request', async () => {
    const requests = mount([]);
    await screen.findByText('Nobody on file yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add a person' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));
    expect(await screen.findByText('A name is needed.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('AddContact');
  });

  it('sends every optional field the user did fill in', async () => {
    const requests = mount([], [], {
      AddContact: () => jsonResponse({ data: { addContact: [ALICE] } }),
    });
    await screen.findByText('Nobody on file yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add a person' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Alice Attorney' } });
    fireEvent.change(screen.getByLabelText(/Relationship/), { target: { value: 'friend' } });
    fireEvent.change(screen.getByLabelText(/Email/), { target: { value: 'alice@law.example' } });
    fireEvent.change(screen.getByLabelText(/Phone/), { target: { value: '555-0100' } });
    fireEvent.change(screen.getByLabelText(/Professional role/), {
      target: { value: 'attorney' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));

    await waitFor(() => {
      expect(opNames(requests)).toContain('AddContact');
    });
    expect(requests.find((r) => r.body.query?.includes('AddContact'))?.body.variables).toEqual({
      name: 'Alice Attorney',
      relationship: 'friend',
      email: 'alice@law.example',
      phone: '555-0100',
      professionalKind: 'attorney',
    });
  });

  it('closes and clears the form after a successful add', async () => {
    mount([], [], { AddContact: () => jsonResponse({ data: { addContact: [ALICE] } }) });
    await screen.findByText('Nobody on file yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add a person' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Alice Attorney' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add person' }));

    await screen.findByText('Alice Attorney');
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add a person' }));
    expect(screen.getByLabelText('Name')).toHaveValue('');
  });

  it('shows a professional label on a row that has one', async () => {
    mount([ALICE]);
    // The whole metadata line as one node — a sentence split across elements is
    // one a screen reader can announce in pieces.
    expect(
      await screen.findByText('friend · Attorney · On file: email, phone'),
    ).toBeInTheDocument();
  });

  it('says nothing is on file when nothing is', async () => {
    mount([BOB]);
    expect(await screen.findByText(/No contact details on file/)).toBeInTheDocument();
  });
});
