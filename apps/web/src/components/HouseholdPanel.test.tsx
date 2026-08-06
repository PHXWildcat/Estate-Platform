import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { HouseholdPanel } from './HouseholdPanel';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const PROFILE = {
  userId: 'a1111111-1111-4111-8111-111111111111',
  legalName: 'Jane Quincy Public',
  dob: '1950-04-02',
  ssnLast4: '6789',
  address: '1 Main St',
  phone: '555-0100',
  occupation: 'Architect',
  maritalStatus: 'married',
  stateOfResidence: 'AZ',
};

const CHILD = {
  id: 'c0000000-0000-4000-8000-00000000000a',
  relation: 'child',
  name: 'Kiddo Public',
  dob: '2015-06-01',
  isMinor: true,
  notes: null,
};

function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(
  profile: unknown = PROFILE,
  family: unknown = [CHILD],
  overrides: Partial<Record<string, OperationHandler>> = {},
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    Profile: () => jsonResponse({ data: { profile } }),
    FamilyMembers: () => jsonResponse({ data: { familyMembers: family } }),
    ...overrides,
  });
  render(<HouseholdPanel />);
  return requests;
}

describe('the SSN is shown and never collected', () => {
  it('displays only the last four', async () => {
    mount();
    expect(await screen.findByText('Ends 6789')).toBeInTheDocument();
    expect(screen.queryByText(/6789\d|\d{9}/)).not.toBeInTheDocument();
  });

  it('has no input for it anywhere on the edit form', async () => {
    mount();
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    // Not merely absent from the markup: there is no such argument on the
    // mutation and no such field in the BFF's client either.
    expect(screen.queryByLabelText(/Social Security/i)).not.toBeInTheDocument();
    expect(
      screen.getByText(/We never ask for your Social Security number here./),
    ).toBeInTheDocument();
  });

  it('says nothing at all when none is on file', async () => {
    mount({ ...PROFILE, ssnLast4: null });
    await screen.findByText('Jane Quincy Public');
    expect(screen.queryByText(/Ends /)).not.toBeInTheDocument();
  });
});

describe('a profile that does not exist yet', () => {
  it('invites a first save rather than showing a failure', async () => {
    // Null is a REAL ANSWER — nothing on file — not an outage (the M10 lesson).
    mount(null, []);
    expect(await screen.findByText(/Nothing on file yet./)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add your details' })).toBeInTheDocument();
    expect(screen.queryByText(/went wrong on our side/)).not.toBeInTheDocument();
  });

  it('shows a failure for an actual failure', async () => {
    mount(null, [], { Profile: () => graphqlError('UNKNOWN') });
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
  });
});

describe('saving sends only what the form holds', () => {
  it('sends the six fields it shows and no others', async () => {
    const requests = mount(PROFILE, [], {
      SaveProfile: () => jsonResponse({ data: { saveProfile: { ...PROFILE, occupation: null } } }),
    });
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Occupation'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(opNames(requests)).toContain('SaveProfile');
    });
    const save = requests.find((r) => r.body.query?.includes('SaveProfile'));
    // A box the user emptied is an explicit CLEAR. The SSN is not in this object
    // at all, so the service leaves it alone — which is the whole reason the
    // route stopped being a full replace (M13 PR1).
    expect(save?.body.variables).toEqual({
      legalName: 'Jane Quincy Public',
      dob: '1950-04-02',
      address: '1 Main St',
      phone: '555-0100',
      occupation: null,
      maritalStatus: 'married',
      stateOfResidence: 'AZ',
    });
    expect(save?.body.variables).not.toHaveProperty('ssn');
  });

  it('renders the saved row, not the typed one', async () => {
    mount(PROFILE, [], {
      SaveProfile: () =>
        jsonResponse({ data: { saveProfile: { ...PROFILE, occupation: 'Retired' } } }),
    });
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Occupation'), { target: { value: 'ignored locally' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    expect(await screen.findByText('Retired')).toBeInTheDocument();
    expect(screen.queryByText('ignored locally')).not.toBeInTheDocument();
  });
});

describe('household members', () => {
  it('shows a minor child as such — the fact the readiness check needs', async () => {
    mount(PROFILE, [CHILD]);
    expect(await screen.findByText(/Child · minor · 2015-06-01/)).toBeInTheDocument();
  });

  it('offers the minor question only for a child', async () => {
    mount(PROFILE, []);
    await screen.findByText('Nobody recorded yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add someone' }));
    expect(screen.getByLabelText('Still a minor')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Relation'), { target: { value: 'parent' } });
    expect(screen.queryByLabelText('Still a minor')).not.toBeInTheDocument();
  });

  it('renders the server’s list after adding', async () => {
    mount(PROFILE, [], {
      AddFamilyMember: () => jsonResponse({ data: { addFamilyMember: [CHILD] } }),
    });
    await screen.findByText('Nobody recorded yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add someone' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Kiddo Public' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText('Kiddo Public')).toBeInTheDocument();
  });

  it('renders the server’s list after removing', async () => {
    mount(PROFILE, [CHILD], {
      DeleteFamilyMember: () => jsonResponse({ data: { deleteFamilyMember: [] } }),
    });
    await screen.findByText('Kiddo Public');
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(await screen.findByText('Nobody recorded yet.')).toBeInTheDocument();
  });
});

describe('the rest of the household surface', () => {
  it('offers a sign-in when the session has ended', async () => {
    mount(null, [], { Profile: () => graphqlError('UNAUTHENTICATED') });
    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('shows a failure when the family read fails, not an empty household', async () => {
    mount(PROFILE, [], { FamilyMembers: () => graphqlError('UNKNOWN') });
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
    expect(screen.queryByText('Nobody recorded yet.')).not.toBeInTheDocument();
  });

  it('surfaces a refused save without closing the form', async () => {
    mount(PROFILE, [], { SaveProfile: () => graphqlError('INVALID_REQUEST') });
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Occupation'), { target: { value: 'Retired' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.getByLabelText('Occupation')).toHaveValue('Retired');
  });

  it('refuses an empty legal name locally', async () => {
    const requests = mount(PROFILE, []);
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Legal name'), { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Your legal name is needed.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('SaveProfile');
  });

  it('cancelling an edit restores the stored values', async () => {
    mount(PROFILE, []);
    await screen.findByText('Ends 6789');
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText('Occupation'), { target: { value: 'Changed' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(screen.getByLabelText('Occupation')).toHaveValue('Architect');
  });

  it('refuses a household member with no name', async () => {
    const requests = mount(PROFILE, []);
    await screen.findByText('Nobody recorded yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add someone' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText('A name is needed.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('AddFamilyMember');
  });

  it('surfaces a refused add', async () => {
    mount(PROFILE, [], { AddFamilyMember: () => graphqlError('INVALID_REQUEST') });
    await screen.findByText('Nobody recorded yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add someone' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Kid' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
  });

  it('surfaces a refused removal', async () => {
    mount(PROFILE, [CHILD], { DeleteFamilyMember: () => graphqlError('NOT_FOUND') });
    await screen.findByText('Kiddo Public');
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(await screen.findByText('That isn’t available.')).toBeInTheDocument();
    // The person is still listed: a failed delete must not look like a success.
    expect(screen.getByText('Kiddo Public')).toBeInTheDocument();
  });

  it('sends a date of birth when one is given', async () => {
    const requests = mount(PROFILE, [], {
      AddFamilyMember: () => jsonResponse({ data: { addFamilyMember: [CHILD] } }),
    });
    await screen.findByText('Nobody recorded yet.');
    fireEvent.click(screen.getByRole('button', { name: 'Add someone' }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Kiddo Public' } });
    fireEvent.change(screen.getByLabelText(/Date of birth/), { target: { value: '2015-06-01' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add' }));
    await waitFor(() => {
      expect(opNames(requests)).toContain('AddFamilyMember');
    });
    const add = requests.find((r) => r.body.query?.includes('AddFamilyMember'));
    expect(add?.body.variables).toEqual({
      relation: 'child',
      name: 'Kiddo Public',
      dob: '2015-06-01',
      isMinor: false,
    });
  });
});
