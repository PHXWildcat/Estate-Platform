import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { RoleControls } from './RoleControls';

const CONTACT_ID = 'f0000000-0000-4000-8000-00000000000a';

const EXECUTOR = {
  id: 'e0000000-0000-4000-8000-00000000000a',
  contactId: CONTACT_ID,
  role: 'executor',
  scopeType: 'estate',
  scopeId: null,
  effectiveCondition: 'on_death_verified',
  startsAt: null,
  endsAt: null,
};

const OTHER_CONTACTS_ROLE = {
  ...EXECUTOR,
  id: 'e0000000-0000-4000-8000-00000000000b',
  contactId: 'someone-else',
};

const CONTACT_GRANT = {
  id: 'g0000000-0000-4000-8000-00000000000a',
  resource: 'contact',
  action: 'read',
  createdAt: '2026-08-06T00:00:00.000Z',
};

/** The list of roles this contact holds, distinct from the role PICKER below it. */
function heldRoles(): HTMLElement {
  return screen.getByRole('list', { name: 'Roles held' });
}

function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(
  roles: unknown = [EXECUTOR],
  permissions: unknown = [],
  overrides: Partial<Record<string, OperationHandler>> = {},
  linked: boolean | null = true,
): RecordedRequest[] {
  const { requests } = installGraphqlFetchMock({
    RoleAssignments: () => jsonResponse({ data: { roleAssignments: roles } }),
    RolePermissions: () => jsonResponse({ data: { rolePermissions: permissions } }),
    ...overrides,
  });
  render(<RoleControls contactId={CONTACT_ID} contactName="Bob Brother" linked={linked} />);
  return requests;
}

describe('a designation is not access, and the page says so', () => {
  it('spells out that an on-death role grants nothing today', async () => {
    mount();
    // The same sentence appears on the held role AND under the picker (both
    // default to on_death_verified), which is intended: the meaning must be
    // visible before you commit as well as after.
    expect(
      await screen.findAllByText(
        /It grants no access today: a death has to be reported, reviewed by a person, and confirmed after a waiting period/,
      ),
    ).toHaveLength(2);
  });

  it('says a role with no permission reads nothing', async () => {
    mount([EXECUTOR], []);
    expect(
      await screen.findByText(/Without a permission here, this role reads none of your estate./),
    ).toBeInTheDocument();
  });

  it('warns when the person has no account, so nothing granted can be used', async () => {
    mount([EXECUTOR], [], {}, false);
    expect(
      await screen.findByText(/does not have an account on this platform yet/),
    ).toBeInTheDocument();
  });

  /**
   * Three values, not two: `linked === null` means the read that would have told
   * us failed. Saying "no account yet" then would be a claim about someone's
   * estate on the strength of an outage.
   */
  it('says nothing about accounts when it does not know', async () => {
    mount([EXECUTOR], [], {}, null);
    await waitFor(() => {
      expect(within(heldRoles()).getByText('Executor')).toBeInTheDocument();
    });
    expect(screen.queryByText(/does not have an account/)).not.toBeInTheDocument();
  });
});

describe('only this contact’s roles are shown', () => {
  it('filters out roles belonging to other people', async () => {
    mount([EXECUTOR, OTHER_CONTACTS_ROLE]);
    await waitFor(() => {
      expect(within(heldRoles()).getByText('Executor')).toBeInTheDocument();
    });
    expect(within(heldRoles()).getAllByRole('listitem')).toHaveLength(1);
  });

  it('asks for permissions only for the roles on this page', async () => {
    const requests = mount([EXECUTOR, OTHER_CONTACTS_ROLE], [CONTACT_GRANT]);
    await screen.findByText(/Your estate contacts — Read/);
    await waitFor(() => {
      expect(opNames(requests).filter((n) => n === 'RolePermissions')).toHaveLength(1);
    });
  });
});

describe('the three-way step-up asymmetry', () => {
  it('prompts for a code when naming a role is refused, then retries the same grant', async () => {
    let attempts = 0;
    const requests = mount([], [], {
      GrantRole: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { grantRole: [EXECUTOR] } });
      },
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    await screen.findByText(/No role recorded for Bob Brother yet./);

    fireEvent.click(screen.getByRole('button', { name: 'Name to this role' }));
    expect(
      await screen.findByText(/Naming someone to a role in your estate needs a fresh check/),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and save' }));

    // The SAME grant is retried after the elevation — nobody re-picks a role.
    expect(await screen.findByText('Executor')).toBeInTheDocument();
    expect(opNames(requests).filter((n) => n === 'GrantRole')).toHaveLength(2);
  });

  it('prompts for a code when REMOVING a role too, with its own wording', async () => {
    // Equal, never harder: revoking destroys the executor-resolution path and
    // can strip the last linked contact able to report a death.
    mount([EXECUTOR], [], {
      RevokeRole: () => graphqlError('STEPUP_REQUIRED'),
    });
    await waitFor(() => {
      expect(within(heldRoles()).getByText('Executor')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Remove role' }));
    expect(await screen.findByText(/Removing a role needs a fresh check too/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Confirm and remove' })).toBeInTheDocument();
  });

  it('withdraws a permission with NO code prompt at all', async () => {
    const requests = mount([EXECUTOR], [CONTACT_GRANT], {
      RevokeRolePermission: () => jsonResponse({ data: { revokeRolePermission: [] } }),
    });
    await screen.findByText(/Your estate contacts — Read/);
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));

    // The protective action must never be harder than the permissive one.
    expect(
      await screen.findByText(/Without a permission here, this role reads none of your estate./),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    expect(opNames(requests)).toContain('RevokeRolePermission');
    expect(opNames(requests)).not.toContain('StepUp');
  });

  it('reports a rejected code as a code problem, not a password problem', async () => {
    // Identity answers `invalid_credentials` for a bad TOTP code exactly as for
    // a bad password (the M12 finding). This form has neither on it.
    mount([], [], {
      GrantRole: () => graphqlError('STEPUP_REQUIRED'),
      StepUp: () => graphqlError('INVALID_CREDENTIALS'),
    });
    await screen.findByText(/No role recorded/);
    fireEvent.click(screen.getByRole('button', { name: 'Name to this role' }));
    fireEvent.change(await screen.findByLabelText('Confirm it’s you'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and save' }));

    expect(await screen.findByText(/Codes change every 30 seconds/)).toBeInTheDocument();
    expect(screen.queryByText(/email and password/)).not.toBeInTheDocument();
  });
});

describe('granting a permission', () => {
  it('renders the server’s grant set rather than a local guess', async () => {
    mount([EXECUTOR], [], {
      GrantRolePermission: () => jsonResponse({ data: { grantRolePermission: [CONTACT_GRANT] } }),
    });
    await screen.findByText(/Without a permission here/);
    fireEvent.click(screen.getByRole('button', { name: 'Allow: Your estate contacts' }));
    expect(await screen.findByText(/Your estate contacts — Read/)).toBeInTheDocument();
  });

  it('does not offer a resource that is already granted', async () => {
    mount([EXECUTOR], [CONTACT_GRANT]);
    await screen.findByText(/Your estate contacts — Read/);
    expect(
      screen.queryByRole('button', { name: 'Allow: Your estate contacts' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Allow: Your assets' })).toBeInTheDocument();
  });
});

describe('read failures never read as an empty estate', () => {
  it('surfaces a failed role read rather than "no role recorded"', async () => {
    mount([], [], { RoleAssignments: () => graphqlError('UNKNOWN') });
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
    // "No role recorded" is a claim about someone's estate; an outage is not.
    expect(screen.queryByText(/No role recorded/)).not.toBeInTheDocument();
  });

  it('surfaces a failed permission read', async () => {
    mount([EXECUTOR], [], { RolePermissions: () => graphqlError('UNKNOWN') });
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
  });

  it('reports a non-step-up refusal on a grant without opening the code prompt', async () => {
    mount([], [], { GrantRole: () => graphqlError('INVALID_REQUEST') });
    await screen.findByText(/No role recorded/);
    fireEvent.click(screen.getByRole('button', { name: 'Name to this role' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });

  it('reports a non-step-up refusal on a revoke the same way', async () => {
    mount([EXECUTOR], [], { RevokeRole: () => graphqlError('INVALID_REQUEST') });
    await waitFor(() => {
      expect(within(heldRoles()).getByText('Executor')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'Remove role' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });

  it('reports a refused permission withdrawal', async () => {
    mount([EXECUTOR], [CONTACT_GRANT], {
      RevokeRolePermission: () => graphqlError('NOT_FOUND'),
    });
    await screen.findByText(/Your estate contacts — Read/);
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }));
    expect(await screen.findByText('That isn’t available.')).toBeInTheDocument();
  });

  it('prompts for a code when WIDENING a permission is refused', async () => {
    // Granting is gated like naming a role; only withdrawal is free.
    mount([EXECUTOR], [], { GrantRolePermission: () => graphqlError('STEPUP_REQUIRED') });
    await screen.findByText(/Without a permission here/);
    fireEvent.click(screen.getByRole('button', { name: 'Allow: Your estate contacts' }));
    expect(await screen.findByLabelText('Confirm it’s you')).toBeInTheDocument();
  });

  /**
   * The M13 review's high-severity finding. The refused action was a PERMISSION
   * widen; the retry after elevation used to call grantRole() from the picker's
   * current state, so a genuine TOTP challenge minted an executor designation the
   * owner never chose — onto the settlement/§5.1 executor-resolution chain — and
   * silently dropped the permission they had clicked.
   */
  it('retries THE PERMISSION after elevation, and never mints a role assignment', async () => {
    let attempts = 0;
    const requests = mount([EXECUTOR], [], {
      GrantRolePermission: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { grantRolePermission: [CONTACT_GRANT] } });
      },
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
      // Deliberately present: if the retry dispatched to the wrong action the
      // handler would answer and the assertion below would catch the write.
      GrantRole: () => jsonResponse({ data: { grantRole: [EXECUTOR] } }),
    });
    await screen.findByText(/Without a permission here/);
    fireEvent.click(screen.getByRole('button', { name: 'Allow: Your estate contacts' }));

    // The prompt's words follow the ACTION, not the other branch's.
    expect(
      await screen.findByText(/Allowing a role to read part of your estate/),
    ).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and allow' }));

    // The permission landed...
    expect(await screen.findByText(/Your estate contacts — Read/)).toBeInTheDocument();
    expect(opNames(requests).filter((n) => n === 'GrantRolePermission')).toHaveLength(2);
    // ...and NO designation was written.
    expect(opNames(requests)).not.toContain('GrantRole');
  });

  /**
   * The M13 review's third round, on the fixes themselves: `grantPermission` was
   * the one retried action with no in-flight guard, so its buttons stayed live
   * while a request was open. Two clicks issued two writes — and before migration
   * 005 gave `permission_grants` a uniqueness constraint, two GRANTS, of which
   * withdrawing the one on screen left the other still conferring the read.
   */
  it('a second click cannot widen the same permission twice', async () => {
    let release: () => void = () => undefined;
    const requests = mount([EXECUTOR], [], {
      GrantRolePermission: () =>
        new Promise<Response>((resolve) => {
          release = () => resolve(jsonResponse({ data: { grantRolePermission: [CONTACT_GRANT] } }));
        }),
    });
    await screen.findByText(/Without a permission here/);
    const allow = screen.getByRole('button', { name: 'Allow: Your estate contacts' });
    fireEvent.click(allow);

    // While the write is open the control is disabled, so the second click — the
    // impatient one this defect was actually about — cannot reach the server.
    await waitFor(() => {
      expect(allow).toBeDisabled();
    });
    fireEvent.click(allow);
    release();

    expect(await screen.findByText(/Your estate contacts — Read/)).toBeInTheDocument();
    expect(opNames(requests).filter((n) => n === 'GrantRolePermission')).toHaveLength(1);
  });

  it('cancelling the code prompt leaves everything as it was', async () => {
    mount([], [], { GrantRole: () => graphqlError('STEPUP_REQUIRED') });
    await screen.findByText(/No role recorded/);
    fireEvent.click(screen.getByRole('button', { name: 'Name to this role' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    expect(screen.getByText(/No role recorded/)).toBeInTheDocument();
  });

  it('refuses a malformed code locally, without asking identity', async () => {
    const requests = mount([], [], { GrantRole: () => graphqlError('STEPUP_REQUIRED') });
    await screen.findByText(/No role recorded/);
    fireEvent.click(screen.getByRole('button', { name: 'Name to this role' }));
    fireEvent.change(await screen.findByLabelText('Confirm it’s you'), {
      target: { value: '12' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and save' }));
    expect(await screen.findByText('The code is 6 digits, numbers only.')).toBeInTheDocument();
    expect(opNames(requests)).not.toContain('StepUp');
  });

  it('changing the condition updates the sentence under the picker', async () => {
    mount([]);
    await screen.findByText(/No role recorded/);
    fireEvent.change(screen.getByLabelText('When it applies'), { target: { value: 'immediate' } });
    expect(screen.getByText(/only for what you separately allow below/)).toBeInTheDocument();
  });
});

describe('the retry outcome is reported, not guessed', () => {
  it('clears the prompt once a permission actually applies', async () => {
    let attempts = 0;
    mount([EXECUTOR], [], {
      GrantRolePermission: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({ data: { grantRolePermission: [CONTACT_GRANT] } });
      },
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    await screen.findByText(/Without a permission here/);
    fireEvent.click(screen.getByRole('button', { name: 'Allow: Your estate contacts' }));
    fireEvent.change(await screen.findByLabelText('Confirm it’s you'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and allow' }));

    await screen.findByText(/Your estate contacts — Read/);
    // The prompt goes away on success — it used to linger because only the role
    // paths cleared it.
    await waitFor(() => {
      expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
    });
  });

  it('reports a non-step-up permission failure without retrying', async () => {
    const requests = mount([EXECUTOR], [], {
      GrantRolePermission: () => graphqlError('INVALID_REQUEST'),
    });
    await screen.findByText(/Without a permission here/);
    fireEvent.click(screen.getByRole('button', { name: 'Allow: Your assets' }));
    expect(await screen.findByText(/wasn’t right/)).toBeInTheDocument();
    expect(opNames(requests).filter((n) => n === 'GrantRolePermission')).toHaveLength(1);
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });
});
