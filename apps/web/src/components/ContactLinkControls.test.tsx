import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { ContactLinkControls } from './ContactLinkControls';

const CONTACT_ID = 'f0000000-0000-4000-8000-00000000000a';
const CODE = 'ESL1-ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789-ABCD';

function opNames(requests: readonly RecordedRequest[]): string[] {
  return requests.map((request) => request.body.query?.split(/[\s({]+/)[1] ?? '<unknown>');
}

function mount(
  linked: boolean | null,
  overrides: Partial<Record<string, OperationHandler>> = {},
): { requests: RecordedRequest[]; onChanged: jest.Mock } {
  const { requests } = installGraphqlFetchMock({
    InviteContactLink: () =>
      jsonResponse({
        data: { inviteContactLink: { code: CODE, expiresAt: '2026-08-13T00:00:00.000Z' } },
      }),
    ...overrides,
  });
  const onChanged = jest.fn();
  render(
    <ContactLinkControls
      contactId={CONTACT_ID}
      contactName="Bob Brother"
      linked={linked}
      onChanged={onChanged}
    />,
  );
  return { requests, onChanged };
}

describe('the platform never sends the code, and says so', () => {
  it('tells the owner they deliver it themselves, before minting', () => {
    mount(false);
    expect(screen.getByText(/we never send it for you/i)).toBeInTheDocument();
  });

  it('shows the code once, with the fact that it cannot be shown again', async () => {
    mount(false);
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    expect(await screen.findByText(CODE)).toBeInTheDocument();
    expect(screen.getByText(/only time we can show it to you/i)).toBeInTheDocument();
  });

  it('renders the code as text, never as a link', async () => {
    mount(false);
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    const node = await screen.findByText(CODE);
    expect(node.tagName).toBe('CODE');
    // Nothing in this ceremony is clickable — M9's doctrine is "we never link".
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('takes the dead code off the screen when it is withdrawn', async () => {
    mount(false, {
      RevokeContactLinkInvitation: () =>
        jsonResponse({ data: { revokeContactLinkInvitation: { ok: true } } }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    await screen.findByText(CODE);
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw this code' }));
    await waitFor(() => {
      expect(screen.queryByText(CODE)).not.toBeInTheDocument();
    });
    expect(screen.getByText('That code no longer works.')).toBeInTheDocument();
  });
});

describe('the step-up asymmetry is visible here', () => {
  it('prompts for a code when minting is refused, then retries the same mint', async () => {
    let attempts = 0;
    const { requests } = mount(false, {
      InviteContactLink: () => {
        attempts += 1;
        return attempts === 1
          ? graphqlError('STEPUP_REQUIRED')
          : jsonResponse({
              data: { inviteContactLink: { code: CODE, expiresAt: '2026-08-13T00:00:00.000Z' } },
            });
      },
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    expect(await screen.findByLabelText('Confirm it’s you')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm and create the code' }));

    expect(await screen.findByText(CODE)).toBeInTheDocument();
    expect(opNames(requests).filter((n) => n === 'InviteContactLink')).toHaveLength(2);
  });

  it('removes a live link with NO code prompt', async () => {
    const { requests, onChanged } = mount(true, {
      UnlinkContact: () => jsonResponse({ data: { unlinkContact: { ok: true } } }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Remove the link' }));
    await waitFor(() => {
      expect(onChanged).toHaveBeenCalled();
    });
    // Protective, so it must never be harder than the permissive direction.
    expect(opNames(requests)).not.toContain('StepUp');
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });
});

describe('what a linked contact can do is stated plainly', () => {
  it('says a linked person can report a death, and how to stop it', () => {
    mount(true);
    expect(screen.getByText(/able to report a death on your account/)).toBeInTheDocument();
    expect(screen.getByText(/verifying your identity from/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Security' })).toHaveAttribute('href', '/security');
  });

  /*
   * A REGRESSION PIN, NOT A COPY TEST. Settlement reads owner liveness from
   * identity's append-only step-up ledger, which only a verified authenticator
   * code writes — so an ordinary sign-in does not void a death case. This copy
   * said "a review you can stop by signing in" until 2026-08-06, which named a
   * remedy that leaves the owner locked out on the one docs/03 §5.1 path where
   * the copy is the whole instruction. Assert the wrong remedy is gone, so a
   * later edit reaching for the shorter sentence fails here.
   */
  it('never tells the owner that signing in stops a death case', () => {
    mount(true);
    expect(screen.queryByText(/signing in/i)).not.toBeInTheDocument();
  });

  it('says an unlinked person cannot use anything granted to them', () => {
    mount(false);
    expect(screen.getByText(/nothing you grant them can be used yet/)).toBeInTheDocument();
  });
});

describe('three values, not two', () => {
  it('claims nothing about accounts when the read failed, and offers no invitation', () => {
    mount(null);
    expect(screen.getByText(/could not check whether/i)).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Create an invitation code' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove the link' })).not.toBeInTheDocument();
  });
});

describe('refusals', () => {
  it('surfaces ALREADY_LINKED with its own remedy', async () => {
    mount(false, { InviteContactLink: () => graphqlError('ALREADY_LINKED') });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    expect(await screen.findByText(/already has an account linked/)).toBeInTheDocument();
  });

  it('surfaces the notification precondition as a wait, not a dead end', async () => {
    mount(true, { UnlinkContact: () => graphqlError('NOTIFICATIONS_UNAVAILABLE') });
    fireEvent.click(screen.getByRole('button', { name: 'Remove the link' }));
    expect(await screen.findByText(/haven’t made the change/)).toBeInTheDocument();
  });
});

describe('the remaining paths', () => {
  it('surfaces a non-step-up refusal on the mint without opening the prompt', async () => {
    mount(false, { InviteContactLink: () => graphqlError('UNKNOWN') });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    expect(await screen.findByText(/went wrong on our side/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });

  it('surfaces a refused withdrawal and leaves the code on screen', async () => {
    mount(false, {
      RevokeContactLinkInvitation: () => graphqlError('NOT_FOUND'),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    await screen.findByText(CODE);
    fireEvent.click(screen.getByRole('button', { name: 'Withdraw this code' }));
    expect(await screen.findByText('That isn’t available.')).toBeInTheDocument();
    // A failed withdrawal must not imply the code is dead — it still works.
    expect(screen.getByText(CODE)).toBeInTheDocument();
  });

  it('cancelling the step-up prompt closes it', async () => {
    mount(false, { InviteContactLink: () => graphqlError('STEPUP_REQUIRED') });
    fireEvent.click(screen.getByRole('button', { name: 'Create an invitation code' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByLabelText('Confirm it’s you')).not.toBeInTheDocument();
  });
});
