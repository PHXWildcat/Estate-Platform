import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { SignOutButton } from './SignOutButton';

const pushMock = jest.fn();
const refreshMock = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
}));

describe('SignOutButton', () => {
  it('navigates to sign-in once the server confirms revocation', async () => {
    installGraphqlFetchMock({ Logout: () => jsonResponse({ data: { logout: { ok: true } } }) });
    render(<SignOutButton />);

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith('/login');
    });
    expect(refreshMock).toHaveBeenCalled();
  });

  it('TELLS the user when sign-out failed, and does not navigate away', async () => {
    // The dangerous outcome is a reassuring "signed out" over a live session.
    installGraphqlFetchMock({ Logout: () => graphqlError('UNKNOWN') });
    render(<SignOutButton />);

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/still signed in/);
    expect(pushMock).not.toHaveBeenCalled();
  });

  it('disables itself while in flight, so a double-click cannot double-revoke', async () => {
    installGraphqlFetchMock({
      // Never settles during the assertion window.
      Logout: () => ({ ok: true, json: () => new Promise(() => undefined) }) as unknown as Response,
    });
    render(<SignOutButton />);

    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('button', { name: 'Signing out…' })).toBeDisabled();
    expect(pushMock).not.toHaveBeenCalled();
  });
});
