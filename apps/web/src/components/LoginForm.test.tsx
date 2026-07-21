import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { errorCopy } from '../lib/copy';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { LoginForm } from './LoginForm';

const pushMock = jest.fn();
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock }),
}));

function fillAndSubmit(email: string, password: string): void {
  fireEvent.change(screen.getByLabelText('Email address'), { target: { value: email } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } });
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
}

describe('LoginForm', () => {
  it('shows one generic message on INVALID_CREDENTIALS — no account-existence detail', async () => {
    installGraphqlFetchMock({ Login: () => graphqlError('INVALID_CREDENTIALS', 'user not found') });
    render(<LoginForm />);

    fillAndSubmit('person@example.com', 'a-long-enough-passphrase');

    expect(await screen.findByText(errorCopy.INVALID_CREDENTIALS)).toBeInTheDocument();
    // The server's internal reason must never reach the page.
    expect(screen.queryByText(/user not found/)).not.toBeInTheDocument();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it('navigates home after a successful sign-in', async () => {
    installGraphqlFetchMock({ Login: () => jsonResponse({ data: { login: { ok: true } } }) });
    render(<LoginForm />);

    fillAndSubmit('person@example.com', 'a-long-enough-passphrase');

    await waitFor(() => expect(pushMock).toHaveBeenCalledWith('/'));
  });

  it('validates before submitting', async () => {
    const { fetchMock } = installGraphqlFetchMock({});
    render(<LoginForm />);

    fillAndSubmit('nope', 'short');

    expect(
      await screen.findByText('Enter a valid email address, like name@example.com.'),
    ).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
