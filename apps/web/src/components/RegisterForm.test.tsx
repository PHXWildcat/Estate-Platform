import { fireEvent, render, screen } from '@testing-library/react';
import { errorCopy } from '../lib/copy';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type RecordedRequest,
} from '../test-utils/graphql-fetch-mock';
import { RegisterForm } from './RegisterForm';

function fillAndSubmit(email: string, password: string): void {
  fireEvent.change(screen.getByLabelText('Email address'), { target: { value: email } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } });
  fireEvent.click(screen.getByRole('button', { name: 'Create account' }));
}

describe('RegisterForm', () => {
  it('associates labels with inputs and wires error regions for assistive tech', () => {
    const { container } = render(<RegisterForm />);

    const emailInput = screen.getByLabelText('Email address');
    expect(emailInput).toHaveAttribute('id', 'email');
    expect(emailInput.getAttribute('aria-describedby')).toContain('email-error');

    const passwordInput = screen.getByLabelText('Password');
    expect(passwordInput.getAttribute('aria-describedby')).toContain('password-error');
    expect(passwordInput.getAttribute('aria-describedby')).toContain('password-hint');

    const emailError = container.querySelector('#email-error');
    expect(emailError).toHaveAttribute('aria-live', 'polite');
    const passwordError = container.querySelector('#password-error');
    expect(passwordError).toHaveAttribute('aria-live', 'polite');
  });

  it('shows validation messages and does not call the server on invalid input', async () => {
    const { fetchMock } = installGraphqlFetchMock({});
    render(<RegisterForm />);

    fillAndSubmit('not-an-email', 'short');

    expect(
      await screen.findByText('Enter a valid email address, like name@example.com.'),
    ).toBeInTheDocument();
    expect(screen.getByText(/Use at least 12 characters/, { exact: false })).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();

    const emailInput = screen.getByLabelText('Email address');
    expect(emailInput).toHaveAttribute('aria-invalid', 'true');
  });

  it('submits valid input to the Register operation and shows the success panel', async () => {
    let requests: RecordedRequest[] = [];
    ({ requests } = installGraphqlFetchMock({
      Register: () => jsonResponse({ data: { register: { ok: true } } }),
    }));
    render(<RegisterForm />);

    fillAndSubmit('person@example.com', 'a-long-enough-passphrase');

    expect(await screen.findByText('Your account is ready')).toBeInTheDocument();
    expect(requests).toHaveLength(1);
    const request = requests[0];
    expect(request?.body.query).toContain('mutation Register');
    expect(request?.body.variables).toEqual({
      email: 'person@example.com',
      password: 'a-long-enough-passphrase',
    });
    expect(request?.body.extensions?.persistedQuery?.sha256Hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('maps a server failure to generic copy', async () => {
    installGraphqlFetchMock({ Register: () => graphqlError('INVALID_REQUEST') });
    render(<RegisterForm />);

    fillAndSubmit('person@example.com', 'a-long-enough-passphrase');

    expect(await screen.findByText(errorCopy.INVALID_REQUEST)).toBeInTheDocument();
    expect(screen.queryByText('redacted-by-test')).not.toBeInTheDocument();
  });
});
