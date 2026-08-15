import { fireEvent, render, screen } from '@testing-library/react';
import { errorCopy } from '../lib/copy';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { PasswordResetForm } from './PasswordResetForm';

/**
 * M20 PR3 — the reset surface. The load-bearing properties are the same two
 * the address change carries, sharpened by the signed-out context: the request
 * answer may not claim a send (identity answers 202 identically for an unknown
 * address, the floor, and a real mail), and the completion form must work with
 * NO request made in this tab — the mail deliberately contains no link, so a
 * fresh browser is the DESIGNED arrival, not an edge case.
 */
describe('PasswordResetForm', () => {
  function completeWith(values: { code: string; password: string; confirm: string }): void {
    fireEvent.change(screen.getByLabelText('Code from the email'), {
      target: { value: values.code },
    });
    fireEvent.change(screen.getByLabelText('New password'), {
      target: { value: values.password },
    });
    fireEvent.change(screen.getByLabelText('Confirm new password'), {
      target: { value: values.confirm },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Reset password' }));
  }

  it('asks for a code WITHOUT claiming anything was sent', async () => {
    const calls: Array<Record<string, unknown>> = [];
    installGraphqlFetchMock({
      RequestPasswordReset: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { requestPasswordReset: { ok: true } } });
      },
    });
    render(<PasswordResetForm />);

    fireEvent.change(screen.getByLabelText('Email address'), {
      target: { value: 'owner@example.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Email me a reset code' }));

    // CONDITIONAL ON EVERYTHING THE SERVER REFUSES TO SAY: whether the address
    // has an account AND whether the 30-minute floor swallowed the send. A
    // flat "we've sent you an email" is false for exactly the callers the
    // silence protects.
    const notice = await screen.findByText(/a code is on its way to it/);
    expect(notice.textContent).toContain('If owner@example.test has an Estate account');
    expect(notice.textContent).toContain('last half hour');
    expect(screen.queryByText(/We’ve sent|We have sent/)).not.toBeInTheDocument();
    expect(calls).toEqual([{ email: 'owner@example.test' }]);
  });

  it('offers the completion form with NO request made in this tab', () => {
    // The mail carries no link (M9: "we never link you"), so the person
    // holding a code may never have touched this browser. Both forms render
    // together, unconditionally.
    installGraphqlFetchMock({});
    render(<PasswordResetForm />);

    expect(screen.getByLabelText('Code from the email')).toBeEnabled();
    expect(screen.getByLabelText('New password')).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Reset password' })).toBeEnabled();
  });

  it('refuses a short password and a mismatched confirmation locally', async () => {
    let calls = 0;
    installGraphqlFetchMock({
      CompletePasswordReset: () => {
        calls += 1;
        return jsonResponse({ data: { completePasswordReset: { ok: true } } });
      },
    });
    render(<PasswordResetForm />);

    completeWith({ code: 'PR1-ABCD', password: 'shrt', confirm: 'shrt' });
    // The error's own distinctive sentence, not /at least 12 characters/ —
    // the hint text under the field matches that too, permanently.
    expect(await screen.findByText(/Longer passphrases are stronger/)).toBeInTheDocument();

    completeWith({
      code: 'PR1-ABCD',
      password: 'a-brand-new-passphrase',
      confirm: 'a-brand-new-typo',
    });
    expect(await screen.findByText('Those passwords don’t match.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('resets, says BOTH consequences, and replaces the forms with the sign-in step', async () => {
    const calls: Array<Record<string, unknown>> = [];
    installGraphqlFetchMock({
      CompletePasswordReset: (variables) => {
        calls.push(variables as Record<string, unknown>);
        return jsonResponse({ data: { completePasswordReset: { ok: true } } });
      },
    });
    render(<PasswordResetForm />);

    completeWith({
      // Retyped the way a person retypes it — the canonical fold lives in
      // identity, so it must travel EXACTLY as typed.
      code: ' pr1 abcd-efgh ',
      password: 'a-brand-new-passphrase',
      confirm: 'a-brand-new-passphrase',
    });

    // Signed out EVERYWHERE — including here — and signed in NOWHERE. A user
    // who expects a reset to log them in reads the login screen as failure, so
    // the surface says what happens next and offers exactly that step.
    expect(
      await screen.findByText(
        'Password reset. Every device has been signed out — including this one.',
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in with your new password' })).toHaveAttribute(
      'href',
      '/login',
    );
    // The spent ceremony's forms are GONE — the trimmed code went to the wire.
    expect(screen.queryByLabelText('Code from the email')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument();
    expect(calls).toEqual([{ code: 'pr1 abcd-efgh', newPassword: 'a-brand-new-passphrase' }]);
    // And the vault sentence survives into the success state: a reset that
    // does not open the vault is the fact 2SKD exists to guarantee.
    expect(screen.getByText(/Your vault is unchanged/)).toBeInTheDocument();
  });

  it('points a refused code at the request form ABOVE, not at a resend that is elsewhere', async () => {
    // Third surface, third remedy for one refused code: the verification
    // panel's copy says "send yourself a new one" (its resend button), the
    // address change's says "cancel and start again" — here the request form
    // is on this very page, so the copy points up at it.
    installGraphqlFetchMock({
      CompletePasswordReset: () => graphqlError('INVALID_VERIFICATION_CODE'),
    });
    render(<PasswordResetForm />);

    completeWith({
      code: 'PR1-WRONG',
      password: 'a-brand-new-passphrase',
      confirm: 'a-brand-new-passphrase',
    });

    const message = await screen.findByText(/ask for a new one above/);
    expect(message.textContent).toContain('single-use');
    expect(screen.queryByText(errorCopy.INVALID_VERIFICATION_CODE)).not.toBeInTheDocument();
  });

  it('names the likely field behind a server-side INVALID_REQUEST', async () => {
    // Reachable despite the local pre-flight: the two rules live in different
    // repositories and the local one is advisory.
    installGraphqlFetchMock({
      CompletePasswordReset: () => graphqlError('INVALID_REQUEST'),
    });
    render(<PasswordResetForm />);

    completeWith({
      code: 'PR1-ABCD',
      password: 'a-brand-new-passphrase',
      confirm: 'a-brand-new-passphrase',
    });

    const message = await screen.findByText(/most likely the new password is too short/);
    expect(message.textContent).toContain('Nothing has been changed');
  });

  it('treats a missing field as NO DATA, never as success', async () => {
    // A BFF predating these mutations answers `{"data":{}}` — and "password
    // reset, sign in with the new one" on the strength of a version skew would
    // strand the user at a login their old password still owns.
    installGraphqlFetchMock({
      CompletePasswordReset: () => jsonResponse({ data: {} }),
    });
    render(<PasswordResetForm />);

    completeWith({
      code: 'PR1-ABCD',
      password: 'a-brand-new-passphrase',
      confirm: 'a-brand-new-passphrase',
    });

    expect(await screen.findByText(errorCopy.UNKNOWN)).toBeInTheDocument();
    expect(screen.queryByText(/Password reset\./)).not.toBeInTheDocument();
  });
});
