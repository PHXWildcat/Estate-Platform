import { fireEvent, render, screen } from '@testing-library/react';
import { errorCopy } from '../lib/copy';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { SecurityPanel } from './SecurityPanel';

const session = {
  userId: 'a0c8f6de-0000-4000-8000-000000000001',
  mfaLevel: 'mfa',
  stepUpFresh: false,
};

function sessionHandler(): Response {
  return jsonResponse({ data: { session } });
}

describe('SecurityPanel', () => {
  it('shows a sign-in prompt when the session is unauthenticated', async () => {
    installGraphqlFetchMock({ Session: () => graphqlError('UNAUTHENTICATED') });
    render(<SecurityPanel />);

    expect(await screen.findByText('Sign in required')).toBeInTheDocument();
    expect(screen.queryByText('Export data (demo)')).not.toBeInTheDocument();
  });

  it('reveals the step-up form when export fails with STEPUP_REQUIRED, then succeeds after step-up', async () => {
    let exportCalls = 0;
    const exportHandler: OperationHandler = () => {
      exportCalls += 1;
      return exportCalls === 1
        ? graphqlError('STEPUP_REQUIRED')
        : jsonResponse({ data: { exportDemo: { ok: true } } });
    };
    installGraphqlFetchMock({
      Session: sessionHandler,
      ExportDemo: exportHandler,
      StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    });
    render(<SecurityPanel />);

    // Step-up form is hidden until needed.
    const exportButton = await screen.findByRole('button', { name: 'Export data (demo)' });
    expect(screen.queryByLabelText('6-digit code')).not.toBeInTheDocument();

    // First export attempt: blocked, step-up form revealed with generic copy.
    fireEvent.click(exportButton);
    expect(await screen.findByText(errorCopy.STEPUP_REQUIRED)).toBeInTheDocument();
    const codeInput = screen.getByLabelText('6-digit code');
    expect(codeInput).toBeInTheDocument();
    expect(screen.queryByText(/Export started/)).not.toBeInTheDocument();

    // Complete step-up.
    fireEvent.change(codeInput, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm identity' }));
    expect(
      await screen.findByText('Identity verified. You can retry the protected action now.'),
    ).toBeInTheDocument();

    // Retry export: success only now that step-up is fresh.
    fireEvent.click(screen.getByRole('button', { name: 'Export data (demo)' }));
    expect(await screen.findByText(/Export started/)).toBeInTheDocument();
    expect(exportCalls).toBe(2);
  });

  it('rejects a malformed step-up code client-side', async () => {
    installGraphqlFetchMock({ Session: sessionHandler });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Verify your identity' }));
    fireEvent.change(screen.getByLabelText('6-digit code'), { target: { value: '12ab' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm identity' }));

    expect(await screen.findByText('The code is 6 digits, numbers only.')).toBeInTheDocument();
  });

  it('shows the otpauth URI as copyable text after enrollment begins', async () => {
    installGraphqlFetchMock({
      Session: sessionHandler,
      TotpEnroll: () =>
        jsonResponse({
          data: { totpEnroll: { otpauthUri: 'otpauth://totp/Estate:demo?secret=ABC123' } },
        }),
    });
    render(<SecurityPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Re-enroll authenticator app' }));

    const uriField = await screen.findByLabelText('Enrollment link (otpauth URI)');
    expect(uriField).toHaveValue('otpauth://totp/Estate:demo?secret=ABC123');
    expect(uriField).toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(screen.getByLabelText('6-digit code')).toBeInTheDocument();
  });
});
