import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { EmailVerificationPanel } from './EmailVerificationPanel';
import { gqlRequest } from '../graphql/client';

jest.mock('../graphql/client', () => ({ gqlRequest: jest.fn() }));

const mockedRequest = gqlRequest as unknown as jest.Mock;

/** One canned answer per operation, so ordering assumptions cannot creep in. */
function respond(answers: Record<string, unknown>): void {
  mockedRequest.mockImplementation((operation: string) => {
    const answer = answers[operation];
    if (answer === undefined) {
      throw new Error(`unexpected operation ${operation}`);
    }
    return Promise.resolve(answer);
  });
}

beforeEach(() => {
  mockedRequest.mockReset();
});

describe('EmailVerificationPanel', () => {
  it('says what verification is FOR, not just that it is outstanding', async () => {
    // An owner who ignores this is later refused at emergency-access
    // configuration and link-code minting, and nothing at THAT moment explains
    // why. The cause has to be visible before the effect.
    respond({ EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } } });
    render(<EmailVerificationPanel />);

    await screen.findByText(/hasn’t been confirmed yet/);
    expect(screen.getByText(/emergency access to your vault/)).toBeInTheDocument();
    expect(screen.getByText(/won’t be able to set up emergency access/)).toBeInTheDocument();
  });

  it('renders UNAVAILABLE as a platform problem, never as "unverified"', async () => {
    // Rendering it as unverified would send somebody to complete a ceremony
    // that cannot currently run — the same mistake as a gate that cannot tell
    // an outage from a refusal.
    respond({ EmailVerification: { ok: true, data: { emailVerification: 'UNAVAILABLE' } } });
    render(<EmailVerificationPanel />);

    await screen.findByText(/can’t check your email address right now/);
    expect(screen.queryByText(/hasn’t been confirmed yet/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /confirm address/i })).not.toBeInTheDocument();
  });

  it('confirms a code and re-reads the SERVER rather than flipping a local flag', async () => {
    const answers: Record<string, unknown> = {
      EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } },
      VerifyEmail: { ok: true, data: { verifyEmail: { ok: true } } },
    };
    respond(answers);
    render(<EmailVerificationPanel />);
    await screen.findByText(/hasn’t been confirmed yet/);

    // The server becomes the authority for the next read.
    answers.EmailVerification = { ok: true, data: { emailVerification: 'VERIFIED' } };
    fireEvent.change(screen.getByLabelText(/code from the email/i), {
      target: { value: 'EV1-K7MN' },
    });
    fireEvent.click(screen.getByRole('button', { name: /confirm address/i }));

    await screen.findByText(/Your email address is confirmed/);
    expect(mockedRequest).toHaveBeenCalledWith('VerifyEmail', { code: 'EV1-K7MN' });
  });

  it('sends the code EXACTLY as typed — no second copy of the canonical fold', async () => {
    // The fold and the length measurement live in identity. A copy here would
    // be a rule that can disagree with the one that matters, which is the
    // documents-upload lesson: never a client-side second opinion on a
    // server-side gate.
    respond({
      EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } },
      VerifyEmail: { ok: true, data: { verifyEmail: { ok: true } } },
    });
    render(<EmailVerificationPanel />);
    await screen.findByText(/hasn’t been confirmed yet/);

    fireEvent.change(screen.getByLabelText(/code from the email/i), {
      target: { value: '  ev1k7mn0000  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: /confirm address/i }));

    await waitFor(() =>
      expect(mockedRequest).toHaveBeenCalledWith('VerifyEmail', { code: 'ev1k7mn0000' }),
    );
  });

  it('explains WHY a code stops working, because the server refuses to say which', async () => {
    // One uniform `invalid_code` for unknown, expired, spent, revoked and
    // attempt-exhausted is the control. The cost lands on the copy, which has
    // to carry the possibilities rather than ask the user to guess.
    respond({
      EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } },
      VerifyEmail: { ok: false, code: 'INVALID_VERIFICATION_CODE' },
    });
    render(<EmailVerificationPanel />);
    await screen.findByText(/hasn’t been confirmed yet/);

    fireEvent.change(screen.getByLabelText(/code from the email/i), { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: /confirm address/i }));

    const message = await screen.findByText(/That code didn’t work/);
    // It must NOT say anything about an email and password: that is the M12
    // collision, where one shared code produced copy about a field the form
    // does not have.
    expect(message.textContent ?? '').not.toMatch(/password/i);
    expect(message.textContent ?? '').toMatch(/expire/i);
    expect(message.textContent ?? '').toMatch(/only be used once/i);
  });

  it('reports the re-issue floor honestly rather than claiming a send', async () => {
    // It is the only rate limit on this path. A user told "sent" who receives
    // nothing keeps pressing, which is exactly the traffic the floor exists to
    // prevent.
    respond({
      EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } },
      ResendEmailVerification: { ok: true, data: { resendEmailVerification: 'TOO_SOON' } },
    });
    render(<EmailVerificationPanel />);
    await screen.findByText(/hasn’t been confirmed yet/);

    fireEvent.click(screen.getByRole('button', { name: /send a new code/i }));
    await screen.findByText(/Give it a minute/);
  });

  it('refuses to submit an empty code without asking the server', async () => {
    respond({ EmailVerification: { ok: true, data: { emailVerification: 'UNVERIFIED' } } });
    render(<EmailVerificationPanel />);
    await screen.findByText(/hasn’t been confirmed yet/);

    fireEvent.click(screen.getByRole('button', { name: /confirm address/i }));
    await screen.findByText(/Enter the code from the email/);
    expect(mockedRequest).toHaveBeenCalledTimes(1); // the initial status read only
  });
});
