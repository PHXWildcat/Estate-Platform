import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { AccountSecurity } from './AccountSecurity';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const session = {
  userId: 'a0c8f6de-0000-4000-8000-000000000001',
  mfaLevel: 'MFA',
  stepUpFresh: false,
};

/**
 * ONE PAGE, TWO PANELS, ONE FACT (M20 PR2).
 *
 * `EmailVerificationPanel` reads whether the stored address is proved;
 * `SecurityPanel` can now move that address, and completing the move VOUCHES
 * for the new one in the same statement (redeeming the mailed code proved the
 * mailbox seconds earlier). Without a re-read, a previously-unverified owner
 * finishes the ceremony and goes on reading "your email address hasn't been
 * confirmed yet" directly above the sentence saying it has.
 *
 * This is the only place that property is observable: neither panel's own spec
 * renders the other, so a callback quietly dropped — or a `key` that stops
 * changing — is invisible everywhere else.
 */
describe('AccountSecurity', () => {
  it('re-reads the verification status after the address is changed', async () => {
    // The server's answer moves because the ceremony moved it. The panel must
    // ASK again rather than be told by a sibling holding a boolean.
    let verificationReads = 0;
    let verified = false;
    installGraphqlFetchMock({
      Session: () => jsonResponse({ data: { session } }),
      Sessions: () => jsonResponse({ data: { sessions: [] } }),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      EmailVerification: () => {
        verificationReads += 1;
        return jsonResponse({
          data: { emailVerification: verified ? 'VERIFIED' : 'UNVERIFIED' },
        });
      },
      CompleteEmailChange: () => {
        verified = true;
        return jsonResponse({ data: { completeEmailChange: { ok: true } } });
      },
    });
    render(<AccountSecurity />);

    expect(
      await screen.findByText('Your email address hasn’t been confirmed yet.'),
    ).toBeInTheDocument();
    const readsBefore = verificationReads;

    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-ABCD-EFGH' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));

    expect(await screen.findByText('Your email address is confirmed.')).toBeInTheDocument();
    expect(verificationReads).toBeGreaterThan(readsBefore);
    // And the stale claim is GONE, not merely joined by a newer one — a page
    // that says both at once is worse than one that says the wrong thing.
    expect(
      screen.queryByText('Your email address hasn’t been confirmed yet.'),
    ).not.toBeInTheDocument();
  });

  it('does NOT re-read when the change was refused', async () => {
    // The re-read is a consequence of the address moving. Firing it on a
    // failure would spend a round trip to be told what the panel already knows,
    // and would make a refused ceremony look like an event.
    let verificationReads = 0;
    installGraphqlFetchMock({
      Session: () => jsonResponse({ data: { session } }),
      Sessions: () => jsonResponse({ data: { sessions: [] } }),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      EmailVerification: () => {
        verificationReads += 1;
        return jsonResponse({ data: { emailVerification: 'UNVERIFIED' } });
      },
      CompleteEmailChange: () => graphqlError('INVALID_VERIFICATION_CODE'),
    });
    render(<AccountSecurity />);

    await screen.findByText('Your email address hasn’t been confirmed yet.');
    const readsBefore = verificationReads;

    fireEvent.change(screen.getByLabelText('Code from the new address'), {
      target: { value: 'EC1-WRONG' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm new address' }));

    await screen.findByText(/cancel this change and start again/);
    await waitFor(() => {
      expect(verificationReads).toBe(readsBefore);
    });
  });

  it('keeps the two code fields distinguishable', async () => {
    // Both panels carry a "paste the code you were mailed" field, for two
    // different ceremonies with two different codes (EV1- and EC1-). Identical
    // labels would be two inputs neither a person tabbing through nor a query
    // could tell apart — the M15 PR3 defect, which on THIS page would mean
    // pasting an address-change code into the verification form and being told,
    // uniformly and correctly, that it was not accepted.
    installGraphqlFetchMock({
      Session: () => jsonResponse({ data: { session } }),
      Sessions: () => jsonResponse({ data: { sessions: [] } }),
      Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
      EmailVerification: () => jsonResponse({ data: { emailVerification: 'UNVERIFIED' } }),
    });
    render(<AccountSecurity />);

    await screen.findByText('Your email address hasn’t been confirmed yet.');

    const labels = Array.from(document.querySelectorAll('label')).map((el) =>
      (el.textContent ?? '').trim(),
    );
    expect(labels.length).toBeGreaterThan(4);
    expect(new Set(labels).size).toBe(labels.length);
    // Named individually so a merge that makes them agree fails HERE rather
    // than in whichever unrelated test queries by label next.
    expect(labels).toContain('Code from the email');
    expect(labels).toContain('Code from the new address');
  });
});
