import { act, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { RailAccount } from './RailAccount';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

const SESSION = { userId: 'u-1', mfaLevel: 'MFA', stepUpFresh: false };

/**
 * THE CHROME'S SESSION INDICATOR (M24 PR4).
 *
 * The rail reads `Session` once at mount and then lives for the whole visit,
 * so what it asserts is only as true as the moment it asked. Before this PR
 * nothing could correct it: the page's content could collapse to its
 * signed-out arm while the rail two hundred pixels away still showed a green
 * dot and the word "Signed in", and the security-state indicator was the one
 * that was wrong. Staleness in the PERMISSIVE direction is the direction that
 * matters.
 *
 * The correction arrives through the transport's session-ended announcement,
 * fired at the one place the app learns a session is DEAD rather than merely
 * unreachable — a refused refresh. An outage must never sign anybody out, so
 * the third test here is the one that keeps this control honest.
 */
describe('the rail says what is true about the session', () => {
  it('shows signed-in state for a live session, and nothing personal', async () => {
    installGraphqlFetchMock({ Session: () => jsonResponse({ data: { session: SESSION } }) });
    render(<RailAccount />);

    expect(await screen.findByText('Signed in')).toBeInTheDocument();
    // The payload carries a user id; the chrome renders no identity at all.
    expect(screen.queryByText(/u-1/)).toBeNull();
  });

  it('STOPS saying "Signed in" when a later read finds the session dead', async () => {
    // The laptop tab sitting on a page while the phone revokes this session.
    // The rail asked before that happened; the announcement is how it learns.
    let sessionAlive = true;
    installGraphqlFetchMock({
      Session: () =>
        sessionAlive
          ? jsonResponse({ data: { session: SESSION } })
          : graphqlError('UNAUTHENTICATED'),
      Refresh: () => graphqlError('UNAUTHENTICATED'),
      Documents: () => graphqlError('UNAUTHENTICATED'),
    });
    render(<RailAccount />);
    expect(await screen.findByText('Signed in')).toBeInTheDocument();

    // Any other surface's read dies — the rail is not the one that asked.
    sessionAlive = false;
    const { gqlRequest } = await import('../graphql/client');
    await act(async () => {
      await gqlRequest('Documents', {});
    });

    await waitFor(() => {
      expect(screen.queryByText('Signed in')).toBeNull();
    });
    expect(screen.getByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('an OUTAGE does not sign anybody out — only a refused refresh does', async () => {
    /*
     * The other direction, and the reason the announcement is fired from the
     * refused-refresh branch rather than from every UNAUTHENTICATED: a refresh
     * that could not be COMPLETED says nothing about the session. Announcing
     * there would tell a user with a live 30-day credential that they had been
     * signed out, during an outage, on cookies the BFF deliberately left in
     * place.
     */
    installGraphqlFetchMock({
      Session: () => jsonResponse({ data: { session: SESSION } }),
      Documents: () => graphqlError('UNAUTHENTICATED'),
      Refresh: () => jsonResponse({}, false),
    });
    render(<RailAccount />);
    expect(await screen.findByText('Signed in')).toBeInTheDocument();

    const { gqlRequest } = await import('../graphql/client');
    let result: Awaited<ReturnType<typeof gqlRequest>> | undefined;
    await act(async () => {
      result = await gqlRequest('Documents', {});
    });

    // Anti-vacuity: the read really did fail, and with the outage code — so
    // the rail's survival below is the guard working, not a read that
    // succeeded.
    expect(result?.ok).toBe(false);
    expect(screen.getByText('Signed in')).toBeInTheDocument();
  });
});
