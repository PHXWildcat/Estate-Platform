import { act, render, screen, waitFor } from '@testing-library/react';
import { UnverifiedAddressBanner } from './UnverifiedAddressBanner';
import { gqlRequest } from '../graphql/client';
import { notifyOperationSuccess } from '../graphql/operation-events';
import { resetSharedReadsForTests } from '../graphql/read-cache';

jest.mock('../graphql/client', () => ({ gqlRequest: jest.fn() }));

let mockPathname = '/assets';
jest.mock('next/navigation', () => ({ usePathname: (): string => mockPathname }));

const mockedRequest = gqlRequest as unknown as jest.Mock;

beforeEach(() => {
  mockedRequest.mockReset();
  mockPathname = '/assets';
  resetSharedReadsForTests();
});

describe('UnverifiedAddressBanner', () => {
  it('shows the CAUSE before the user meets the effect', async () => {
    // Since M14 PR2 an unverified address silently withholds capabilities:
    // arming emergency access and minting a link code both refuse. Those
    // refusals arrive somewhere else entirely and explain nothing, so this is
    // the line that connects them.
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'UNVERIFIED' } });
    render(<UnverifiedAddressBanner />);

    await screen.findByText(/isn’t confirmed/);
    expect(screen.getByRole('link', { name: /confirm it now/i })).toHaveAttribute(
      'href',
      '/security',
    );
  });

  it.each([['VERIFIED'], ['UNAVAILABLE']])('renders NOTHING for %s', async (status) => {
    // VERIFIED is obvious. UNAVAILABLE is the interesting one: it is a fact
    // about the platform, not the user, and telling somebody to go and confirm
    // an address during a notifications outage sends them to a ceremony that
    // cannot run. Silence is the honest failure mode here — the settings page
    // says it properly when they get there.
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: status } });
    const { container } = render(<UnverifiedAddressBanner />);

    await waitFor(() => expect(mockedRequest).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when the caller is not authenticated', async () => {
    // The shell already handles signed-out; a banner about an address would be
    // noise on a page that is about to redirect.
    mockedRequest.mockResolvedValue({ ok: false, code: 'UNAUTHENTICATED' });
    const { container } = render(<UnverifiedAddressBanner />);

    await waitFor(() => expect(mockedRequest).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('asks once per render, and never polls', async () => {
    // The read costs identity a notifications round trip, which is exactly why
    // it is not a field on the session resolver that backs every request. The
    // shared cache must not change how often the server is asked — one mount,
    // one question.
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'UNVERIFIED' } });
    render(<UnverifiedAddressBanner />);

    await screen.findByText(/isn’t confirmed/);
    expect(mockedRequest).toHaveBeenCalledTimes(1);
    expect(mockedRequest).toHaveBeenCalledWith('EmailVerification', {});
  });

  it('re-asks on navigation — the documented freshness, preserved through the cache', async () => {
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'UNVERIFIED' } });
    const { rerender } = render(<UnverifiedAddressBanner />);
    await screen.findByText(/isn’t confirmed/);
    expect(mockedRequest).toHaveBeenCalledTimes(1);

    mockPathname = '/documents';
    rerender(<UnverifiedAddressBanner />);

    await waitFor(() => expect(mockedRequest).toHaveBeenCalledTimes(2));
    // The old answer is merely old, not known wrong — it keeps rendering
    // while the re-ask is in flight (exactly the pre-cache behavior).
    expect(screen.getByText(/isn’t confirmed/)).toBeInTheDocument();
  });

  it('clears the moment a vouching ceremony completes — NO navigation needed', async () => {
    // THE §6v RESIDUAL THIS PR CLOSES (docs/03, [OWNER: M24] #1): the banner
    // lives outside the /security page's tree, so completing verification
    // used to leave it asking for a confirmation that had just happened until
    // the next navigation. The transport announces the mutation; the cache
    // invalidates; the banner re-ASKS — the server stays the authority, no
    // boolean is passed between trees.
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'UNVERIFIED' } });
    render(<UnverifiedAddressBanner />);
    await screen.findByText(/isn’t confirmed/);

    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'VERIFIED' } });
    act(() => {
      notifyOperationSuccess('VerifyEmail');
    });

    await waitFor(() => expect(screen.queryByText(/isn’t confirmed/)).not.toBeInTheDocument());
    // A re-read happened — the banner did not merely hide on a guess.
    expect(mockedRequest).toHaveBeenCalledTimes(2);
  });
});
