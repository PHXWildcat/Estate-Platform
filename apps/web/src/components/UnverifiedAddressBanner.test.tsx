import { render, screen, waitFor } from '@testing-library/react';
import { UnverifiedAddressBanner } from './UnverifiedAddressBanner';
import { gqlRequest } from '../graphql/client';

jest.mock('../graphql/client', () => ({ gqlRequest: jest.fn() }));
jest.mock('next/navigation', () => ({ usePathname: (): string => '/assets' }));

const mockedRequest = gqlRequest as unknown as jest.Mock;

beforeEach(() => {
  mockedRequest.mockReset();
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
    // it is not a field on the session resolver that backs every request.
    mockedRequest.mockResolvedValue({ ok: true, data: { emailVerification: 'UNVERIFIED' } });
    render(<UnverifiedAddressBanner />);

    await screen.findByText(/isn’t confirmed/);
    expect(mockedRequest).toHaveBeenCalledTimes(1);
    expect(mockedRequest).toHaveBeenCalledWith('EmailVerification', {});
  });
});
