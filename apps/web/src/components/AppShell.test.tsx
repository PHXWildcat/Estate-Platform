import { render, screen } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { AppShell } from './AppShell';

const pushMock = jest.fn();
const refreshMock = jest.fn();
let pathname = '/assets';
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock, refresh: refreshMock }),
  usePathname: () => pathname,
}));

const SESSION = {
  userId: 'b6c9a1de-0000-4000-8000-000000000001',
  mfaLevel: 'mfa',
  stepUpFresh: false,
};

function sessionHandler(): Response {
  return jsonResponse({ data: { session: SESSION } });
}

describe('AppShell', () => {
  beforeEach(() => {
    pathname = '/assets';
  });

  it('renders grouped rail navigation and marks the current page in every nav', async () => {
    installGraphqlFetchMock({ Session: sessionHandler });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    expect(screen.getByText('page content')).toBeInTheDocument();

    // Rail + mobile tab bar are both "Main" navigation landmarks; the group
    // label proves the rail renders its sectioned form ("Protection" appears
    // nowhere else).
    expect(screen.getAllByRole('navigation', { name: 'Main' })).toHaveLength(2);
    expect(screen.getByText('Protection')).toBeInTheDocument();

    // Every live "Assets" link is current; no "Overview" link is.
    for (const link of screen.getAllByRole('link', { name: 'Assets' })) {
      expect(link).toHaveAttribute('aria-current', 'page');
    }
    for (const link of screen.getAllByRole('link', { name: 'Overview' })) {
      expect(link).not.toHaveAttribute('aria-current');
    }

    await screen.findByText('Signed in');
  });

  it('shows shipped-backend surfaces as inert previews, never dead links', async () => {
    installGraphqlFetchMock({ Session: sessionHandler });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    // Documents left this list in M12 and People in M13, each when the surface
    // for its long-shipped service landed. Vault is the last preview, and it
    // stays one until the docs/03 TB6 isolated origin exists — at which point it
    // becomes an OUTBOUND link, never an in-app route.
    for (const label of ['Vault']) {
      expect(screen.getByText(label)).toBeInTheDocument();
      expect(screen.queryByRole('link', { name: new RegExp(label) })).not.toBeInTheDocument();
    }
    // …and Documents and People are real destinations in both navigations.
    for (const [label, href] of [
      ['Documents', '/documents'],
      ['People', '/people'],
    ] as const) {
      const links = screen.getAllByRole('link', { name: label });
      expect(links.length).toBeGreaterThan(0);
      for (const link of links) {
        expect(link).toHaveAttribute('href', href);
      }
    }
    await screen.findByText('Signed in');
  });

  it('offers sign-out once the session is confirmed', async () => {
    installGraphqlFetchMock({ Session: sessionHandler });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    expect(await screen.findByText('Signed in')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
  });

  it('offers sign-in when unauthenticated', async () => {
    installGraphqlFetchMock({ Session: () => graphqlError('UNAUTHENTICATED') });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    expect(await screen.findByRole('link', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Create account' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
  });

  it('admits it could not check the session instead of guessing', async () => {
    installGraphqlFetchMock({ Session: () => graphqlError('UNKNOWN') });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    expect(await screen.findByText(/couldn’t check your session/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in' })).toBeInTheDocument();
  });
});
