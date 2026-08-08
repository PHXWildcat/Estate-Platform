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

  it('has NO inert previews left, and Vault leads to the interstitial', async () => {
    installGraphqlFetchMock({ Session: sessionHandler });
    render(
      <AppShell>
        <p>page content</p>
      </AppShell>,
    );

    // Documents left the preview list in M12, People in M13 and Vault in M15,
    // each when the surface for its long-shipped service landed. Nothing is a
    // preview any more, so the assertion is the inverse of what it used to be.
    expect(document.querySelector('.rail-soon')).toBeNull();

    // Vault points at the INTERSTITIAL, not at the vault. Zone A is on an
    // isolated origin reached by a step-up-gated single-use handoff, which a
    // hyperlink cannot mint — so the nav's long-standing promise of "outbound,
    // never an in-app route" is kept one step further along, by the page this
    // link leads to.
    for (const [label, href] of [
      ['Documents', '/documents'],
      ['People', '/people'],
      ['Vault', '/vault'],
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
