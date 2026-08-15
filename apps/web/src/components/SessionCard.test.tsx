import { render, screen } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
} from '../test-utils/graphql-fetch-mock';
import { SessionCard } from './SessionCard';

/**
 * THE HOME PAGE'S SESSION CARD HAD NO TEST AT ALL until M20 PR1, and it carried
 * the third copy of the `mfaLevel` case defect: it compared the wire's `"NONE"`
 * against `'none'`, so it told every account — including one with no
 * `mfa_methods` row — that MFA was enrolled. This is the first surface a signed-in
 * user sees, so it is where that claim is read most.
 *
 * The two branches are pinned separately because they are two different claims
 * about someone's account, and the one that was broken is the one that says a
 * protection is MISSING. A card that can only ever say "enrolled" is
 * indistinguishable from a working card for every user who is.
 */
const SESSION = {
  userId: 'a0c8f6de-0000-4000-8000-000000000001',
  stepUpFresh: false,
};

function withMfaLevel(mfaLevel: string): void {
  installGraphqlFetchMock({
    Session: () => jsonResponse({ data: { session: { ...SESSION, mfaLevel } } }),
  });
}

describe('SessionCard', () => {
  it('says MFA is NOT enrolled when the session carries no factor', async () => {
    withMfaLevel('NONE');
    render(<SessionCard />);

    expect(await screen.findByText('MFA not enrolled')).toBeInTheDocument();
    expect(screen.queryByText('MFA enrolled')).not.toBeInTheDocument();
  });

  it('says MFA IS enrolled when the session carries one', async () => {
    withMfaLevel('MFA');
    render(<SessionCard />);

    expect(await screen.findByText('MFA enrolled')).toBeInTheDocument();
    expect(screen.queryByText('MFA not enrolled')).not.toBeInTheDocument();
  });

  it('offers sign-in rather than a security claim when signed out', async () => {
    installGraphqlFetchMock({ Session: () => graphqlError('UNAUTHENTICATED') });
    render(<SessionCard />);

    expect(await screen.findByText('Get started')).toBeInTheDocument();
    expect(screen.queryByText(/MFA/)).not.toBeInTheDocument();
  });
});
