import { render, screen } from '@testing-library/react';
import OperatorPage from './page';
import { NAV_GROUPS } from '../../../components/AppNav';
import { installGraphqlFetchMock } from '../../../test-utils/graphql-fetch-mock';

/**
 * The operator route (M21 PR3a).
 *
 * The interesting assertion here is an ABSENCE, and it is asserted because
 * nothing else could see it. `/operator` is deliberately not in `NAV_GROUPS`:
 * minting the handoff is role-blind, so this page WORKS for every signed-in
 * account, and a product for ten million people should not put "open the
 * operator console" in the navigation of an estate. That decision lives in the
 * page's docstring, which is a comment — and a comment is not a control. Adding
 * a nav entry is PR3b's question, once there is a surface behind it, and this
 * turns red if somebody answers it here by accident.
 */
describe('the /operator route', () => {
  it('renders the interstitial and nothing else', () => {
    installGraphqlFetchMock({});
    render(<OperatorPage />);
    expect(screen.getByRole('button', { name: /open the console/i })).toBeInTheDocument();
    expect(screen.getByText(/does not make you an operator/i)).toBeInTheDocument();
  });

  it('is NOT in the app navigation, on purpose', () => {
    const hrefs = NAV_GROUPS.flatMap((group) => group.items.map((item) => item.href));
    expect(hrefs).not.toContain('/operator');
    // Anti-vacuity: a nav that lost every item would satisfy the line above.
    expect(hrefs).toContain('/vault');
    expect(hrefs.filter((h) => h !== undefined).length).toBeGreaterThanOrEqual(7);
  });
});
