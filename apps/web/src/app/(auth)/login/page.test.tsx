import { render, screen } from '@testing-library/react';
import { installGraphqlFetchMock } from '../../../test-utils/graphql-fetch-mock';
import LoginPage from './page';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), refresh: jest.fn() }),
}));

/**
 * One assertion, and it is a reachability pin rather than a layout one: the
 * reset page is where a locked-out user must END UP, and a page reachable only
 * by typing its URL is the zero-callers gap wearing a frontend costume — a
 * ceremony that exists and that nobody in the product ever points at. The
 * login page is the one place a person who cannot sign in is guaranteed to be
 * standing.
 */
describe('login page', () => {
  it('offers the password-reset path from the one place a locked-out user reaches', () => {
    installGraphqlFetchMock({});
    render(<LoginPage />);

    expect(screen.getByRole('link', { name: 'Reset it' })).toHaveAttribute('href', '/reset');
  });
});
