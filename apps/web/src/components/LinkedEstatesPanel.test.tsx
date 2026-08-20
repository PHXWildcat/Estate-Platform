import { render, screen, waitFor } from '@testing-library/react';
import type { LinkedEstateInfo } from '../graphql/client';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { LinkedEstatesPanel } from './LinkedEstatesPanel';

/**
 * Estates that name you (M22 PR4a).
 *
 * The panel is a read with no controls, so what is worth pinning is what it
 * says when the server says something unusual: a null name must not become
 * "Unknown", a failed read must not become "nobody has named you", and a link
 * with no role attached must still be shown rather than filtered away.
 */

function estate(over: Partial<LinkedEstateInfo> = {}): LinkedEstateInfo {
  return {
    ownerUserId: 'owner-1',
    contactId: 'contact-1',
    ownerName: 'Ada Lovelace',
    roles: ['executor'],
    ...over,
  };
}

function handlers(h?: OperationHandler): Record<string, OperationHandler> {
  return {
    LinkedEstates: h ?? (() => jsonResponse({ data: { linkedEstates: [estate()] } })),
  };
}

it('names the estate and the role held in it', async () => {
  installGraphqlFetchMock(handlers());
  render(<LinkedEstatesPanel />);
  expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
  expect(screen.getByText(/executor/i)).toBeInTheDocument();
});

it('says an owner has no name rather than inventing one', async () => {
  // Null means the owner never saved a profile. "Unknown" would be this app
  // asserting something the server declined to say.
  installGraphqlFetchMock(
    handlers(() => jsonResponse({ data: { linkedEstates: [estate({ ownerName: null })] } })),
  );
  render(<LinkedEstatesPanel />);
  expect(await screen.findByText(/hasn’t added their name yet/i)).toBeInTheDocument();
  expect(screen.queryByText(/unknown/i)).not.toBeInTheDocument();
});

it('shows a link that carries no role at all', async () => {
  // Being linked without a role_assignment is a real state, and it still
  // carries the capability that matters — filtering it would hide an estate
  // this person really is named in.
  installGraphqlFetchMock(
    handlers(() => jsonResponse({ data: { linkedEstates: [estate({ roles: [] })] } })),
  );
  render(<LinkedEstatesPanel />);
  expect(await screen.findByText(/linked, with no role yet/i)).toBeInTheDocument();
});

it('offers no control to leave an estate', async () => {
  // Deliberate: the link is the OWNER's record of their own intent, and a
  // contact removing themselves would edit somebody else's plan silently.
  installGraphqlFetchMock(handlers());
  render(<LinkedEstatesPanel />);
  await screen.findByText('Ada Lovelace');
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
});

it('refuses to say "nobody has named you" when the read failed', async () => {
  installGraphqlFetchMock(handlers(() => graphqlError('UNKNOWN')));
  render(<LinkedEstatesPanel />);
  expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
  expect(screen.queryByText(/nobody has named you/i)).not.toBeInTheDocument();
});

it('says the reassuring thing only when the server actually said it', async () => {
  installGraphqlFetchMock(handlers(() => jsonResponse({ data: { linkedEstates: [] } })));
  render(<LinkedEstatesPanel />);
  expect(await screen.findByText(/nobody has named you/i)).toBeInTheDocument();
});

it('treats a version-skewed BFF’s missing field as no data', async () => {
  installGraphqlFetchMock(handlers(() => jsonResponse({ data: {} })));
  render(<LinkedEstatesPanel />);
  await waitFor(() => {
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
  });
});
