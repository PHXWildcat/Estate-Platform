import { render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { SettlingEstatesPanel } from './SettlingEstatesPanel';

/**
 * THE EXECUTOR'S FRONT DOOR ON THE OVERVIEW PAGE (M23 PR2).
 *
 * The property this file exists for is that the panel is INVISIBLE to everybody
 * who is settling nothing — which is virtually everybody. It sits on the first
 * screen after sign-in, so a heading about death cases that renders for ten
 * million people is the memento mori that kept `/security/cases` out of the nav
 * rail, and an error card about a feature the reader has never used is the same
 * problem wearing a different face.
 *
 * That makes this the ONE place in the app where a failed read renders as
 * nothing rather than as its own panel, and it is deliberate rather than an
 * oversight of the rule: an executor who reaches the overview and sees no panel
 * loses nothing they can act on, where every other reader would be shown an
 * error about a surface that does not concern them.
 */

function handlers(estates?: OperationHandler): Record<string, OperationHandler> {
  return {
    ExecutorCases:
      estates ??
      (() =>
        jsonResponse({
          data: {
            executorCases: [
              {
                caseId: 'case-1',
                ownerName: 'Ada Lovelace',
                status: 'verified',
                verifiedAt: '2026-08-19T00:00:00.000Z',
              },
            ],
          },
        })),
  };
}

describe('the estates you are settling', () => {
  it('names the estate and links to it by CASE id', async () => {
    installGraphqlFetchMock(handlers());
    render(<SettlingEstatesPanel />);
    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
    // The link carries a case id and nothing else — no user id, and no name in
    // the URL, which would sit in history and in any `Referer` leaving here.
    expect(screen.getByRole('link', { name: /open/i })).toHaveAttribute('href', '/estates/case-1');
  });

  it('renders NOTHING when there is nothing to settle', async () => {
    installGraphqlFetchMock(handlers(() => jsonResponse({ data: { executorCases: [] } })));
    const { container } = render(<SettlingEstatesPanel />);
    await waitFor(() => {
      expect(container).toBeEmptyDOMElement();
    });
  });

  it('renders NOTHING on a failed read — never an error card about death cases', async () => {
    installGraphqlFetchMock(handlers(() => graphqlError('UNKNOWN')));
    const { container } = render(<SettlingEstatesPanel />);
    await waitFor(() => {
      expect(container).toBeEmptyDOMElement();
    });
  });

  it('treats a version-skewed BFF’s missing field as no data', async () => {
    installGraphqlFetchMock(handlers(() => jsonResponse({ data: {} })));
    const { container } = render(<SettlingEstatesPanel />);
    await waitFor(() => {
      expect(container).toBeEmptyDOMElement();
    });
  });

  it('says in words when an owner has no name, never "Unknown"', async () => {
    installGraphqlFetchMock(
      handlers(() =>
        jsonResponse({
          data: {
            executorCases: [
              { caseId: 'case-9', ownerName: null, status: 'active', verifiedAt: null },
            ],
          },
        }),
      ),
    );
    render(<SettlingEstatesPanel />);
    expect(await screen.findByText(/an estate with no name on file/i)).toBeInTheDocument();
    expect(screen.queryByText(/unknown/i)).not.toBeInTheDocument();
  });

  it('does not promise access — a verified case is the right to ASK', async () => {
    installGraphqlFetchMock(handlers());
    render(<SettlingEstatesPanel />);
    await screen.findByText('Ada Lovelace');
    // Every stage is an operator's decision, and this list cannot see the
    // ladder. Telling somebody they have access here would be the surface
    // offering what the server will refuse.
    expect(screen.getByText(/released in stages/i)).toBeInTheDocument();
    expect(screen.queryByText(/you have access/i)).not.toBeInTheDocument();
  });
});
