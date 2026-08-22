import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { AccountErasurePanel } from './AccountErasurePanel';

/**
 * ACCOUNT ERASURE ON /security (M25 PR4).
 *
 * The state machine is small; what is worth asserting is everything the copy
 * and the controls PROMISE, because this is the one panel where a wrong promise
 * is unrecoverable:
 *
 *  - a request that has started offers NO stop button (a control that does
 *    nothing is worse than its absence — the person believes they stopped it);
 *  - a cancel that came back with a request is NOT reported as success;
 *  - a failed READ never renders the arm button, because "we could not ask"
 *    must not look like "nothing is scheduled";
 *  - the two refusals keep their own sentences, one of which names a remedy;
 *  - withdrawing costs no confirmation and no step-up, while arming costs both.
 */

const PENDING = { status: 'pending', requestedAt: '2026-08-21T12:00:00.000Z' };
const EXECUTING = { status: 'executing', requestedAt: '2026-08-21T12:00:00.000Z' };

function handlers(
  options: {
    read?: OperationHandler;
    request?: OperationHandler;
    cancel?: OperationHandler;
  } = {},
): Record<string, OperationHandler> {
  return {
    AccountErasure: options.read ?? (() => jsonResponse({ data: { accountErasure: null } })),
    RequestAccountErasure:
      options.request ?? (() => jsonResponse({ data: { requestAccountErasure: PENDING } })),
    CancelAccountErasure:
      options.cancel ?? (() => jsonResponse({ data: { cancelAccountErasure: null } })),
    StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
  };
}

async function begin(): Promise<void> {
  fireEvent.click(await screen.findByRole('button', { name: /erase this account/i }));
}

describe('when nothing is scheduled', () => {
  it('does not start on the first press — the confirmation is a step', async () => {
    const request = jest.fn(() => jsonResponse({ data: { requestAccountErasure: PENDING } }));
    installGraphqlFetchMock(handlers({ request }));
    render(<AccountErasurePanel />);

    await begin();
    // The confirmation is showing, and NOTHING has been sent. Arming on the
    // first click would make the most irreversible action in the product the
    // easiest one to trigger by accident.
    expect(await screen.findByText(/before you start/i)).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it('SAYS WHAT IS NOT ERASED, because the platform reaches one domain of eight', async () => {
    // The copy assertion that matters most. Erasure destroys identity's key
    // today and nothing else; a panel implying the whole account was gone
    // would be making a promise docs/03 §6nn says the platform cannot keep.
    installGraphqlFetchMock(handlers());
    render(<AccountErasurePanel />);
    await begin();
    expect(await screen.findByText(/are not erased yet/i)).toBeInTheDocument();
    expect(screen.getByText(/no way to undo it once it runs/i)).toBeInTheDocument();
  });

  it('lets you back out of the confirmation without sending anything', async () => {
    const request = jest.fn(() => jsonResponse({ data: { requestAccountErasure: PENDING } }));
    installGraphqlFetchMock(handlers({ request }));
    render(<AccountErasurePanel />);
    await begin();
    fireEvent.click(await screen.findByRole('button', { name: /keep my account/i }));
    await waitFor(() => expect(screen.queryByText(/before you start/i)).not.toBeInTheDocument());
    expect(request).not.toHaveBeenCalled();
  });

  it('arms it, and then shows a way to stop it', async () => {
    let scheduled = false;
    installGraphqlFetchMock(
      handlers({
        read: () => jsonResponse({ data: { accountErasure: scheduled ? PENDING : null } }),
        request: () => {
          scheduled = true;
          return jsonResponse({ data: { requestAccountErasure: PENDING } });
        },
      }),
    );
    render(<AccountErasurePanel />);
    await begin();
    fireEvent.click(await screen.findByRole('button', { name: /yes, begin erasing/i }));

    expect(await screen.findByText(/erasure is scheduled/i)).toBeInTheDocument();
    expect(
      await screen.findByRole('button', { name: /stop this and keep my account/i }),
    ).toBeInTheDocument();
  });

  it('asks for a fresh factor when identity says so', async () => {
    installGraphqlFetchMock(handlers({ request: () => graphqlError('STEPUP_REQUIRED') }));
    render(<AccountErasurePanel />);
    await begin();
    fireEvent.click(await screen.findByRole('button', { name: /yes, begin erasing/i }));
    expect(await screen.findByText(/needs a fresh check/i)).toBeInTheDocument();
  });

  it('KEEPS THE TWO REFUSALS APART, and one of them names a remedy', async () => {
    installGraphqlFetchMock(handlers({ request: () => graphqlError('OPEN_DEATH_REPORT') }));
    const view = render(<AccountErasurePanel />);
    await begin();
    fireEvent.click(await screen.findByRole('button', { name: /yes, begin erasing/i }));
    // Sends them to the case, not to support — a control firing must not read
    // as an outage, and this one has a remedy the owner can take themselves.
    expect(await screen.findByText(/death report is open/i)).toBeInTheDocument();
    view.unmount();

    installGraphqlFetchMock(handlers({ request: () => graphqlError('ERASURE_NOT_PERMITTED') }));
    render(<AccountErasurePanel />);
    await begin();
    fireEvent.click(await screen.findByRole('button', { name: /yes, begin erasing/i }));
    expect(await screen.findByText(/can’t be erased in its current state/i)).toBeInTheDocument();
  });
});

describe('when a request is already live', () => {
  it('withdraws with ONE press — no confirmation, no factor', async () => {
    // The inverted asymmetry, asserted. The protective action must never be
    // harder than the permissive one, and here the permissive one is the
    // destructive one.
    let scheduled = true;
    const cancel = jest.fn(() => {
      scheduled = false;
      return jsonResponse({ data: { cancelAccountErasure: null } });
    });
    installGraphqlFetchMock(
      handlers({
        read: () => jsonResponse({ data: { accountErasure: scheduled ? PENDING : null } }),
        cancel,
      }),
    );
    render(<AccountErasurePanel />);

    fireEvent.click(await screen.findByRole('button', { name: /stop this and keep my account/i }));
    expect(await screen.findByText(/nothing has been erased/i)).toBeInTheDocument();
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/before you start/i)).not.toBeInTheDocument();
  });

  it('OFFERS NO STOP BUTTON once it is running', async () => {
    // A button that cannot work is worse than no button: the person presses it
    // and believes they stopped an erasure that is destroying keys.
    installGraphqlFetchMock(
      handlers({ read: () => jsonResponse({ data: { accountErasure: EXECUTING } }) }),
    );
    render(<AccountErasurePanel />);
    expect(await screen.findByText(/erasure is running/i)).toBeInTheDocument();
    expect(screen.getByText(/can no longer be stopped/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /stop this/i })).not.toBeInTheDocument();
  });

  it('treats a state it does not recognise as NOT withdrawable', async () => {
    // Identity owns this vocabulary and it grows. A build that met 'completed'
    // and offered a stop button would be offering to cancel something already
    // finished — so the allowlist decides, never a check for 'executing'.
    installGraphqlFetchMock(
      handlers({
        read: () => jsonResponse({ data: { accountErasure: { ...PENDING, status: 'completed' } } }),
      }),
    );
    render(<AccountErasurePanel />);
    expect(await screen.findByText(/erasure is running/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /stop this/i })).not.toBeInTheDocument();
  });

  it('does NOT report a too-late cancel as success', async () => {
    installGraphqlFetchMock(
      handlers({
        read: () => jsonResponse({ data: { accountErasure: PENDING } }),
        cancel: () => jsonResponse({ data: { cancelAccountErasure: EXECUTING } }),
      }),
    );
    render(<AccountErasurePanel />);
    fireEvent.click(await screen.findByRole('button', { name: /stop this and keep my account/i }));
    expect(await screen.findByText(/already started running/i)).toBeInTheDocument();
    expect(screen.queryByText(/nothing has been erased/i)).not.toBeInTheDocument();
  });
});

describe('when the read fails', () => {
  it('never offers to start something it could not ask about', async () => {
    // "We could not ask" must not look like "nothing is scheduled". Rendering
    // the arm button here would invite a second request against an account
    // that may already have one.
    installGraphqlFetchMock(handlers({ read: () => graphqlError('UNAUTHENTICATED') }));
    render(<AccountErasurePanel />);
    await screen.findByRole('button', { name: /try again/i });
    expect(screen.queryByRole('button', { name: /erase this account/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/erasure is scheduled/i)).not.toBeInTheDocument();
  });
});
