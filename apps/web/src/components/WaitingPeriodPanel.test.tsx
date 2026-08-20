import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { WaitingPeriodPanel } from './WaitingPeriodPanel';

/**
 * The waiting period (M22 PR3).
 *
 * The interesting assertions are the two refusals. `CASE_OPEN` is a CONTROL
 * FIRING — the window is frozen precisely because someone is trying to use it —
 * and reading it as bad input sends an owner back to edit a number that was
 * never the problem. And a failed read must not fall back to the default of 5,
 * which would show a person a protection level the server never claimed.
 */

function handlers(
  options: {
    settings?: OperationHandler;
    setPeriod?: OperationHandler;
  } = {},
): Record<string, OperationHandler> {
  return {
    SettlementSettings:
      options.settings ??
      (() => jsonResponse({ data: { settlementSettings: { waitingPeriodDays: 5 } } })),
    SetSettlementWaitingPeriod:
      options.setPeriod ??
      (() => jsonResponse({ data: { setSettlementWaitingPeriod: { waitingPeriodDays: 30 } } })),
    StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    Passkeys: () => jsonResponse({ data: { passkeys: [] } }),
  };
}

describe('reading the current setting', () => {
  it('renders the server’s number', async () => {
    installGraphqlFetchMock(
      handlers({
        settings: () => jsonResponse({ data: { settlementSettings: { waitingPeriodDays: 21 } } }),
      }),
    );
    render(<WaitingPeriodPanel />);
    expect(await screen.findByText(/currently 21/i)).toBeInTheDocument();
  });

  it('shows a failure as a failure, never as the 5-day default', async () => {
    installGraphqlFetchMock(handlers({ settings: () => graphqlError('UNKNOWN') }));
    render(<WaitingPeriodPanel />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
    expect(screen.queryByText(/currently 5/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
  });

  it('treats a version-skewed BFF’s missing field as no data', async () => {
    installGraphqlFetchMock(handlers({ settings: () => jsonResponse({ data: {} }) }));
    render(<WaitingPeriodPanel />);
    expect(await screen.findByRole('button', { name: /try again/i })).toBeInTheDocument();
  });
});

describe('changing it', () => {
  it('raises the step-up prompt and applies the refused value on retry', async () => {
    let attempts = 0;
    const { requests } = installGraphqlFetchMock(
      handlers({
        setPeriod: () => {
          attempts += 1;
          return attempts === 1
            ? graphqlError('STEPUP_REQUIRED')
            : jsonResponse({
                data: { setSettlementWaitingPeriod: { waitingPeriodDays: 30 } },
              });
        },
      }),
    );
    render(<WaitingPeriodPanel />);
    const field = await screen.findByRole('spinbutton');
    fireEvent.change(field, { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(await screen.findByText(/fresh identity check/i)).toBeInTheDocument();

    // THE RETRY CARRIES ITS OWN ARGUMENT. The form is gone — the prompt
    // replaced it — so a retry that re-read the field would send nothing.
    const sent = requests
      .filter((r) => r.body.query?.includes('SetSettlementWaitingPeriod'))
      .map((r) => r.body.variables);
    expect(sent[0]).toEqual({ days: 30 });
  });

  it('keeps the frozen-window refusal apart from bad input', async () => {
    installGraphqlFetchMock(handlers({ setPeriod: () => graphqlError('CASE_OPEN') }));
    render(<WaitingPeriodPanel />);
    fireEvent.change(await screen.findByRole('spinbutton'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(await screen.findByText(/frozen until it’s resolved/i)).toBeInTheDocument();
    expect(screen.queryByText(/wasn’t right/i)).not.toBeInTheDocument();
  });

  it('refuses an out-of-range value before spending a round trip', async () => {
    const { requests } = installGraphqlFetchMock(handlers());
    render(<WaitingPeriodPanel />);
    fireEvent.change(await screen.findByRole('spinbutton'), { target: { value: '2' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(await screen.findByText(/between 5 and 60/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(
        requests.filter((r) => r.body.query?.includes('SetSettlementWaitingPeriod')),
      ).toHaveLength(0);
    });
  });

  it('confirms a successful change', async () => {
    installGraphqlFetchMock(handlers());
    render(<WaitingPeriodPanel />);
    fireEvent.change(await screen.findByRole('spinbutton'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    expect(await screen.findByText(/we’ll wait 30 days/i)).toBeInTheDocument();
  });

  it('Cancel on the prompt returns the form, with the value still in it', async () => {
    installGraphqlFetchMock(handlers({ setPeriod: () => graphqlError('STEPUP_REQUIRED') }));
    render(<WaitingPeriodPanel />);
    fireEvent.change(await screen.findByRole('spinbutton'), { target: { value: '30' } });
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }));
    fireEvent.click(await screen.findByRole('button', { name: /cancel/i }));
    const field = await screen.findByRole('spinbutton');
    expect(field).toHaveValue(30);
  });

  it('lets a failed read be retried', async () => {
    let call = 0;
    installGraphqlFetchMock(
      handlers({
        settings: () => {
          call += 1;
          return call === 1
            ? graphqlError('UNKNOWN')
            : jsonResponse({ data: { settlementSettings: { waitingPeriodDays: 5 } } });
        },
      }),
    );
    render(<WaitingPeriodPanel />);
    fireEvent.click(await screen.findByRole('button', { name: /try again/i }));
    expect(await screen.findByRole('spinbutton')).toBeInTheDocument();
  });
});
