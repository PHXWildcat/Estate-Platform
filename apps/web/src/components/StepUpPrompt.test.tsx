import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { StepUpPrompt } from './StepUpPrompt';
import { STEP_UP_PROPAGATION_BUDGET_MS, STEP_UP_RETRY_INTERVAL_MS } from '../lib/step-up';

/**
 * The prompt's two contracts, both established by the M13 review: it retries the
 * action it was given, and it keeps retrying while the PEER's session cache is
 * still answering from before the elevation — a delay the platform documents
 * (the 2026-07-23 short-TTL positive cache) and which a single-shot retry turned
 * into a prompt that sat there doing nothing after an accepted code.
 */
function mount(
  onElevated: () => Promise<'applied' | 'stale'>,
  overrides: Partial<Record<string, OperationHandler>> = {},
): { cancel: jest.Mock } {
  installGraphqlFetchMock({
    StepUp: () => jsonResponse({ data: { stepUp: { ok: true } } }),
    ...overrides,
  });
  const cancel = jest.fn();
  render(
    <StepUpPrompt
      idPrefix="t"
      hint="because reasons"
      submitLabel="Confirm"
      onElevated={onElevated}
      onCancel={cancel}
    />,
  );
  return { cancel };
}

function submitCode(code = '123456'): void {
  fireEvent.change(screen.getByLabelText('Confirm it’s you'), { target: { value: code } });
  fireEvent.click(screen.getByRole('button', { name: /Confirm/ }));
}

describe('retrying past the session-cache delay', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  it('keeps retrying while the peer still answers stale, then stops on success', async () => {
    let calls = 0;
    const onElevated = jest.fn(() => {
      calls += 1;
      return Promise.resolve<'applied' | 'stale'>(calls < 3 ? 'stale' : 'applied');
    });
    mount(onElevated);
    submitCode();

    await waitFor(() => {
      expect(onElevated).toHaveBeenCalledTimes(1);
    });
    // "Applying…" rather than a silent form: an accepted code that has not
    // landed yet must not look like nothing happening.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Applying…' })).toBeInTheDocument();
    });

    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS);
    await waitFor(() => {
      expect(onElevated).toHaveBeenCalledTimes(3);
    });
    // Stopped as soon as it applied — no spinning past success.
    expect(onElevated).toHaveBeenCalledTimes(3);
  });

  it('gives up at the deadline with an honest, actionable message', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('stale'));
    mount(onElevated);
    submitCode();

    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS + 5_000);
    await waitFor(() => {
      expect(screen.getByText(/Your check went through — try that again/)).toBeInTheDocument();
    });
    // Never blames the code: it was accepted.
    expect(screen.queryByText(/Codes change every 30 seconds/)).not.toBeInTheDocument();
  });

  it('does not retry at all when the code itself is rejected', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    mount(onElevated, { StepUp: () => graphqlError('INVALID_CREDENTIALS') });
    submitCode();

    await waitFor(() => {
      expect(screen.getByText(/Codes change every 30 seconds/)).toBeInTheDocument();
    });
    expect(onElevated).not.toHaveBeenCalled();
  });

  it('refuses a malformed code locally, without asking identity', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    mount(onElevated);
    submitCode('12');
    await waitFor(() => {
      expect(screen.getByText('The code is 6 digits, numbers only.')).toBeInTheDocument();
    });
    expect(onElevated).not.toHaveBeenCalled();
  });

  it('cancels before anything was submitted', () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    const { cancel } = mount(onElevated);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(cancel).toHaveBeenCalled();
    expect(onElevated).not.toHaveBeenCalled();
  });

  /**
   * THE CASE THAT MATTERED AND WAS NOT THERE. The previous "cancels without
   * retrying" test (kept above, renamed for what it does) clicked Cancel before
   * any code was submitted — so `onElevated` was never going to be called and it
   * passed whether or not Cancel stopped the loop. It did not: a probe against
   * the real RoleControls issued a third GrantRole AFTER Cancel, which succeeded
   * and wrote an executor designation onto the §5.1 chain.
   *
   * A step-up prompt is a consent ceremony. This pins the one property that makes
   * it one.
   */
  it('STOPS retrying the moment the owner cancels, and applies nothing after', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('stale'));
    mount(onElevated);
    submitCode();

    // Let the first attempt and one retry happen, so the loop is genuinely running.
    await jest.advanceTimersByTimeAsync(STEP_UP_RETRY_INTERVAL_MS * 2);
    const callsBeforeCancel = onElevated.mock.calls.length;
    expect(callsBeforeCancel).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    // Run well past the whole propagation budget: not one further attempt.
    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS * 2);
    expect(onElevated).toHaveBeenCalledTimes(callsBeforeCancel);
  });

  it('does not apply the action when cancelled while identity is still deciding', async () => {
    // The narrow window between submitting the code and the elevation landing.
    let releaseStepUp: () => void = () => undefined;
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    installGraphqlFetchMock({
      StepUp: () =>
        new Promise((resolve) => {
          releaseStepUp = () => {
            resolve(jsonResponse({ data: { stepUp: { ok: true } } }));
          };
        }) as never,
    });
    const cancel = jest.fn();
    render(
      <StepUpPrompt
        idPrefix="t"
        hint="because reasons"
        submitLabel="Confirm"
        onElevated={onElevated}
        onCancel={cancel}
      />,
    );
    submitCode();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    releaseStepUp();

    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS);
    // The elevation may have been granted — harmless on its own — but the action
    // the owner declined must not have run.
    expect(onElevated).not.toHaveBeenCalled();
  });

  it('a fresh submission re-arms after an earlier cancel', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    mount(onElevated);
    submitCode();
    await jest.advanceTimersByTimeAsync(0);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    onElevated.mockClear();

    // Cancelling one attempt must not veto the next one the user chooses to make.
    submitCode();
    await jest.advanceTimersByTimeAsync(STEP_UP_RETRY_INTERVAL_MS);
    expect(onElevated).toHaveBeenCalled();
  });
});
