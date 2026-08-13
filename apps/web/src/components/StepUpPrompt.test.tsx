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

    // WAIT for the form to come back rather than assuming the previous attempt
    // has finished tearing down. This test failed in CI and passed everywhere
    // else, because `submitCode` queries the button by /Confirm/ and the label is
    // `waiting ? 'Applying…' : busy ? 'Checking…' : submitLabel` — so whether it
    // matched depended on how many microtask ticks `advanceTimersByTimeAsync(0)`
    // drained versus how many the gqlRequest chain needed. Waiting states the
    // precondition instead of racing it; loosening the matcher would have deleted
    // the signal that the form is mid-flight, which is a thing worth being able
    // to see.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Confirm' })).toBeEnabled();
    });

    // Cancelling one attempt must not veto the next one the user chooses to make.
    submitCode();
    await jest.advanceTimersByTimeAsync(STEP_UP_RETRY_INTERVAL_MS);
    expect(onElevated).toHaveBeenCalled();
  });
});

/**
 * CANCEL RESTORES THE FORM ON ITS OWN.
 *
 * These are the other end of the same fact the flaky test above was tripping
 * over. `abandon()` used to set the abort flag and call `onCancel`, leaving
 * `busy` to be cleared by the continuation of the request being cancelled —
 * which works whenever that request settles, and neither await in `submit` has a
 * timeout. The protective action must not be contingent on the permissive one
 * finishing, which is the same rule the paired-devices list follows by keeping
 * revocation ungated.
 */
describe('cancel does not leave the form wedged', () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  /** A step-up call that never answers: a stalled peer, or a dead connection. */
  function mountWithHangingStepUp(onElevated: () => Promise<'applied' | 'stale'>): void {
    installGraphqlFetchMock({ StepUp: () => new Promise<Response>(() => undefined) });
    render(
      <StepUpPrompt
        idPrefix="t"
        hint="because reasons"
        submitLabel="Confirm"
        onElevated={onElevated}
        onCancel={() => undefined}
      />,
    );
  }

  it('comes back immediately even when the request never answers', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    mountWithHangingStepUp(onElevated);
    submitCode();
    expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    // SYNCHRONOUSLY, with nothing awaited: there is nothing to wait FOR. Before
    // this fix the only way out of this state was a page reload.
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeEnabled();

    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS * 2);
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeEnabled();
    expect(onElevated).not.toHaveBeenCalled();
  });

  it('comes back when cancelled from inside the retry loop, not just the first call', async () => {
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('stale'));
    mount(onElevated);
    submitCode();

    // Get the loop genuinely running, so `waiting` is set and not just `busy`.
    await jest.advanceTimersByTimeAsync(STEP_UP_RETRY_INTERVAL_MS * 2);
    expect(screen.getByRole('button', { name: 'Applying…' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeEnabled();
  });

  /**
   * The hazard clearing `busy` on cancel INTRODUCES, and why the abort flag had
   * to become a counter. With the form interactive again the owner can start a
   * second attempt while the first is still in flight; `submit()` re-arms consent
   * on the way in, so a boolean flag would have the abandoned request see consent
   * restored — by a different submission — and apply the action a second time.
   */
  it('never applies an abandoned attempt, even once a newer one has re-armed consent', async () => {
    let releaseFirst: () => void = () => undefined;
    let stepUpCalls = 0;
    const onElevated = jest.fn(() => Promise.resolve<'applied' | 'stale'>('applied'));
    installGraphqlFetchMock({
      StepUp: () => {
        stepUpCalls += 1;
        if (stepUpCalls > 1) return jsonResponse({ data: { stepUp: { ok: true } } });
        return new Promise<Response>((resolve) => {
          releaseFirst = () => {
            resolve(jsonResponse({ data: { stepUp: { ok: true } } }));
          };
        });
      },
    });
    render(
      <StepUpPrompt
        idPrefix="t"
        hint="because reasons"
        submitLabel="Confirm"
        onElevated={onElevated}
        onCancel={() => undefined}
      />,
    );

    submitCode(); // attempt 1 — hangs
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    submitCode(); // attempt 2 — the consent that actually counts
    await jest.advanceTimersByTimeAsync(0);
    expect(onElevated).toHaveBeenCalledTimes(1);

    releaseFirst(); // the abandoned attempt finally answers
    await jest.advanceTimersByTimeAsync(STEP_UP_PROPAGATION_BUDGET_MS);
    expect(onElevated).toHaveBeenCalledTimes(1);
  });
});

/**
 * THE PASSKEY PATH (M17 PR5). The double is faithful about absences (the M16
 * chrome-double rule): jsdom really has no PublicKeyCredential, so the default
 * expectation everywhere else in this file — no passkey button — is the
 * platform's own truth, not a mock's generosity. These cases install exactly
 * the capability they claim.
 */
describe('StepUpPrompt passkey path', () => {
  function installPasskeyCapability(get: jest.Mock): void {
    (window as unknown as Record<string, unknown>)['PublicKeyCredential'] =
      function stub(): void {};
    (navigator as unknown as Record<string, unknown>)['credentials'] = { get };
  }

  afterEach(() => {
    delete (window as unknown as Record<string, unknown>)['PublicKeyCredential'];
    delete (navigator as unknown as Record<string, unknown>)['credentials'];
  });

  const ASSERTION = {
    id: 'cred',
    rawId: new Uint8Array([1]).buffer,
    type: 'public-key',
    authenticatorAttachment: null,
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: new Uint8Array([2]).buffer,
      authenticatorData: new Uint8Array([3]).buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: null,
    },
  };
  const OPTIONS = { challenge: 'AQID', rpId: 'localhost' };

  it('offers the button only when the account HAS passkeys and the browser can', async () => {
    installPasskeyCapability(jest.fn());
    mount(jest.fn(), {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
    });
    expect(await screen.findByText('Use a passkey')).toBeInTheDocument();
  });

  it('renders NO button when the list read fails — TOTP must not be hostage to a nicety', async () => {
    installPasskeyCapability(jest.fn());
    mount(jest.fn(), { Passkeys: () => graphqlError('UNKNOWN') });
    // The TOTP field is there; the passkey button never appears.
    expect(screen.getByLabelText('Confirm it’s you')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('Use a passkey')).not.toBeInTheDocument();
    });
  });

  it('walks the ceremony and retries the refused action, exactly like a TOTP elevation', async () => {
    const get = jest.fn().mockResolvedValue(ASSERTION);
    installPasskeyCapability(get);
    const onElevated = jest.fn().mockResolvedValue('applied' as const);
    mount(onElevated, {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
      WebauthnStepUpOptions: () => jsonResponse({ data: { webauthnStepUpOptions: OPTIONS } }),
      WebauthnStepUp: () =>
        jsonResponse({ data: { webauthnStepUp: { stepupExpiresAt: '2026-08-13T12:05:00Z' } } }),
    });

    fireEvent.click(await screen.findByText('Use a passkey'));
    await waitFor(() => {
      expect(onElevated).toHaveBeenCalledTimes(1);
    });
    expect(get).toHaveBeenCalledTimes(1);
  });

  it('a closed sheet says so in local words and re-enables the form', async () => {
    installPasskeyCapability(jest.fn().mockRejectedValue(new DOMException('x', 'NotAllowedError')));
    const onElevated = jest.fn();
    mount(onElevated, {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
      WebauthnStepUpOptions: () => jsonResponse({ data: { webauthnStepUpOptions: OPTIONS } }),
    });

    fireEvent.click(await screen.findByText('Use a passkey'));
    expect(await screen.findByText(/prompt was closed or timed out/)).toBeInTheDocument();
    // The action never ran, and the form is usable again.
    expect(onElevated).not.toHaveBeenCalled();
    expect(screen.getByText('Confirm')).not.toBeDisabled();
  });

  it('a refused OPTIONS mint renders through the platform copy table', async () => {
    installPasskeyCapability(jest.fn());
    mount(jest.fn(), {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
      WebauthnStepUpOptions: () => graphqlError('WEBAUTHN_FAILED'),
    });
    fireEvent.click(await screen.findByText('Use a passkey'));
    // The BFF's refusal, in the BFF's words — a platform fact, unlike a closed
    // sheet, which is a device fact.
    expect(await screen.findByText(/passkey wasn’t accepted/)).toBeInTheDocument();
  });

  it('a REFUSED assertion verify renders the platform copy and re-enables the form', async () => {
    installPasskeyCapability(jest.fn().mockResolvedValue(ASSERTION));
    mount(jest.fn(), {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
      WebauthnStepUpOptions: () => jsonResponse({ data: { webauthnStepUpOptions: OPTIONS } }),
      WebauthnStepUp: () => graphqlError('WEBAUTHN_FAILED'),
    });
    fireEvent.click(await screen.findByText('Use a passkey'));
    expect(await screen.findByText(/passkey wasn’t accepted/)).toBeInTheDocument();
    expect(screen.getByText('Confirm')).not.toBeDisabled();
  });

  it('CANCEL during the platform sheet abandons the attempt — the ceremony await is ownable', async () => {
    // The sheet never settles; Cancel must not wait for it (the M6 rule the
    // component already applies to identity calls, extended to the new await).
    let settleSheet: (value: unknown) => void = () => {};
    installPasskeyCapability(
      jest.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            settleSheet = resolve;
          }),
      ),
    );
    const onElevated = jest.fn();
    const verifySubmitted = jest.fn();
    const { cancel } = mount(onElevated, {
      Passkeys: () =>
        jsonResponse({
          data: {
            passkeys: [
              {
                id: 'pk-1',
                nickname: null,
                isHardwareKey: false,
                createdAt: '2026-08-01T00:00:00Z',
                lastUsedAt: null,
              },
            ],
          },
        }),
      WebauthnStepUpOptions: () => jsonResponse({ data: { webauthnStepUpOptions: OPTIONS } }),
      WebauthnStepUp: () => {
        verifySubmitted();
        return jsonResponse({
          data: { webauthnStepUp: { stepupExpiresAt: '2026-08-13T12:05:00Z' } },
        });
      },
    });

    fireEvent.click(await screen.findByText('Use a passkey'));
    await waitFor(() => {
      expect(screen.getByText('Checking…')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByText('Cancel'));
    expect(cancel).toHaveBeenCalled();
    // The form came back WITHOUT the sheet settling.
    expect(screen.getByText('Confirm')).not.toBeDisabled();

    // The sheet finally resolves — and the abandoned continuation must apply
    // NOTHING (the M13-round-3 property, on the new await). The sharp half:
    // the assertion is never SUBMITTED. Submitting it would spend a ceremony
    // the user cancelled — and a successful verify elevates the session
    // server-side, a consent violation even with the retry suppressed.
    settleSheet(ASSERTION);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(verifySubmitted).not.toHaveBeenCalled();
    expect(onElevated).not.toHaveBeenCalled();
  });
});
