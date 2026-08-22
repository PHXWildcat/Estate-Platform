'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type ErasureRequestInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { formatDateTime } from '../lib/datetime';
import type { StepUpRetryOutcome } from '../lib/step-up';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * ACCOUNT ERASURE, on /security (M25 PR4) — the owner's own crypto-shred.
 *
 * A SIBLING PANEL, and last on the page. It is the one action here that cannot
 * be undone, and it reads a different service concern from its neighbours; the
 * `WaitingPeriodPanel` precedent applies unchanged.
 *
 * THE COPY IS THE HARD PART OF THIS COMPONENT, not the state machine. Two
 * things must be true of every sentence below and neither is automatic:
 *
 *  1. IT MUST NOT PROMISE MORE THAN THE PLATFORM DOES. Erasure reaches ONE of
 *     eight domains today — identity's own keys — because the other services
 *     holding this account's encrypted data have no erasure transport yet
 *     (docs/03 §6nn). "Your account has been erased" would be false. So the
 *     panel says what is destroyed now, says the rest is queued, and never
 *     claims completion the ledger cannot support.
 *  2. IT MUST NOT UNDERSTATE THE IRREVERSIBILITY EITHER. This is not a
 *     deactivation and there is no support path that restores it — the key is
 *     gone. Copy that softened it would be the kinder sentence and the crueller
 *     outcome.
 *
 * THE ASYMMETRY IS INVERTED HERE, deliberately, and it is the reason arming has
 * a confirm step and withdrawing does not. Normally the permissive action is
 * gated and the protective one is free; here the permissive action IS the
 * destructive one. Arming costs a deliberate confirmation AND a fresh factor;
 * withdrawing is one button, no prompt, no re-read of anything.
 *
 * WHAT IT DOES NOT DO: offer a cancel while a request is EXECUTING. The driver
 * has claimed it and nothing can stop it, so a button there would be a control
 * that does nothing — worse than its absence, because the person would believe
 * they had stopped it.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; request: ErasureRequestInfo | null }
  | { kind: 'error'; message: string };

/**
 * Which states can still be withdrawn. An ALLOWLIST rather than a check for
 * 'executing', because identity owns this vocabulary and it grows: a state this
 * build has not met must fall through to "cannot be withdrawn from here",
 * never to an enabled button whose press would be refused.
 */
const WITHDRAWABLE: readonly string[] = ['pending'];

export function AccountErasurePanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [confirming, setConfirming] = useState(false);
  const [steppingUp, setSteppingUp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('AccountErasure', {});
    if (result.ok) {
      // `null` is a real answer here — nothing outstanding — and it is the
      // common one. Unlike a missing NUMBER, a missing object is the data.
      setState({ kind: 'ready', request: result.data.accountErasure });
      return;
    }
    setState({ kind: 'error', message: messageFor(result.code) });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const arm = useCallback(async (): Promise<StepUpRetryOutcome> => {
    setError(null);
    const result = await gqlRequest('RequestAccountErasure', {});
    if (result.ok) {
      setConfirming(false);
      setSteppingUp(false);
      setNotice(
        'Erasure has begun. You can still stop it until it starts running — see the date below.',
      );
      await load();
      return 'applied';
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setSteppingUp(true);
      return 'stale';
    }
    // EVERY OTHER REFUSAL ENDS THE CEREMONY, including the two that are
    // controls firing. `OPEN_DEATH_REPORT` carries its own sentence and its own
    // remedy, and collapsing it into a generic failure would tell somebody
    // whose account is being settled out from under them that we are broken.
    setSteppingUp(false);
    setConfirming(false);
    setError(messageFor(result.code));
    return 'applied';
  }, [load]);

  const withdraw = useCallback(async (): Promise<void> => {
    setError(null);
    setNotice(null);
    const result = await gqlRequest('CancelAccountErasure', {});
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    // A RETURNED REQUEST MEANS THE WITHDRAWAL DID NOT TAKE. There is exactly
    // one cause — the driver already claimed it — and rendering this as
    // success would be the worst lie this product could tell.
    if (result.data.cancelAccountErasure !== null) {
      setError('This has already started running and can no longer be stopped.');
    } else {
      setNotice('Stopped. Nothing has been erased and your account is unchanged.');
    }
    await load();
  }, [load]);

  const request = state.kind === 'ready' ? state.request : null;
  const withdrawable = request !== null && WITHDRAWABLE.includes(request.status);

  return (
    <section aria-labelledby="erasure-heading" className="card mb-8 p-6">
      <h2 id="erasure-heading" className="text-lg font-semibold">
        Erase this account
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        This closes your account and destroys the key that protects your sign-in details, so what it
        protected can never be read again — by us or by anyone. It is not a deactivation, and there
        is no way to undo it once it runs.
      </p>

      {state.kind === 'loading' ? <p className="text-sm text-ink-muted">Loading…</p> : null}

      {state.kind === 'error' ? (
        <>
          {/* A failed read is not "nothing outstanding". Never render the arm
              button here: it would offer to start something while we cannot
              say whether it has already started. */}
          <p className="text-sm text-ink-muted">{state.message}</p>
          <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
            Try again
          </button>
        </>
      ) : null}

      {notice !== null ? <FormStatus tone="success" message={notice} /> : null}
      {error !== null ? <FormStatus tone="error" message={error} /> : null}

      {state.kind === 'ready' && request === null ? (
        steppingUp ? (
          // The prompt REPLACES the confirmation it guards, never nests in it.
          <StepUpPrompt
            idPrefix="account-erasure-stepup"
            hint="Erasing your account needs a fresh check. Enter the six-digit code from your authenticator."
            submitLabel="Confirm and begin erasing"
            onElevated={arm}
            onCancel={() => {
              setSteppingUp(false);
              setConfirming(false);
            }}
          />
        ) : confirming ? (
          <div className="rounded-lg border border-danger/40 bg-danger/10 p-4">
            <h3 className="text-sm font-semibold">Before you start</h3>
            <ul className="mt-2 max-w-prose list-disc space-y-1 pl-5 text-sm text-ink-muted">
              <li>
                We wait before starting, so you can change your mind. Until then you can stop this
                with one button.
              </li>
              <li>
                When it runs, your account closes, every device is signed out, and your email
                address stops working for signing in.
              </li>
              <li>
                The key protecting your sign-in details is destroyed. Nobody can recover what it
                protected, including us.
              </li>
              <li>
                Your documents, assets and other records are queued to be erased as each part of the
                platform is connected. They are not erased yet.
              </li>
            </ul>
            {/*
              THE SAFE ACTION IS THE PROMINENT ONE, and the order is deliberate:
              "Keep my account" is primary and comes first. There is no
              `btn-danger` in this design system and this panel is not the place
              to invent one — a destructive control that is the easiest thing on
              the screen to press is a design decision, not a styling gap.
            */}
            <div className="mt-4 flex flex-wrap gap-3">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setConfirming(false)}
              >
                Keep my account
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => void arm()}>
                Yes, begin erasing my account
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => {
              setNotice(null);
              setError(null);
              setConfirming(true);
            }}
          >
            Erase this account…
          </button>
        )
      ) : null}

      {state.kind === 'ready' && request !== null ? (
        <div className="rounded-lg border border-danger/40 bg-danger/10 p-4">
          <p className="text-sm font-semibold">
            {withdrawable ? 'Erasure is scheduled' : 'Erasure is running'}
          </p>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            You asked for this on {formatDateTime(request.requestedAt)}.{' '}
            {withdrawable
              ? 'Nothing has been destroyed yet. You can still stop it.'
              : 'It has started and can no longer be stopped.'}
          </p>
          {withdrawable ? (
            // ONE BUTTON, NO PROMPT, NO CONFIRMATION. The protective action must
            // never be harder than the permissive one — and an owner whose
            // session was briefly taken has to be able to disarm this with
            // nothing but the session they already hold.
            <button type="button" className="btn btn-primary mt-4" onClick={() => void withdraw()}>
              Stop this and keep my account
            </button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
