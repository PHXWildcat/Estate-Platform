'use client';

import { useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { stepUpMessageFor } from '../lib/copy';
import {
  ceremonyFailureMessage,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  webauthnSupported,
} from '../lib/webauthn';
import {
  STEP_UP_PROPAGATION_BUDGET_MS,
  STEP_UP_RETRY_INTERVAL_MS,
  type StepUpRetryOutcome,
} from '../lib/step-up';
import { validateTotpCode } from '../lib/validation';

/**
 * The inline step-up prompt, extracted at its THIRD caller (M13).
 *
 * Step-up is a detour by nature — the server refuses until the session has a
 * fresh check — and the pattern the consent controls (M10) and the document
 * generator (M12) both settled on is to ask HERE and retry the SAME action, so
 * nobody loses a filled-in form to an authentication round trip. M13 needs it on
 * every role change, which would have made four hand-written copies of a form
 * whose wording is load-bearing: `stepUpMessageFor` exists because identity
 * answers `invalid_credentials` for a rejected TOTP code exactly as for a
 * rejected password, and a copy that forgot it would tell someone their password
 * was wrong about a form with no password on it. One component, one place for
 * that to be right.
 *
 * `onElevated` runs after identity accepts the code, and is expected to re-run
 * THE ACTION THAT WAS REFUSED — this component owns no knowledge of what that
 * is, but the M13 review found a caller retrying a DIFFERENT action, so the
 * contract is worth restating: whatever the server refused is what must run.
 *
 * IT MAY HAVE TO RUN MORE THAN ONCE, and that is not a flake. Peer services
 * learn about the elevation by introspecting the token through a short-TTL
 * POSITIVE cache, so for up to one TTL after a genuine step-up the peer still
 * answers from a cached un-elevated session. A single-shot retry therefore left
 * the prompt sitting there doing nothing for a user whose code was accepted —
 * the review's finding. `onElevated` reports `stale` for exactly that case and
 * the prompt polls to the documented deadline (see lib/step-up.ts).
 *
 * CANCEL ABORTS THE LOOP, AND SO DOES UNMOUNTING. That is the fix for the worst
 * defect in this component's own short history: the retry loop had no abort, and
 * Cancel only asked the parent to hide the prompt — so for up to the whole
 * propagation budget after the owner declined, the loop kept retrying and could
 * still APPLY the action they had just cancelled. Measured, not theorised: a
 * probe against the real RoleControls issued a third `GrantRole` after Cancel,
 * it succeeded, and an `executor`/`on_death_verified` designation appeared on the
 * §5.1 executor-resolution chain with no UI signal at all (React 19 makes the
 * post-unmount `setState` a silent no-op, so even the give-up message went
 * nowhere). A step-up prompt is a CONSENT ceremony; an action that proceeds after
 * consent is withdrawn is the one thing it must never do.
 *
 * WHAT THAT PROMISE DOES NOT COVER, narrowed by the M21 PR4 review because the
 * paragraph above read as an absolute and is not one. The abort is checked
 * AROUND `onElevated()`, never inside it — so it governs whether the loop asks
 * AGAIN and whether the RESULT is acted on, and it cannot touch anything the
 * callback itself did while it was running. A callback whose side effect lands
 * before it returns has already applied the action by the time this component
 * gets to look. That is not hypothetical: both handoff launchers minted a code,
 * set the form action and navigated to an isolated origin inside the await, and
 * a Cancel pressed mid-flight arrived far too late to stop any of it.
 *
 * SO THE CALLER OWNS THAT WINDOW. A callback that performs a side effect must
 * record the withdrawal itself (`onCancel`) and re-check it after its own await,
 * before doing anything — which is what `OperatorLaunch` and `VaultLaunch` now
 * do. Callbacks that only READ and return a verdict, or whose whole effect is a
 * `setState` this component's own counter already gates, need nothing.
 *
 * CANCEL ALSO RESTORES THE FORM ITSELF, rather than leaving that to the thing it
 * is cancelling. It used to set the abort flag and call `onCancel`, and nothing
 * else — every path of the in-flight `submit()` does clear `busy`, so the form
 * came back whenever the promise settled. WHENEVER IT SETTLED. Neither await in
 * here carries a timeout, so a stalled identity call or a dead connection left
 * the prompt after Cancel with its submit button disabled and reading
 * "Checking…" forever, with a page reload as the only way out — a consent form
 * that the owner has declined and cannot use. The same rule this milestone
 * applies to revoking a session applies to cancelling a step-up: THE PROTECTIVE
 * ACTION MUST NOT BE CONTINGENT ON THE PERMISSIVE ONE FINISHING. Seen at a much
 * shorter timescale first, as a flaky test that re-submitted before the previous
 * attempt had torn down and found a disabled button.
 *
 * WHAT IT DOES NOT COVER, stated rather than left to be discovered: the two
 * earlier callers keep their own copies. `ConsentControls` could adopt this
 * as-is; `DocumentGenerator` cannot, because its prompt is rendered INSIDE the
 * intake form (deliberately — the answers must survive the round trip) and this
 * component renders a `<form>`, which HTML does not allow to nest. Adding an
 * "actually a div" mode to satisfy one caller would put the branch back inside
 * the thing being shared. So the rule for anyone adding a fifth prompt: use this
 * unless you are inside a form, and if you are, the wording still has to come
 * from `stepUpMessageFor`.
 *
 * THE PASSKEY PATH (M17 PR5) IS SELF-CONTAINED: the prompt asks the BFF for the
 * caller's passkey list itself, on mount, once — so every caller of this
 * component gained the option without threading a prop, and a caller that
 * predates passkeys cannot render a broken button. The list read failing, the
 * browser lacking the API, or the account holding none all collapse to the same
 * answer: no button, TOTP as before. The ceremony await sits under the SAME
 * ownership counter as everything else — Cancel while the platform sheet is up
 * abandons the attempt, and a sheet that never settles cannot wedge the form
 * because `abandon` restores it without waiting (the rule above, applied to a
 * new awaited thing). Browser-side ceremony failures (the sheet closed, a
 * timeout) render through `ceremonyFailureMessage`, never through the BFF error
 * table: a cancellation is a fact about this device, and laundering it into a
 * platform refusal would tell a user something is wrong with their account.
 */
export interface StepUpPromptProps {
  /** Why the check is needed, in this surface's own words. */
  hint: string;
  submitLabel: string;
  /**
   * Retry the refused action. Return `stale` when the server STILL answers
   * `stepup_required` — the prompt then waits for the peer's session cache to
   * expire and tries again, up to `STEP_UP_PROPAGATION_BUDGET_MS`.
   */
  onElevated: () => Promise<StepUpRetryOutcome>;
  onCancel: () => void;
  /** Distinguishes the field ids when more than one prompt can exist on a page. */
  idPrefix: string;
}

export function StepUpPrompt({
  hint,
  submitLabel,
  onElevated,
  onCancel,
  idPrefix,
}: StepUpPromptProps): ReactElement {
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [hasPasskey, setHasPasskey] = useState(false);
  /**
   * WHICH SUBMISSION CURRENTLY OWNS THIS FORM.
   *
   * A counter rather than the `abandoned` boolean it replaces, and the reason is
   * that Cancel now clears `busy`: with the form interactive again, the owner can
   * start a SECOND attempt while the first is still in flight, and a boolean
   * cannot tell "nobody owns this any more" from "somebody else does". The first
   * attempt's `submit()` re-arms the flag on the way in, so when the abandoned
   * request finally answered it would see consent restored — by a different
   * submission — and run the action a second time. Every abandon and every submit
   * bumps this, so a continuation proceeds only while the number it captured is
   * still the live one, which is strictly the question each of them is asking.
   *
   * A ref rather than state because the running loop needs the CURRENT value; a
   * state variable captured in its closure would be forever whatever it was when
   * the loop started.
   */
  const activeAttempt = useRef(0);

  // Unmounting is withdrawal too: a user who navigates away has not consented to
  // whatever the loop was still about to try. No state is touched here — there
  // is nothing left to render — only the ownership claim is retired.
  useEffect(
    () => () => {
      activeAttempt.current += 1;
    },
    [],
  );

  // Discover the passkey option. Once, on mount, and failure means silence:
  // this read exists to decide whether a BUTTON renders, and a prompt that
  // blocked or errored on it would make TOTP hostage to a nicety.
  useEffect(() => {
    if (!webauthnSupported()) {
      return;
    }
    let alive = true;
    void gqlRequest('Passkeys', {}).then((result) => {
      if (alive && result.ok) {
        const list = (result.data as { passkeys?: unknown[] }).passkeys;
        setHasPasskey(Array.isArray(list) && list.length > 0);
      }
    });
    return () => {
      alive = false;
    };
  }, []);

  function abandon(): void {
    activeAttempt.current += 1;
    // Restore the form HERE rather than in the continuation of the thing being
    // cancelled: neither await in `submit` has a timeout, so a request that never
    // answers would otherwise leave a declined consent form permanently disabled.
    setBusy(false);
    setWaiting(false);
    onCancel();
  }

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    const validation = validateTotpCode(code);
    setCodeError(validation);
    if (validation !== null) {
      return;
    }
    // A fresh submission re-arms: Cancel on a PREVIOUS attempt must not veto this
    // one, and this attempt takes ownership from any that is still in flight.
    // Claimed before the first await, so a double submit cannot interleave.
    activeAttempt.current += 1;
    const mine = activeAttempt.current;
    /**
     * Is this continuation still the one the form belongs to? False after a
     * Cancel, after an unmount, and after the owner has started a newer attempt
     * — three situations that share the only consequence that matters here:
     * nothing this continuation does may be applied or rendered.
     */
    const owns = (): boolean => activeAttempt.current === mine;

    setBusy(true);
    const stepUp = await gqlRequest('StepUp', { code });
    if (!owns()) {
      // Cancelled (or superseded) while identity was deciding. The elevation may
      // well have been granted — that is harmless, it grants no action by itself
      // — but the action the owner declined must not run. `busy` is deliberately
      // NOT cleared: either `abandon` already cleared it, or a newer attempt owns
      // it and clearing it here would re-enable a form that is mid-flight.
      return;
    }
    if (!stepUp.ok) {
      setBusy(false);
      setCodeError(stepUpMessageFor(stepUp.code));
      return;
    }
    setCode('');
    await retryElevated(owns);
  }

  /**
   * The post-elevation retry loop, shared by both factors (M17 PR5 extracted
   * it at its second user): fresh for five minutes — but the PEER may not know
   * yet, so retry to the documented deadline rather than once, and say so
   * while waiting: a silent prompt after an accepted factor reads as "nothing
   * happened".
   */
  async function retryElevated(owns: () => boolean): Promise<void> {
    const deadline = Date.now() + STEP_UP_PROPAGATION_BUDGET_MS;
    let outcome = await onElevated();
    while (outcome === 'stale' && Date.now() < deadline && owns()) {
      setWaiting(true);
      await new Promise((resolve) => setTimeout(resolve, STEP_UP_RETRY_INTERVAL_MS));
      // Checked AFTER the wait as well as in the condition: the whole point is
      // that Cancel lands while we are sleeping.
      if (!owns()) {
        break;
      }
      outcome = await onElevated();
    }
    if (!owns()) {
      return;
    }
    setWaiting(false);
    setBusy(false);
    if (outcome === 'stale') {
      // Past the deadline and still refused. Honest, and actionable: nothing was
      // lost, and pressing again is the remedy.
      setCodeError('That took longer than expected. Your check went through — try that again.');
    }
  }

  async function submitPasskey(): Promise<void> {
    // The same ownership claim the TOTP path takes — the ceremony await is one
    // more thing Cancel must be able to walk away from.
    activeAttempt.current += 1;
    const mine = activeAttempt.current;
    const owns = (): boolean => activeAttempt.current === mine;

    setCodeError(null);
    setBusy(true);
    const optionsResult = await gqlRequest('WebauthnStepUpOptions', {});
    if (!owns()) {
      return;
    }
    const options = optionsResult.ok
      ? (optionsResult.data as { webauthnStepUpOptions?: unknown }).webauthnStepUpOptions
      : undefined;
    if (!optionsResult.ok || options === undefined || options === null) {
      // A missing field is NO DATA, never data (the M11 rule).
      setBusy(false);
      setCodeError(stepUpMessageFor(optionsResult.ok ? 'UNKNOWN' : optionsResult.code));
      return;
    }
    let credential: PublicKeyCredential | null = null;
    try {
      credential = (await navigator.credentials.get({
        publicKey: decodeRequestOptions(options as Parameters<typeof decodeRequestOptions>[0]),
      })) as PublicKeyCredential | null;
    } catch (err) {
      if (!owns()) {
        return;
      }
      setBusy(false);
      setCodeError(ceremonyFailureMessage(err));
      return;
    }
    if (!owns()) {
      return;
    }
    if (!credential) {
      setBusy(false);
      setCodeError(ceremonyFailureMessage(null));
      return;
    }
    const verify = await gqlRequest('WebauthnStepUp', {
      response: encodeAuthenticationResponse(credential),
    });
    if (!owns()) {
      return;
    }
    if (!verify.ok) {
      setBusy(false);
      setCodeError(stepUpMessageFor(verify.code));
      return;
    }
    await retryElevated(owns);
  }

  return (
    <form
      className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
      noValidate
      onSubmit={(event) => {
        void submit(event);
      }}
    >
      <label className="field-label" htmlFor={`${idPrefix}-code`}>
        Confirm it’s you
      </label>
      <p id={`${idPrefix}-hint`} className="field-hint">
        {hint}
      </p>
      <input
        id={`${idPrefix}-code`}
        className="field-input mt-1 max-w-[12rem]"
        inputMode="numeric"
        autoComplete="one-time-code"
        value={code}
        aria-describedby={`${idPrefix}-hint ${idPrefix}-error`}
        onChange={(event) => {
          setCode(event.target.value);
        }}
      />
      <div id={`${idPrefix}-error`} role="status" aria-live="polite">
        {codeError !== null ? <p className="field-error">{codeError}</p> : null}
      </div>
      <div className="mt-3 flex gap-3">
        <button type="submit" className="btn btn-primary" disabled={busy}>
          {waiting ? 'Applying…' : busy ? 'Checking…' : submitLabel}
        </button>
        {hasPasskey ? (
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy}
            onClick={() => {
              void submitPasskey();
            }}
          >
            Use a passkey
          </button>
        ) : null}
        <button type="button" className="btn btn-secondary" onClick={abandon}>
          Cancel
        </button>
      </div>
    </form>
  );
}
