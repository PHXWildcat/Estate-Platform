'use client';

import { useEffect, useRef, useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { errorCopy } from '../lib/copy';
import { StepUpPrompt } from './StepUpPrompt';
import { FormStatus } from './FormStatus';

/**
 * THE ONLY PLACE IN THIS APP THAT KNOWS THE VAULT ORIGIN EXISTS (M15).
 *
 * Zone A lives on a separate origin (docs/03 TB6), and the app shell's nav has
 * committed since the Evergreen-rail redesign to sending users OUTBOUND rather
 * than rendering a vault route in-app. This page is that outbound step, and it
 * is deliberately an interstitial rather than a bare link: the handoff is a
 * ceremony worth explaining before it happens, and a user who is about to be
 * asked for a vault password should know why the address bar is about to
 * change.
 *
 * HOW AUTHORITY CROSSES, and why it looks like this:
 *
 *   · `startVaultHandoff` mints a single-use code, step-up gated at identity.
 *   · The code goes into a HIDDEN FIELD and the browser submits a TOP-LEVEL
 *     POST to the vault origin. Not a redirect with the code in the query
 *     string, not a fragment: a form body is the only shape that keeps it out
 *     of browser history, out of the `Referer`, and out of every intermediary's
 *     access log — the same reasoning that moved M12's document search off the
 *     query string.
 *   · The vault origin redeems it server-side and sets its own `__Host-`
 *     cookie. Nothing this app can read ever holds a vault credential.
 *
 * A stolen code is worth 60 seconds and, if redeemed, a 15-minute
 * vault-audience session with no refresh token — which still decrypts nothing
 * without the vault password and the Secret Key.
 */

export function VaultLaunch(): ReactElement {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  /*
   * CONSENT WITHDRAWN, which `StepUpPrompt`'s ownership counter cannot express
   * from where it sits. That counter is checked AFTER `onElevated()` resolves —
   * and this component's whole side effect (mint the code, fill the field, set
   * the action, navigate) happens INSIDE that call, so the counter can only
   * ever discard the return value of a handoff that has already left. Pressing
   * Cancel while the retry's mint is in flight landed the browser on the
   * vault origin with a live code, and an in-flight refusal answering
   * STEPUP_REQUIRED re-opened the prompt that had just been dismissed.
   *
   * The withdrawal therefore has to be legible HERE, in the one window between
   * the response arriving and anything being done with it.
   */
  const withdrawn = useRef(false);
  const violationRef = useRef<((event: SecurityPolicyViolationEvent) => void) | null>(null);

  function detachViolationWatch(): void {
    if (!violationRef.current) return;
    document.removeEventListener('securitypolicyviolation', violationRef.current);
    violationRef.current = null;
  }

  /*
   * Armed immediately before every submit and left attached afterwards, because
   * the violation it watches for is dispatched ASYNCHRONOUSLY (see `open()`).
   * Re-arming replaces the previous listener rather than stacking a second, and
   * the effect below detaches it if this component goes away first — those two
   * are the only ways it stops listening, and both are exercised.
   *
   * There is deliberately NO `withdrawn` check here. It would never fire: the
   * prompt is dismissed before the submit, so a cancel can only land while the
   * mint is in flight, and that path returns before anything is submitted and
   * before this is ever armed. A guard no test can reach is a guard nobody has
   * read.
   */
  function watchForBlockedSubmit(): void {
    detachViolationWatch();
    const onViolation = (event: SecurityPolicyViolationEvent): void => {
      if (event.violatedDirective !== 'form-action') return;
      detachViolationWatch();
      setError(errorCopy.VAULT_UNAVAILABLE);
    };
    violationRef.current = onViolation;
    document.addEventListener('securitypolicyviolation', onViolation);
  }

  // The listener outlives the submit by design, so unmounting must take it
  // with it — otherwise a violation from an abandoned attempt would call
  // `setError` on a component that is gone.
  useEffect(() => detachViolationWatch, []);

  async function open(): Promise<'applied' | 'stale'> {
    setError(null);
    setBusy(true);
    try {
      const result = await gqlRequest('StartVaultHandoff', {});
      if (withdrawn.current) {
        // Nothing is applied and nothing is re-opened. Returning 'applied'
        // rather than 'stale' also stops the retry loop asking again.
        return 'applied';
      }
      if (!result.ok) {
        if (result.code === 'STEPUP_REQUIRED') {
          setStepUpOpen(true);
          return 'stale';
        }
        // A refusal a fresh identity check cannot fix must not leave a live
        // prompt on screen inviting one — the M20 PR5 finding, which reached
        // `SecurityPanel` and not the two launchers.
        setStepUpOpen(false);
        setError(errorCopy[result.code]);
        return 'applied';
      }
      /*
       * SHAPE-CHECK BEFORE DESTRUCTURING. A BFF that predates this mutation
       * answers `{"data":{}}`, and reading `.code` off `undefined` would throw
       * where the user sees nothing — the M11 browser-only defect, which is the
       * third milestone running to meet it. Worse here than there: the
       * alternative failure is a form posting `code=undefined` at the vault
       * origin. A missing field is NO DATA, never data.
       */
      const handoff = result.data.startVaultHandoff as
        { code?: unknown; vaultOrigin?: unknown } | undefined;
      const code = typeof handoff?.code === 'string' ? handoff.code : null;
      const vaultOrigin = typeof handoff?.vaultOrigin === 'string' ? handoff.vaultOrigin : null;
      const form = formRef.current;
      if (code === null || vaultOrigin === null || !form || !codeRef.current) {
        setStepUpOpen(false);
        setError(errorCopy.VAULT_UNAVAILABLE);
        return 'applied';
      }
      // The action is set from the SERVER's value at submit time rather than
      // rendered into the markup, so a stale build cannot post a live code at
      // an origin the deployment has moved.
      form.action = `${vaultOrigin}/open`;
      codeRef.current.value = code;
      setStepUpOpen(false);

      /*
       * A BLOCKED SUBMIT IS SILENT, and this page has a live single-use code in
       * the DOM at this exact moment. `form-action` is baked into the app's CSP
       * at BUILD time while the BFF serves this origin at REQUEST time, and
       * nothing outside the compose stack forces the two to agree — so a
       * deployment that moves the origin without rebuilding the image gets a
       * POST the browser refuses, no exception, no rejected promise, and a
       * button that simply goes back to idle. Twice already this repo has been
       * bitten by a build-arg-versus-runtime split; the difference here is that
       * the failure leaves a credential behind.
       *
       * THE VIOLATION EVENT IS ASYNCHRONOUS, which the first version of this
       * code got wrong and asserted the opposite of. It listened, submitted,
       * removed the listener in a `finally` and read the flag — so the flag was
       * read a task before the event could set it and the refusal branch was
       * DEAD CODE. Measured in Chrome against `form-action 'none'`: the submit
       * is refused (the URL does not change), the event does arrive, and the
       * synchronous read is `false` in both the blocked and the allowed case,
       * i.e. it carried no information at all. The repo's own jsdom double hid
       * it by dispatching synchronously — a double more generous than the
       * platform.
       *
       * So the listener OUTLIVES the call. On the success path the navigation
       * discards this document and the listener with it; on the path where it
       * does not, the violation lands a moment later and is reported then.
       * BEST-EFFORT, and worth saying plainly: this reports a refusal the
       * browser chose to tell us about. The guarantee on this path is the
       * unconditional clear below, not the message.
       */
      watchForBlockedSubmit();
      try {
        form.submit();
      } finally {
        /*
         * CLEARED WHATEVER HAPPENED. On the normal path the navigation discards
         * this document and the clear is redundant; on every path where it does
         * not, the code would otherwise sit readable in the DOM for as long as
         * the page lives. Script on THIS origin cannot mint a handoff — minting
         * is step-up gated — but it can read one out of a field, and this origin
         * is the weaker of the two by design (its `script-src` is deliberately
         * not locked down, Next's bootstrap needing nonces). Submission
         * serialises the body synchronously, so clearing here cannot race it.
         */
        codeRef.current.value = '';
      }
      return 'applied';
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h1 className="panel-title">Open your vault</h1>
      <p className="panel-note">
        Your vault lives on a separate, isolated address. Passwords, recovery codes and other
        secrets there are encrypted on your device — Estate stores only the encrypted result and
        cannot read them, even under a court order.
      </p>
      <p className="panel-note">
        You will be asked to confirm your identity before the vault opens, and again for your vault
        password once you arrive. Estate never learns either one.
      </p>

      {/*
        The form carries no visible input and never navigates on its own. Its
        `action` is assigned in `open()` from the value the BFF returned; the
        `code` field is filled the moment before submit and lives only as long
        as this page does.
      */}
      <form ref={formRef} method="POST" hidden>
        <input ref={codeRef} type="hidden" name="code" />
      </form>

      <button
        type="button"
        className="button-primary"
        disabled={busy}
        onClick={() => {
          // A fresh press is a fresh ceremony. Re-arming here rather than in
          // `open()` is what keeps the retry path (`onElevated`) from clearing
          // a withdrawal the user has just made.
          withdrawn.current = false;
          void open();
        }}
      >
        {busy ? 'Opening…' : 'Open the vault'}
      </button>

      {stepUpOpen ? (
        <StepUpPrompt
          hint="Opening the vault needs a fresh identity check."
          submitLabel="Open the vault"
          idPrefix="vault-launch"
          onElevated={open}
          onCancel={() => {
            withdrawn.current = true;
            setStepUpOpen(false);
          }}
        />
      ) : null}

      <FormStatus tone="error" message={error} />
    </section>
  );
}
