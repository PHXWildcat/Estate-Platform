'use client';

import { useEffect, useRef, useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { errorCopy } from '../lib/copy';
import { StepUpPrompt } from './StepUpPrompt';
import { FormStatus } from './FormStatus';

/**
 * THE ONLY PLACE IN THIS APP THAT KNOWS THE OPERATOR ORIGIN EXISTS (M21 PR3a).
 *
 * The platform operator console lives on a separate origin (docs/03 TB7), for
 * the same reasons Zone A does: its own `__Host-` cookie, its own strict CSP
 * with no inline script and enforced Trusted Types, and no framework on the
 * page an operator reads before approving a death case.
 *
 * HOW AUTHORITY CROSSES is the vault ceremony verbatim, and deliberately so —
 * one shape, reviewed once:
 *
 *   · `startOperatorHandoff` mints a single-use code, step-up gated at identity
 *     and account-audience only, so a vault or operator session cannot mint
 *     another credential.
 *   · The code goes into a HIDDEN FIELD and the browser submits a TOP-LEVEL
 *     POST to the operator origin. Not a redirect with the code in the query
 *     string, not a fragment: a form body is the only shape that keeps it out
 *     of browser history, out of the `Referer`, and out of every intermediary's
 *     access log.
 *   · The operator origin redeems it server-side and sets its own `__Host-`
 *     cookie. Nothing this app can read ever holds an operator credential.
 *
 * WHAT OPENING IT DOES NOT DO, said on the page as well as here: it does not
 * make anybody an operator. Minting is ROLE-BLIND by construction — identity
 * holds no settlement credential, there is no join between the auth and core
 * clusters, and identity has no concept of a role — so an `operator` audience
 * is a RESTRICTION on where a credential may be spent, never a claim about who
 * is holding it. Whether the caller may act on a settlement case is decided by
 * `settlement_operators`, in settlement, inside the transaction that would act
 * (M21 PR2's `OperatorGate`). This page says that in as many words, because a
 * console anyone can open is a console whose users need to know what opening it
 * bought them: nothing.
 *
 * A stolen code is worth 60 seconds and, if redeemed, a 15-minute
 * operator-audience session with no refresh token — which reaches three
 * identity routes and, until M21 PR3b, no settlement route at all.
 */

export function OperatorLaunch(): ReactElement {
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
   * operator console origin with a live code, and an in-flight refusal answering
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
      setError(errorCopy.OPERATOR_UNAVAILABLE);
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
      const result = await gqlRequest('StartOperatorHandoff', {});
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
       * where the user sees nothing — the M11 browser-only defect, which the
       * vault launcher met first. The alternative failure is worse than a blank
       * screen: a form posting `code=undefined` at the operator origin. A
       * missing field is NO DATA, never data.
       */
      const handoff = result.data.startOperatorHandoff as
        { code?: unknown; operatorOrigin?: unknown } | undefined;
      const code = typeof handoff?.code === 'string' ? handoff.code : null;
      const operatorOrigin =
        typeof handoff?.operatorOrigin === 'string' ? handoff.operatorOrigin : null;
      const form = formRef.current;
      if (code === null || operatorOrigin === null || !form || !codeRef.current) {
        setStepUpOpen(false);
        setError(errorCopy.OPERATOR_UNAVAILABLE);
        return 'applied';
      }
      // The action is set from the SERVER's value at submit time rather than
      // rendered into the markup, so a stale build cannot post a live code at
      // an origin the deployment has moved.
      form.action = `${operatorOrigin}/open`;
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
    <section className="card p-6">
      <h1 className="text-2xl font-semibold tracking-tight">Open the operator console</h1>
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        Platform operators review settlement cases on a separate, isolated address. This page hands
        you over to it; everything past this point runs on a different host with its own session.
      </p>
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        Opening the console does not make you an operator. Whether you may act on a case is decided
        when you try, against a list only a platform administrator can change — so if you are not on
        it, the console will open and every action will be refused.
      </p>
      {/*
        STATED AS A RESTRICTION, and REWRITTEN by M21 PR3b's review round.

        This is the FIRST place a user reads what an operator session is, and it
        carried "reaches none of your own estate" — an absolute PR3b made false
        and then corrected in `sessions.ts` and on the console's own screen
        while leaving this copy, the earliest one, standing. Its own test pinned
        the false sentence, so the suite was green over it.

        Four of the thirteen settlement routes reach a case through
        `assertCaseVisible`, which admits the decedent, the reporter and the
        estate's executor as well as an operator — so a console session CAN see
        a case its holder is party to. What is true is the restriction: an
        audience says where a credential may be spent, never who is spending it.
      */}
      <p className="mt-2 max-w-prose text-sm text-ink-muted">
        You will be asked to confirm your identity first. The session you arrive with lasts fifteen
        minutes and cannot be renewed. It cannot reach your assets, documents, people or vault, and
        it cannot change your account.
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
        className="btn btn-primary mt-4"
        disabled={busy}
        onClick={() => {
          // A fresh press is a fresh ceremony. Re-arming here rather than in
          // `open()` is what keeps the retry path (`onElevated`) from clearing
          // a withdrawal the user has just made.
          withdrawn.current = false;
          void open();
        }}
      >
        {busy ? 'Opening…' : 'Open the console'}
      </button>

      {stepUpOpen ? (
        <StepUpPrompt
          hint="Opening the operator console needs a fresh identity check."
          submitLabel="Open the console"
          idPrefix="operator-launch"
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
