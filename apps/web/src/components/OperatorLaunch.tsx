'use client';

import { useRef, useState, type ReactElement } from 'react';
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

  async function open(): Promise<'applied' | 'stale'> {
    setError(null);
    setBusy(true);
    try {
      const result = await gqlRequest('StartOperatorHandoff', {});
      if (!result.ok) {
        if (result.code === 'STEPUP_REQUIRED') {
          setStepUpOpen(true);
          return 'stale';
        }
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
        setError(errorCopy.OPERATOR_UNAVAILABLE);
        return 'applied';
      }
      // The action is set from the SERVER's value at submit time rather than
      // rendered into the markup, so a stale build cannot post a live code at
      // an origin the deployment has moved.
      form.action = `${operatorOrigin}/open`;
      codeRef.current.value = code;
      setStepUpOpen(false);
      form.submit();
      return 'applied';
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <h1 className="panel-title">Open the operator console</h1>
      <p className="panel-note">
        Platform operators review settlement cases on a separate, isolated address. This page hands
        you over to it; everything past this point runs on a different host with its own session.
      </p>
      <p className="panel-note">
        Opening the console does not make you an operator. Whether you may act on a case is decided
        when you try, against a list only a platform administrator can change — so if you are not on
        it, the console will open and every action will be refused.
      </p>
      <p className="panel-note">
        You will be asked to confirm your identity first. The session you arrive with lasts fifteen
        minutes, cannot be renewed, and reaches none of your own estate.
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
          onCancel={() => setStepUpOpen(false)}
        />
      ) : null}

      <FormStatus tone="error" message={error} />
    </section>
  );
}
