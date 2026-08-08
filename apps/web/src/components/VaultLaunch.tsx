'use client';

import { useRef, useState, type ReactElement } from 'react';
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

  async function open(): Promise<'applied' | 'stale'> {
    setError(null);
    setBusy(true);
    try {
      const result = await gqlRequest('StartVaultHandoff', {});
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
        setError(errorCopy.VAULT_UNAVAILABLE);
        return 'applied';
      }
      // The action is set from the SERVER's value at submit time rather than
      // rendered into the markup, so a stale build cannot post a live code at
      // an origin the deployment has moved.
      form.action = `${vaultOrigin}/open`;
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
          onCancel={() => setStepUpOpen(false)}
        />
      ) : null}

      <FormStatus tone="error" message={error} />
    </section>
  );
}
