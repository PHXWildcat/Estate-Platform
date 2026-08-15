'use client';

import { useState, type ReactElement } from 'react';
import { EmailVerificationPanel } from './EmailVerificationPanel';
import { SecurityPanel } from './SecurityPanel';

/**
 * The /security page's client half, and it exists for exactly one reason: TWO
 * PANELS ON THIS PAGE DESCRIBE THE SAME FACT (M20 PR2).
 *
 * `EmailVerificationPanel` reads whether the stored address is proved.
 * `SecurityPanel` can now MOVE that address — and completing a change vouches
 * for the new one in the same statement that switches it, because entering the
 * mailed code proved the mailbox seconds earlier. So a previously-unverified
 * owner finishes the ceremony and, without this, goes on reading "your email
 * address hasn't been confirmed yet" a few centimetres above the sentence
 * saying it has: one page contradicting itself about a control, which is the
 * shape M19 PR2 found in the trust card and M20 PR1 found in the session card.
 *
 * THE FIX IS A RE-READ, NOT A SHARED BOOLEAN. Bumping the key re-mounts the
 * panel, which re-asks the server; the alternative — passing a verified flag
 * down — would make this component the authority on a fact identity owns, which
 * is what the ConsentControls rule forbids ("render the server's answer, never
 * an optimistic local one"). It costs one GraphQL round trip, and only on the
 * rare occasion an address actually changes.
 *
 * RESIDUAL, recorded in docs/03 §6n rather than papered over: the app-shell
 * `UnverifiedAddressBanner` is outside this tree and re-reads only on
 * navigation, so it can keep asking for a confirmation that has just happened
 * until the user moves to another page. That is the harmless direction — it
 * nags about something already done rather than hiding a real gap — and closing
 * it properly means a shared client cache this app does not have.
 */
export function AccountSecurity(): ReactElement {
  // Not a counter of anything meaningful — only a remount token. Starts at 0
  // and only ever increases, so React can never reuse a stale instance.
  const [addressVersion, setAddressVersion] = useState(0);

  return (
    <>
      <section className="mb-8">
        <h2 className="text-lg font-medium tracking-tight">Email address</h2>
        <p className="mb-3 mt-1 max-w-prose text-sm text-ink-muted">
          Confirming your address is what lets us reach you when someone tries to open your estate —
          and some protections stay switched off until you do.
        </p>
        <EmailVerificationPanel key={addressVersion} />
      </section>
      <SecurityPanel
        onAddressChanged={() => {
          setAddressVersion((version) => version + 1);
        }}
      />
    </>
  );
}
