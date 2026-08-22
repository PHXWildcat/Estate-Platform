'use client';

import { useState, type ReactElement } from 'react';
import { AccountErasurePanel } from './AccountErasurePanel';
import { EmailVerificationPanel } from './EmailVerificationPanel';
import { SecurityPanel } from './SecurityPanel';
import { WaitingPeriodPanel } from './WaitingPeriodPanel';

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
 * THE BANNER OUTSIDE THIS TREE IS HANDLED ELSEWHERE (M24 PR1, closing the §6v
 * residual once recorded here): the app-shell `UnverifiedAddressBanner` reads
 * through the shared read cache, and the transport announces every successful
 * mutation — so completing either vouching ceremony invalidates that read and
 * the banner re-asks without waiting for a navigation. Nothing here needs to
 * tell it; that is the point of the mechanism (see graphql/read-cache.ts).
 *
 * The remount below is NOT replaced by that cache, deliberately: this panel
 * reads directly and holds form state (a half-typed code) that a completed
 * address change makes stale, and the key bump resets both in one move. Two
 * mechanisms, two jobs — the cache refreshes a fact, the remount resets a
 * ceremony.
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
      {/*
        M22 PR3. A SIBLING, not a section inside SecurityPanel: it reads a
        different service and owns a different fact, and that file is long
        enough that folding a settlement round trip into it would give the
        credentials panel a second reason to re-render. It sits last because
        it is the setting people revisit least.
      */}
      <WaitingPeriodPanel />
      {/*
        M25 PR4, and LAST on purpose. It is the only action on this page that
        cannot be undone, so it sits below every protection someone might have
        come here to adjust instead — nobody should meet it on the way to
        changing a password.
      */}
      <AccountErasurePanel />
    </>
  );
}
