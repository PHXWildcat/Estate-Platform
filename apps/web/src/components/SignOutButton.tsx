'use client';

import { useRouter } from 'next/navigation';
import { useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';

/**
 * Signs the current session out: the BFF revokes it server-side, then expires
 * both httpOnly cookies. On failure the user is TOLD, not reassured — a
 * "signed out" message over a still-live session would be the worst outcome,
 * so the button only navigates away after the server confirms.
 *
 * `tone` restyles for the surface it sits on (the evergreen rail vs. cards);
 * behavior is identical.
 */
export function SignOutButton({ tone = 'surface' }: { tone?: 'surface' | 'rail' }): ReactElement {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  async function signOut(): Promise<void> {
    setBusy(true);
    setFailed(false);
    const result = await gqlRequest('Logout', {});
    if (result.ok || result.code === 'UNAUTHENTICATED') {
      // AN ALREADY-DEAD SESSION IS THE OUTCOME THIS BUTTON WANTED (M24 PR4).
      // A revoked-elsewhere or expired session answers UNAUTHENTICATED here,
      // and the failure arm below then told the owner "you are still signed
      // in" — a positive claim that a dead credential is live, made in a
      // `role="alert"`, to somebody who may have pressed this precisely
      // because they suspected the session was compromised. Fail closed means
      // DE-ESCALATE: nothing is left to revoke, so the protective outcome
      // already holds and the honest answer is the sign-in page. The failure
      // arm keeps its meaning for what it was written for — a refusal where
      // the credential SURVIVES.
      router.push('/login');
      router.refresh();
      return;
    }
    setBusy(false);
    setFailed(true);
  }

  const rail = tone === 'rail';
  return (
    <span
      className={rail ? 'inline-flex flex-col items-end gap-1' : 'inline-flex items-center gap-2'}
    >
      <button
        type="button"
        className={rail ? 'btn btn-rail px-3 py-1 text-xs' : 'btn btn-secondary'}
        disabled={busy}
        onClick={() => {
          void signOut();
        }}
      >
        {busy ? 'Signing out…' : 'Sign out'}
      </button>
      {failed ? (
        <span role="alert" className={rail ? 'text-xs text-rail-danger' : 'text-sm text-ink-muted'}>
          Sign-out didn’t complete — you are still signed in. Try again.
        </span>
      ) : null}
    </span>
  );
}
