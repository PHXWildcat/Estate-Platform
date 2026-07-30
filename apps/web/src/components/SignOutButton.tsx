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
    if (result.ok) {
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
