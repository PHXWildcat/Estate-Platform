'use client';

import Link from 'next/link';
import { useEffect, useState, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { SignOutButton } from './SignOutButton';

type SessionState = 'loading' | 'signedOut' | 'error' | 'signedIn';

/**
 * The rail's account section. The session payload deliberately carries no
 * name or email (the BFF exposes only userId + MFA state), so this shows
 * signed-in STATE, not identity — nothing personal renders in the chrome.
 */
export function RailAccount(): ReactElement {
  const [state, setState] = useState<SessionState>('loading');

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await gqlRequest('Session', {});
      if (cancelled) return;
      if (result.ok && result.data.session !== null) {
        setState('signedIn');
      } else if (!result.ok && result.code === 'UNAUTHENTICATED') {
        setState('signedOut');
      } else if (result.ok) {
        setState('signedOut');
      } else {
        setState('error');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state === 'loading') {
    return (
      <div className="border-t border-rail-line px-2.5 pt-3" role="status">
        <p className="text-xs text-rail-muted">Checking session…</p>
      </div>
    );
  }

  if (state === 'signedIn') {
    return (
      <div className="border-t border-rail-line px-2.5 pt-3">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-2 text-[0.8125rem] font-medium text-rail-ink">
            <span aria-hidden="true" className="h-2 w-2 rounded-full bg-rail-accent" />
            Signed in
          </span>
          <SignOutButton tone="rail" />
        </div>
      </div>
    );
  }

  return (
    <div className="border-t border-rail-line px-2.5 pt-3">
      {state === 'error' ? (
        <p className="mb-2 text-xs text-rail-muted">We couldn’t check your session.</p>
      ) : null}
      <div className="flex flex-col gap-2">
        <Link className="btn btn-primary w-full" href="/login">
          Sign in
        </Link>
        <Link className="btn btn-rail w-full" href="/register">
          Create account
        </Link>
      </div>
    </div>
  );
}
