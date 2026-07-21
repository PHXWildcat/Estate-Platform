'use client';

import Link from 'next/link';
import { useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type SessionInfo } from '../graphql/client';

type SessionState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'signedIn'; session: SessionInfo };

export function SessionCard(): ReactElement {
  const [state, setState] = useState<SessionState>({ kind: 'loading' });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const result = await gqlRequest('Session', {});
      if (cancelled) return;
      if (result.ok && result.data.session !== null) {
        setState({ kind: 'signedIn', session: result.data.session });
      } else if (!result.ok && result.code === 'UNAUTHENTICATED') {
        setState({ kind: 'signedOut' });
      } else if (result.ok) {
        setState({ kind: 'signedOut' });
      } else {
        setState({ kind: 'error' });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Checking your session…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t check your session right now. You can still{' '}
          <Link className="text-accent underline underline-offset-2" href="/login">
            sign in
          </Link>
          .
        </p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Get started</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Create an account to begin organizing your estate, or sign in to pick up where you left
          off.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/register">
            Create account
          </Link>
          <Link className="btn btn-secondary" href="/login">
            Sign in
          </Link>
        </div>
      </div>
    );
  }

  const { session } = state;
  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold">Signed in</h2>
      <dl className="mt-4 space-y-3 text-sm">
        <div>
          <dt className="font-semibold">User ID</dt>
          <dd className="mt-1 font-mono text-xs text-ink-muted">{session.userId}</dd>
        </div>
        <div>
          <dt className="font-semibold">Security level</dt>
          <dd className="mt-1 flex flex-wrap gap-2">
            {session.mfaLevel === 'none' ? (
              <span className="chip chip-warn">MFA not enrolled</span>
            ) : (
              <span className="chip chip-success">MFA enrolled</span>
            )}
            {session.stepUpFresh ? (
              <span className="chip chip-success">Step-up fresh</span>
            ) : (
              <span className="chip">Step-up not fresh</span>
            )}
          </dd>
        </div>
      </dl>
      <Link className="btn btn-secondary mt-5" href="/security">
        Manage security
      </Link>
    </div>
  );
}
