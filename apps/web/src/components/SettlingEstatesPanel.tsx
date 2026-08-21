'use client';

import { useEffect, useState, type ReactElement } from 'react';
import Link from 'next/link';
import { gqlRequest, type ExecutorCaseInfo } from '../graphql/client';

/**
 * THE EXECUTOR'S FRONT DOOR (M23 PR2), on the overview page.
 *
 * SELF-HIDING, and that is the whole reason it can live here. Virtually
 * everybody is settling nothing, and a permanent "Estates you're settling"
 * heading on ten million home pages is the memento mori that kept
 * `/security/cases` out of the nav rail. This panel renders NOTHING at all
 * until settlement returns a case — including on a failed read, which is the
 * one place in the app that rule bends, and it bends because the alternative
 * is worse: an error card about a feature the reader has never used and cannot
 * act on, on the first screen after sign-in.
 *
 * WHY THE OVERVIEW AND NOT THE NAV. An executor has been asked to settle
 * somebody's estate, usually days after a death, and the one thing they should
 * not have to do is hunt. The rail is static and cannot grow a conditional
 * entry, so the surface is unlisted and reached from the page every session
 * starts on.
 *
 * WHAT IT DOES NOT SAY. Not "you have access" — a verified case is the right
 * to ASK for access, one stage at a time, and each stage is an operator's
 * decision. Promising access on a list that cannot see the ladder would be the
 * surface offering what the server will refuse.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; cases: ExecutorCaseInfo[] }
  /** No panel, no error card. See the docstring — the read failed silently. */
  | { kind: 'silent' };

export function estateName(kase: { ownerName: string | null }): string {
  // A null name is the server saying this owner never filled in a profile, not
  // a value to invent. Never "Unknown".
  return kase.ownerName ?? 'An estate';
}

export function SettlingEstatesPanel(): ReactElement | null {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  useEffect(() => {
    let live = true;
    void (async (): Promise<void> => {
      const result = await gqlRequest('ExecutorCases', {});
      if (!live) return;
      // A missing field is NO DATA. Destructuring `{"data":{}}` from a
      // version-skewed BFF would render an empty list as a real answer.
      if (result.ok && Array.isArray(result.data.executorCases)) {
        setState({ kind: 'ready', cases: result.data.executorCases });
        return;
      }
      setState({ kind: 'silent' });
    })();
    return () => {
      live = false;
    };
  }, []);

  if (state.kind !== 'ready' || state.cases.length === 0) {
    return null;
  }

  return (
    <section aria-labelledby="settling-heading" className="card p-6">
      <h2 id="settling-heading" className="text-lg font-semibold">
        {state.cases.length === 1 ? 'An estate you’re settling' : 'Estates you’re settling'}
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        You’ve been named executor and the death has been verified. Access to what you need is
        released in stages, and each one is reviewed by our team before it opens.
      </p>
      <ul className="space-y-3">
        {state.cases.map((kase) => (
          <li
            key={kase.caseId}
            className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3 first:border-t-0 first:pt-0"
          >
            <span>
              <span className="font-medium">
                {kase.ownerName ?? (
                  <span className="text-ink-muted">An estate with no name on file</span>
                )}
              </span>
            </span>
            <Link href={`/estates/${kase.caseId}`} className="btn btn-secondary">
              Open
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
