'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type SettlementCaseInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { caseDetail, caseHeadline, formatDate, isOpen, reportSourceLabel } from '../lib/settlement';
import type { StepUpRetryOutcome } from '../lib/step-up';
import { FormStatus } from './FormStatus';
import { StepUpPrompt } from './StepUpPrompt';

/**
 * THE OWNER'S KILL SWITCH (M22 PR3, docs/03 §5.1 control 3).
 *
 * The settlement backend has been complete since M7 and driven end to end by
 * the e2e suite, and until this component the only way for a living person to
 * close a fraudulent death case naming them was curl. That is why this shipped
 * BEFORE the reporting screen: filing a death report is already one tap by
 * design, and putting the permissive half in front of ten million people while
 * the protective half needed a terminal is the exact inversion of "the
 * protective action must never be harder than the permissive one".
 *
 * THE STEP-UP HERE IS NOT FRICTION, IT IS THE EVIDENCE. Signing in freshly is
 * itself the proof of life that kills the case — docs/03 §5.1 says any owner
 * sign-in with step-up MFA voids a case on the spot. So the ceremony is not a
 * tax on the protective path; it is the protective path. A bare stolen bearer
 * must not reach it, in either direction: a thief must not be able to keep a
 * fraudulent case alive OR kill a legitimate one.
 *
 * A FAILED READ IS NOT AN EMPTY ONE. "No cases" is overwhelmingly the true
 * answer and it is reassuring; a refused read that rendered as "no cases" would
 * be reassurance the server never gave. The two have separate branches.
 */

type PendingVoid = { caseId: string };

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; cases: SettlementCaseInfo[] }
  | { kind: 'error'; message: string };

export function SettlementCases(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [pending, setPending] = useState<PendingVoid | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('SettlementCases', {});
    // A MISSING FIELD IS NO DATA. A BFF that predates this query answers
    // `{"data":{}}`, and destructuring that into an empty list would tell an
    // owner they have no cases on the word of a server that was never asked.
    if (result.ok && Array.isArray(result.data.settlementCases)) {
      setState({ kind: 'ready', cases: result.data.settlementCases });
      return;
    }
    setState({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /**
   * Runs the void. Returns the StepUpPrompt contract: 'stale' while the peer
   * still answers stepup_required (the prompt polls to its deadline),
   * 'applied' once the case is closed.
   */
  const runVoid = useCallback(
    async (target: PendingVoid): Promise<StepUpRetryOutcome> => {
      setFormError(null);
      const result = await gqlRequest('VoidSettlementCase', { caseId: target.caseId });
      if (result.ok) {
        setPending(null);
        setNotice('That case is closed. Nothing about your estate was released.');
        await load();
        return 'applied';
      }
      if (result.code === 'STEPUP_REQUIRED') {
        // Either the prompt has not run yet (open it), or the elevation has
        // not propagated to settlement's introspection cache (keep waiting).
        setPending(target);
        return 'stale';
      }
      setPending(null);
      setFormError(messageFor(result.code));
      // A refused void leaves the case exactly as it was, and the list is how
      // the owner sees that — particularly on SETTLEMENT_UNAVAILABLE, where
      // nothing changed and the row must still show its kill switch.
      await load();
      return 'applied';
    },
    [load],
  );

  if (state.kind === 'loading') {
    return <p className="text-sm text-ink-muted">Checking…</p>;
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">We couldn’t check this</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">{state.message}</p>
        <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
          Try again
        </button>
      </div>
    );
  }

  const aboutMe = state.cases.filter((row) => row.aboutMe);
  const filedByMe = state.cases.filter((row) => !row.aboutMe);

  return (
    <div>
      <FormStatus tone="success" message={notice} />
      <FormStatus tone="error" message={formError} />

      <section aria-labelledby="about-me-heading" className="mb-8">
        <h2 id="about-me-heading" className="text-lg font-semibold">
          Cases about you
        </h2>
        {aboutMe.length === 0 ? (
          <p className="mt-2 max-w-prose text-sm text-ink-muted">
            Nobody has reported you as deceased. If they ever do, you’ll see it here and be able to
            close it yourself — and we’ll try to reach you on every channel we have.
          </p>
        ) : (
          <ul className="mt-4 space-y-4">
            {aboutMe.map((row) => (
              <li key={row.caseId} className="card p-6">
                <h3 className="font-medium">{caseHeadline(row)}</h3>
                <p className="mt-1 max-w-prose text-sm text-ink-muted">{caseDetail(row)}</p>
                <dl className="mt-4 grid grid-cols-1 gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="text-ink-muted">How it arrived</dt>
                    <dd>{reportSourceLabel(row.reportSource)}</dd>
                  </div>
                  <div>
                    <dt className="text-ink-muted">Opened</dt>
                    <dd>{formatDate(row.createdAt) ?? 'Recently'}</dd>
                  </div>
                  {row.waitingPeriodEnds !== null && isOpen(row) ? (
                    <div>
                      <dt className="text-ink-muted">Waiting period ends</dt>
                      <dd>{formatDate(row.waitingPeriodEnds) ?? 'Soon'}</dd>
                    </div>
                  ) : null}
                  <div>
                    <dt className="text-ink-muted">Evidence attached</dt>
                    <dd>{row.evidenceCount}</dd>
                  </div>
                </dl>
                {/*
                  ONE PROMPT AT A TIME, and it REPLACES the control it guards
                  rather than sitting beside it — the step-up rule. Rendering
                  both would leave a live "Close this case" button under an open
                  prompt for a different one.
                */}
                {pending?.caseId === row.caseId ? (
                  <div className="mt-4">
                    <StepUpPrompt
                      idPrefix={`void-${row.caseId}`}
                      hint="Confirming your identity is what closes this case — it proves you’re alive."
                      submitLabel="Confirm and close this case"
                      onElevated={() => runVoid({ caseId: row.caseId })}
                      onCancel={() => {
                        setPending(null);
                      }}
                    />
                  </div>
                ) : row.voidable ? (
                  <button
                    type="button"
                    className="btn btn-primary mt-4"
                    disabled={pending !== null}
                    onClick={() => void runVoid({ caseId: row.caseId })}
                  >
                    Close this case — I’m alive
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/*
        The same list carries cases this person REPORTED, because settlement
        selects both with one OR. They are shown apart and carry no control:
        the kill switch belongs to the subject, and Cedar refuses it to the
        reporter — offering it here would be an action the server declines.
      */}
      {filedByMe.length > 0 ? (
        <section aria-labelledby="filed-heading">
          <h2 id="filed-heading" className="text-lg font-semibold">
            Reports you’ve made
          </h2>
          <ul className="mt-4 space-y-4">
            {filedByMe.map((row) => (
              <li key={row.caseId} className="card p-6">
                <h3 className="font-medium">{caseHeadline(row)}</h3>
                <p className="mt-1 text-sm text-ink-muted">
                  Opened {formatDate(row.createdAt) ?? 'recently'} · {row.evidenceCount} piece
                  {row.evidenceCount === 1 ? '' : 's'} of evidence
                </p>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
