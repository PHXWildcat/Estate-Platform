'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import Link from 'next/link';
import { gqlRequest, type DocumentInfo, type SettlementCaseInfo } from '../graphql/client';
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

/** Which reported case has its attach form open, and what it can offer. */
type Attaching = {
  caseId: string;
  documents: DocumentInfo[] | null;
  documentId: string;
};

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; cases: SettlementCaseInfo[] }
  | { kind: 'error'; message: string };

export function SettlementCases(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [pending, setPending] = useState<PendingVoid | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [attaching, setAttaching] = useState<Attaching | null>(null);
  const [saving, setSaving] = useState(false);

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
  /**
   * Open the attach form for one reported case, and read the caller's own
   * documents to fill it. Read on OPEN rather than with the case list: most
   * visits to this page never touch it, and a list nobody uses is a request
   * nobody needed.
   */
  const openAttach = useCallback(async (caseId: string): Promise<void> => {
    setFormError(null);
    setNotice(null);
    setAttaching({ caseId, documents: null, documentId: '' });
    const result = await gqlRequest('Documents', {});
    setAttaching((current) =>
      current?.caseId === caseId
        ? {
            ...current,
            // `null` stays `null` on a failed read — the form says it could
            // not load them rather than showing an empty list, which would
            // read as "you have no documents".
            documents:
              result.ok && Array.isArray(result.data.documents)
                ? // A sealed document is Zone A ciphertext no reviewer could
                  // ever read; attaching one is evidence guaranteed to tell
                  // nobody anything.
                  result.data.documents.filter((doc) => !doc.sealed)
                : null,
          }
        : current,
    );
  }, []);

  const runAttach = useCallback(async (target: Attaching): Promise<void> => {
    const chosen = target.documents?.find((doc) => doc.documentId === target.documentId);
    if (!chosen) return;
    setSaving(true);
    setFormError(null);
    const result = await gqlRequest('AttachCaseEvidence', {
      caseId: target.caseId,
      documentId: chosen.documentId,
      // Pinned to the version that exists NOW. Evidence names a version
      // because a document can be replaced, and a reviewer must see the one
      // that was meant.
      version: chosen.currentVersion,
    });
    setSaving(false);
    if (result.ok && result.data.attachCaseEvidence) {
      const updated = result.data.attachCaseEvidence;
      setAttaching(null);
      setNotice('We’ve attached that to the case.');
      setState((current) =>
        current.kind === 'ready'
          ? {
              ...current,
              cases: current.cases.map((row) => (row.caseId === updated.caseId ? updated : row)),
            }
          : current,
      );
      return;
    }
    setFormError(result.ok ? messageFor('UNKNOWN') : messageFor(result.code));
  }, []);

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
        selects both with one OR. They are shown apart, and the ONE control
        they carry is the attach: the kill switch belongs to the subject and
        Cedar refuses it to the reporter, so offering that here would be an
        action the server declines. `evidence_add` is the one verb Cedar DOES
        grant the reporter, and M22 PR4c is where it got a caller.
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

                {attaching?.caseId === row.caseId ? (
                  <div className="mt-4">
                    {attaching.documents === null ? (
                      /* Could not read them — NOT "you have none". */
                      <p className="text-sm text-ink-muted">
                        We couldn’t load your documents just now. Please try again in a moment.
                      </p>
                    ) : attaching.documents.length === 0 ? (
                      <p className="text-sm text-ink-muted">
                        You haven’t uploaded any documents yet.{' '}
                        <Link
                          href="/documents"
                          className="font-medium text-ink underline underline-offset-4"
                        >
                          Upload one
                        </Link>{' '}
                        and you can attach it here.
                      </p>
                    ) : (
                      <>
                        {/*
                          The label names WHICH case this field belongs to. Two
                          reported cases would otherwise put two fields called
                          "Document" on one page.
                        */}
                        <label htmlFor={`attach-${row.caseId}`} className="field-label">
                          Document to attach to this report
                        </label>
                        <select
                          id={`attach-${row.caseId}`}
                          className="field-input"
                          value={attaching.documentId}
                          onChange={(event) => {
                            setAttaching({ ...attaching, documentId: event.target.value });
                          }}
                        >
                          <option value="">Choose a document…</option>
                          {attaching.documents.map((doc) => (
                            <option key={doc.documentId} value={doc.documentId}>
                              {doc.title}
                            </option>
                          ))}
                        </select>
                      </>
                    )}
                    <div className="mt-3 flex flex-wrap gap-3">
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={saving || attaching.documentId === ''}
                        onClick={() => void runAttach(attaching)}
                      >
                        {saving ? 'Attaching…' : 'Attach'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        disabled={saving}
                        onClick={() => {
                          setAttaching(null);
                        }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : isOpen(row) ? (
                  /*
                    OFFERED ONLY WHILE THE CASE IS OPEN. Settlement accepts
                    evidence in `reported` and `verifying` only and answers 409
                    otherwise, so a button on a resolved case would be an
                    action the server refuses — and `isOpen` is the same
                    predicate the owner's half already renders from.
                  */
                  <button
                    type="button"
                    className="btn btn-secondary mt-4"
                    onClick={() => void openAttach(row.caseId)}
                  >
                    Attach a document
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}
