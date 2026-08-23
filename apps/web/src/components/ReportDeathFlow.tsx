'use client';

import { useCallback, useEffect, useState, type ReactElement } from 'react';
import Link from 'next/link';
import {
  gqlRequest,
  type DocumentInfo,
  type ReportableEstateInfo,
  type SettlementCaseInfo,
} from '../graphql/client';
import { messageFor } from '../lib/copy';
import { roleLabel } from '../lib/people';
import { FormStatus } from './FormStatus';

/**
 * FILING A DEATH REPORT (M22 PR4c) — the permissive half of settlement, and
 * the last of its seven routes to get a consumer.
 *
 * THE ORDER THIS SHIPPED IN IS THE POINT. The owner's kill switch went first
 * (PR3), because the protective action must never be harder than the
 * permissive one and until PR3 closing a fraudulent case about yourself
 * required a terminal. Only once that was one click did filing get a screen.
 *
 * NOT STEP-UP GATED, and the settlement controller's docstring is the argument
 * rather than an omission: filing ADDS SCRUTINY rather than authority. The
 * case locks nothing, the owner is notified on every channel we have, and they
 * close it with one ungated click. A gate here would fall on a grieving
 * contact signing in on a borrowed device, and would stop nothing a token
 * thief actually wants.
 *
 * WHAT REPLACES A GATE IS A REVIEW STEP. Not a credential and not a refusal —
 * it costs one click and turns nobody away. It exists because the consequence
 * is legible to us and not to the person clicking: somebody who is alive gets
 * told, on every channel we have, that they were reported dead. Naming whose
 * estate it is and what happens next is the honest way to make a one-tap
 * action deliberate.
 *
 * NO USER ID LIVES IN THIS COMPONENT. An estate is named by `contactId` and
 * the mutation takes the same handle; the BFF resolves it against settlement's
 * own list, so entitlement is checked against the service rather than trusted
 * from an argument this app supplies.
 */

type Screen =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'picking'; estates: ReportableEstateInfo[] }
  | { kind: 'reviewing'; estates: ReportableEstateInfo[]; estate: ReportableEstateInfo }
  | { kind: 'filed'; estate: ReportableEstateInfo; kase: SettlementCaseInfo };

/** A document this app can offer as evidence, or the reason it can offer none. */
type Attachable =
  { kind: 'loading' } | { kind: 'unavailable' } | { kind: 'ready'; documents: DocumentInfo[] };

function estateName(estate: ReportableEstateInfo): string {
  // A null name is the server saying there is no name, not a value to invent.
  return estate.ownerName ?? 'this estate';
}

export function ReportDeathFlow(): ReactElement {
  const [screen, setScreen] = useState<Screen>({ kind: 'loading' });
  const [attachable, setAttachable] = useState<Attachable>({ kind: 'loading' });
  const [documentId, setDocumentId] = useState<string>('');
  const [filing, setFiling] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const load = useCallback(async (): Promise<void> => {
    setScreen({ kind: 'loading' });
    const result = await gqlRequest('ReportableEstates', {});
    // A missing field is NO DATA. Destructuring `{"data":{}}` from a
    // version-skewed BFF would tell somebody there is nobody they can report
    // on, on the word of a server that was never asked.
    if (result.ok && Array.isArray(result.data.reportableEstates)) {
      setScreen({ kind: 'picking', estates: result.data.reportableEstates });
      return;
    }
    setScreen({
      kind: 'error',
      message: result.ok ? messageFor('UNKNOWN') : messageFor(result.code),
    });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /**
   * Documents are read when the review screen opens and never on mount: most
   * people who reach this page will read it and leave, and a list nobody is
   * going to use is a request nobody needed to make.
   */
  const loadDocuments = useCallback(async (): Promise<void> => {
    setAttachable({ kind: 'loading' });
    const result = await gqlRequest('Documents', {});
    if (result.ok && Array.isArray(result.data.documents)) {
      setAttachable({
        kind: 'ready',
        documents: result.data.documents.filter(
          // SEALED DOCUMENTS ARE EXCLUDED, and not as tidying. A sealed
          // document is Zone A: the server holds opaque ciphertext and no
          // reviewer could ever read it, so offering one would attach
          // evidence that is guaranteed to tell nobody anything.
          (doc) => !doc.sealed,
        ),
      });
      return;
    }
    // A failed read is not an empty one — the form says a certificate cannot
    // be attached RIGHT NOW rather than implying there are none.
    setAttachable({ kind: 'unavailable' });
  }, []);

  const openReview = (estate: ReportableEstateInfo, estates: ReportableEstateInfo[]): void => {
    setFormError(null);
    setDocumentId('');
    setScreen({ kind: 'reviewing', estates, estate });
    void loadDocuments();
  };

  const file = async (estate: ReportableEstateInfo): Promise<void> => {
    setFiling(true);
    setFormError(null);
    const chosen =
      attachable.kind === 'ready'
        ? attachable.documents.find((doc) => doc.documentId === documentId)
        : undefined;
    const result = await gqlRequest('ReportDeath', {
      contactId: estate.contactId,
      // BOTH OR NEITHER. A document id without its version names no document,
      // and the BFF refuses the pair when only one arrives rather than
      // guessing version 1 — which would pin evidence to a draft.
      ...(chosen ? { documentId: chosen.documentId, documentVersion: chosen.currentVersion } : {}),
    });
    setFiling(false);
    if (result.ok && result.data.reportDeath) {
      setScreen({ kind: 'filed', estate, kase: result.data.reportDeath });
      return;
    }
    setFormError(result.ok ? messageFor('UNKNOWN') : messageFor(result.code));
  };

  if (screen.kind === 'loading') {
    return <p className="text-sm text-ink-muted">Loading…</p>;
  }

  if (screen.kind === 'error') {
    return (
      <section className="card p-6">
        {/* A refused read is not "nobody" — it costs its own panel. */}
        <h2 className="text-lg font-semibold">We couldn’t check this</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">{screen.message}</p>
        <button type="button" className="btn btn-secondary mt-4" onClick={() => void load()}>
          Try again
        </button>
      </section>
    );
  }

  if (screen.kind === 'filed') {
    return (
      <section aria-live="polite" className="card p-6">
        <h2 className="text-lg font-semibold">Thank you — we’ve opened a case</h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          We’ve recorded your report about {estateName(screen.estate)} and a member of our team will
          review it. Nothing in the estate is released while that happens, and we’ll try to reach
          them on every channel we have — if they’re able to respond, the case closes and nothing
          changes.
        </p>
        <p className="mt-3 max-w-prose text-sm text-ink-muted">
          You don’t need to do anything else. You can follow this case, and attach anything further,
          from{' '}
          <Link
            href="/security/cases"
            className="font-medium text-ink underline underline-offset-4"
          >
            your settlement page
          </Link>
          .
        </p>
      </section>
    );
  }

  if (screen.kind === 'reviewing') {
    const { estate } = screen;
    return (
      <section aria-labelledby="review-heading" className="card p-6">
        <h2 id="review-heading" className="text-lg font-semibold">
          Report the death of {estateName(estate)}
        </h2>
        <p className="mt-2 max-w-prose text-sm text-ink-muted">
          Please read this before confirming. It isn’t a test of who you are — it’s what happens
          next.
        </p>

        <ul className="mt-4 max-w-prose list-disc space-y-2 pl-5 text-sm text-ink-muted">
          <li>
            We’ll try to reach {estateName(estate)} on every channel we have, to tell them a report
            has been made.
          </li>
          <li>
            Nothing in their estate is unlocked or released. A member of our team reviews every
            report, and there is a waiting period after that.
          </li>
          <li>
            If they’re alive, they can close the case themselves at any point, immediately — and
            nothing will have changed.
          </li>
          <li>Your name is recorded on the case as the person who reported it.</li>
        </ul>

        <div className="mt-6">
          <h3 className="text-sm font-medium">Death certificate (optional)</h3>
          <p className="mb-2 mt-1 max-w-prose text-sm text-ink-muted">
            If you’ve uploaded one, you can attach it now. It isn’t required — you can add one
            later, and a report without one is reviewed just the same.
          </p>
          {attachable.kind === 'loading' ? (
            <p className="text-sm text-ink-muted">Checking your documents…</p>
          ) : null}
          {attachable.kind === 'unavailable' ? (
            /* Not "you have none": we could not read the list. */
            <p className="text-sm text-ink-muted">
              We couldn’t load your documents just now, so you can’t attach one here. You can still
              file this report and add a certificate afterwards.
            </p>
          ) : null}
          {attachable.kind === 'ready' ? (
            attachable.documents.length === 0 ? (
              <p className="text-sm text-ink-muted">
                You haven’t uploaded any documents yet.{' '}
                <Link
                  href="/documents"
                  className="font-medium text-ink underline underline-offset-4"
                >
                  You can upload one
                </Link>{' '}
                and come back, or file this report now without it.
              </p>
            ) : (
              <>
                <label htmlFor="evidence-document" className="field-label">
                  Document to attach
                </label>
                <select
                  id="evidence-document"
                  className="field-input"
                  value={documentId}
                  onChange={(event) => {
                    setDocumentId(event.target.value);
                  }}
                >
                  <option value="">Don’t attach anything</option>
                  {attachable.documents.map((doc) => (
                    <option key={doc.documentId} value={doc.documentId}>
                      {doc.title}
                    </option>
                  ))}
                </select>
              </>
            )
          ) : null}
        </div>

        <FormStatus tone="error" message={formError} />

        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            className="btn btn-primary"
            disabled={filing}
            onClick={() => void file(estate)}
          >
            {filing ? 'Filing…' : 'Confirm and report'}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={filing}
            onClick={() => {
              setFormError(null);
              setScreen({ kind: 'picking', estates: screen.estates });
            }}
          >
            Go back
          </button>
        </div>
      </section>
    );
  }

  return (
    <section aria-labelledby="picker-heading" className="card p-6">
      <h2 id="picker-heading" className="text-lg font-semibold">
        Whose death are you reporting?
      </h2>
      <p className="mb-4 mt-1 max-w-prose text-sm text-ink-muted">
        You can report on the estates that name you. If someone is missing from this list, they
        haven’t linked you to their plan — ask their family to contact us instead.
      </p>

      {screen.estates.length === 0 ? (
        <p className="text-sm text-ink-muted">
          Nobody has linked you to their plan, so there’s no estate you can report on here. If you
          need to tell us about a death, contact us and we’ll help.
        </p>
      ) : (
        <ul className="space-y-3">
          {screen.estates.map((estate) => (
            <li
              key={estate.contactId}
              className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3 first:border-t-0 first:pt-0"
            >
              <span>
                <span className="font-medium">
                  {estate.ownerName ?? (
                    <span className="text-ink-muted">Someone who hasn’t added their name yet</span>
                  )}
                </span>
                <span className="ml-2 text-sm text-ink-muted">
                  {estate.roles.length === 0
                    ? 'Linked, with no role yet'
                    : estate.roles.map(roleLabel).join(', ')}
                </span>
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  openReview(estate, screen.estates);
                }}
              >
                Report a death
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
