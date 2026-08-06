'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import {
  gqlRequest,
  type DocumentContentInfo,
  type DocumentDetailInfo,
  type DocumentVersionInfo,
} from '../graphql/client';
import { messageFor, stepUpMessageFor } from '../lib/copy';
import { validateTotpCode } from '../lib/validation';
import {
  documentKindLabel,
  documentSourceLabel,
  executionStatusLabel,
  executionStatusMeaning,
  executionStatusTone,
  formatBytes,
  formatDateTime,
  transitionLabel,
} from '../lib/documents';
import { DocumentViewer } from './DocumentViewer';

/**
 * One document: what it is, what state it is in, and its version history (M12).
 *
 * READING A VERSION IS A DELIBERATE ACT, and the code says so by structure
 * rather than by comment. The panel loads metadata and versions on mount, and
 * content ONLY when someone presses Read on a specific version — because each
 * such call is an audited decrypt downstream, appearing on the user's own audit
 * trail and consuming a KMS operation. There is no prefetch, no "open the
 * latest automatically", and no cache that would make a second read look free:
 * pressing Read again asks again, which is the honest behaviour when the event
 * is the record of who looked at what.
 *
 * A CRYPTO-SHREDDED VERSION SAYS SO PERMANENTLY. `CONTENT_ERASED` is the one
 * failure here with no retry offered — the key was destroyed on purpose, and a
 * "try again" affordance would have someone press it forever.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'notFound' }
  | { kind: 'error' }
  | { kind: 'ready'; document: DocumentDetailInfo; versions: DocumentVersionInfo[] };

type ContentState =
  | { kind: 'idle' }
  | { kind: 'loading'; version: number }
  | { kind: 'failed'; version: number; message: string }
  | { kind: 'ready'; content: DocumentContentInfo };

export interface DocumentDetailPanelProps {
  readonly documentId: string;
}

export function DocumentDetailPanel({ documentId }: DocumentDetailPanelProps): ReactElement {
  const router = useRouter();
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [content, setContent] = useState<ContentState>({ kind: 'idle' });
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [executedAt, setExecutedAt] = useState('');
  /** True once the server has asked for a fresh identity check to delete. */
  const [stepUpNeeded, setStepUpNeeded] = useState(false);
  const [code, setCode] = useState('');
  const [codeError, setCodeError] = useState<string | null>(null);
  const [stepUpBusy, setStepUpBusy] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    const [document, versions] = await Promise.all([
      gqlRequest('Document', { documentId }),
      gqlRequest('DocumentVersions', { documentId }),
    ]);
    if (document.ok && versions.ok) {
      /*
       * A RESPONSE MISSING ITS FIELDS IS NOT DATA (the M11 rule), and
       * `allowedTransitions` is checked as carefully as the rest — this page
       * dereferenced it before the check existed, and a version skew
       * white-screened it, which is the third time that shape has appeared.
       *
       * Treating a missing ladder as an EMPTY one would be worse than the
       * crash: an empty ladder is a real answer the service gives when it
       * cannot resolve the formalities from a verified template, so a skew
       * would be indistinguishable from that fail-closed state. "We couldn't
       * load this" is the only honest reading of a payload we do not
       * understand.
       */
      if (
        typeof document.data.document?.documentId === 'string' &&
        Array.isArray(document.data.document.allowedTransitions) &&
        Array.isArray(versions.data.documentVersions)
      ) {
        setState({
          kind: 'ready',
          document: document.data.document,
          versions: versions.data.documentVersions,
        });
        return;
      }
      setState({ kind: 'error' });
      return;
    }
    const code = !document.ok ? document.code : !versions.ok ? versions.code : 'UNKNOWN';
    if (code === 'UNAUTHENTICATED') {
      setState({ kind: 'signedOut' });
      return;
    }
    setState(code === 'NOT_FOUND' ? { kind: 'notFound' } : { kind: 'error' });
  }, [documentId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function read(version: number): Promise<void> {
    setContent({ kind: 'loading', version });
    const result = await gqlRequest('DocumentContent', { documentId, version });
    if (!result.ok) {
      setContent({ kind: 'failed', version, message: messageFor(result.code) });
      return;
    }
    if (typeof result.data.documentContent?.content !== 'string') {
      setContent({ kind: 'failed', version, message: messageFor('UNKNOWN') });
      return;
    }
    setContent({ kind: 'ready', content: result.data.documentContent });
  }

  /**
   * Attest one rung. `executedAt` accompanies EXACTLY the `executed`
   * attestation — the service refuses the pairing either way round, and the
   * form reveals the date field only for that step so the rule is visible
   * rather than discovered.
   */
  async function attest(status: string): Promise<void> {
    setActionError(null);
    if (status === 'executed' && executedAt.length === 0) {
      setActionError('Enter the date it was signed before recording it as executed.');
      return;
    }
    setBusy(true);
    const result = await gqlRequest('SetDocumentStatus', {
      documentId,
      status,
      ...(status === 'executed' ? { executedAt } : {}),
    });
    if (!result.ok) {
      setBusy(false);
      setActionError(messageFor(result.code));
      return;
    }
    /*
     * USE THE LADDER THE TRANSITION RETURNED. The service sends the new ladder
     * with the answer precisely so a client does not have to re-read to learn
     * it — and the first version of this handler re-read anyway, AND cleared
     * `busy` before awaiting, so the page rendered the PRE-transition rungs,
     * enabled, until the round trip landed. Three places claimed the opposite
     * property (CLAUDE.md, docs/04, and the service's own comment), which is
     * how the M12 review found it.
     *
     * Version history is untouched by a status change, so there is nothing
     * else to re-read.
     */
    const updated = result.data.setDocumentStatus;
    if (
      typeof updated?.executionStatus !== 'string' ||
      !Array.isArray(updated.allowedTransitions)
    ) {
      // A response we do not understand is not data. The write landed, so
      // re-read rather than guessing at the new state.
      setBusy(false);
      setExecutedAt('');
      await load();
      return;
    }
    setState((previous) =>
      previous.kind === 'ready'
        ? {
            ...previous,
            document: {
              ...previous.document,
              executionStatus: updated.executionStatus,
              executedAt: updated.executedAt,
              allowedTransitions: updated.allowedTransitions,
            },
          }
        : previous,
    );
    setExecutedAt('');
    setBusy(false);
  }

  async function remove(): Promise<void> {
    setActionError(null);
    setBusy(true);
    const result = await gqlRequest('DeleteDocument', { documentId });
    setBusy(false);
    if (result.ok) {
      setStepUpNeeded(false);
      router.push('/documents');
      return;
    }
    if (result.code === 'STEPUP_REQUIRED') {
      setStepUpNeeded(true);
      return;
    }
    // LEGAL_HOLD lands here with its own sentence: it is the one refusal on
    // this page that authenticating harder cannot resolve, so it must not lead
    // the user to a code prompt.
    setActionError(messageFor(result.code));
  }

  async function submitStepUp(event: FormEvent): Promise<void> {
    event.preventDefault();
    const validation = validateTotpCode(code);
    setCodeError(validation);
    if (validation !== null) return;
    setStepUpBusy(true);
    const stepUp = await gqlRequest('StepUp', { code });
    setStepUpBusy(false);
    if (!stepUp.ok) {
      setCodeError(stepUpMessageFor(stepUp.code));
      return;
    }
    setCode('');
    await remove();
  }

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading this document…</p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">Documents belong to your account.</p>
        <Link className="btn btn-primary mt-4" href="/login">
          Sign in
        </Link>
      </div>
    );
  }

  if (state.kind === 'notFound') {
    return (
      <div className="card p-6" role="status">
        {/* Uniform: it must not distinguish "no such document" from "not yours". */}
        <p className="text-sm text-ink-muted">{messageFor('NOT_FOUND')}</p>
        <Link className="btn btn-secondary mt-4" href="/documents">
          Back to documents
        </Link>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load this document. Please try again in a moment.
        </p>
      </div>
    );
  }

  const { document, versions } = state;
  // Regeneration is refused downstream once signing starts, and only a document
  // generated from a template can be re-rendered at all. Offering the action
  // where the server would refuse it is how a UI teaches people to distrust it.
  const revisable =
    document.source === 'generated' &&
    (document.executionStatus === 'draft' || document.executionStatus === 'generated');

  return (
    <div className="space-y-4">
      <section aria-labelledby="document-heading" className="card p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 max-w-prose flex-1">
            <h2 id="document-heading" className="text-base font-semibold">
              {document.title}
            </h2>
            <p className="mt-1 text-[0.8125rem] text-ink-muted">
              {documentKindLabel(document.docType)} · {documentSourceLabel(document.source)} ·
              version {document.currentVersion}
            </p>
            <p className="mt-1 text-[0.8125rem] text-ink-muted">
              {executionStatusMeaning(document.executionStatus)}
              {document.executedAt !== null ? ` Executed ${document.executedAt}.` : ''}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            {document.legalHold ? <span className="chip chip-warn">Legal hold</span> : null}
            {document.sealed ? <span className="chip">Sealed</span> : null}
            <span className={executionStatusTone(document.executionStatus)}>
              {executionStatusLabel(document.executionStatus)}
            </span>
          </div>
        </div>

        {document.legalHold ? (
          <p className="mt-3 max-w-prose text-[0.8125rem] text-ink-muted">
            This document is preserved as part of an estate matter and cannot be deleted while that
            is in place.
          </p>
        ) : null}

        {revisable ? (
          <Link
            className="btn btn-secondary mt-4"
            href={`/documents/${document.documentId}/revise`}
          >
            Create a new version
          </Link>
        ) : null}
      </section>

      <section aria-labelledby="status-heading" className="card p-5 sm:p-6">
        <h2 id="status-heading" className="text-base font-semibold">
          Record what has happened
        </h2>
        {/*
          THE CAPTION HAS TO MATCH WHERE THE LADDER CAME FROM. For a generated
          document the steps are the reviewed template's own requirements for
          its state. For an UPLOAD there is no template at all — `template_id`
          is null and the service applies a platform default — so claiming
          template authority there would be a statement about the law that
          nothing behind it supports, on a surface where the upload form itself
          offers instrument kinds like `will`. (M12 review.)
        */}
        <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
          {document.source === 'generated'
            ? 'The platform records the steps you have taken in the real world; it does not witness them. The steps below are the ones this document’s own template requires for its state — no more, and none of them skippable.'
            : 'The platform records the steps you have taken in the real world; it does not witness them. This document was uploaded rather than generated here, so we have no state-specific template behind it — these are general steps, and they are not a statement of what your state requires.'}
        </p>

        {document.allowedTransitions.length === 0 ? (
          <p className="mt-3 max-w-prose text-[0.8125rem] text-ink-muted" role="status">
            {document.executionStatus === 'revoked' || document.executionStatus === 'superseded'
              ? 'This document is finished — there is nothing further to record.'
              : 'We can’t confirm the signing steps this document needs right now, so we’re not offering any. Nothing is lost; please try again later.'}
          </p>
        ) : (
          <>
            <div className="mt-3 flex flex-wrap gap-3">
              {document.allowedTransitions.map((status) => (
                <button
                  key={status}
                  type="button"
                  className="btn btn-secondary"
                  disabled={busy}
                  onClick={() => {
                    void attest(status);
                  }}
                >
                  {transitionLabel(status)}
                </button>
              ))}
            </div>
            {document.allowedTransitions.includes('executed') ? (
              <div className="mt-3 max-w-[16rem]">
                <label className="field-label" htmlFor="executed-at">
                  Date signed
                </label>
                <input
                  id="executed-at"
                  className="field-input"
                  type="date"
                  value={executedAt}
                  aria-describedby="executed-at-hint"
                  onChange={(event) => {
                    setExecutedAt(event.target.value);
                  }}
                />
                <p id="executed-at-hint" className="field-hint">
                  Required to record it as executed, and only for that step.
                </p>
              </div>
            ) : null}
          </>
        )}

        <div className="mt-4 border-t border-line pt-4">
          {/*
           * A HELD DOCUMENT IS NOT OFFERED FOR DELETION AT ALL.
           *
           * Found by driving the real app: the service runs its step-up guard
           * at the controller and checks the legal hold inside the handler, so
           * a stale session gets `stepup_required` FIRST and the hold only
           * after. The page faithfully rendered that — and walked someone
           * through finding their authenticator to be told, correctly, that the
           * document cannot be deleted anyway. The server ordering is fine
           * (defence in depth); offering the action was not. The same rule the
           * revise link follows: never offer what the server would refuse.
           */}
          {document.legalHold ? (
            <p className="max-w-prose text-[0.8125rem] text-ink-muted" role="status">
              {messageFor('LEGAL_HOLD')} It stays in your list, and everything else on this page
              still works.
            </p>
          ) : (
            <>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy}
                onClick={() => {
                  void remove();
                }}
              >
                Delete this document
              </button>
              <p className="mt-2 max-w-prose text-[0.8125rem] text-ink-muted">
                Deleting removes it from your list and needs a fresh identity check. The encrypted
                copy and its history are kept until they are erased for good, which is a separate
                act.
              </p>
            </>
          )}
        </div>

        {stepUpNeeded ? (
          <form
            className="mt-4 rounded-[var(--radius-card)] border border-line p-4"
            noValidate
            onSubmit={(event) => {
              void submitStepUp(event);
            }}
          >
            <label className="field-label" htmlFor="delete-stepup-code">
              Confirm it’s you
            </label>
            <p id="delete-stepup-hint" className="field-hint">
              Deleting a document needs a fresh check. Enter the six-digit code from your
              authenticator.
            </p>
            <input
              id="delete-stepup-code"
              className="field-input mt-1 max-w-[12rem]"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              aria-describedby="delete-stepup-hint delete-stepup-error"
              onChange={(event) => {
                setCode(event.target.value);
              }}
            />
            <div id="delete-stepup-error" role="status" aria-live="polite">
              {codeError !== null ? <p className="field-error">{codeError}</p> : null}
            </div>
            <div className="mt-3 flex gap-3">
              <button type="submit" className="btn btn-primary" disabled={stepUpBusy}>
                {stepUpBusy ? 'Checking…' : 'Confirm and delete'}
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setStepUpNeeded(false);
                  setCode('');
                  setCodeError(null);
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        ) : null}

        <div role="status" aria-live="polite">
          {actionError !== null ? <p className="mt-3 text-sm text-danger">{actionError}</p> : null}
        </div>
      </section>

      <section aria-labelledby="versions-heading" className="card p-5 sm:p-6">
        <h2 id="versions-heading" className="text-base font-semibold">
          Versions
        </h2>
        <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
          Every version is kept. Opening one decrypts it and records that you did — it will appear
          in your own activity history.
        </p>
        <ul className="mt-3">
          {versions.map((version) => (
            <li
              key={version.version}
              className="flex flex-wrap items-start justify-between gap-3 border-b border-line py-3 last:border-b-0 sm:flex-nowrap"
            >
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">Version {version.version}</p>
                <p className="mt-1 text-[0.8125rem] text-ink-muted">
                  {formatDateTime(version.createdAt)} · {formatBytes(version.sizeBytes)} ·{' '}
                  {version.mime}
                </p>
              </div>
              <button
                type="button"
                className="btn btn-secondary shrink-0"
                disabled={content.kind === 'loading'}
                onClick={() => {
                  void read(version.version);
                }}
              >
                {content.kind === 'loading' && content.version === version.version
                  ? 'Opening…'
                  : 'Read'}
              </button>
            </li>
          ))}
        </ul>
      </section>

      <div role="status" aria-live="polite">
        {content.kind === 'failed' ? (
          <div className="card p-5">
            <p className="text-sm font-medium">Version {content.version} couldn’t be opened</p>
            <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">{content.message}</p>
          </div>
        ) : null}
      </div>

      {content.kind === 'ready' ? (
        <section aria-labelledby="content-heading" className="card p-5 sm:p-6">
          <h2 id="content-heading" className="text-base font-semibold">
            Version {content.content.version}
          </h2>
          <DocumentViewer content={content.content} />
        </section>
      ) : null}
    </div>
  );
}
