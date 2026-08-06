'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type DocumentInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import {
  documentKindLabel,
  documentSourceLabel,
  executionStatusLabel,
  executionStatusMeaning,
  executionStatusTone,
  formatDateTime,
  sortDocuments,
} from '../lib/documents';
import { DocumentUpload } from './DocumentUpload';

/**
 * The document list (M12) — the first consumer of routes the service has had
 * since M4.
 *
 * NOTHING HERE DECRYPTS ANYTHING. Every content read downstream is an audited
 * KMS operation on the user's own trail (`crypto.field.decrypted` plus
 * `document.content.viewed`), so a list that previewed content would turn one
 * page load into one such event per document. The list shows metadata: title,
 * kind, status, when it last changed. Reading a document is a deliberate act on
 * its own page, and it produces exactly one audit event.
 *
 * THE STATUS IS THE POINT, not decoration. The readiness surface already tells
 * people "your will has not been executed"; this is where that stops being an
 * observation they cannot act on. So the chip carries a sentence — "Created but
 * not signed — it does not direct anything yet" — rather than leaving
 * "Generated" to be read as "done".
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; documents: DocumentInfo[] };

/**
 * Built as ONE string rather than interpolated JSX fragments, so it reaches the
 * DOM as a single text node: a sentence split across elements is a sentence a
 * screen reader can announce in pieces, and one a test can only match by
 * accident.
 */
function summaryLine(documents: readonly DocumentInfo[], inForce: number): string {
  if (documents.length === 0) {
    return 'Nothing on file yet.';
  }
  const pending = documents.length - inForce;
  if (pending === 0) {
    return 'Every document on file has been executed.';
  }
  const verb = pending === 1 ? 'it directs' : 'they direct';
  return `${pending} of ${documents.length} not executed yet, so ${verb} nothing.`;
}

function DocumentRow({ document }: { document: DocumentInfo }): ReactElement {
  const meaning = executionStatusMeaning(document.executionStatus);
  return (
    <li className="border-b border-line py-4 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 max-w-prose flex-1">
          <Link
            className="text-sm font-medium underline-offset-2 hover:underline"
            href={`/documents/${document.documentId}`}
          >
            {/* User-authored label, rendered as a text child — never as markup. */}
            {document.title}
          </Link>
          <p className="mt-1 text-[0.8125rem] text-ink-muted">
            {documentKindLabel(document.docType)} · {documentSourceLabel(document.source)} · updated{' '}
            {formatDateTime(document.updatedAt)}
          </p>
          {meaning.length > 0 ? (
            <p className="mt-1 text-[0.8125rem] text-ink-muted">{meaning}</p>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {document.legalHold ? <span className="chip chip-warn">Legal hold</span> : null}
          <span className={executionStatusTone(document.executionStatus)}>
            {executionStatusLabel(document.executionStatus)}
          </span>
        </div>
      </div>
    </li>
  );
}

/**
 * Encrypted search (M12 PR2), and it is worth knowing what it is not.
 *
 * The query becomes per-user HMAC tokens and matches ciphertext-side, so
 * NOTHING IS DECRYPTED to answer it — which is why searching, unlike reading,
 * produces no decrypt event. The cost of that design is stated where a user
 * meets it: matching is by whole indexed word, so "lake" finds the lake house
 * and "lak" finds nothing. There is no semantic search and no fuzzy match to
 * add later without an embedding index, which the platform deliberately does
 * not have (M10).
 */
const SEARCH_MIN_LENGTH = 3;

type SearchState =
  | { kind: 'off' }
  | { kind: 'searching' }
  | { kind: 'failed'; message: string }
  | { kind: 'results'; query: string; documents: DocumentInfo[] };

export function DocumentsPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState<SearchState>({ kind: 'off' });

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('Documents', {});
    if (result.ok) {
      /*
       * A WELL-FORMED RESPONSE MISSING ITS FIELD IS NOT DATA. `gqlRequest`
       * answers `ok` for any `data` object, so an ordinary version skew between
       * this app and the BFF arrives as `{"data":{}}` — which white-screened the
       * conversation surface in M11 before the same guard was added there. An
       * honest "we couldn't load this" beats a blank screen, and beats an empty
       * list that reads as "you have no documents".
       */
      if (Array.isArray(result.data.documents)) {
        setState({ kind: 'ready', documents: result.data.documents });
        return;
      }
      setState({ kind: 'error' });
      return;
    }
    setState(result.code === 'UNAUTHENTICATED' ? { kind: 'signedOut' } : { kind: 'error' });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function runSearch(event: FormEvent): Promise<void> {
    event.preventDefault();
    const trimmed = query.trim();
    if (trimmed.length === 0) {
      setSearch({ kind: 'off' });
      return;
    }
    if (trimmed.length < SEARCH_MIN_LENGTH) {
      // The server's own bound, said before the request rather than after.
      setSearch({
        kind: 'failed',
        message: `Search needs at least ${SEARCH_MIN_LENGTH} characters.`,
      });
      return;
    }
    setSearch({ kind: 'searching' });
    const result = await gqlRequest('DocumentSearch', { query: trimmed });
    if (!result.ok) {
      setSearch({ kind: 'failed', message: messageFor(result.code) });
      return;
    }
    if (!Array.isArray(result.data.documentSearch)) {
      setSearch({ kind: 'failed', message: messageFor('UNKNOWN') });
      return;
    }
    setSearch({ kind: 'results', query: trimmed, documents: result.data.documentSearch });
  }

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading your documents…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load your documents. Please try again in a moment — this is not a statement
          about what you have on file.
        </p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Your documents belong to your account. Sign in to see them.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
          <Link className="btn btn-secondary" href="/register">
            Create account
          </Link>
        </div>
      </div>
    );
  }

  const documents = sortDocuments(state.documents);
  const inForce = documents.filter((doc) => doc.executionStatus === 'executed').length;

  return (
    <div className="space-y-4">
      <section aria-label="Summary" className="card p-5">
        <h2 className="text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-ink-muted">
          In force
        </h2>
        <p className="mt-1.5 text-4xl font-semibold tabular-nums tracking-tight">{inForce}</p>
        <p className="mt-1.5 text-[0.8125rem] text-ink-muted">{summaryLine(documents, inForce)}</p>
      </section>

      <section aria-labelledby="documents-heading" className="card p-5 sm:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <h2 id="documents-heading" className="text-base font-semibold">
            {search.kind === 'results' ? `Matches for “${search.query}”` : 'Your documents'}
          </h2>
          <Link className="btn btn-primary" href="/documents/new">
            Create a document
          </Link>
        </div>

        <form
          className="mt-3 flex flex-wrap gap-2"
          noValidate
          onSubmit={(event) => {
            void runSearch(event);
          }}
        >
          <label className="sr-only" htmlFor="document-search">
            Search your documents
          </label>
          <input
            id="document-search"
            className="field-input max-w-[18rem] flex-1"
            placeholder="Search your documents"
            value={query}
            aria-describedby="document-search-hint"
            onChange={(event) => {
              setQuery(event.target.value);
              if (event.target.value.trim().length === 0) {
                setSearch({ kind: 'off' });
              }
            }}
          />
          <button
            type="submit"
            className="btn btn-secondary"
            disabled={search.kind === 'searching'}
          >
            {search.kind === 'searching' ? 'Searching…' : 'Search'}
          </button>
          {search.kind === 'results' ? (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setQuery('');
                setSearch({ kind: 'off' });
              }}
            >
              Clear
            </button>
          ) : null}
        </form>
        <p id="document-search-hint" className="field-hint">
          Searching never decrypts anything — it matches encrypted keywords, so it finds whole words
          rather than parts of them.
        </p>

        <div role="status" aria-live="polite">
          {search.kind === 'failed' ? (
            <p className="mt-2 text-sm text-danger">{search.message}</p>
          ) : null}
        </div>

        {renderList(search.kind === 'results' ? search.documents : documents, search)}
      </section>

      <DocumentUpload
        onUploaded={() => {
          // Re-read from the server rather than appending locally: what the
          // service stored is the record, and an upload can change the list in
          // ways this component did not predict.
          void load();
        }}
      />
    </div>
  );
}

/**
 * The list body, for both the full list and a result set. A search that matched
 * nothing says exactly that — never the empty-estate copy, which would be a
 * claim about the account rather than about the query.
 */
function renderList(documents: readonly DocumentInfo[], search: SearchState): ReactElement {
  if (documents.length === 0) {
    return (
      <p className="mt-3 max-w-prose text-[0.8125rem] text-ink-muted">
        {search.kind === 'results'
          ? 'Nothing matched. Encrypted search matches whole words, so try a different one.'
          : 'Nothing on file yet. Documents you create here are encrypted with a key of their own, and only you can read them.'}
      </p>
    );
  }
  return (
    <ul className="mt-3">
      {documents.map((document) => (
        <DocumentRow key={document.documentId} document={document} />
      ))}
    </ul>
  );
}
