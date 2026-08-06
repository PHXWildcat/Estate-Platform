'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type ReactElement } from 'react';
import { gqlRequest, type DocumentInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { DocumentGenerator } from './DocumentGenerator';

/**
 * Resolves which document is being revised, then hands the same generator the
 * revise target (M12).
 *
 * It exists because the generator needs the document's KIND to offer only
 * templates that could produce a new version of THIS instrument — the service
 * refuses a mismatched template anyway, and a picker that lets you choose one
 * it will refuse is a UI that teaches people to distrust it.
 *
 * IT ALSO REFUSES BEFORE THE FORM RATHER THAN AFTER. Regeneration is rejected
 * downstream once signing has started, so a signed document gets an explanation
 * here instead of a filled-in questionnaire and a 409.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'unavailable'; message: string }
  | { kind: 'refused'; document: DocumentInfo }
  | { kind: 'ready'; document: DocumentInfo };

export interface DocumentRevisePanelProps {
  readonly documentId: string;
}

export function DocumentRevisePanel({ documentId }: DocumentRevisePanelProps): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  const load = useCallback(async (): Promise<void> => {
    const result = await gqlRequest('Document', { documentId });
    if (!result.ok) {
      setState({ kind: 'unavailable', message: messageFor(result.code) });
      return;
    }
    // A response missing its field is not data (the M11 rule).
    const document = result.data.document;
    if (typeof document?.documentId !== 'string') {
      setState({ kind: 'unavailable', message: messageFor('UNKNOWN') });
      return;
    }
    const revisable =
      document.source === 'generated' &&
      (document.executionStatus === 'draft' || document.executionStatus === 'generated');
    setState(revisable ? { kind: 'ready', document } : { kind: 'refused', document });
  }, [documentId]);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading this document…</p>
      </div>
    );
  }

  if (state.kind === 'unavailable') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">{state.message}</p>
        <Link className="btn btn-secondary mt-4" href="/documents">
          Back to documents
        </Link>
      </div>
    );
  }

  if (state.kind === 'refused') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm font-medium">This document can’t be revised</p>
        <p className="mt-1 max-w-prose text-[0.8125rem] text-ink-muted">
          {state.document.source === 'generated'
            ? messageFor('DOCUMENT_NOT_EDITABLE')
            : 'It was uploaded rather than generated here, so there is no template to re-render it from.'}
        </p>
        <Link className="btn btn-secondary mt-4" href={`/documents/${documentId}`}>
          Back to the document
        </Link>
      </div>
    );
  }

  return (
    <DocumentGenerator
      revise={{
        documentId: state.document.documentId,
        docType: state.document.docType,
        title: state.document.title,
      }}
    />
  );
}
