import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { DocumentDetailPanel } from '../../../../components/DocumentDetailPanel';

/**
 * The title stays generic on purpose. `documents.title` is user-authored and
 * would otherwise reach the browser tab, the window title and any screen
 * recording — cheap disclosure for no benefit, since the page already shows it.
 */
export const metadata: Metadata = { title: 'Document' };

export default async function DocumentPage({
  params,
}: {
  params: Promise<{ documentId: string }>;
}): Promise<ReactElement> {
  const { documentId } = await params;
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Document</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Its history, and the contents of any version you choose to open.
          </p>
        </div>
        <Link className="btn btn-secondary" href="/documents">
          Back
        </Link>
      </div>
      <div className="mt-6">
        <DocumentDetailPanel documentId={documentId} />
      </div>
    </div>
  );
}
