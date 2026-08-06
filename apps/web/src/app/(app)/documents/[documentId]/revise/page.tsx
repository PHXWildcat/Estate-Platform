import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { DocumentRevisePanel } from '../../../../../components/DocumentRevisePanel';

export const metadata: Metadata = { title: 'New version' };

export default async function ReviseDocumentPage({
  params,
}: {
  params: Promise<{ documentId: string }>;
}): Promise<ReactElement> {
  const { documentId } = await params;
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">New version</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            The previous version is kept. Your earlier answers were never stored, so this asks for
            them again — the encrypted document is the record, not the form you filled in.
          </p>
        </div>
        <Link className="btn btn-secondary" href={`/documents/${documentId}`}>
          Back
        </Link>
      </div>
      <div className="mt-6">
        <DocumentRevisePanel documentId={documentId} />
      </div>
    </div>
  );
}
