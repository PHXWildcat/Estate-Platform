import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { DocumentsPanel } from '../../../components/DocumentsPanel';

export const metadata: Metadata = { title: 'Documents' };

export default function DocumentsPage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Documents</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Each document is encrypted under a key of its own, so erasing one erases exactly it.
            Creating a document is a fact about your account, not legal advice.
          </p>
        </div>
      </div>
      <div className="mt-6">
        <DocumentsPanel />
      </div>
    </div>
  );
}
