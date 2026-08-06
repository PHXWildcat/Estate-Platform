import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { DocumentGenerator } from '../../../../components/DocumentGenerator';

export const metadata: Metadata = { title: 'Create a document' };

export default function NewDocumentPage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Create a document</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Generated from a template reviewed for your state. A generated document is not in force
            until it has been signed with the formalities that state requires.
          </p>
        </div>
        <Link className="btn btn-secondary" href="/documents">
          Back
        </Link>
      </div>
      <div className="mt-6">
        <DocumentGenerator />
      </div>
    </div>
  );
}
