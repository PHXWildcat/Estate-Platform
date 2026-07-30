import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { AssetsPanel } from '../../../components/AssetsPanel';

export const metadata: Metadata = { title: 'Assets' };

export default function AssetsPage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Assets</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Every value encrypted at rest; every change kept as permanent, auditable history.
          </p>
        </div>
        <a className="btn btn-primary" href="#add-asset">
          Add asset
        </a>
      </div>
      <div className="mt-6">
        <AssetsPanel />
      </div>
    </div>
  );
}
