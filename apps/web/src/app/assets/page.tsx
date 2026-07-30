import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { AssetsPanel } from '../../components/AssetsPanel';

export const metadata: Metadata = { title: 'Assets' };

export default function AssetsPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Assets</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        Your estate’s inventory. Every value is encrypted at rest, and every change is kept as a
        permanent, auditable history.
      </p>
      <AssetsPanel />
    </div>
  );
}
