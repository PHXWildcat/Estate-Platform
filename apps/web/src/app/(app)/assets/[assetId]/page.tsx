import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { AssetDetailPanel } from '../../../../components/AssetDetailPanel';

/**
 * The title stays generic on purpose (the documents-page rule): the asset's
 * title is user-authored estate data and must not reach the browser tab,
 * window title, or a screen recording — the page already shows it.
 */
export const metadata: Metadata = { title: 'Asset' };

export default async function AssetPage({
  params,
}: {
  params: Promise<{ assetId: string }>;
}): Promise<ReactElement> {
  const { assetId } = await params;
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Asset</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Its record, its value over time, and the permanent history of every change.
          </p>
        </div>
        <Link className="btn btn-secondary" href="/assets">
          Back
        </Link>
      </div>
      <div className="mt-6">
        <AssetDetailPanel assetId={assetId} />
      </div>
    </div>
  );
}
