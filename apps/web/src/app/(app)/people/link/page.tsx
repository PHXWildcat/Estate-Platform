import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { RedeemLinkPanel } from '../../../../components/RedeemLinkPanel';

export const metadata: Metadata = { title: 'Accept an invitation' };

export default function RedeemLinkPage(): ReactElement {
  return (
    <div>
      <h1 className="text-[1.375rem] font-semibold tracking-tight">Accept an invitation</h1>
      <p className="mt-1 max-w-prose text-sm text-ink-muted">
        If someone named you in their estate plan, they can give you a code that links this account
        to their record of you. They hand it to you directly — we never send codes.
      </p>
      <div className="mt-6">
        <RedeemLinkPanel />
      </div>
    </div>
  );
}
