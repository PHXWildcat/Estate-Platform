import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { EstateSettlement } from '../../../../components/EstateSettlement';

/**
 * SETTLING ONE ESTATE (M23 PR2). Unlisted, like `/people/report`, and for a
 * related but distinct reason: that page is unlisted because a standing
 * "Report a death" entry advertises the permissive action, and this one
 * because a standing "Estates you're settling" entry is empty for virtually
 * everybody — the `/security/cases` argument. It is reached from the overview,
 * where an executor arrives every session.
 *
 * THE URL CARRIES A CASE ID AND NOTHING ELSE. No decedent user id, and no name
 * — a URL naming whose estate you are settling would sit in browser history
 * and in any `Referer` leaving the origin. Since M23 PR1 a case id names
 * something only to a caller with authority over it.
 */
export const metadata: Metadata = { title: 'Settling an estate' };

export default async function EstatePage({
  params,
}: {
  params: Promise<{ caseId: string }>;
}): Promise<ReactElement> {
  const { caseId } = await params;
  return (
    <div>
      <h1 className="text-[1.375rem] font-semibold tracking-tight">Settling an estate</h1>
      <p className="mt-1 max-w-prose text-sm text-ink-muted">
        You’ve been named executor. Access to the estate opens in stages, and our team reviews each
        one.
      </p>
      <div className="mt-6">
        <EstateSettlement caseId={caseId} />
      </div>
    </div>
  );
}
