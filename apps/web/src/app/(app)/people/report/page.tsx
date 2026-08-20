import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { ReportDeathFlow } from '../../../../components/ReportDeathFlow';

export const metadata: Metadata = { title: 'Report a death' };

/**
 * The reporter's surface (M22 PR4c).
 *
 * A ROUTE OF ITS OWN AND NOT IN `AppNav`, for the reason `/security/cases`
 * gives and one more. That page is unlisted because it is empty for virtually
 * everybody and a standing "Death cases" item is a memento mori for ten
 * million people; this one is unlisted because a permanent "Report a death"
 * entry would advertise the PERMISSIVE action more prominently than any
 * protective one, which is the inversion this milestone exists to avoid.
 *
 * IT SITS UNDER /people, not under /security. Security is where a person
 * manages the protections on their OWN account — the waiting period, the kill
 * switch, the cases filed about them. This is about somebody else's estate,
 * and it is reached from the panel that already lists exactly those estates.
 * Putting it on the security page would mix two audiences on the one surface
 * that must never be ambiguous about which one it is addressing.
 *
 * NO ID IN THE URL. The estate is chosen on the page rather than passed as a
 * query parameter — the rule the operator console states for case ids, and it
 * applies harder here: a link naming whose death you were about to report
 * would sit in browser history and in any `Referer` that leaves the origin.
 */
export default function ReportDeathPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Report a death</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        If someone who named you in their plan has died, you can tell us here. We’ll review it
        ourselves before anything in their estate is released, and we’ll try to reach them first.{' '}
        <Link href="/people" className="font-medium text-ink underline underline-offset-4">
          Back to People
        </Link>
        .
      </p>
      <ReportDeathFlow />
    </div>
  );
}
